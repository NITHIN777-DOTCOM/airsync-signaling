import crypto from 'node:crypto';
import WebSocket from 'ws';

/**
 * A stand-in for a real AirSync device, used by the test scenario.
 *
 * It generates the same kind of key the real clients use (EC P-256, DER-encoded ECDSA
 * signatures) so the handshake exercised here is the genuine one — the signaling server
 * cannot tell this apart from the Android or desktop client.
 *
 * Every frame on this connection is JSON text: the server carries only WebRTC signaling
 * (SDP offers/answers, ICE candidates), never media, so there is no binary channel.
 */
export class TestClient {
  constructor(label, url) {
    this.label = label;
    this.url = url;

    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    this.privateKey = privateKey;
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    this.publicKeyB64 = spki.toString('base64');
    this.fingerprint = fingerprintOf(spki);

    this.ws = null;
    this.controlMessages = [];
    this.waiters = [];
    this.closeInfo = null;
  }

  connect() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.url);

      this.ws.on('open', resolve);
      this.ws.on('error', (err) => {
        if (!this.closeInfo) reject(err);
      });

      // A message is either handed to a waiter that is already blocked on it, or
      // buffered for a later wait -- never both, or it would be delivered twice.
      this.ws.on('message', (data) => {
        const msg = JSON.parse(data.toString('utf8'));
        if (!this.#notify({ kind: 'control', payload: msg })) this.controlMessages.push(msg);
      });

      this.ws.on('close', (code, reasonBuf) => {
        this.closeInfo = { code, reason: reasonBuf.toString('utf8') };
        this.#notify({ kind: 'close', payload: this.closeInfo });
      });
    });
  }

  /** Completes the challenge/response handshake, targeting `targetFingerprint`. */
  async authenticate(targetFingerprint, { corruptSignature = false } = {}) {
    const challenge = await this.waitForControl('challenge');
    const nonce = Buffer.from(challenge.nonce, 'base64');

    // Same primitive both real clients use: ECDSA over SHA-256, DER-encoded.
    let signature = crypto.sign('sha256', nonce, {
      key: this.privateKey,
      dsaEncoding: 'der'
    });

    if (corruptSignature) {
      // Sign a different nonce -- structurally valid, cryptographically wrong.
      signature = crypto.sign('sha256', crypto.randomBytes(32), {
        key: this.privateKey,
        dsaEncoding: 'der'
      });
    }

    this.send({
      type: 'auth',
      publicKey: this.publicKeyB64,
      signature: signature.toString('base64'),
      target: targetFingerprint
    });
  }

  send(obj) {
    this.ws.send(JSON.stringify(obj));
  }

  /** Sends a WebRTC signaling frame addressed to `target`. */
  sendOffer(target, sdp) {
    this.send({ type: 'offer', target, sdp });
  }

  sendAnswer(target, sdp) {
    this.send({ type: 'answer', target, sdp });
  }

  sendIceCandidate(target, candidate) {
    this.send({ type: 'ice-candidate', target, candidate });
  }

  /** Resolves with the next (or already-buffered) control message of `type`. */
  waitForControl(type, timeoutMs = 5000) {
    const existing = this.controlMessages.find((m) => m.type === type);
    if (existing) {
      this.controlMessages = this.controlMessages.filter((m) => m !== existing);
      return Promise.resolve(existing);
    }
    return this.#wait(
      (evt) => evt.kind === 'control' && evt.payload.type === type,
      timeoutMs,
      `control "${type}"`
    );
  }

  /** Resolves with { code, reason } once the socket closes. */
  waitForClose(timeoutMs = 5000) {
    if (this.closeInfo) return Promise.resolve(this.closeInfo);
    return this.#wait((evt) => evt.kind === 'close', timeoutMs, 'close');
  }

  close() {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.close();
  }

  terminate() {
    if (this.ws) this.ws.terminate();
  }

  #wait(predicate, timeoutMs, description) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiters = this.waiters.filter((w) => w !== waiter);
        reject(new Error(`[${this.label}] timed out after ${timeoutMs}ms waiting for ${description}`));
      }, timeoutMs);

      const waiter = {
        matches: predicate,
        resolve: (payload) => {
          clearTimeout(timer);
          resolve(payload);
        }
      };
      this.waiters.push(waiter);
    });
  }

  /**
   * Hands `evt` to the first waiter whose predicate matches, removing it.
   * Returns whether a waiter consumed the event.
   */
  #notify(evt) {
    const index = this.waiters.findIndex((waiter) => waiter.matches(evt));
    if (index === -1) return false;
    const [waiter] = this.waiters.splice(index, 1);
    waiter.resolve(evt.payload);
    return true;
  }
}

/** Mirrors the fingerprint format used by the server and both real clients. */
export function fingerprintOf(spkiDer) {
  const digest = crypto.createHash('sha256').update(spkiDer).digest();
  return Array.from(digest.subarray(0, 8))
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(':');
}
