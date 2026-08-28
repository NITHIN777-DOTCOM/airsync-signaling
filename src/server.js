import http from 'node:http';
import crypto from 'node:crypto';
import { WebSocketServer } from 'ws';

import { config, CloseCode } from './config.js';
import { log } from './logger.js';
import { Registry } from './registry.js';
import { RateLimiter } from './rateLimiter.js';
import { handleTurnCredentialsRequest } from './turn.js';
import {
  parsePublicKey,
  fingerprintOf,
  isValidFingerprint,
  verifyChallengeSignature,
  generateChallenge
} from './identity.js';

/**
 * Wire protocol
 * -------------
 * Every frame is a JSON *text* frame. There is no binary channel: this server carries
 * only WebRTC signaling metadata (SDP offers/answers and ICE candidates), and the media
 * itself flows peer-to-peer over the connection those messages negotiate.
 *
 *   server -> client
 *     { type: "challenge",          nonce, expiresInMs }
 *     { type: "authenticated",      fingerprint, target }
 *     { type: "peer-connected",     peer }
 *     { type: "peer-not-connected", peer }
 *     { type: "peer-disconnected",  peer }
 *     { type: "error",              reason }
 *     { type: "pong" }
 *
 *   client -> server
 *     { type: "auth",          publicKey, signature, target }
 *     { type: "ping" }
 *     { type: "offer",         target, sdp }
 *     { type: "answer",        target, sdp }
 *     { type: "ice-candidate", target, candidate }
 *
 * Handshake: connect -> server sends `challenge` -> client signs the raw nonce bytes
 * with its device private key and replies `auth` -> server verifies and replies
 * `authenticated`, then either `peer-connected` (mutual target already waiting) or
 * `peer-not-connected`.
 *
 * Signaling: once paired, `offer` / `answer` / `ice-candidate` frames are forwarded
 * verbatim to the paired peer. If the peer is not connected the sender gets
 * `{ type: "error", reason: "target device offline" }` and nothing is queued.
 */

const State = {
  AWAITING_AUTH: 'awaiting_auth',
  AUTHENTICATED: 'authenticated',
  PAIRED: 'paired',
  CLOSED: 'closed'
};

/** Signaling frames this server will forward between paired peers. */
const RELAYABLE_TYPES = new Set(['offer', 'answer', 'ice-candidate']);

/**
 * Outbound buffer ceiling per socket. A peer that cannot drain as fast as its partner
 * sends would otherwise grow this process's memory without bound, so the session is
 * dropped instead. Nothing is buffered to disk — the server never holds signaling data.
 */
const MAX_BUFFERED_BYTES = 32 * 1024 * 1024;

export function createSignalingServer() {
  const registry = new Registry();
  const rateLimiter = new RateLimiter();
  const sockets = new Set();

  const httpServer = http.createServer((req, res) => {
    // Plain HTTP surface, intentionally separate from the WebSocket upgrade path so
    // Railway's health checks never touch signaling logic.
    if (req.method === 'GET' && (req.url === '/health' || req.url === '/health/')) {
      const body = JSON.stringify({
        status: 'ok',
        uptimeSeconds: Math.round(process.uptime()),
        connections: sockets.size,
        ...registry.stats()
      });
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(body);
      return;
    }

    // Authenticated ICE/TURN credential lookup. Auth (signed challenge) is enforced
    // inside the handler; this route is otherwise independent of the signaling logic.
    const turnUrl = safeUrl(req.url);
    if (req.method === 'GET' && turnUrl && turnUrl.pathname === '/turn-credentials') {
      return handleTurnCredentialsRequest(res, turnUrl, clientIp(req));
    }

    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'error', reason: 'not_found' }));
  });

  const wss = new WebSocketServer({ noServer: true, maxPayload: config.maxPayloadBytes });

  httpServer.on('upgrade', (req, socket, head) => {
    const ip = clientIp(req);
    const url = safeUrl(req.url);

    if (!url || url.pathname !== config.wsPath) {
      log.warn('upgrade_rejected', { ip, reason: 'bad_path', path: url?.pathname ?? null });
      return rejectUpgrade(socket, 404, 'Not Found');
    }

    if (sockets.size >= config.maxConnections) {
      log.warn('upgrade_rejected', { ip, reason: 'server_full', connections: sockets.size });
      return rejectUpgrade(socket, 503, 'Service Unavailable');
    }

    if (rateLimiter.isRateLimited(ip)) {
      log.warn('upgrade_rejected', { ip, reason: 'rate_limited' });
      return rejectUpgrade(socket, 429, 'Too Many Requests');
    }

    if (rateLimiter.isAtConnectionLimit(ip)) {
      log.warn('upgrade_rejected', { ip, reason: 'per_ip_limit' });
      return rejectUpgrade(socket, 429, 'Too Many Requests');
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
      handleConnection(ws, ip);
    });
  });

  function handleConnection(ws, ip) {
    const session = {
      connId: crypto.randomBytes(4).toString('hex'),
      ip,
      socket: ws,
      state: State.AWAITING_AUTH,
      challenge: generateChallenge(),
      challengeIssuedAt: Date.now(),
      publicKeyB64: null,
      fingerprint: null,
      targetFingerprint: null,
      peer: null,
      lastSeen: Date.now(),
      messagesIn: 0,
      messagesRelayed: 0,
      timers: { auth: null, unpaired: null }
    };

    sockets.add(session);
    rateLimiter.addConnection(ip);
    log.info('connection_open', { connId: session.connId, ip, connections: sockets.size });

    send(session, {
      type: 'challenge',
      nonce: session.challenge.toString('base64'),
      expiresInMs: config.challengeTtlMs
    });

    session.timers.auth = setTimeout(() => {
      log.warn('auth_timeout', { connId: session.connId, ip });
      closeSession(session, CloseCode.AUTH_TIMEOUT, 'auth timeout');
    }, config.authTimeoutMs);

    ws.on('message', (data, isBinary) => {
      session.lastSeen = Date.now();
      if (isBinary) {
        log.warn('bad_control_frame', { connId: session.connId, reason: 'binary_frame' });
        return closeSession(session, CloseCode.BAD_MESSAGE, 'binary frames not supported');
      }
      handleControl(session, data);
    });

    ws.on('pong', () => {
      session.lastSeen = Date.now();
    });

    ws.on('error', (err) => {
      log.warn('socket_error', { connId: session.connId, error: err.message });
    });

    ws.on('close', (code) => {
      teardown(session, code);
    });
  }

  /** JSON frames. Auth/ping are handled here; signaling frames are forwarded to the peer. */
  function handleControl(session, data) {
    let message;
    try {
      message = JSON.parse(data.toString('utf8'));
    } catch {
      log.warn('bad_control_frame', { connId: session.connId, reason: 'invalid_json' });
      return closeSession(session, CloseCode.BAD_MESSAGE, 'invalid json');
    }

    if (!message || typeof message.type !== 'string') {
      return closeSession(session, CloseCode.BAD_MESSAGE, 'missing type');
    }

    if (message.type === 'auth') return handleAuth(session, message);
    if (message.type === 'ping') return send(session, { type: 'pong' });
    if (RELAYABLE_TYPES.has(message.type)) return handleSignal(session, message);

    log.warn('unknown_control_type', { connId: session.connId, type: message.type });
    return send(session, { type: 'error', reason: 'unknown_message_type' });
  }

  /**
   * Verifies the signed challenge, then registers the session and attempts to pair.
   *
   * The server's only question is "does this connection control the private key behind
   * this public key?". It intentionally has no list of permitted devices: which two
   * devices may talk was settled during local pairing, and duplicating that here would
   * mean maintaining a central registry the design explicitly avoids.
   */
  function handleAuth(session, message) {
    if (session.state !== State.AWAITING_AUTH) {
      return closeSession(session, CloseCode.BAD_MESSAGE, 'already authenticated');
    }

    if (Date.now() - session.challengeIssuedAt > config.challengeTtlMs) {
      log.warn('auth_failed', { connId: session.connId, ip: session.ip, reason: 'challenge_expired' });
      return closeSession(session, CloseCode.AUTH_FAILED, 'challenge expired');
    }

    const publicKey = parsePublicKey(message.publicKey);
    if (!publicKey) {
      log.warn('auth_failed', { connId: session.connId, ip: session.ip, reason: 'invalid_public_key' });
      return closeSession(session, CloseCode.AUTH_FAILED, 'invalid public key');
    }

    if (!verifyChallengeSignature(publicKey, session.challenge, message.signature)) {
      log.warn('auth_failed', { connId: session.connId, ip: session.ip, reason: 'bad_signature' });
      return closeSession(session, CloseCode.AUTH_FAILED, 'signature verification failed');
    }

    const fingerprint = fingerprintOf(message.publicKey);
    const target = message.target;

    if (!isValidFingerprint(target)) {
      log.warn('auth_failed', { connId: session.connId, fingerprint, reason: 'invalid_target' });
      return closeSession(session, CloseCode.AUTH_FAILED, 'invalid target fingerprint');
    }
    if (target === fingerprint) {
      log.warn('auth_failed', { connId: session.connId, fingerprint, reason: 'self_target' });
      return closeSession(session, CloseCode.AUTH_FAILED, 'cannot target self');
    }

    clearTimeout(session.timers.auth);
    session.timers.auth = null;
    session.state = State.AUTHENTICATED;
    session.publicKeyB64 = message.publicKey;
    session.fingerprint = fingerprint;
    session.targetFingerprint = target;

    // One live connection per identity, so pairing is never ambiguous.
    const displaced = registry.register(session);
    if (displaced) {
      log.info('session_replaced', { connId: displaced.connId, fingerprint });
      closeSession(displaced, CloseCode.REPLACED, 'replaced by newer connection');
    }

    log.info('auth_ok', {
      connId: session.connId,
      ip: session.ip,
      fingerprint,
      target
    });

    send(session, { type: 'authenticated', fingerprint, target });

    const peer = registry.tryPair(session);
    if (peer) {
      establishPair(session, peer);
      return;
    }

    // No peer right now. Say so plainly and hold the socket briefly in case the peer
    // is a moment behind — nothing is queued, and the timer below reaps it.
    send(session, { type: 'peer-not-connected', peer: target });
    log.info('peer_not_connected', { connId: session.connId, fingerprint, target });

    session.timers.unpaired = setTimeout(() => {
      log.info('unpaired_timeout', { connId: session.connId, fingerprint, target });
      closeSession(session, CloseCode.PEER_NOT_CONNECTED, 'peer not connected');
    }, config.unpairedTimeoutMs);
  }

  function establishPair(a, b) {
    for (const s of [a, b]) {
      if (s.timers.unpaired) {
        clearTimeout(s.timers.unpaired);
        s.timers.unpaired = null;
      }
      s.state = State.PAIRED;
    }

    send(a, { type: 'peer-connected', peer: b.fingerprint });
    send(b, { type: 'peer-connected', peer: a.fingerprint });

    log.info('signaling_pair_established', {
      connIds: [a.connId, b.connId],
      fingerprints: [a.fingerprint, b.fingerprint]
    });
  }

  /**
   * Forwards a WebRTC signaling frame (`offer` / `answer` / `ice-candidate`) to the
   * paired peer, verbatim. The server does not parse or transform the SDP or the
   * candidate — it only checks that the sender is paired and that the frame is
   * addressed to the peer it is actually paired with.
   */
  function handleSignal(session, message) {
    if (session.state !== State.PAIRED || !session.peer) {
      return send(session, { type: 'error', reason: 'target device offline' });
    }

    const target = message.target;
    if (!isValidFingerprint(target)) {
      return send(session, { type: 'error', reason: 'invalid target fingerprint' });
    }
    if (target !== session.peer.fingerprint) {
      return send(session, { type: 'error', reason: 'target device offline' });
    }

    const peer = session.peer;
    if (peer.socket.readyState !== peer.socket.OPEN) {
      return closeSession(session, CloseCode.PEER_DISCONNECTED, 'peer disconnected');
    }

    // Slow-consumer guard: drop the session rather than let the outbound buffer grow
    // without bound.
    if (peer.socket.bufferedAmount > MAX_BUFFERED_BYTES) {
      log.warn('backpressure_limit', {
        connId: peer.connId,
        fingerprint: peer.fingerprint,
        bufferedBytes: peer.socket.bufferedAmount
      });
      closeSession(peer, CloseCode.IDLE_TIMEOUT, 'peer too slow');
      return;
    }

    session.messagesIn += 1;
    session.messagesRelayed += 1;
    peer.lastSeen = Date.now();

    // Forwarded verbatim: the exact object the sender sent, including `target`, so the
    // receiver can tell which device the frame came from via its own pairing.
    peer.socket.send(JSON.stringify(message));
  }

  function send(session, payload) {
    if (session.socket.readyState !== session.socket.OPEN) return;
    try {
      session.socket.send(JSON.stringify(payload));
    } catch (err) {
      log.warn('control_send_failed', { connId: session.connId, error: err.message });
    }
  }

  function closeSession(session, code, reason) {
    if (session.state === State.CLOSED) return;
    try {
      session.socket.close(code, reason);
    } catch {
      try {
        session.socket.terminate();
      } catch {
        /* already gone */
      }
    }
  }

  /**
   * Single teardown path for a socket, whatever caused it. Critically, this also closes
   * the paired peer so a signaling session can never be left half-open.
   */
  function teardown(session, closeCode) {
    if (session.state === State.CLOSED) return;
    const previousState = session.state;
    session.state = State.CLOSED;

    for (const key of Object.keys(session.timers)) {
      if (session.timers[key]) {
        clearTimeout(session.timers[key]);
        session.timers[key] = null;
      }
    }

    sockets.delete(session);
    rateLimiter.removeConnection(session.ip);

    const peer = registry.unpair(session);
    if (session.fingerprint) registry.unregister(session);

    log.info('connection_close', {
      connId: session.connId,
      ip: session.ip,
      fingerprint: session.fingerprint,
      previousState,
      closeCode,
      messagesRelayed: session.messagesRelayed,
      connections: sockets.size
    });

    if (peer) {
      log.info('signaling_pair_closed', {
        connIds: [session.connId, peer.connId],
        fingerprints: [session.fingerprint, peer.fingerprint],
        cause: 'peer_disconnected'
      });
      send(peer, { type: 'peer-disconnected', peer: session.fingerprint });
      closeSession(peer, CloseCode.PEER_DISCONNECTED, 'peer disconnected');
    }
  }

  // Heartbeat: ping every live socket and reap anything that has gone quiet past the
  // idle window. Also sweeps expired rate-limit windows.
  const heartbeat = setInterval(() => {
    const now = Date.now();
    for (const session of sockets) {
      if (now - session.lastSeen > config.idleTimeoutMs) {
        log.info('idle_timeout', {
          connId: session.connId,
          fingerprint: session.fingerprint,
          idleMs: now - session.lastSeen
        });
        closeSession(session, CloseCode.IDLE_TIMEOUT, 'idle timeout');
        continue;
      }
      if (session.socket.readyState === session.socket.OPEN) {
        try {
          session.socket.ping();
        } catch {
          /* closing anyway */
        }
      }
    }
    rateLimiter.sweep();
  }, config.heartbeatIntervalMs);
  heartbeat.unref?.();

  function listen() {
    return new Promise((resolve) => {
      httpServer.listen(config.port, config.host, () => {
        const addr = httpServer.address();
        log.info('server_listening', {
          host: config.host,
          port: addr.port,
          wsPath: config.wsPath,
          healthPath: '/health',
          maxConnections: config.maxConnections,
          maxPayloadBytes: config.maxPayloadBytes
        });
        resolve(addr);
      });
    });
  }

  async function close() {
    clearInterval(heartbeat);
    registry.closeAll(CloseCode.SERVER_SHUTDOWN, 'server shutting down');
    for (const session of sockets) {
      closeSession(session, CloseCode.SERVER_SHUTDOWN, 'server shutting down');
    }
    wss.close();
    await new Promise((resolve) => httpServer.close(resolve));
    log.info('server_closed', {});
  }

  return { httpServer, listen, close, registry, sockets };
}

function rejectUpgrade(socket, statusCode, statusText) {
  try {
    socket.write(`HTTP/1.1 ${statusCode} ${statusText}\r\nConnection: close\r\n\r\n`);
  } catch {
    /* peer already gone */
  }
  socket.destroy();
}

function safeUrl(rawUrl) {
  try {
    return new URL(rawUrl, 'http://placeholder');
  } catch {
    return null;
  }
}

/**
 * Railway terminates TLS at its edge and passes the real client address in
 * `x-forwarded-for` (comma-separated, client first), so prefer it when present and fall
 * back to the socket address for local runs. Only ever used for rate limiting and log
 * correlation — never for trust.
 */
function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    const first = forwarded.split(',')[0].trim();
    if (first) return first;
  }
  return req.socket.remoteAddress ?? 'unknown';
}
