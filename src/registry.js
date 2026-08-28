import { log } from './logger.js';

/**
 * Tracks authenticated clients by fingerprint and decides when two of them form a
 * relay pair.
 *
 * Pairing requires *mutual* targeting: A must name B as its target and B must name A.
 * A one-sided request never opens a pipe, so a client cannot attach itself to a peer
 * that did not ask for it.
 *
 * Nothing here holds payload data. The registry only knows who is connected and who
 * each side is waiting for.
 */
export class Registry {
  #byFingerprint = new Map(); // fingerprint -> session

  /**
   * Registers an authenticated session. If that fingerprint is already connected the
   * older session is returned so the caller can evict it — one live connection per
   * identity keeps pairing unambiguous.
   */
  register(session) {
    const existing = this.#byFingerprint.get(session.fingerprint);
    this.#byFingerprint.set(session.fingerprint, session);
    return existing && existing !== session ? existing : null;
  }

  unregister(session) {
    const current = this.#byFingerprint.get(session.fingerprint);
    // Guard against a stale session evicting the socket that replaced it.
    if (current === session) this.#byFingerprint.delete(session.fingerprint);
  }

  get(fingerprint) {
    return this.#byFingerprint.get(fingerprint) ?? null;
  }

  /**
   * Attempts to pair `session` with the peer it is targeting.
   *
   * Returns the peer session when a mutual match is found and both were free, else
   * null. Mutating both sides here (rather than in the caller) keeps the paired state
   * of the two sessions from ever diverging.
   */
  tryPair(session) {
    if (session.peer) return null;

    const candidate = this.#byFingerprint.get(session.targetFingerprint);
    if (!candidate || candidate === session) return null;
    if (candidate.peer) return null;
    if (candidate.targetFingerprint !== session.fingerprint) return null;

    session.peer = candidate;
    candidate.peer = session;
    return candidate;
  }

  /** Breaks the pairing on both sides, returning the former peer (or null). */
  unpair(session) {
    const peer = session.peer;
    if (!peer) return null;
    session.peer = null;
    if (peer.peer === session) peer.peer = null;
    return peer;
  }

  get size() {
    return this.#byFingerprint.size;
  }

  stats() {
    let paired = 0;
    for (const session of this.#byFingerprint.values()) {
      if (session.peer) paired += 1;
    }
    return { authenticated: this.#byFingerprint.size, pairedSessions: paired };
  }

  /** Closes every tracked session — used on graceful shutdown. */
  closeAll(code, reason) {
    for (const session of this.#byFingerprint.values()) {
      try {
        session.socket.close(code, reason);
      } catch (err) {
        log.warn('shutdown_close_failed', { connId: session.connId, error: err.message });
      }
    }
    this.#byFingerprint.clear();
  }
}
