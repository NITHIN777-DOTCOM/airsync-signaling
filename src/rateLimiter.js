import { config } from './config.js';

/**
 * Fixed-window connection-attempt limiter keyed by remote address, plus a live count of
 * concurrent sockets per address.
 *
 * Deliberately in-memory and per-instance: this is a cheap guard against a single host
 * hammering the relay, not a distributed quota system. On Fly.io with several machines
 * each enforces its own budget, which is fine for the threat it addresses.
 */
export class RateLimiter {
  #windows = new Map(); // ip -> { count, resetAt }
  #active = new Map(); // ip -> concurrent socket count

  /** Records an attempt. Returns true when the address is over its window budget. */
  isRateLimited(ip) {
    const now = Date.now();
    const entry = this.#windows.get(ip);

    if (!entry || now >= entry.resetAt) {
      this.#windows.set(ip, { count: 1, resetAt: now + config.rateLimitWindowMs });
      return false;
    }

    entry.count += 1;
    return entry.count > config.rateLimitMaxAttempts;
  }

  /** Whether this address already holds the maximum allowed concurrent sockets. */
  isAtConnectionLimit(ip) {
    return (this.#active.get(ip) ?? 0) >= config.maxConnectionsPerIp;
  }

  addConnection(ip) {
    this.#active.set(ip, (this.#active.get(ip) ?? 0) + 1);
  }

  removeConnection(ip) {
    const next = (this.#active.get(ip) ?? 1) - 1;
    if (next <= 0) this.#active.delete(ip);
    else this.#active.set(ip, next);
  }

  /** Drops expired windows so the map cannot grow without bound. */
  sweep() {
    const now = Date.now();
    for (const [ip, entry] of this.#windows) {
      if (now >= entry.resetAt) this.#windows.delete(ip);
    }
  }

  stats() {
    return { trackedWindows: this.#windows.size, trackedAddresses: this.#active.size };
  }
}
