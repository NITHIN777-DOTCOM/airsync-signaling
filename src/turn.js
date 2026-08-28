import { config } from './config.js';
import { log } from './logger.js';
import { parsePublicKey, verifyChallengeSignature, fingerprintOf } from './identity.js';

/**
 * `GET /turn-credentials`
 * ----------------------
 * Hands an authenticated device the ICE server list it needs to set up a WebRTC
 * connection — the public STUN URL always, and credentialed TURN URLs when this
 * deployment can source TURN credentials.
 *
 * Credential sourcing (tried in order, see {@link resolveTurnCredentials}):
 *   1. dynamic       — mint a short-lived pair from Metered's REST API (METERED_API_KEY)
 *   2. static-fallback — the fixed TURN_USERNAME / TURN_PASSWORD env pair
 *   3. stun-only     — neither available; the response carries just the STUN entry
 *
 * Auth reuses the same primitives as the WebSocket handshake (src/identity.js): the
 * caller proves control of its device private key by signing a challenge. Because this
 * is a plain GET with no prior server round-trip, the challenge is the caller's own
 * current timestamp; the server accepts it only within `config.turnAuthWindowMs`, which
 * bounds replay. Unauthenticated callers get 401 and never see credentials.
 *
 * Query parameters:
 *   publicKey  - base64 X.509 SPKI DER, EC P-256 (the device id, same as the WS `auth`)
 *   timestamp  - unix epoch milliseconds, as a string
 *   signature  - base64 DER ECDSA/SHA-256 over the UTF-8 bytes of `timestamp`
 */

/**
 * Builds the iceServers array. STUN first, always. The four TURN entries are appended
 * only when a credential pair was resolved — a missing pair degrades to STUN-only
 * rather than erroring, since TURN is a fallback for when direct/STUN P2P fails.
 *
 * @param {{username: string, credential: string}|null} creds
 */
export function buildIceServers(creds) {
  const { turn } = config;
  const iceServers = [{ urls: turn.stunUrl }];

  if (creds && creds.username && creds.credential) {
    for (const urls of turn.turnUrls) {
      iceServers.push({ urls, username: creds.username, credential: creds.credential });
    }
  }

  return iceServers;
}

/**
 * Calls Metered's "Create TURN Credential" API to mint a fresh, auto-expiring
 * username/password pair. Returns null on any problem (no key, non-2xx, timeout,
 * malformed body) so the caller can fall back — a failure here must never surface as a
 * request error.
 *
 * The call is bounded by `config.metered.apiTimeoutMs` via an AbortController, so a
 * hung upstream cannot stall the `/turn-credentials` response.
 */
async function fetchDynamicTurnCredentials() {
  const { metered } = config;
  if (!metered.apiKey) return null;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), metered.apiTimeoutMs);

  try {
    const url = `${metered.apiUrl}?secretKey=${encodeURIComponent(metered.apiKey)}`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ expiryInSeconds: metered.credentialTtlSeconds }),
      signal: controller.signal
    });

    if (!response.ok) {
      log.warn('turn_metered_api_failed', { reason: 'http_error', status: response.status });
      return null;
    }

    const data = await response.json().catch(() => null);
    // Metered returns { username, password, expiryInSeconds, ... }; accept a couple of
    // credential field spellings defensively.
    const username = data && typeof data.username === 'string' ? data.username : null;
    const credential =
      data && (data.password || data.credential || data.key || null);

    if (!username || !credential) {
      log.warn('turn_metered_api_failed', { reason: 'missing_fields_in_response' });
      return null;
    }

    return {
      username,
      credential,
      ttlSeconds: Number(data.expiryInSeconds) || metered.credentialTtlSeconds
    };
  } catch (err) {
    const reason = err && err.name === 'AbortError' ? 'timeout' : 'request_error';
    log.warn('turn_metered_api_failed', { reason });
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Resolves the TURN credential pair to serve, and how it was obtained.
 * @returns {Promise<{source: 'dynamic'|'static-fallback'|'stun-only',
 *                     username: string|null, credential: string|null,
 *                     ttlSeconds?: number}>}
 */
async function resolveTurnCredentials() {
  const dynamic = await fetchDynamicTurnCredentials();
  if (dynamic) {
    return { source: 'dynamic', ...dynamic };
  }

  const { turn } = config;
  if (turn.username && turn.credential) {
    return { source: 'static-fallback', username: turn.username, credential: turn.credential };
  }

  return { source: 'stun-only', username: null, credential: null };
}

function deny(res, status, reason) {
  const body = JSON.stringify({ status: 'error', reason });
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(body);
}

/**
 * Handles a `GET /turn-credentials` request. `url` is the already-parsed URL object for
 * the request (so the caller decides routing); `ip` is only for log correlation.
 *
 * Async: it may make one outbound HTTP call to Metered. All failure modes are handled
 * internally — it never rejects.
 */
export async function handleTurnCredentialsRequest(res, url, ip) {
  try {
    // --- auth check (unchanged) --------------------------------------------------
    const publicKeyB64 = url.searchParams.get('publicKey');
    const timestampRaw = url.searchParams.get('timestamp');
    const signatureB64 = url.searchParams.get('signature');

    if (!publicKeyB64 || !timestampRaw || !signatureB64) {
      log.warn('turn_auth_failed', { ip, reason: 'missing_parameters' });
      return deny(res, 401, 'missing publicKey, timestamp or signature');
    }

    const timestamp = Number(timestampRaw);
    if (!Number.isFinite(timestamp) || Math.abs(Date.now() - timestamp) > config.turnAuthWindowMs) {
      log.warn('turn_auth_failed', { ip, reason: 'stale_or_invalid_timestamp' });
      return deny(res, 401, 'timestamp missing, malformed, or outside the allowed window');
    }

    const publicKey = parsePublicKey(publicKeyB64);
    if (!publicKey) {
      log.warn('turn_auth_failed', { ip, reason: 'invalid_public_key' });
      return deny(res, 401, 'invalid public key');
    }

    if (!verifyChallengeSignature(publicKey, Buffer.from(timestampRaw, 'utf8'), signatureB64)) {
      log.warn('turn_auth_failed', { ip, reason: 'bad_signature' });
      return deny(res, 401, 'signature verification failed');
    }
    // --- end auth check --------------------------------------------------------

    const fingerprint = fingerprintOf(publicKeyB64);
    const creds = await resolveTurnCredentials();
    const iceServers = buildIceServers(creds);

    // `source` records dynamic / static-fallback / stun-only; the credential values
    // themselves are never logged.
    log.info('turn_credentials_issued', {
      ip,
      fingerprint,
      source: creds.source,
      turnIncluded: creds.source !== 'stun-only',
      entries: iceServers.length,
      ...(creds.ttlSeconds ? { ttlSeconds: creds.ttlSeconds } : {})
    });

    const body = JSON.stringify({ iceServers });
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(body);
  } catch (err) {
    log.error('turn_credentials_error', { ip, error: err && err.message });
    if (!res.headersSent) deny(res, 500, 'internal error');
  }
}
