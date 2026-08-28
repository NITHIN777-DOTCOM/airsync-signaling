/**
 * All tunables in one place, overridable by environment variable so Railway's service
 * variables can adjust limits without a code change.
 */

function num(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export const config = {
  // Railway injects PORT; 8787 locally so it never collides with the desktop app's
  // 53317/53399 range.
  port: num('PORT', 8787),
  host: process.env.HOST || '0.0.0.0',

  /** WebSocket upgrades are only accepted here. /health is plain HTTP, kept separate. */
  wsPath: process.env.WS_PATH || '/signal',

  /**
   * Time from TCP connect to a valid `auth` message. Anything slower is either broken
   * or probing, and holds a socket open for nothing.
   */
  authTimeoutMs: num('AUTH_TIMEOUT_MS', 10_000),

  /**
   * How long an authenticated client may wait for its target peer before being closed.
   * This is deliberately a *waiting* window, not a queue: no signaling message is ever
   * buffered, the client simply stays connected in case its peer shows up shortly.
   */
  unpairedTimeoutMs: num('UNPAIRED_TIMEOUT_MS', 60_000),

  /** Idle time (no frames, no pong) on a paired session before it is torn down. */
  idleTimeoutMs: num('IDLE_TIMEOUT_MS', 300_000),

  /** Heartbeat interval; a client that misses a pong for `idleTimeoutMs` is dropped. */
  heartbeatIntervalMs: num('HEARTBEAT_INTERVAL_MS', 30_000),

  /** Largest single WebSocket frame accepted, in bytes. Guards memory. */
  maxPayloadBytes: num('MAX_PAYLOAD_BYTES', 16 * 1024 * 1024),

  /** Hard ceiling on concurrent sockets across the whole process. */
  maxConnections: num('MAX_CONNECTIONS', 1000),

  /** Concurrent sockets allowed from a single remote address. */
  maxConnectionsPerIp: num('MAX_CONNECTIONS_PER_IP', 20),

  /** Connection attempts allowed per address inside `rateLimitWindowMs`. */
  rateLimitMaxAttempts: num('RATE_LIMIT_MAX_ATTEMPTS', 30),
  rateLimitWindowMs: num('RATE_LIMIT_WINDOW_MS', 60_000),

  /** Nonce lifetime; a challenge not answered within this is refused. */
  challengeTtlMs: num('CHALLENGE_TTL_MS', 10_000),

  /**
   * Clock-skew allowance on the signed timestamp a client presents to
   * `GET /turn-credentials`. That request has no server-issued nonce (it is a plain
   * GET), so the client signs its own current time and the server only accepts it
   * inside this window — which also bounds how long a captured request can be replayed.
   */
  turnAuthWindowMs: num('TURN_AUTH_WINDOW_MS', 30_000),

  /**
   * ICE server configuration served by `GET /turn-credentials`.
   *
   * The STUN/TURN hostnames and ports are Metered's fixed public relay endpoints —
   * not secret and not expected to change — so they are hardcoded here rather than
   * being env vars.
   *
   * `username` / `credential` are the *static fallback* pair (TURN_USERNAME /
   * TURN_PASSWORD). They are now optional: the primary path mints short-lived
   * credentials per request via `config.metered` (see turn.js). These are only used
   * when the Metered API key is absent or the API call fails, and if neither source is
   * available STUN-only is served. No credential value is ever logged.
   */
  turn: {
    stunUrl: 'stun:stun.relay.metered.ca:80',
    turnUrls: [
      'turn:global.relay.metered.ca:80',
      'turn:global.relay.metered.ca:80?transport=tcp',
      'turn:global.relay.metered.ca:443',
      'turns:global.relay.metered.ca:443?transport=tcp'
    ],
    username: process.env.TURN_USERNAME || null,
    credential: process.env.TURN_PASSWORD || null
  },

  /**
   * Short-lived TURN credential provisioning via Metered's REST API.
   *
   * When `apiKey` is set, `GET /turn-credentials` calls Metered's "Create TURN
   * Credential" endpoint once per request to mint a fresh username/password pair that
   * auto-expires after `credentialTtlSeconds`. This is the preferred source: rotating,
   * per-client credentials that cannot outlive their TTL if leaked.
   *
   * If `apiKey` is unset, or the call fails / times out (`apiTimeoutMs`), turn.js falls
   * back to the static `config.turn` pair, then to STUN-only.
   */
  metered: {
    apiKey: process.env.METERED_API_KEY || null,

    /**
     * Metered "Create TURN Credential" endpoint. The default targets Metered's shared
     * relay API; for a dedicated Metered app, set this to
     * `https://<your-app>.metered.live/api/v1/turn/credential`.
     */
    apiUrl: process.env.METERED_API_URL || 'https://relay.metered.ca/api/v1/turn/credential',

    /** Lifetime requested for each minted credential pair (Metered's `expiryInSeconds`). */
    credentialTtlSeconds: num('TURN_CREDENTIAL_TTL_SECONDS', 3600),

    /**
     * Abort the Metered call after this long and fall back. A slow or hung upstream
     * must never stall the `/turn-credentials` response.
     */
    apiTimeoutMs: num('METERED_API_TIMEOUT_MS', 5_000)
  },

  logLevel: process.env.LOG_LEVEL || 'info'
};

/** Whether the static fallback TURN pair (TURN_USERNAME / TURN_PASSWORD) is present. */
export function hasStaticTurnCredentials() {
  return Boolean(config.turn.username && config.turn.credential);
}

/** Whether dynamic (Metered API) credential minting is configured. */
export function hasMeteredApiKey() {
  return Boolean(config.metered.apiKey);
}

/** Whether any TURN credential source — dynamic or static fallback — is available. */
export function hasAnyTurnCredentialSource() {
  return hasMeteredApiKey() || hasStaticTurnCredentials();
}

/**
 * Application-defined WebSocket close codes (4000-4999 is the reserved private range).
 * Clients switch on these, so the numbers are part of the wire contract.
 */
export const CloseCode = {
  AUTH_TIMEOUT: 4001,
  AUTH_FAILED: 4002,
  BAD_MESSAGE: 4003,
  PEER_NOT_CONNECTED: 4004,
  PEER_DISCONNECTED: 4005,
  IDLE_TIMEOUT: 4006,
  RATE_LIMITED: 4007,
  SERVER_FULL: 4008,
  REPLACED: 4009,
  SERVER_SHUTDOWN: 4010
};
