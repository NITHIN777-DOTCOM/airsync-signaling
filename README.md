# AirSync Signaling Server

A stateless WebSocket **WebRTC signaling** server that lets an AirSync phone and laptop
find each other and negotiate a peer-to-peer connection when they are **not** on the
same network and local mDNS discovery cannot reach.

It only carries the negotiation, never the data:

- **No storage.** Signaling frames (SDP offers/answers, ICE candidates) are forwarded to
  the paired peer and immediately forgotten. Nothing is written to disk, queued, or
  buffered for later delivery.
- **No device registry.** It never decides *which* devices may talk to each other —
  that trust was established locally during pairing. It only proves that a connection
  genuinely controls the private key behind the public key it claims.
- **No media.** Once the two devices have exchanged an offer/answer and candidates, the
  actual file transfer runs directly between them over WebRTC. This server is not in
  that path and there is no binary channel on it.

If the intended peer is not connected right now, the server says so (`peer-not-connected`,
and `error: "target device offline"` for any signaling frame) and delivers nothing. The
apps' existing QUEUED/retry logic handles trying again later.

---

## Quick start (local)

```bash
npm install
npm start                 # listens on http://127.0.0.1:8787
```

In a second terminal:

```bash
npm test                  # full walkthrough against the running server
npm run test:limits       # timeout / rate-limit guards (starts its own instance)
npm run test:turn         # GET /turn-credentials: auth, dynamic creds (mocked Metered API), fallbacks
```

`npm test` covers: health endpoint → client A authenticates and is told its peer is
absent → client B authenticates → pair forms → SDP offer/answer and ICE candidates
relayed verbatim both ways → one side disconnects → the other is closed with code 4005.
It also checks the auth rejection paths and that no state is left behind.

Point the tests elsewhere with `SIGNAL_URL` / `SIGNAL_HTTP`:

```bash
SIGNAL_URL=wss://your-app.up.railway.app/signal \
SIGNAL_HTTP=https://your-app.up.railway.app npm test
```

### Manual poking

```bash
curl http://127.0.0.1:8787/health
```

A raw WebSocket tool is awkward here because the client must *sign* a challenge, so
`test/client.js` is the practical way to drive it by hand:

```js
import { TestClient } from './test/client.js';
const c = new TestClient('me', 'ws://127.0.0.1:8787/signal');
await c.connect();
await c.authenticate('AA:BB:CC:DD:EE:FF:00:11'); // peer's fingerprint
console.log(await c.waitForControl('authenticated'));
```

---

## Protocol

Every frame is a JSON **text** frame. There is no binary channel — this server carries
only signaling metadata, and the media flows peer-to-peer over the WebRTC connection
those frames negotiate.

### Handshake

```
client                              server
  |------- WS connect /signal ------->|
  |<------ {type:"challenge",         |
  |          nonce, expiresInMs} -----|
  |                                   |
  | sign(nonce) with device key       |
  |------- {type:"auth",              |
  |          publicKey, signature,    |
  |          target} ---------------->|
  |                                   | verify signature
  |<------ {type:"authenticated",     |
  |          fingerprint, target} ----|
  |                                   |
  |<------ {type:"peer-connected"}    |  ...if the peer is already waiting
  |          or                       |
  |<------ {type:"peer-not-connected"}|  ...otherwise
```

- `publicKey` — base64 X.509 SPKI DER, EC **P-256** (`prime256v1`).
- `signature` — DER-encoded ECDSA over SHA-256 of the raw nonce bytes. This is exactly
  what Android's `SHA256withECDSA` and Node's `crypto.sign('sha256', …)` produce, so
  both existing clients work unmodified.
- `target` — the peer's fingerprint: SHA-256 over SPKI DER, first 8 bytes, uppercase
  colon-hex (e.g. `A1:B2:C3:D4:E5:F6:07:18`). Same format the apps already use.

**Pairing is mutual.** A and B only get connected when A targets B *and* B targets A. A
one-sided request never forms a pair.

### Signaling (after `peer-connected`)

Once paired, either side sends any of the three frames below. The server forwards the
frame **verbatim** to the paired peer — it does not parse or rewrite the SDP or the
candidate. The `target` must be the fingerprint of the peer you are actually paired
with; anything else (or a frame sent before pairing) returns
`{type:"error", reason:"target device offline"}` and nothing is queued.

| client → server | forwarded to peer as | fields |
|---|---|---|
| `{type:"offer", target, sdp}` | identical object | `sdp`: the RTCSessionDescription SDP string |
| `{type:"answer", target, sdp}` | identical object | `sdp`: the RTCSessionDescription SDP string |
| `{type:"ice-candidate", target, candidate}` | identical object | `candidate`: the RTCIceCandidateInit (or `null` for end-of-candidates) |

The receiver identifies the sender through its own pairing — the server guarantees a
socket is only ever paired with one peer at a time.

### Server → client messages

| message | meaning |
|---|---|
| `challenge` | sign `nonce` and reply with `auth` |
| `authenticated` | signature verified; `fingerprint` is your derived identity |
| `peer-connected` | peer is here; you may now exchange `offer` / `answer` / `ice-candidate` |
| `peer-not-connected` | peer absent; nothing is queued, you may wait briefly |
| `offer` / `answer` / `ice-candidate` | a signaling frame forwarded from your peer, verbatim |
| `peer-disconnected` | your peer went away; you are about to be closed |
| `error` | `{reason}`, e.g. `target device offline`, `unknown_message_type` |
| `pong` | reply to a client `ping` |

### Close codes

| code | name | meaning |
|---|---|---|
| 4001 | `AUTH_TIMEOUT` | no valid `auth` within the auth window |
| 4002 | `AUTH_FAILED` | bad signature, bad key, bad/self target |
| 4003 | `BAD_MESSAGE` | malformed frame, or a binary frame (not supported) |
| 4004 | `PEER_NOT_CONNECTED` | waited for the peer, it never arrived |
| 4005 | `PEER_DISCONNECTED` | the other half of the pair went away |
| 4006 | `IDLE_TIMEOUT` | no traffic within the idle window, or too slow to drain |
| 4007 | `RATE_LIMITED` | too many connection attempts |
| 4008 | `SERVER_FULL` | global connection cap reached |
| 4009 | `REPLACED` | same fingerprint connected again elsewhere |
| 4010 | `SERVER_SHUTDOWN` | server is restarting — reconnect, this is not a peer loss |

---

## HTTP endpoints

### `GET /health`

Plain HTTP, unauthenticated. Returns `200` and `{"status":"ok","uptimeSeconds":…,"connections":…,"authenticated":…,"pairedSessions":…}`. This is the Railway health-check target and is deliberately separate from the `/signal` upgrade path.

### `GET /turn-credentials`

Returns the ICE server list a device needs before opening its WebRTC peer connection.

**Authenticated** — using the same challenge/response primitive as the WebSocket
handshake. Since this is a plain GET with no server round-trip, the client signs its
own current timestamp and the server accepts it only within `TURN_AUTH_WINDOW_MS`
(default 30 s). Unauthenticated or bad-signature requests get `401` and never see
credentials.

Query parameters:

| param | value |
|---|---|
| `publicKey` | base64 X.509 SPKI DER, EC P-256 — the device id, same as the WS `auth` message |
| `timestamp` | unix epoch **milliseconds**, as a string |
| `signature` | base64 DER ECDSA/SHA-256 over the UTF-8 bytes of the `timestamp` string |

```bash
# pseudo — see test/turn-credentials.js for a working signer
ts=$(node -e 'process.stdout.write(String(Date.now()))')
sig=... # crypto.sign('sha256', Buffer.from(ts), { key: devicePrivateKey, dsaEncoding: 'der' })
curl "https://<service>.up.railway.app/turn-credentials?publicKey=$PUB&timestamp=$ts&signature=$SIG"
```

Response (`200`), when a TURN credential source is available:

```json
{
  "iceServers": [
    { "urls": "stun:stun.relay.metered.ca:80" },
    { "urls": "turn:global.relay.metered.ca:80", "username": "…", "credential": "…" },
    { "urls": "turn:global.relay.metered.ca:80?transport=tcp", "username": "…", "credential": "…" },
    { "urls": "turn:global.relay.metered.ca:443", "username": "…", "credential": "…" },
    { "urls": "turns:global.relay.metered.ca:443?transport=tcp", "username": "…", "credential": "…" }
  ]
}
```

The `username` / `credential` in the four TURN entries are always the same pair, and
where they come from is resolved per request:

| # | source | when |
|---|---|---|
| 1 | **dynamic** | `METERED_API_KEY` is set — the server `POST`s to Metered's *Create TURN Credential* REST API (`<app>.metered.live/api/v1/turn/credential?secretKey=…`, body `{expiryInSeconds, label}`) and mints a fresh pair that auto-expires after `TURN_CREDENTIAL_TTL_SECONDS` (default 3600). This is the preferred path: rotating, per-request credentials that cannot outlive their TTL if leaked. |
| 2 | **static fallback** | the Metered key is absent, **or** the API call returned non-2xx / timed out (`METERED_API_TIMEOUT_MS`, default 5 s) — the server falls back to the fixed `TURN_USERNAME` / `TURN_PASSWORD` pair if both are set. |
| 3 | **stun-only** | neither source is available — the response is the STUN entry alone (below). Still `200`; signaling and direct/STUN P2P are unaffected, only the relayed fallback is lost. |

Each response logs a `turn_credentials_issued` line with `source: "dynamic" | "static-fallback" | "stun-only"` (never the credential values); a failed Metered call logs `turn_metered_api_failed` with a `reason`. A `turn_credentials_missing` warning is logged at startup only when *neither* source is configured.

> ⚠️ **`METERED_API_KEY` must be the account-wide _Secret Key_ from the Metered
> dashboard's _Developers_ tab** — the key that can create/list/delete TURN credentials.
> It is **not** the per-credential _API Key_ shown next to an individual credential on
> the _TURN Credentials_ page: that one is credential-scoped, can only fetch that single
> credential's ICE list, and will fail here. (The env var keeps the `_API_KEY` name for
> compatibility; the value it needs is the Secret Key.) The Metered success response
> also contains its own `apiKey` field — that is the credential-scoped key for the
> credential just minted, and the server deliberately ignores it.

STUN-only response:

```json
{ "iceServers": [ { "urls": "stun:stun.relay.metered.ca:80" } ] }
```

`TURN_USERNAME` / `TURN_PASSWORD` are now **optional** — they are the fallback only, no
longer the primary source. A deployment with `METERED_API_KEY` set does not need them
(though keeping them set is a reasonable belt-and-braces for Metered API outages).

The STUN/TURN **hostnames and ports** (`stun.relay.metered.ca:80`,
`global.relay.metered.ca` on `80`/`443`, plus the `?transport=tcp` and `turns:`
variants) are Metered's fixed public endpoints — hardcoded in `src/config.js`, **not**
configurable via env. Only the credentials are secret.

---

## Configuration

Every value is environment-overridable, so limits can be tuned on Railway (service
**Variables**) without a code change.

| env var | default | purpose |
|---|---|---|
| `PORT` | `8787` (`8080` in Docker; Railway injects its own) | HTTP + WS listen port |
| `WS_PATH` | `/signal` | WebSocket upgrade path |
| `AUTH_TIMEOUT_MS` | `10000` | connect → valid `auth` |
| `UNPAIRED_TIMEOUT_MS` | `60000` | how long an authenticated client waits for its peer |
| `IDLE_TIMEOUT_MS` | `300000` | silence on a paired session before teardown |
| `HEARTBEAT_INTERVAL_MS` | `30000` | ping cadence |
| `MAX_PAYLOAD_BYTES` | `16777216` | largest single frame |
| `MAX_CONNECTIONS` | `1000` | process-wide socket cap |
| `MAX_CONNECTIONS_PER_IP` | `20` | concurrent sockets per address |
| `RATE_LIMIT_MAX_ATTEMPTS` | `30` | connection attempts per window per address |
| `RATE_LIMIT_WINDOW_MS` | `60000` | rate-limit window |
| `CHALLENGE_TTL_MS` | `10000` | nonce lifetime |
| `TURN_AUTH_WINDOW_MS` | `30000` | clock-skew allowance on the signed timestamp for `GET /turn-credentials` |
| `METERED_API_KEY` | _(unset)_ | **secret** — the Metered **Secret Key** (Developers tab), *not* the per-credential API Key. When set, `/turn-credentials` mints a fresh short-lived credential pair per request. The preferred credential source. |
| `TURN_CREDENTIAL_TTL_SECONDS` | `3600` | lifetime requested for each dynamically-minted credential pair (Metered's `expiryInSeconds`) |
| `METERED_CREDENTIAL_LABEL` | `airsync-signaling` | `label` sent with each Create-Credential call, for spotting them in the Metered dashboard |
| `METERED_API_URL` | `https://airsync.metered.live/api/v1/turn/credential` | Metered *Create TURN Credential* endpoint. The `airsync` is this account's Metered app name — override if the app is renamed/moved. Not secret. |
| `METERED_API_TIMEOUT_MS` | `5000` | abort the Metered API call after this long and fall back |
| `TURN_USERNAME` | _(unset)_ | **secret**, **optional** — static fallback TURN username, used only when the Metered API is unset or fails |
| `TURN_PASSWORD` | _(unset)_ | **secret**, **optional** — static fallback TURN credential, paired with `TURN_USERNAME` |
| `LOG_LEVEL` | `info` | `error` \| `warn` \| `info` \| `debug` |

**TURN credential sourcing:** set `METERED_API_KEY` for the primary (dynamic, auto-expiring)
path. `TURN_USERNAME` / `TURN_PASSWORD` are an optional static fallback for when the
Metered API is unreachable. With neither, `/turn-credentials` serves STUN only. The
TURN/STUN hostnames themselves are **not** env vars — they are fixed public Metered
endpoints hardcoded in `src/config.js` (`config.turn`).

---

## Logging

One JSON object per line on stdout/stderr — the shape Railway's log viewer expects.

```json
{"ts":"…","level":"info","event":"signaling_pair_established","connIds":["999cf755","d610c2b0"],"fingerprints":["4A:5F:…","47:BC:…"]}
```

Events: `server_listening`, `connection_open`, `auth_ok`, `auth_failed`,
`peer_not_connected`, `signaling_pair_established`, `signaling_pair_closed`,
`connection_close`, `idle_timeout`, `unpaired_timeout`, `upgrade_rejected`,
`backpressure_limit`, `turn_credentials_source` (startup), `turn_credentials_issued`
(with `source`), `turn_auth_failed`, `turn_metered_api_failed`, `turn_credentials_error`,
`turn_credentials_missing`.

**SDP and ICE contents are never logged**, and **TURN credentials are never logged** —
only metadata (fingerprints, connection ids, states, close codes, relayed-message
counts, and whether a TURN pair was included in a response).

---

## Deploying to Railway

The repo ships a `Dockerfile` and a `railway.json`, so Railway needs no dashboard
configuration beyond creating the service.

### One-time setup

1. Push this directory to a Git repo (GitHub/GitLab).
2. In Railway: **New Project → Deploy from repo**, and pick this repo. If the signaling
   server lives in a subdirectory of a larger repo, set the service **Root Directory**
   to `airsync-signaling/`.
3. Railway reads `railway.json`:
   - **Builder:** `DOCKERFILE` (`Dockerfile` at the service root).
   - **Health check:** `GET /health`, which returns `200` with a small JSON body
     (`{"status":"ok",…}`) and is deliberately separate from the `/signal` WebSocket
     upgrade path.
   - **Restart policy:** `ON_FAILURE`, up to 10 retries.
   - **Replicas:** `1` — signaling state is in-memory and pairing needs both peers on
     the same instance, so do **not** scale this horizontally without a shared
     backplane (see below).
4. Under the service → **Settings → Networking**, click **Generate Domain**. Railway
   gives you `https://<service>.up.railway.app` and terminates TLS at its edge.
5. Under the service → **Variables**, set the TURN credential source:

   | variable | value |
   |---|---|
   | `METERED_API_KEY` | the **Secret Key** from Metered → **Developers** tab — **the recommended setup**. The server mints a fresh, auto-expiring credential pair per request. **Not** the per-credential API Key from the TURN Credentials page. |
   | `TURN_CREDENTIAL_TTL_SECONDS` | _(optional)_ credential lifetime, default `3600` |
   | `METERED_API_URL` | _(optional)_ only if the Metered app name is not `airsync` (default `https://airsync.metered.live/api/v1/turn/credential`) |
   | `TURN_USERNAME` / `TURN_PASSWORD` | _(optional)_ static fallback pair, used only if the Metered API is unset or unreachable |

   The TURN/STUN hostnames are fixed and hardcoded — do not add them as variables. If
   you set none of the above the server still boots and signaling works; `GET
   /turn-credentials` returns STUN only and logs a `turn_credentials_missing` warning, so
   the relayed (TURN) fallback is unavailable until a credential source is configured.

Railway injects `PORT` automatically; the server binds it. Any of the other tunables
from the configuration table can be added under **Variables** if you need them.

### Deploy

```bash
git push          # Railway builds and deploys on every push to the linked branch
```

Watch the build and runtime logs in the Railway dashboard, then:

```bash
curl https://<service>.up.railway.app/health
```

Your clients connect to:

```
wss://<service>.up.railway.app/signal
```

Note `wss://`, not `ws://` — Railway's edge is HTTPS/WSS and the server itself speaks
plain HTTP internally.

### Things worth knowing before you deploy

- **Single instance.** Rate limiting is in-memory and, more importantly, a signaling
  pair only works if both peers hit the same process. Keep `numReplicas` at `1`. If you
  ever need to scale out, the registry/pairing layer needs a shared store (e.g. Redis
  pub/sub) first.
- **One connection per identity.** A second connection with the same fingerprint evicts
  the first (close code 4009).
- **Sleep / cold start.** If the service is allowed to sleep on idle, the first phone
  to connect after a quiet period eats a cold start. Disable app sleep (or keep a
  cheap always-on plan) if that latency matters.
- **TLS is Railway's, end-to-end encryption is the WebRTC layer's.** `wss://` protects
  the hop to the signaling server; the server operator could in principle see the SDP.
  The media path is a separate DTLS-SRTP channel negotiated directly between the two
  devices — this server never sees it.

### Verifying the Docker build locally

Railway uses the same `Dockerfile`. To check it before pushing:

```bash
docker build -t airsync-signaling .
docker run --rm -e PORT=8080 -p 8080:8080 airsync-signaling
curl http://127.0.0.1:8080/health
```
