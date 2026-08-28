import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';

import { TestClient } from './client.js';

/**
 * Covers GET /turn-credentials, including the dynamic (Metered REST API) credential
 * flow and its fallbacks. The Metered API is mocked by a local HTTP server whose
 * behaviour the test switches per phase; the signaling server is pointed at it via
 * METERED_API_URL.
 *
 *   (a) unauthenticated / bad-signature / stale-timestamp requests are rejected 401
 *   (b) dynamic success      -> TURN entries carry the freshly-minted username/password,
 *                               and dynamic wins even when static env creds are also set
 *   (c) dynamic HTTP error   -> falls back to the static TURN_USERNAME / TURN_PASSWORD pair
 *   (d) dynamic timeout      -> treated as failure, same static fallback
 *   (e) no Metered key, static present -> static-fallback path
 *   (f) neither source       -> STUN-only, still 200, auth still enforced
 *
 * No real credentials anywhere — dynamic and static values are placeholders (override
 * the static pair via TEST_TURN_USERNAME / TEST_TURN_PASSWORD if pointing at a live relay).
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const entry = path.join(here, '..', 'src', 'index.js');

// Static fallback pair (TURN_USERNAME / TURN_PASSWORD). Placeholders — never real creds.
const STATIC_USERNAME = process.env.TEST_TURN_USERNAME || 'static-turn-username-PLACEHOLDER';
const STATIC_PASSWORD = process.env.TEST_TURN_PASSWORD || 'static-turn-password-PLACEHOLDER';

// What the mocked Metered API hands back on the success path. Placeholders.
const DYNAMIC_USERNAME = 'dynamic-turn-username-PLACEHOLDER';
const DYNAMIC_PASSWORD = 'dynamic-turn-password-PLACEHOLDER';

const METERED_API_KEY = 'mock-metered-secret-key-PLACEHOLDER';
const EXPECTED_TTL = 3600;

const EXPECTED_STUN = 'stun:stun.relay.metered.ca:80';
const EXPECTED_TURN_URLS = [
  'turn:global.relay.metered.ca:80',
  'turn:global.relay.metered.ca:80?transport=tcp',
  'turn:global.relay.metered.ca:443',
  'turns:global.relay.metered.ca:443?transport=tcp'
];

let passed = 0;
let failed = 0;

function check(label, condition, detail) {
  if (condition) {
    passed += 1;
    console.log(`  PASS  ${label}${detail ? `  (${detail})` : ''}`);
  } else {
    failed += 1;
    console.log(`  FAIL  ${label}${detail ? `  (${detail})` : ''}`);
  }
}

/**
 * Mock Metered "Create TURN Credential" API.
 *   mode 'success' -> 200 { username, password, expiryInSeconds }
 *   mode 'error'   -> 500
 *   mode 'hang'    -> never responds (exercises the client-side timeout)
 * Records the last request's parsed body + secretKey for assertions.
 */
function startMeteredMock(port) {
  const state = { mode: 'success', lastBody: null, lastSecretKey: null, hung: [] };
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      state.lastSecretKey = new URL(req.url, `http://localhost:${port}`).searchParams.get('secretKey');
      try {
        state.lastBody = JSON.parse(raw || '{}');
      } catch {
        state.lastBody = null;
      }

      if (state.mode === 'hang') {
        state.hung.push(res); // left open; closed on server teardown
        return;
      }
      if (state.mode === 'error') {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'mock upstream failure' }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          username: DYNAMIC_USERNAME,
          password: DYNAMIC_PASSWORD,
          expiryInSeconds: EXPECTED_TTL
        })
      );
    });
  });
  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => {
      resolve({
        state,
        url: `http://127.0.0.1:${port}/api/v1/turn/credential`,
        close: () => {
          state.hung.forEach((res) => res.destroy());
          server.close();
        }
      });
    });
  });
}

function startServer(port, extraEnv) {
  const child = spawn(process.execPath, [entry], {
    env: { ...process.env, PORT: String(port), LOG_LEVEL: 'warn', ...extraEnv },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  return new Promise((resolve) => {
    child.stdout.once('data', () => resolve(child));
    setTimeout(() => resolve(child), 1200);
  });
}

function httpGet(url) {
  return new Promise((resolve, reject) => {
    http
      .get(url, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          let json = null;
          try {
            json = JSON.parse(body);
          } catch {
            /* left null */
          }
          resolve({ status: res.statusCode, body, json });
        });
      })
      .on('error', reject);
  });
}

/** Builds a signed /turn-credentials query string for `device`. */
function signedQuery(device, { timestamp = Date.now(), corrupt = false } = {}) {
  const ts = String(timestamp);
  const signedBytes = corrupt ? crypto.randomBytes(16) : Buffer.from(ts, 'utf8');
  const signature = crypto.sign('sha256', signedBytes, {
    key: device.privateKey,
    dsaEncoding: 'der'
  });
  return new URLSearchParams({
    publicKey: device.publicKeyB64,
    timestamp: ts,
    signature: signature.toString('base64')
  }).toString();
}

/** Asserts a 5-entry iceServers array: STUN + the 4 TURN URLs with the given creds. */
function checkFullShape(prefix, iceServers, username, password) {
  check(
    `${prefix} iceServers is an array of 5 entries`,
    Array.isArray(iceServers) && iceServers.length === 5,
    `len ${iceServers?.length}`
  );
  check(
    `${prefix} entry 0 is the STUN url with no credentials`,
    iceServers?.[0]?.urls === EXPECTED_STUN &&
      iceServers?.[0]?.username === undefined &&
      iceServers?.[0]?.credential === undefined,
    JSON.stringify(iceServers?.[0])
  );
  check(
    `${prefix} entries 1-4 are the TURN urls with the expected username/credential`,
    JSON.stringify(iceServers) ===
      JSON.stringify([
        { urls: EXPECTED_STUN },
        ...EXPECTED_TURN_URLS.map((urls) => ({ urls, username, credential: password }))
      ]),
    JSON.stringify(iceServers?.slice(1))
  );
}

async function main() {
  const device = new TestClient('turn-tester', 'ws://unused'); // only used for its key pair

  const MOCK_PORT = 8795;
  const mock = await startMeteredMock(MOCK_PORT);

  try {
    // ========================================================================
    console.log('Phase 1 — dynamic credentials (Metered API succeeds)\n');
    // ========================================================================
    mock.state.mode = 'success';
    const PORT_A = 8790;
    const BASE_A = `http://127.0.0.1:${PORT_A}`;
    const dyn = await startServer(PORT_A, {
      METERED_API_KEY,
      METERED_API_URL: mock.url,
      // Static pair is ALSO set here, to prove dynamic takes precedence over it.
      TURN_USERNAME: STATIC_USERNAME,
      TURN_PASSWORD: STATIC_PASSWORD
    });

    try {
      // (a) auth rejection paths
      const noAuth = await httpGet(`${BASE_A}/turn-credentials`);
      check('(a) request with no credentials is rejected 401', noAuth.status === 401, `got ${noAuth.status}`);
      check('(a) rejection body carries no iceServers', !noAuth.json?.iceServers);

      const badSig = await httpGet(`${BASE_A}/turn-credentials?${signedQuery(device, { corrupt: true })}`);
      check('(a) request with a bad signature is rejected 401', badSig.status === 401, `got ${badSig.status}`);

      const stale = await httpGet(
        `${BASE_A}/turn-credentials?${signedQuery(device, { timestamp: Date.now() - 5 * 60_000 })}`
      );
      check('(a) request with a stale timestamp is rejected 401', stale.status === 401, `got ${stale.status}`);

      // (b) dynamic success
      const ok = await httpGet(`${BASE_A}/turn-credentials?${signedQuery(device)}`);
      check('(b) valid signed request returns 200', ok.status === 200, `got ${ok.status}`);
      checkFullShape('(b)', ok.json?.iceServers, DYNAMIC_USERNAME, DYNAMIC_PASSWORD);
      check(
        '(b) TURN entries use the dynamic pair, not the static env pair',
        ok.json?.iceServers?.[1]?.username === DYNAMIC_USERNAME &&
          ok.json?.iceServers?.[1]?.username !== STATIC_USERNAME
      );
      check(
        '(b) Metered API was called with the configured secret key',
        mock.state.lastSecretKey === METERED_API_KEY,
        mock.state.lastSecretKey
      );
      check(
        `(b) Metered API was asked for expiryInSeconds=${EXPECTED_TTL}`,
        mock.state.lastBody?.expiryInSeconds === EXPECTED_TTL,
        JSON.stringify(mock.state.lastBody)
      );
    } finally {
      dyn.kill('SIGTERM');
    }

    // ========================================================================
    console.log('\nPhase 2 — Metered API returns an error -> static fallback\n');
    // ========================================================================
    mock.state.mode = 'error';
    const PORT_B = 8791;
    const BASE_B = `http://127.0.0.1:${PORT_B}`;
    const errFallback = await startServer(PORT_B, {
      METERED_API_KEY,
      METERED_API_URL: mock.url,
      TURN_USERNAME: STATIC_USERNAME,
      TURN_PASSWORD: STATIC_PASSWORD
    });

    try {
      const ok = await httpGet(`${BASE_B}/turn-credentials?${signedQuery(device)}`);
      check('(c) still returns 200 when the Metered API errors', ok.status === 200, `got ${ok.status}`);
      checkFullShape('(c)', ok.json?.iceServers, STATIC_USERNAME, STATIC_PASSWORD);
    } finally {
      errFallback.kill('SIGTERM');
    }

    // ========================================================================
    console.log('\nPhase 3 — Metered API hangs -> timeout -> static fallback\n');
    // ========================================================================
    mock.state.mode = 'hang';
    const PORT_C = 8792;
    const BASE_C = `http://127.0.0.1:${PORT_C}`;
    const timeoutFallback = await startServer(PORT_C, {
      METERED_API_KEY,
      METERED_API_URL: mock.url,
      METERED_API_TIMEOUT_MS: '400', // fail fast instead of the 5s default
      TURN_USERNAME: STATIC_USERNAME,
      TURN_PASSWORD: STATIC_PASSWORD
    });

    try {
      const started = Date.now();
      const ok = await httpGet(`${BASE_C}/turn-credentials?${signedQuery(device)}`);
      const elapsed = Date.now() - started;
      check('(d) still returns 200 when the Metered API hangs', ok.status === 200, `got ${ok.status}`);
      check('(d) responded shortly after the API timeout, not after a long hang', elapsed < 3000, `${elapsed}ms`);
      checkFullShape('(d)', ok.json?.iceServers, STATIC_USERNAME, STATIC_PASSWORD);
    } finally {
      timeoutFallback.kill('SIGTERM');
    }

    // ========================================================================
    console.log('\nPhase 4 — no Metered key, static pair only\n');
    // ========================================================================
    const PORT_D = 8793;
    const BASE_D = `http://127.0.0.1:${PORT_D}`;
    const staticOnly = await startServer(PORT_D, {
      METERED_API_KEY: '',
      TURN_USERNAME: STATIC_USERNAME,
      TURN_PASSWORD: STATIC_PASSWORD
    });

    try {
      const ok = await httpGet(`${BASE_D}/turn-credentials?${signedQuery(device)}`);
      check('(e) returns 200 with the static pair when no Metered key is set', ok.status === 200, `got ${ok.status}`);
      checkFullShape('(e)', ok.json?.iceServers, STATIC_USERNAME, STATIC_PASSWORD);
    } finally {
      staticOnly.kill('SIGTERM');
    }

    // ========================================================================
    console.log('\nPhase 5 — no credential source at all -> STUN only\n');
    // ========================================================================
    const PORT_E = 8794;
    const BASE_E = `http://127.0.0.1:${PORT_E}`;
    const stunOnly = await startServer(PORT_E, {
      METERED_API_KEY: '',
      TURN_USERNAME: '',
      TURN_PASSWORD: ''
    });

    try {
      const ok = await httpGet(`${BASE_E}/turn-credentials?${signedQuery(device)}`);
      check('(f) valid request still returns 200 with no credential source', ok.status === 200, `got ${ok.status}`);
      check(
        '(f) iceServers contains exactly the STUN entry',
        JSON.stringify(ok.json?.iceServers) === JSON.stringify([{ urls: EXPECTED_STUN }]),
        JSON.stringify(ok.json?.iceServers)
      );

      const noAuth = await httpGet(`${BASE_E}/turn-credentials`);
      check('(f) unauthenticated request is still rejected 401', noAuth.status === 401, `got ${noAuth.status}`);
    } finally {
      stunOnly.kill('SIGTERM');
    }
  } finally {
    mock.close();
  }

  console.log(`\n${'='.repeat(50)}`);
  console.log(`${failed === 0 ? 'ALL CHECKS PASSED' : `${failed} CHECK(S) FAILED`}  —  ${passed} passed, ${failed} failed`);
  console.log('='.repeat(50));
  process.exitCode = failed === 0 ? 0 : 1;
}

main()
  .catch((err) => {
    console.error(`\nTURN credentials test aborted: ${err.message}`);
    process.exitCode = 1;
  })
  .finally(() => setTimeout(() => process.exit(process.exitCode ?? 0), 300));
