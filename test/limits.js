import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import WebSocket from 'ws';

import { TestClient } from './client.js';

/**
 * Exercises the resource-exhaustion guards.
 *
 * These use timeouts measured in minutes by default, so this spins up its own server on
 * a separate port with aggressive values via env overrides — which doubles as proof
 * that the config is genuinely environment-tunable for Railway.
 */

const PORT = 8788;
const WS_URL = `ws://127.0.0.1:${PORT}/signal`;
const here = path.dirname(fileURLToPath(import.meta.url));
const entry = path.join(here, '..', 'src', 'index.js');

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

function startServer() {
  const child = spawn(process.execPath, [entry], {
    env: {
      ...process.env,
      PORT: String(PORT),
      AUTH_TIMEOUT_MS: '800',
      UNPAIRED_TIMEOUT_MS: '1200',
      RATE_LIMIT_MAX_ATTEMPTS: '3',
      RATE_LIMIT_WINDOW_MS: '10000',
      LOG_LEVEL: 'warn'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  return new Promise((resolve) => {
    const onData = () => resolve(child);
    child.stdout.once('data', onData);
    // LOG_LEVEL=warn silences the listening line, so fall back to a short delay.
    setTimeout(() => resolve(child), 1200);
  });
}

async function main() {
  console.log(`Signaling limits test (own instance on :${PORT} with fast timeouts)\n`);
  const server = await startServer();

  try {
    // -------------------------------------------------------------------------
    console.log('1. Connect but never authenticate');
    const silent = new TestClient('silent', WS_URL);
    await silent.connect();
    await silent.waitForControl('challenge');
    const t0 = Date.now();
    const silentClose = await silent.waitForClose(4000);
    check(
      'idle unauthenticated client closed with 4001 (AUTH_TIMEOUT)',
      silentClose.code === 4001,
      `code=${silentClose.code} after ${Date.now() - t0}ms`
    );

    // -------------------------------------------------------------------------
    console.log('\n2. Authenticate, but the target peer never arrives');
    const waiting = new TestClient('waiting', WS_URL);
    const ghost = new TestClient('ghost', WS_URL).fingerprint;
    await waiting.connect();
    await waiting.authenticate(ghost);
    await waiting.waitForControl('authenticated');
    await waiting.waitForControl('peer-not-connected');
    const t1 = Date.now();
    const waitingClose = await waiting.waitForClose(4000);
    check(
      'unpaired client reaped with 4004 (PEER_NOT_CONNECTED)',
      waitingClose.code === 4004,
      `code=${waitingClose.code} after ${Date.now() - t1}ms`
    );
    check(
      'it waited for the peer rather than closing instantly',
      Date.now() - t1 >= 900,
      `waited ${Date.now() - t1}ms (configured 1200ms)`
    );

    // -------------------------------------------------------------------------
    console.log('\n3. Connection-attempt rate limiting (3 per 10s)');
    const results = [];
    for (let i = 0; i < 6; i++) {
      const outcome = await new Promise((resolve) => {
        const ws = new WebSocket(WS_URL);
        ws.on('open', () => {
          resolve('opened');
          ws.close();
        });
        ws.on('error', (err) => resolve(err.message));
      });
      results.push(outcome);
    }
    const opened = results.filter((r) => r === 'opened').length;
    const refused = results.filter((r) => r !== 'opened').length;
    check(
      'attempts beyond the window budget are refused',
      refused > 0,
      `${opened} opened, ${refused} refused`
    );
    check(
      'refusal is an HTTP 429 at upgrade time',
      results.some((r) => typeof r === 'string' && r.includes('429')),
      results.find((r) => r !== 'opened')
    );
  } finally {
    server.kill('SIGTERM');
  }

  console.log(`\n${'='.repeat(50)}`);
  console.log(`${failed === 0 ? 'ALL CHECKS PASSED' : `${failed} CHECK(S) FAILED`}  —  ${passed} passed, ${failed} failed`);
  console.log('='.repeat(50));
  process.exitCode = failed === 0 ? 0 : 1;
}

main()
  .catch((err) => {
    console.error(`\nLimits test aborted: ${err.message}`);
    process.exitCode = 1;
  })
  .finally(() => setTimeout(() => process.exit(process.exitCode ?? 0), 300));
