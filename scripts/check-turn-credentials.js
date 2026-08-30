#!/usr/bin/env node
import crypto from 'node:crypto';
import http from 'node:http';
import https from 'node:https';

/**
 * Manual debug helper — NOT part of the test suite.
 *
 * Hits a running signaling server's `GET /turn-credentials` twice, 3 seconds apart,
 * with one fixed device keypair, and reports whether the TURN username changed between
 * the two responses:
 *
 *   - DIFFERENT  -> the server is minting short-lived credentials per request via the
 *                   Metered REST API (the dynamic path is working)
 *   - SAME       -> the server is serving a fixed pair (static TURN_USERNAME /
 *                   TURN_PASSWORD fallback, or a cached/identical dynamic response)
 *
 * Usage:
 *   node scripts/check-turn-credentials.js https://your-app.up.railway.app
 *   node scripts/check-turn-credentials.js http://127.0.0.1:8787
 *
 * Dependency-free: Node built-in crypto + http/https only, same key-gen approach as
 * test/client.js (EC P-256, DER-encoded ECDSA signatures).
 */

const rawBase = process.argv[2];
if (!rawBase) {
  console.error('Usage: node scripts/check-turn-credentials.js <server-base-url>');
  console.error('   e.g. node scripts/check-turn-credentials.js https://your-app.up.railway.app');
  process.exit(2);
}

const base = rawBase.replace(/\/+$/, '');

// --- 1. one fixed P-256 keypair for both requests (matches test/client.js) -----------
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'prime256v1'
});
const publicKeyB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

/**
 * 2. Builds the signed query string per the /turn-credentials auth scheme:
 *    sign the UTF-8 bytes of the current-timestamp string with the device key,
 *    DER-encoded ECDSA/SHA-256, base64.
 */
function signedQuery() {
  const timestamp = String(Date.now());
  const signature = crypto
    .sign('sha256', Buffer.from(timestamp, 'utf8'), { key: privateKey, dsaEncoding: 'der' })
    .toString('base64');
  return new URLSearchParams({ publicKey: publicKeyB64, timestamp, signature }).toString();
}

/** 3. GET {base}/turn-credentials?<signed query>, returning parsed JSON. */
function fetchCredentials() {
  const url = `${base}/turn-credentials?${signedQuery()}`;
  const client = url.startsWith('https:') ? https : http;

  return new Promise((resolve, reject) => {
    const req = client.get(url, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode}: ${body.slice(0, 200)}`));
          return;
        }
        try {
          resolve(JSON.parse(body));
        } catch {
          reject(new Error(`response was not JSON: ${body.slice(0, 200)}`));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(15_000, () => req.destroy(new Error('request timed out after 15s')));
  });
}

/** Unique usernames across the TURN (not STUN) entries of an iceServers array. */
function turnUsernames(payload) {
  const servers = Array.isArray(payload?.iceServers) ? payload.iceServers : [];
  const names = new Set();
  for (const entry of servers) {
    const urls = Array.isArray(entry.urls) ? entry.urls : [entry.urls];
    if (urls.some((u) => typeof u === 'string' && u.startsWith('turn'))) {
      if (entry.username) names.add(entry.username);
    }
  }
  return [...names];
}

function describe(names) {
  if (names.length === 0) return '(none — STUN-only response, no TURN credentials)';
  return names.join(', ');
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  console.log(`Target: ${base}/turn-credentials`);
  console.log(`Device: ${publicKeyB64.slice(0, 24)}… (one keypair, reused for both requests)\n`);

  // 4. first request
  const first = turnUsernames(await fetchCredentials());
  console.log(`Request 1 TURN username(s): ${describe(first)}`);

  // 5. wait 3 seconds, repeat with the same keypair
  console.log('Waiting 3 seconds…');
  await wait(3000);
  const second = turnUsernames(await fetchCredentials());
  console.log(`Request 2 TURN username(s): ${describe(second)}\n`);

  // 6. side by side + verdict
  console.log('  request 1 :', describe(first));
  console.log('  request 2 :', describe(second));
  console.log();

  if (first.length === 0 && second.length === 0) {
    console.log('INCONCLUSIVE — the server returned STUN only both times.');
    console.log('No TURN credential source is configured (METERED_API_KEY / TURN_USERNAME).');
    process.exit(1);
  }

  const same = first.length === second.length && first.every((n, i) => n === second[i]);
  if (same) {
    console.log('SAME (static/cached) — the TURN username did not change between requests.');
    console.log('The server is serving a fixed pair (static TURN_USERNAME fallback, or the');
    console.log('Metered API returned an identical credential both times).');
    process.exit(1);
  }

  console.log('DIFFERENT (dynamic, working) — the TURN username changed between requests.');
  console.log('The server is minting fresh short-lived credentials per request.');
}

main().catch((err) => {
  console.error(`\nFailed: ${err.message}`);
  process.exit(1);
});
