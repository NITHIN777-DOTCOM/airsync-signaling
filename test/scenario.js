import crypto from 'node:crypto';
import http from 'node:http';
import WebSocket from 'ws';

import { TestClient } from './client.js';

/**
 * End-to-end walkthrough against a running signaling server.
 *
 * Start the server first (`npm start`), then `npm test`. Override the target with
 * SIGNAL_URL / SIGNAL_HTTP if you are not on the defaults.
 */

const WS_URL = process.env.SIGNAL_URL || 'ws://127.0.0.1:8787/signal';
const HTTP_URL = process.env.SIGNAL_HTTP || 'http://127.0.0.1:8787';

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

function section(title) {
  console.log(`\n${title}`);
  console.log('-'.repeat(title.length));
}

function httpGet(url) {
  return new Promise((resolve, reject) => {
    http
      .get(url, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => resolve({ status: res.statusCode, body }));
      })
      .on('error', reject);
  });
}

async function main() {
  console.log(`AirSync signaling scenario\n  ws:   ${WS_URL}\n  http: ${HTTP_URL}`);

  // ---------------------------------------------------------------------------
  section('1. Health endpoint (Railway check target)');
  // ---------------------------------------------------------------------------
  const health = await httpGet(`${HTTP_URL}/health`);
  check('GET /health returns 200', health.status === 200, `got ${health.status}`);
  let healthJson = null;
  try {
    healthJson = JSON.parse(health.body);
  } catch {
    /* handled below */
  }
  check('health body is JSON with status ok', healthJson?.status === 'ok', health.body.slice(0, 80));

  const notFound = await httpGet(`${HTTP_URL}/nope`);
  check('unknown HTTP path returns 404', notFound.status === 404, `got ${notFound.status}`);

  // ---------------------------------------------------------------------------
  section('2. Client A authenticates, peer not yet connected');
  // ---------------------------------------------------------------------------
  const phone = new TestClient('phone', WS_URL);
  const laptop = new TestClient('laptop', WS_URL);
  console.log(`  phone  fingerprint: ${phone.fingerprint}`);
  console.log(`  laptop fingerprint: ${laptop.fingerprint}`);

  await phone.connect();
  await phone.authenticate(laptop.fingerprint);

  const phoneAuth = await phone.waitForControl('authenticated');
  check('phone receives "authenticated"', phoneAuth.type === 'authenticated');
  check(
    'server derived the same fingerprint the client did',
    phoneAuth.fingerprint === phone.fingerprint,
    `${phoneAuth.fingerprint}`
  );

  const notConnected = await phone.waitForControl('peer-not-connected');
  check('phone told peer is not connected', notConnected.peer === laptop.fingerprint);

  // ---------------------------------------------------------------------------
  section('3. Client B authenticates -> mutual target forms a signaling pair');
  // ---------------------------------------------------------------------------
  await laptop.connect();
  await laptop.authenticate(phone.fingerprint);
  await laptop.waitForControl('authenticated');

  const laptopPaired = await laptop.waitForControl('peer-connected');
  const phonePaired = await phone.waitForControl('peer-connected');
  check('laptop receives "peer-connected"', laptopPaired.peer === phone.fingerprint);
  check('phone receives "peer-connected"', phonePaired.peer === laptop.fingerprint);

  // ---------------------------------------------------------------------------
  section('4. SDP / ICE relayed verbatim in both directions');
  // ---------------------------------------------------------------------------
  const offer = {
    type: 'offer',
    target: laptop.fingerprint,
    sdp: `v=0\r\no=- ${crypto.randomBytes(8).toString('hex')} 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\n`
  };
  phone.send(offer);
  const offerRcv = await laptop.waitForControl('offer');
  check(
    'phone -> laptop offer forwarded verbatim',
    JSON.stringify(offerRcv) === JSON.stringify(offer),
    `sdp ${offerRcv.sdp?.length} chars`
  );

  const answer = {
    type: 'answer',
    target: phone.fingerprint,
    sdp: `v=0\r\no=- ${crypto.randomBytes(8).toString('hex')} 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=setup:active\r\n`
  };
  laptop.send(answer);
  const answerRcv = await phone.waitForControl('answer');
  check(
    'laptop -> phone answer forwarded verbatim',
    JSON.stringify(answerRcv) === JSON.stringify(answer),
    `sdp ${answerRcv.sdp?.length} chars`
  );

  // Several ICE candidates back to back, to confirm ordering is preserved.
  const candidates = [1, 2, 3, 4, 5].map((n) => ({
    type: 'ice-candidate',
    target: laptop.fingerprint,
    candidate: { candidate: `candidate:${n} 1 udp 2122260223 192.168.1.${n} 5${n}000 typ host`, sdpMLineIndex: 0 }
  }));
  for (const c of candidates) phone.send(c);
  const received = [];
  for (let i = 0; i < candidates.length; i++) received.push(await laptop.waitForControl('ice-candidate'));
  check(
    'ICE candidate order preserved across 5 messages',
    JSON.stringify(received) === JSON.stringify(candidates),
    received.map((c) => c.candidate.candidate.split(' ')[0]).join(',')
  );

  // A frame addressed to someone other than the paired peer is refused.
  phone.send({ type: 'offer', target: 'AA:BB:CC:DD:EE:FF:00:11', sdp: 'v=0' });
  const misaddressed = await phone.waitForControl('error');
  check(
    'signaling frame to a non-peer target is refused',
    misaddressed.reason === 'target device offline',
    misaddressed.reason
  );

  // ---------------------------------------------------------------------------
  section('5. One side disconnects -> server closes the other side');
  // ---------------------------------------------------------------------------
  phone.close();

  const laptopNotice = await laptop.waitForControl('peer-disconnected');
  check('laptop notified "peer-disconnected"', laptopNotice.peer === phone.fingerprint);

  const laptopClose = await laptop.waitForClose();
  check(
    'laptop socket closed by server with code 4005 (PEER_DISCONNECTED)',
    laptopClose.code === 4005,
    `code=${laptopClose.code} reason="${laptopClose.reason}"`
  );

  // ---------------------------------------------------------------------------
  section('6. Auth rejection paths');
  // ---------------------------------------------------------------------------
  const badSig = new TestClient('bad-signature', WS_URL);
  const someTarget = new TestClient('unused', WS_URL).fingerprint;
  await badSig.connect();
  await badSig.authenticate(someTarget, { corruptSignature: true });
  const badSigClose = await badSig.waitForClose();
  check(
    'invalid signature rejected with 4002 (AUTH_FAILED)',
    badSigClose.code === 4002,
    `code=${badSigClose.code} reason="${badSigClose.reason}"`
  );

  const selfTarget = new TestClient('self-target', WS_URL);
  await selfTarget.connect();
  await selfTarget.authenticate(selfTarget.fingerprint);
  const selfClose = await selfTarget.waitForClose();
  check(
    'self-targeting rejected with 4002',
    selfClose.code === 4002,
    `code=${selfClose.code} reason="${selfClose.reason}"`
  );

  const badTarget = new TestClient('bad-target', WS_URL);
  await badTarget.connect();
  await badTarget.authenticate('not-a-fingerprint');
  const badTargetClose = await badTarget.waitForClose();
  check(
    'malformed target fingerprint rejected with 4002',
    badTargetClose.code === 4002,
    `code=${badTargetClose.code}`
  );

  // ---------------------------------------------------------------------------
  section('7. Signaling before pairing is refused (nothing is buffered)');
  // ---------------------------------------------------------------------------
  const lonely = new TestClient('lonely', WS_URL);
  const absentPeer = new TestClient('absent', WS_URL).fingerprint;
  await lonely.connect();
  await lonely.authenticate(absentPeer);
  await lonely.waitForControl('peer-not-connected');
  lonely.sendOffer(absentPeer, 'v=0\r\n');
  const refusal = await lonely.waitForControl('error');
  check(
    'offer before pairing gets error "target device offline"',
    refusal.reason === 'target device offline',
    refusal.reason
  );
  lonely.close();

  // ---------------------------------------------------------------------------
  section('8. WebSocket upgrade on a wrong path is refused');
  // ---------------------------------------------------------------------------
  const wrongPath = await new Promise((resolve) => {
    const ws = new WebSocket(WS_URL.replace('/signal', '/not-the-signal'));
    ws.on('open', () => {
      ws.close();
      resolve('opened');
    });
    ws.on('error', (err) => resolve(err.message));
  });
  check('upgrade on wrong path refused', wrongPath !== 'opened', String(wrongPath).slice(0, 60));

  // ---------------------------------------------------------------------------
  section('9. Server released all state');
  // ---------------------------------------------------------------------------
  await new Promise((r) => setTimeout(r, 300));
  const finalHealth = JSON.parse((await httpGet(`${HTTP_URL}/health`)).body);
  check(
    'no lingering authenticated sessions',
    finalHealth.authenticated === 0,
    `authenticated=${finalHealth.authenticated}, connections=${finalHealth.connections}`
  );
  check('no lingering paired sessions', finalHealth.pairedSessions === 0);

  console.log(`\n${'='.repeat(50)}`);
  console.log(`${failed === 0 ? 'ALL CHECKS PASSED' : `${failed} CHECK(S) FAILED`}  —  ${passed} passed, ${failed} failed`);
  console.log('='.repeat(50));
  process.exitCode = failed === 0 ? 0 : 1;
}

main()
  .catch((err) => {
    console.error(`\nScenario aborted: ${err.message}`);
    process.exitCode = 1;
  })
  .finally(() => {
    // Give close frames a moment to flush, then let the process end on its own.
    setTimeout(() => process.exit(process.exitCode ?? 0), 300);
  });
