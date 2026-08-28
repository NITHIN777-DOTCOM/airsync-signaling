import crypto from 'node:crypto';

/**
 * Device identity primitives, kept byte-compatible with the two AirSync clients.
 *
 * The clients generate EC P-256 (prime256v1) key pairs:
 *  - Android: AndroidKeyStore, non-exportable, signs with "SHA256withECDSA"
 *  - Desktop: Node `crypto`, private key sealed with Electron safeStorage
 *
 * Both hand out their public key as base64 X.509 SubjectPublicKeyInfo DER, and both
 * produce DER-encoded ECDSA signatures — Java's "SHA256withECDSA" and Node's
 * `crypto.sign('sha256', ...)` with `dsaEncoding: 'der'` are the same format, which is
 * what lets this server verify either client with one code path.
 */

const EXPECTED_CURVE = 'prime256v1';

/** Longest base64 public key accepted. A P-256 SPKI is ~124 chars; this is slack. */
const MAX_PUBLIC_KEY_CHARS = 500;

/** Longest base64 signature accepted. DER P-256 signatures are ~96 chars. */
const MAX_SIGNATURE_CHARS = 300;

/**
 * Parses a base64 SPKI DER public key, rejecting anything that is not an EC P-256 key.
 * Returns a KeyObject, or null if unusable.
 *
 * Restricting the curve matters: without it a caller could present, say, an RSA key and
 * still produce a valid signature, which would authenticate an identity whose
 * fingerprint the real clients could never generate.
 */
export function parsePublicKey(publicKeyB64) {
  if (typeof publicKeyB64 !== 'string') return null;
  if (publicKeyB64.length === 0 || publicKeyB64.length > MAX_PUBLIC_KEY_CHARS) return null;

  let der;
  try {
    der = Buffer.from(publicKeyB64, 'base64');
  } catch {
    return null;
  }
  if (der.length === 0) return null;

  // Base64.from() silently ignores junk, so round-trip to reject malformed input
  // rather than accepting a string that decodes to something arbitrary.
  if (der.toString('base64') !== publicKeyB64.replace(/\s/g, '')) return null;

  try {
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ec') return null;
    if (key.asymmetricKeyDetails?.namedCurve !== EXPECTED_CURVE) return null;
    return key;
  } catch {
    return null;
  }
}

/**
 * SHA-256 over the SPKI DER bytes, first 8 bytes, uppercase colon-separated hex
 * (e.g. "A1:B2:C3:D4:E5:F6:07:18").
 *
 * Byte-identical to DeviceIdentity.fingerprintOf() on Android and fingerprintOfSpki()
 * on the desktop — clients address each other by this string, so it must not drift.
 */
export function fingerprintOf(publicKeyB64) {
  const der = Buffer.from(publicKeyB64, 'base64');
  const digest = crypto.createHash('sha256').update(der).digest();
  return Array.from(digest.subarray(0, 8))
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(':');
}

/** Whether a string looks like one of our fingerprints. */
export function isValidFingerprint(value) {
  return typeof value === 'string' && /^[0-9A-F]{2}(:[0-9A-F]{2}){7}$/.test(value);
}

/**
 * Verifies that `signatureB64` is a valid ECDSA/SHA-256 signature over `challenge`
 * made by the private key matching `publicKey`.
 *
 * This is the whole of the relay's trust model: it proves the connection controls the
 * claimed private key. It deliberately does *not* decide whether two devices are
 * allowed to talk — that trust was established locally during pairing, and the relay
 * keeps no registry of its own.
 */
export function verifyChallengeSignature(publicKey, challenge, signatureB64) {
  if (typeof signatureB64 !== 'string') return false;
  if (signatureB64.length === 0 || signatureB64.length > MAX_SIGNATURE_CHARS) return false;

  let signature;
  try {
    signature = Buffer.from(signatureB64, 'base64');
  } catch {
    return false;
  }
  if (signature.length === 0) return false;

  try {
    return crypto.verify('sha256', challenge, { key: publicKey, dsaEncoding: 'der' }, signature);
  } catch {
    return false;
  }
}

/** 32 cryptographically random bytes for a connection's challenge nonce. */
export function generateChallenge() {
  return crypto.randomBytes(32);
}
