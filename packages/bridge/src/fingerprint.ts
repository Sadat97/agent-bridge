// Fingerprint of an identity public key: SHA-256, shown as 12 groups of 5
// decimal digits (a 60-digit safety number). The digits are the first 60 of
// the hash interpreted as an integer and padded to 78 digits.
//
// The same digits are the QR payload `agbfp:v1:<60 digits>`. People compare
// either form out of band. `agb contact verify` accepts both.

import { createHash } from 'node:crypto';

export const FINGERPRINT_QR_PREFIX = 'agbfp:v1:';

export function fingerprint(publicKey: Uint8Array): string {
  return formatFingerprint(fingerprintDigits(publicKey));
}

export function fingerprintDigits(publicKey: Uint8Array): string {
  const digest = createHash('sha256').update(publicKey).digest();
  let value = 0n;
  for (const byte of digest) value = (value << 8n) + BigInt(byte);
  return value.toString(10).padStart(78, '0').slice(0, 60);
}

export function fingerprintQrPayload(publicKey: Uint8Array): string {
  return FINGERPRINT_QR_PREFIX + fingerprintDigits(publicKey);
}

export function formatFingerprint(digits: string): string {
  return digits.match(/.{5}/g)!.join(' ');
}

/**
 * Accepts the grouped safety number, the 60 digits, or the QR payload.
 * Returns the 60 digits, or undefined when the input is not one of those.
 */
export function parseFingerprint(input: string): string | undefined {
  let text = input.trim();
  if (text.toLowerCase().startsWith(FINGERPRINT_QR_PREFIX)) text = text.slice(FINGERPRINT_QR_PREFIX.length);
  const digits = text.replaceAll(/[\s-]/g, '');
  if (!/^\d{60}$/.test(digits)) return undefined;
  return digits;
}
