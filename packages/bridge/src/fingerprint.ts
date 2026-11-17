// Fingerprint of an identity public key: SHA-256, shown as 12 groups of 5
// decimal digits. The digits are the first 60 of the hash interpreted as an
// integer and padded to 78 digits. People compare this out of band.

import { createHash } from 'node:crypto';

export function fingerprint(publicKey: Uint8Array): string {
  const digest = createHash('sha256').update(publicKey).digest();
  let value = 0n;
  for (const byte of digest) value = (value << 8n) + BigInt(byte);
  const digits = value.toString(10).padStart(78, '0').slice(0, 60);
  return digits.match(/.{5}/g)!.join(' ');
}
