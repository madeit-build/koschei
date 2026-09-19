import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';
import { HPKE_INFO } from './envelope.ts';

// One suite, no negotiation. Matches ISO 18013-7 and RFC 9180 Appendix A.3.
export const suite = new CipherSuite({
  kem: new DhkemP256HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes128Gcm(),
});

export interface SealOptions {
  info?: Uint8Array;
  // Ephemeral key material. Test vectors only; production callers must not set it.
  ekm?: Uint8Array;
}

export interface OpenOptions {
  info?: Uint8Array;
}

export async function hpkeSeal(
  recipientPublicKey: CryptoKey,
  plaintext: Uint8Array,
  aad: Uint8Array,
  options: SealOptions = {},
): Promise<{ enc: Uint8Array; ct: Uint8Array }> {
  const response = await suite.seal(
    { recipientPublicKey, info: options.info ?? HPKE_INFO, ...(options.ekm ? { ekm: options.ekm } : {}) },
    plaintext,
    aad,
  );
  return { enc: new Uint8Array(response.enc), ct: new Uint8Array(response.ct) };
}

export async function hpkeOpen(
  recipientPrivateKey: CryptoKey,
  enc: Uint8Array,
  ct: Uint8Array,
  aad: Uint8Array,
  options: OpenOptions = {},
): Promise<Uint8Array> {
  const plaintext = await suite.open({ recipientKey: recipientPrivateKey, enc, info: options.info ?? HPKE_INFO }, ct, aad);
  return new Uint8Array(plaintext);
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error('bad hex');
  return Uint8Array.from({ length: hex.length / 2 }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16));
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
