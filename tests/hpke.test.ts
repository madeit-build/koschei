import { describe, expect, it } from 'vitest';
import { HPKE_INFO } from '../src/envelope.ts';
import { bytesToHex, hexToBytes, hpkeOpen, hpkeSeal, suite } from '../src/hpke.ts';
import { RFC9180_A3_1 as V } from './fixtures/rfc9180-a3-1.ts';

describe('RFC 9180 A.3.1 known answers', () => {
  it('derives the recipient key pair from ikmR', async () => {
    const kp = await suite.kem.deriveKeyPair(hexToBytes(V.ikmR));
    expect(bytesToHex(new Uint8Array(await suite.kem.serializePublicKey(kp.publicKey)))).toBe(V.pkRm);
  });

  it('opens the vector ciphertext (recipient side)', async () => {
    const kp = await suite.kem.deriveKeyPair(hexToBytes(V.ikmR));
    const pt = await hpkeOpen(kp.privateKey, hexToBytes(V.enc), hexToBytes(V.encryption0.ct), hexToBytes(V.encryption0.aad), {
      info: hexToBytes(V.info),
    });
    expect(bytesToHex(pt)).toBe(V.encryption0.pt);
  });

  it('reproduces the vector enc and ct with the vector ikmE (sender side)', async () => {
    const pkR = await suite.kem.deserializePublicKey(hexToBytes(V.pkRm));
    const { enc, ct } = await hpkeSeal(pkR, hexToBytes(V.encryption0.pt), hexToBytes(V.encryption0.aad), {
      info: hexToBytes(V.info),
      ekm: hexToBytes(V.ikmE),
    });
    expect(bytesToHex(enc)).toBe(V.pkEm);
    expect(bytesToHex(ct)).toBe(V.encryption0.ct);
  });
});

describe('seal/open with the sealed-input info', () => {
  it('round-trips and binds the aad', async () => {
    const kp = await suite.kem.generateKeyPair();
    const pt = new TextEncoder().encode('hello');
    const aad = new TextEncoder().encode('slot-a');
    const { enc, ct } = await hpkeSeal(kp.publicKey, pt, aad);
    expect(await hpkeOpen(kp.privateKey, enc, ct, aad)).toEqual(pt);
    await expect(hpkeOpen(kp.privateKey, enc, ct, new TextEncoder().encode('slot-b'))).rejects.toThrow();
    await expect(hpkeOpen(kp.privateKey, enc, ct, aad, { info: new TextEncoder().encode('other') })).rejects.toThrow();
  });
  it('uses sealed-input/1 as the default info', () => {
    expect(new TextDecoder().decode(HPKE_INFO)).toBe('sealed-input/1');
  });
});
