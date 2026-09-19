import { describe, expect, it } from 'vitest';
import { sealValue } from '../src/seal.ts';
import { suite } from '../src/hpke.ts';
import { UnsealError, unseal, type UnsealEvent } from '../src/server/unseal.ts';

async function recipient(kid: string) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const privateJwk = { ...(await crypto.subtle.exportKey('jwk', kp.privateKey)), kid, use: 'enc' };
  const publicKey = await suite.kem.importKey('jwk', await crypto.subtle.exportKey('jwk', kp.publicKey), true);
  return { kid, privateJwk, publicKey };
}

const slot = { origin: 'https://www.example.com', action: 'https://api.example.com/enroll', name: 'ssn' };
const expect_ = { origin: 'https://www.example.com', action: 'https://api.example.com/enroll', name: 'ssn' };
const silent = () => {};

describe('unseal', () => {
  it('round-trips a value sealed for the expected slot', async () => {
    const r = await recipient('2026-09');
    const envelope = await sealValue({ value: '123-45-6789', kid: r.kid, recipientPublicKey: r.publicKey, slot });
    expect(envelope.startsWith('sealed1.2026-09.')).toBe(true);
    expect(envelope).not.toContain('6789');
    expect(await unseal(envelope, { privateKey: r.privateJwk, expect: expect_, onEvent: silent })).toBe('123-45-6789');
  });

  it('rejects the wrong origin, action, or name with open-failed', async () => {
    const r = await recipient('k1');
    const envelope = await sealValue({ value: 'x', kid: r.kid, recipientPublicKey: r.publicKey, slot });
    for (const bad of [
      { ...expect_, origin: 'https://evil.example' },
      { ...expect_, action: 'https://api.example.com/update-payment' },
      { ...expect_, name: 'card' },
    ]) {
      await expect(unseal(envelope, { privateKey: r.privateJwk, expect: bad, onEvent: silent })).rejects.toMatchObject({ code: 'open-failed' });
    }
  });

  it('accepts any of several expected origins', async () => {
    const r = await recipient('k1');
    const envelope = await sealValue({ value: 'x', kid: r.kid, recipientPublicKey: r.publicKey, slot });
    const opts = { privateKey: r.privateJwk, expect: { ...expect_, origin: ['https://other.example', 'https://www.example.com'] }, onEvent: silent };
    expect(await unseal(envelope, opts)).toBe('x');
  });

  it('ignores query and fragment on expect.action but requires an absolute URL', async () => {
    const r = await recipient('k1');
    const envelope = await sealValue({ value: 'x', kid: r.kid, recipientPublicKey: r.publicKey, slot });
    expect(await unseal(envelope, { privateKey: r.privateJwk, expect: { ...expect_, action: 'https://api.example.com/enroll?step=2#a' }, onEvent: silent })).toBe('x');
    await expect(unseal(envelope, { privateKey: r.privateJwk, expect: { ...expect_, action: '/enroll' }, onEvent: silent })).rejects.toThrow(TypeError);
  });

  it('reports bad-envelope and unknown-kid', async () => {
    const r = await recipient('k1');
    await expect(unseal('nope', { privateKey: r.privateJwk, expect: expect_, onEvent: silent })).rejects.toMatchObject({ code: 'bad-envelope' });
    const envelope = await sealValue({ value: 'x', kid: 'k2', recipientPublicKey: r.publicKey, slot });
    await expect(unseal(envelope, { privateKey: r.privateJwk, expect: expect_, onEvent: silent })).rejects.toMatchObject({ code: 'unknown-kid' });
  });

  it('selects the private key by kid when several are supplied', async () => {
    const a = await recipient('a');
    const b = await recipient('b');
    const envelope = await sealValue({ value: 'x', kid: 'b', recipientPublicKey: b.publicKey, slot });
    expect(await unseal(envelope, { privateKey: [a.privateJwk, b.privateJwk], expect: expect_, onEvent: silent })).toBe('x');
  });

  it('emits exactly one structured event that never contains the envelope, key, or plaintext', async () => {
    const r = await recipient('k1');
    const envelope = await sealValue({ value: 'SECRET-VALUE', kid: r.kid, recipientPublicKey: r.publicKey, slot });
    const events: UnsealEvent[] = [];
    await unseal(envelope, { privateKey: r.privateJwk, expect: expect_, onEvent: (e) => events.push(e) });
    await unseal(envelope, { privateKey: r.privateJwk, expect: { ...expect_, name: 'card' }, onEvent: (e) => events.push(e) }).catch(() => {});
    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({ event: 'sealed-input.unseal', outcome: 'ok', kid: 'k1' });
    expect(events[1]).toMatchObject({ outcome: 'open-failed', kid: 'k1', expected: { name: 'card' } });
    const serialized = JSON.stringify(events);
    expect(serialized).not.toContain('SECRET-VALUE');
    expect(serialized).not.toContain(envelope.split('.')[3]);
    expect(serialized).not.toContain(r.privateJwk.d as string);
    expect(events[1]?.hint).toMatch(/expect\.origin|expect\.action|expect\.name/);
  });

  it('exposes UnsealError with code and hint', async () => {
    const r = await recipient('k1');
    const err = await unseal('sealed1.k1.AA.AA', { privateKey: r.privateJwk, expect: expect_, onEvent: silent }).catch((e) => e);
    expect(err).toBeInstanceOf(UnsealError);
    expect(err.code).toBe('bad-envelope');
    expect(typeof err.hint).toBe('string');
  });

  it('rejects a malformed or curve-mismatched private key with TypeError and never emits an event', async () => {
    const r = await recipient('k1');
    const badKey = { ...r.privateJwk, crv: 'P-384' };
    const events: UnsealEvent[] = [];
    await expect(unseal('sealed1.k1.AA.AA', { privateKey: badKey, expect: expect_, onEvent: (e) => events.push(e) })).rejects.toThrow(TypeError);
    expect(events).toHaveLength(0);
  });

  it('rejects a private key with no kid with TypeError', async () => {
    const r = await recipient('k1');
    const { kid: _kid, ...keyWithoutKid } = r.privateJwk;
    await expect(unseal('sealed1.k1.AA.AA', { privateKey: keyWithoutKid, expect: expect_, onEvent: silent })).rejects.toThrow(TypeError);
  });
});
