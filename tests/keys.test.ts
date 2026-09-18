import { describe, expect, it } from 'vitest';
import { generateRecipientKey, parseWellKnown, selectEncryptionKey, wellKnownDocument } from '../src/server/keys.ts';
import { suite } from '../src/hpke.ts';

describe('recipient keys', () => {
  it('generates a P-256 pair with kid and use=enc on both halves', async () => {
    const pair = await generateRecipientKey('2026-09');
    expect(pair.publicJwk).toMatchObject({ kty: 'EC', crv: 'P-256', kid: '2026-09', use: 'enc' });
    expect(pair.privateJwk).toMatchObject({ kty: 'EC', crv: 'P-256', kid: '2026-09', use: 'enc' });
    expect(typeof pair.privateJwk.d).toBe('string');
    expect(pair.publicJwk.d).toBeUndefined();
  });

  it('produces keys @hpke/core can import on both sides', async () => {
    const pair = await generateRecipientKey('k');
    const { kid: _a, use: _b, ...pub } = pair.publicJwk as JsonWebKey & { kid?: string; use?: string };
    const { kid: _c, use: _d, ...priv } = pair.privateJwk as JsonWebKey & { kid?: string; use?: string };
    await expect(suite.kem.importKey('jwk', pub, true)).resolves.toBeDefined();
    await expect(suite.kem.importKey('jwk', priv, false)).resolves.toBeDefined();
  });

  it('builds and parses the well-known document', async () => {
    const pair = await generateRecipientKey('k');
    const doc = wellKnownDocument([pair.publicJwk]);
    expect(doc.frame).toBe('/sealed-input/frame.html');
    expect(parseWellKnown(JSON.parse(JSON.stringify(doc)))).toEqual(doc);
    expect(selectEncryptionKey(doc).kid).toBe('k');
  });

  it('rejects malformed documents', () => {
    expect(() => parseWellKnown(null)).toThrow(TypeError);
    expect(() => parseWellKnown({ frame: 5, keys: [] })).toThrow(TypeError);
    expect(() => parseWellKnown({ frame: '/f', keys: 'nope' })).toThrow(TypeError);
    expect(() => selectEncryptionKey({ frame: '/f', keys: [{ kty: 'EC', crv: 'P-384', x: 'a', y: 'b', kid: 'k', use: 'enc' } as JsonWebKey] })).toThrow(TypeError);
    expect(() => selectEncryptionKey({ frame: '/f', keys: [{ kty: 'EC', crv: 'P-256', x: 'a', y: 'b', use: 'enc' } as JsonWebKey] })).toThrow(TypeError);
  });

  it('skips a key whose kid the envelope cannot carry', () => {
    const dotted = { kty: 'EC', crv: 'P-256', x: 'a', y: 'b', kid: 'v1.2', use: 'enc' } as JsonWebKey;
    const plain = { kty: 'EC', crv: 'P-256', x: 'c', y: 'd', kid: 'v1-2', use: 'enc' } as JsonWebKey;
    expect(() => selectEncryptionKey({ frame: '/f', keys: [dotted] })).toThrow(TypeError);
    expect(selectEncryptionKey({ frame: '/f', keys: [dotted, plain] }).kid).toBe('v1-2');
  });
});
