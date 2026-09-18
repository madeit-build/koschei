import { describe, expect, it } from 'vitest';
import {
  EnvelopeFormatError,
  PAD_BLOCK,
  canonicalAction,
  decodeEnvelope,
  encodeEnvelope,
  fromBase64Url,
  padPlaintext,
  slotAad,
  toBase64Url,
  unpadPlaintext,
} from '../src/envelope.ts';

const utf8 = (s: string) => new TextEncoder().encode(s);

describe('base64url', () => {
  it('round-trips and never emits padding or +/', () => {
    const bytes = Uint8Array.from({ length: 70 }, (_, i) => (i * 37) % 256);
    const text = toBase64Url(bytes);
    expect(text).not.toMatch(/[+/=]/);
    expect(fromBase64Url(text)).toEqual(bytes);
  });
  it('rejects characters outside the alphabet', () => {
    expect(() => fromBase64Url('ab+c')).toThrow();
  });
});

describe('slot', () => {
  it('canonicalizes the action to origin + pathname', () => {
    expect(canonicalAction('HTTPS://API.Example.com:443/enroll?step=2#x')).toBe('https://api.example.com/enroll');
    expect(canonicalAction('http://localhost:4781/enroll/')).toBe('http://localhost:4781/enroll/');
  });
  it('builds the AAD with newline separators', () => {
    const aad = slotAad({ origin: 'https://www.example.com', action: 'https://api.example.com/enroll', name: 'ssn' });
    expect(new TextDecoder().decode(aad)).toBe('https://www.example.com\nhttps://api.example.com/enroll\nssn');
  });
});

describe('padding', () => {
  it('pads to a multiple of 32 with a 2-byte length prefix', () => {
    const padded = padPlaintext('123-45-6789');
    expect(padded.length).toBe(PAD_BLOCK);
    expect(padded[0]).toBe(0);
    expect(padded[1]).toBe(11);
    expect(padded.subarray(2, 13)).toEqual(utf8('123-45-6789'));
    expect(padded.subarray(13).every((b) => b === 0)).toBe(true);
  });
  it('grows to the next block when the value fills one', () => {
    expect(padPlaintext('x'.repeat(30)).length).toBe(32);
    expect(padPlaintext('x'.repeat(31)).length).toBe(64);
  });
  it('round-trips unicode', () => {
    expect(unpadPlaintext(padPlaintext('Grüße 🌊'))).toBe('Grüße 🌊');
  });
  it('rejects bad padding', () => {
    expect(() => unpadPlaintext(new Uint8Array(31))).toThrow();
    const tampered = padPlaintext('a');
    tampered[20] = 1;
    expect(() => unpadPlaintext(tampered)).toThrow();
    const overlong = new Uint8Array(32);
    overlong[1] = 40;
    expect(() => unpadPlaintext(overlong)).toThrow();
  });
});

describe('envelope', () => {
  const enc = Uint8Array.from({ length: 65 }, (_, i) => i);
  const ct = Uint8Array.from({ length: 48 }, (_, i) => 255 - i);
  it('encodes and decodes', () => {
    const text = encodeEnvelope({ kid: '2026-09', enc, ct });
    expect(text.startsWith('sealed1.2026-09.')).toBe(true);
    expect(text.split('.')).toHaveLength(4);
    expect(decodeEnvelope(text)).toEqual({ kid: '2026-09', enc, ct });
  });
  it('rejects wrong version, wrong part count, bad kid, wrong enc length, short ct', () => {
    const good = encodeEnvelope({ kid: 'k', enc, ct });
    expect(() => decodeEnvelope(good.replace('sealed1', 'sealed2'))).toThrow(EnvelopeFormatError);
    expect(() => decodeEnvelope(good + '.extra')).toThrow(EnvelopeFormatError);
    expect(() => decodeEnvelope(good.replace('.k.', '.k id.'))).toThrow(EnvelopeFormatError);
    expect(() => decodeEnvelope(encodeEnvelope({ kid: 'k', enc: enc.subarray(0, 64), ct }))).toThrow(EnvelopeFormatError);
    expect(() => decodeEnvelope(encodeEnvelope({ kid: 'k', enc, ct: ct.subarray(0, 47) }))).toThrow(EnvelopeFormatError);
    expect(() => encodeEnvelope({ kid: 'has.dot', enc, ct })).toThrow(EnvelopeFormatError);
  });
});
