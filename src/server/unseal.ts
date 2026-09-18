import { canonicalAction, decodeEnvelope, EnvelopeFormatError, slotAad, unpadPlaintext } from '../envelope.ts';
import { hpkeOpen, suite } from '../hpke.ts';

export type UnsealCode = 'bad-envelope' | 'unknown-kid' | 'open-failed';

export class UnsealError extends Error {
  readonly code: UnsealCode;
  readonly hint: string;

  // Plain fields, not constructor parameter properties: Node's native TypeScript
  // type-stripping (used by `node demo/serve.ts`) rejects parameter properties.
  constructor(code: UnsealCode, message: string, hint: string) {
    super(message);
    this.name = 'UnsealError';
    this.code = code;
    this.hint = hint;
  }
}

export interface UnsealExpect {
  origin: string | string[];
  action: string;
  name: string;
}

export interface UnsealEvent {
  event: 'sealed-input.unseal';
  outcome: 'ok' | UnsealCode;
  kid: string | null;
  expected: { origins: string[]; action: string; name: string };
  hint?: string;
}

export interface UnsealOptions {
  privateKey: JsonWebKey | JsonWebKey[];
  expect: UnsealExpect;
  onEvent?: (event: UnsealEvent) => void;
}

const HINTS: Record<UnsealCode, string> = {
  'bad-envelope': 'The value is not a sealed1 envelope. Check that the field was submitted from a <sealed-input> and not rewritten in transit.',
  'unknown-kid': 'No private key matches the envelope kid. Publish the matching key or add its private JWK to privateKey.',
  'open-failed': 'AEAD rejected the envelope. Check expect.origin (embedding page origin), expect.action (absolute action URL), and expect.name (field name); or the envelope was corrupted.',
};

function defaultOnEvent(event: UnsealEvent): void {
  process.stderr.write(JSON.stringify(event) + '\n');
}

function normalizeExpect(expect: UnsealExpect): { origins: string[]; action: string; name: string } {
  const origins = Array.isArray(expect.origin) ? expect.origin : [expect.origin];
  if (origins.length === 0) throw new TypeError('expect.origin must name at least one origin');
  for (const origin of origins) {
    if (new URL(origin).origin !== origin) throw new TypeError(`expect.origin "${origin}" is not a bare origin`);
  }
  let action: string;
  try {
    action = canonicalAction(expect.action);
  } catch {
    throw new TypeError('expect.action must be an absolute URL');
  }
  if (!expect.name) throw new TypeError('expect.name is required');
  return { origins, action, name: expect.name };
}

async function importPrivateKey(jwk: JsonWebKey): Promise<CryptoKey> {
  const { kid: _kid, use: _use, ...importable } = jwk as JsonWebKey & { kid?: string; use?: string };
  return suite.kem.importKey('jwk', importable, false);
}

// Importing every private key up front, before any onEvent call, keeps a malformed or
// curve-mismatched key a plain configuration-error TypeError rather than an unhandled
// throw mid-unseal that would skip the "exactly one event" and "exactly three codes" contracts.
async function importPrivateKeysByKid(keys: JsonWebKey[]): Promise<Map<string, CryptoKey>> {
  const byKid = new Map<string, CryptoKey>();
  for (const jwk of keys) {
    const kid = (jwk as { kid?: unknown }).kid;
    if (typeof kid !== 'string' || kid === '') throw new TypeError('every private key needs a kid');
    try {
      byKid.set(kid, await importPrivateKey(jwk));
    } catch {
      throw new TypeError(`private key for kid "${kid}" could not be imported as an EC P-256 key`);
    }
  }
  return byKid;
}

export async function unseal(envelopeText: string, options: UnsealOptions): Promise<string> {
  const onEvent = options.onEvent ?? defaultOnEvent;
  const expected = normalizeExpect(options.expect);
  const keys = Array.isArray(options.privateKey) ? options.privateKey : [options.privateKey];
  const privateKeysByKid = await importPrivateKeysByKid(keys);

  const fail = (code: UnsealCode, kid: string | null): never => {
    onEvent({ event: 'sealed-input.unseal', outcome: code, kid, expected, hint: HINTS[code] });
    throw new UnsealError(code, `unseal failed: ${code}`, HINTS[code]);
  };

  let envelope;
  try {
    envelope = decodeEnvelope(envelopeText);
  } catch (error) {
    if (error instanceof EnvelopeFormatError) return fail('bad-envelope', null);
    throw error;
  }

  const privateKey = privateKeysByKid.get(envelope.kid);
  if (!privateKey) return fail('unknown-kid', envelope.kid);

  for (const origin of expected.origins) {
    try {
      const padded = await hpkeOpen(privateKey, envelope.enc, envelope.ct, slotAad({ origin, action: expected.action, name: expected.name }));
      const value = unpadPlaintext(padded);
      onEvent({ event: 'sealed-input.unseal', outcome: 'ok', kid: envelope.kid, expected });
      return value;
    } catch {
      // Try the next expected origin; an AEAD failure is indistinguishable from a wrong slot.
    }
  }
  return fail('open-failed', envelope.kid);
}
