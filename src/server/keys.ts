export interface RecipientKeyPair {
  kid: string;
  privateJwk: JsonWebKey;
  publicJwk: JsonWebKey;
}

export interface WellKnownDocument {
  frame: string;
  keys: JsonWebKey[];
}

export const DEFAULT_FRAME_PATH = '/sealed-input/frame.html';

export async function generateRecipientKey(kid: string): Promise<RecipientKeyPair> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const privateJwk = { ...(await crypto.subtle.exportKey('jwk', pair.privateKey)), kid, use: 'enc' };
  const publicJwk = { ...(await crypto.subtle.exportKey('jwk', pair.publicKey)), kid, use: 'enc' };
  return { kid, privateJwk, publicJwk };
}

export function wellKnownDocument(publicJwks: JsonWebKey[], framePath: string = DEFAULT_FRAME_PATH): WellKnownDocument {
  return { frame: framePath, keys: publicJwks };
}

export function parseWellKnown(json: unknown): WellKnownDocument {
  if (typeof json !== 'object' || json === null) throw new TypeError('well-known must be a JSON object');
  const { frame, keys } = json as { frame?: unknown; keys?: unknown };
  if (typeof frame !== 'string' || frame.length === 0) throw new TypeError('well-known.frame must be a non-empty string');
  if (!Array.isArray(keys)) throw new TypeError('well-known.keys must be an array');
  for (const key of keys) {
    if (typeof key !== 'object' || key === null) throw new TypeError('well-known.keys entries must be objects');
  }
  return { frame, keys: keys as JsonWebKey[] };
}

export function selectEncryptionKey(doc: WellKnownDocument): { kid: string; jwk: JsonWebKey } {
  for (const jwk of doc.keys) {
    const { kty, crv, x, y, kid, use } = jwk as JsonWebKey & { kid?: unknown };
    if (kty === 'EC' && crv === 'P-256' && typeof x === 'string' && typeof y === 'string' && use === 'enc' && typeof kid === 'string' && kid.length > 0) {
      return { kid, jwk };
    }
  }
  throw new TypeError('well-known has no usable key (EC P-256, use=enc, with kid)');
}
