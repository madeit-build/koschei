export const ENVELOPE_VERSION = 'sealed1';
export const HPKE_INFO: Uint8Array = new TextEncoder().encode('sealed-input/1');
export const PAD_BLOCK = 32;
const P256_UNCOMPRESSED_POINT_LENGTH = 65;
const AES_GCM_TAG_LENGTH = 16;
export const KID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;

export interface Slot {
  origin: string;
  action: string;
  name: string;
}

export interface Envelope {
  kid: string;
  enc: Uint8Array;
  ct: Uint8Array;
}

export class EnvelopeFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EnvelopeFormatError';
  }
}

export function canonicalAction(actionUrl: string): string {
  const url = new URL(actionUrl);
  return url.origin + url.pathname;
}

export function slotAad(slot: Slot): Uint8Array {
  return new TextEncoder().encode(`${slot.origin}\n${slot.action}\n${slot.name}`);
}

export function padPlaintext(value: string): Uint8Array {
  const utf8 = new TextEncoder().encode(value);
  if (utf8.length > 0xffff) throw new RangeError('sealed value exceeds 65535 bytes');
  const total = Math.ceil((2 + utf8.length) / PAD_BLOCK) * PAD_BLOCK;
  const out = new Uint8Array(total);
  out[0] = utf8.length >> 8;
  out[1] = utf8.length & 0xff;
  out.set(utf8, 2);
  return out;
}

export function unpadPlaintext(bytes: Uint8Array): string {
  if (bytes.length < PAD_BLOCK || bytes.length % PAD_BLOCK !== 0) {
    throw new EnvelopeFormatError('plaintext is not block-padded');
  }
  const length = ((bytes[0] ?? 0) << 8) | (bytes[1] ?? 0);
  if (2 + length > bytes.length) throw new EnvelopeFormatError('plaintext length prefix exceeds buffer');
  for (let i = 2 + length; i < bytes.length; i++) {
    if (bytes[i] !== 0) throw new EnvelopeFormatError('plaintext padding is not zero');
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(2, 2 + length));
}

export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(text: string): Uint8Array {
  if (!BASE64URL_PATTERN.test(text)) throw new EnvelopeFormatError('not base64url');
  const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export function encodeEnvelope(envelope: Envelope): string {
  if (!KID_PATTERN.test(envelope.kid)) throw new EnvelopeFormatError('kid must match [A-Za-z0-9_-]{1,64}');
  return [ENVELOPE_VERSION, envelope.kid, toBase64Url(envelope.enc), toBase64Url(envelope.ct)].join('.');
}

export function decodeEnvelope(text: string): Envelope {
  const parts = text.split('.');
  if (parts.length !== 4) throw new EnvelopeFormatError('envelope must have four dot-separated parts');
  const [version, kid, encText, ctText] = parts as [string, string, string, string];
  if (version !== ENVELOPE_VERSION) throw new EnvelopeFormatError(`unsupported envelope version ${version}`);
  if (!KID_PATTERN.test(kid)) throw new EnvelopeFormatError('kid must match [A-Za-z0-9_-]{1,64}');
  const enc = fromBase64Url(encText);
  const ct = fromBase64Url(ctText);
  if (enc.length !== P256_UNCOMPRESSED_POINT_LENGTH) throw new EnvelopeFormatError('enc must be a 65-byte P-256 point');
  if (ct.length < PAD_BLOCK + AES_GCM_TAG_LENGTH) throw new EnvelopeFormatError('ciphertext too short');
  return { kid, enc, ct };
}
