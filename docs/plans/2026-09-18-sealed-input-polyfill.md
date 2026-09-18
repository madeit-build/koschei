# Sealed Input Polyfill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A working `<sealed-input>` polyfill, a Node `unseal()` library, `init` and `doctor` CLIs, and a two-origin demo that proves the round trip: typed value never reaches page script, envelope opens only on the recipient for the exact slot it was sealed in.

**Architecture:** Shared TypeScript envelope codec and HPKE wrapper used by both browser and Node. A recipient-hosted iframe (`frame.html`) holds the real `<input>`, seals every keystroke with HPKE to the recipient's own published key, and posts the envelope to the page. A form-associated custom element `<sealed-input>` discovers the recipient from the form `action`, embeds the frame, and exposes the envelope as its form value. A Node `unseal()` reconstructs the slot AAD from server-side expectations and opens the envelope. Demo runs two local origins (page on 4780, recipient on 4781) so the cross-origin boundary is real.

**Tech Stack:** TypeScript 7.0.2 (type-check only, `noEmit`), Node 26 (runs `.ts` directly via native type stripping; needs ≥ 23), npm, `@hpke/core` 1.9.0 (RFC 9180 on WebCrypto, same code in browser and Node), esbuild 0.28.2 (bundles the two browser entry points), vitest 5.0.1 (unit), `@playwright/test` 1.63.0 with Chromium (end-to-end).

**Spec:** `docs/specs/explainer.md` (API, envelope, slot, threat model), `README.md` (usage), `docs/research/prior-art.md` (why).

## Global Constraints

- Envelope format: `sealed1.<kid>.<base64url(enc)>.<base64url(ct)>`; `kid` matches `^[A-Za-z0-9_-]{1,64}$`; `enc` is 65 bytes (P-256 uncompressed point).
- HPKE suite: `DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM`, base mode, single-shot. `info` = UTF-8 `sealed-input/1`.
- Slot AAD: UTF-8 of `<embedding origin> "\n" <action origin + pathname> "\n" <field name>`. Action drops `search` and `hash`.
- Plaintext: `uint16 big-endian length || UTF-8 value || zero padding` to a multiple of 32 bytes. Empty value is never sealed; the form value is `""`.
- `unseal` error codes: exactly `bad-envelope`, `unknown-kid`, `open-failed`. Never log the envelope, the key, or the plaintext.
- `sealed-error` reasons: `recipient-unreachable`, `recipient-invalid`, `frame-blocked`, `no-form-action`, `insecure-action`, `insecure-context`.
- "Secure" means a potentially trustworthy URL: `https:`, or `http:` on `localhost`, `*.localhost`, `127.0.0.1`, `[::1]`. (Task 9 amends the explainer, which currently says only `https:`.)
- The frame seals only to its own origin's key; it rejects an `init` whose action origin differs from `location.origin`.
- Constraints (`pattern`, `minlength`, `maxlength`) freeze on first input; validity is a single `customError` bit.
- Ports: page `4780`, recipient `4781`. Never 8080/3000/5000/8000/9000.
- No framework. Vanilla custom element. ESM everywhere (`"type": "module"`). Relative imports use explicit `.ts` extensions (Node native type stripping requires them; vitest and esbuild accept them).
- Commit after every task. Repo-relative paths only in committed files.

---

### Task 1: Project scaffold and envelope codec

**Files:**
- Create: `package.json`, `tsconfig.json`, `.gitignore`
- Create: `src/envelope.ts`
- Test: `tests/envelope.test.ts`

**Interfaces:**
- Produces:
  - `ENVELOPE_VERSION: 'sealed1'`, `HPKE_INFO: Uint8Array`, `PAD_BLOCK: 32`
  - `interface Slot { origin: string; action: string; name: string }`
  - `slotAad(slot: Slot): Uint8Array`
  - `canonicalAction(actionUrl: string): string` (origin + pathname)
  - `padPlaintext(value: string): Uint8Array`, `unpadPlaintext(bytes: Uint8Array): string`
  - `toBase64Url(bytes: Uint8Array): string`, `fromBase64Url(text: string): Uint8Array`
  - `interface Envelope { kid: string; enc: Uint8Array; ct: Uint8Array }`
  - `encodeEnvelope(e: Envelope): string`, `decodeEnvelope(text: string): Envelope`
  - `class EnvelopeFormatError extends Error`

- [ ] **Step 1: Scaffold the project**

`package.json`:
```json
{
  "name": "koschei",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "description": "A form field the page cannot read. Polyfill and explainer for <sealed-input>.",
  "engines": { "node": ">=23" },
  "scripts": {
    "typecheck": "tsc -p tsconfig.json",
    "test": "vitest run",
    "build": "node scripts/build.ts",
    "demo": "node demo/serve.ts",
    "e2e": "playwright test",
    "koschei": "node bin/koschei.ts"
  },
  "dependencies": {
    "@hpke/core": "1.9.0"
  },
  "devDependencies": {
    "@playwright/test": "1.63.0",
    "@types/node": "26.0.0",
    "esbuild": "0.28.2",
    "typescript": "7.0.2",
    "vitest": "5.0.1"
  }
}
```

`tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "types": ["node"],
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "allowImportingTsExtensions": true,
    "noEmit": true,
    "skipLibCheck": true
  },
  "include": ["src", "tests", "demo", "bin", "scripts", "e2e", "playwright.config.ts"]
}
```

`.gitignore`:
```
node_modules/
dist/
public/
koschei-private.jwk
test-results/
playwright-report/
```

Run: `npm install`
Expected: installs without errors. If `@types/node@26.0.0` does not exist, run `npm view @types/node version` and pin the current 26.x.

- [ ] **Step 2: Write the failing tests**

`tests/envelope.test.ts`:
```ts
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `npx vitest run tests/envelope.test.ts`
Expected: FAIL, "Failed to load url ../src/envelope.ts" or similar module-not-found.

- [ ] **Step 4: Implement the codec**

`src/envelope.ts`:
```ts
export const ENVELOPE_VERSION = 'sealed1';
export const HPKE_INFO: Uint8Array = new TextEncoder().encode('sealed-input/1');
export const PAD_BLOCK = 32;
const P256_UNCOMPRESSED_POINT_LENGTH = 65;
const AES_GCM_TAG_LENGTH = 16;
const KID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx vitest run tests/envelope.test.ts`
Expected: PASS, 11 tests.

Run: `npm run typecheck`
Expected: no output, exit 0.

- [ ] **Step 6: Commit**

```bash
git add package.json package-lock.json tsconfig.json .gitignore src/envelope.ts tests/envelope.test.ts
git commit -m "feat: project scaffold and sealed1 envelope codec"
```

---

### Task 2: HPKE wrapper with RFC 9180 known-answer tests

**Files:**
- Create: `src/hpke.ts`
- Create: `tests/fixtures/rfc9180-a3-1.ts`
- Test: `tests/hpke.test.ts`

**Interfaces:**
- Consumes: `HPKE_INFO` from `src/envelope.ts`
- Produces:
  - `suite: CipherSuite` (the single pinned ciphersuite)
  - `hpkeSeal(recipientPublicKey: CryptoKey, plaintext: Uint8Array, aad: Uint8Array, options?: { info?: Uint8Array; ekm?: Uint8Array }): Promise<{ enc: Uint8Array; ct: Uint8Array }>`
  - `hpkeOpen(recipientPrivateKey: CryptoKey, enc: Uint8Array, ct: Uint8Array, aad: Uint8Array, options?: { info?: Uint8Array }): Promise<Uint8Array>`
  - `hexToBytes(hex: string): Uint8Array`, `bytesToHex(bytes: Uint8Array): string`

- [ ] **Step 1: Write the test vector fixture**

These values are copied from RFC 9180 Appendix A.3.1 (`DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM`, Base mode), extracted from https://www.rfc-editor.org/rfc/rfc9180.txt. Do not retype them from memory.

`tests/fixtures/rfc9180-a3-1.ts`:
```ts
// RFC 9180, Appendix A.3.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, Base mode.
export const RFC9180_A3_1 = {
  info: '4f6465206f6e2061204772656369616e2055726e',
  ikmE: '4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e',
  pkEm: '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4',
  ikmR: '668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550',
  pkRm: '04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0',
  skRm: 'f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2',
  enc: '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4',
  encryption0: {
    pt: '4265617574792069732074727574682c20747275746820626561757479',
    aad: '436f756e742d30',
    ct: '5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434',
  },
} as const;
```

- [ ] **Step 2: Write the failing tests**

`tests/hpke.test.ts`:
```ts
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `npx vitest run tests/hpke.test.ts`
Expected: FAIL, cannot find `../src/hpke.ts`.

- [ ] **Step 4: Implement the wrapper**

`src/hpke.ts`:
```ts
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx vitest run tests/hpke.test.ts`
Expected: PASS, 5 tests.

If only the sender-side test fails while the recipient-side test passes, `@hpke/core`'s `ekm` derivation differs from the RFC's `DeriveKeyPair`. Do not weaken the recipient test. Change the sender test to assert `enc` has length 65 and that `hpkeOpen` with the derived recipient key recovers `pt`, add a comment naming the discrepancy, and note it in the Task 9 README status. Interop is still proven by the recipient-side KAT plus the two-client demo.

- [ ] **Step 6: Commit**

```bash
git add src/hpke.ts tests/hpke.test.ts tests/fixtures/rfc9180-a3-1.ts
git commit -m "feat: HPKE wrapper pinned to DHKEM(P-256)/HKDF-SHA256/AES-128-GCM with RFC 9180 KATs"
```

---

### Task 3: `sealValue` and `unseal`

**Files:**
- Create: `src/seal.ts`
- Create: `src/server/unseal.ts`
- Test: `tests/unseal.test.ts`

**Interfaces:**
- Consumes: `padPlaintext`, `unpadPlaintext`, `slotAad`, `canonicalAction`, `encodeEnvelope`, `decodeEnvelope`, `EnvelopeFormatError`, `Slot` from `src/envelope.ts`; `hpkeSeal`, `hpkeOpen`, `suite` from `src/hpke.ts`
- Produces:
  - `sealValue(params: { value: string; kid: string; recipientPublicKey: CryptoKey; slot: Slot }): Promise<string>`
  - `type UnsealCode = 'bad-envelope' | 'unknown-kid' | 'open-failed'`
  - `class UnsealError extends Error { code: UnsealCode; hint: string }`
  - `interface UnsealExpect { origin: string | string[]; action: string; name: string }`
  - `interface UnsealEvent { event: 'sealed-input.unseal'; outcome: 'ok' | UnsealCode; kid: string | null; expected: { origins: string[]; action: string; name: string }; hint?: string }`
  - `interface UnsealOptions { privateKey: JsonWebKey | JsonWebKey[]; expect: UnsealExpect; onEvent?: (event: UnsealEvent) => void }`
  - `unseal(envelope: string, options: UnsealOptions): Promise<string>`

- [ ] **Step 1: Write the failing tests**

`tests/unseal.test.ts`:
```ts
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
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/unseal.test.ts`
Expected: FAIL, cannot find `../src/seal.ts`.

- [ ] **Step 3: Implement `sealValue`**

`src/seal.ts`:
```ts
import { encodeEnvelope, padPlaintext, slotAad, type Slot } from './envelope.ts';
import { hpkeSeal } from './hpke.ts';

export interface SealParams {
  value: string;
  kid: string;
  recipientPublicKey: CryptoKey;
  slot: Slot;
}

export async function sealValue(params: SealParams): Promise<string> {
  const { enc, ct } = await hpkeSeal(params.recipientPublicKey, padPlaintext(params.value), slotAad(params.slot));
  return encodeEnvelope({ kid: params.kid, enc, ct });
}
```

- [ ] **Step 4: Implement `unseal`**

`src/server/unseal.ts`:
```ts
import { canonicalAction, decodeEnvelope, EnvelopeFormatError, slotAad, unpadPlaintext } from '../envelope.ts';
import { hpkeOpen, suite } from '../hpke.ts';

export type UnsealCode = 'bad-envelope' | 'unknown-kid' | 'open-failed';

export class UnsealError extends Error {
  constructor(
    public readonly code: UnsealCode,
    message: string,
    public readonly hint: string,
  ) {
    super(message);
    this.name = 'UnsealError';
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

export async function unseal(envelopeText: string, options: UnsealOptions): Promise<string> {
  const onEvent = options.onEvent ?? defaultOnEvent;
  const expected = normalizeExpect(options.expect);
  const keys = Array.isArray(options.privateKey) ? options.privateKey : [options.privateKey];

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

  const jwk = keys.find((key) => (key as { kid?: string }).kid === envelope.kid);
  if (!jwk) return fail('unknown-kid', envelope.kid);
  const privateKey = await importPrivateKey(jwk);

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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx vitest run tests/unseal.test.ts`
Expected: PASS, 8 tests.

Run: `npm run typecheck`
Expected: exit 0.

- [ ] **Step 6: Commit**

```bash
git add src/seal.ts src/server/unseal.ts tests/unseal.test.ts
git commit -m "feat: sealValue and unseal with slot-bound AAD and structured events"
```

---

### Task 4: Recipient keys, well-known document, and `koschei init`

**Files:**
- Create: `src/server/keys.ts`
- Create: `src/server/init.ts`
- Create: `bin/koschei.ts`
- Test: `tests/keys.test.ts`

**Interfaces:**
- Consumes: `suite` from `src/hpke.ts`
- Produces:
  - `interface RecipientKeyPair { kid: string; privateJwk: JsonWebKey; publicJwk: JsonWebKey }`
  - `generateRecipientKey(kid: string): Promise<RecipientKeyPair>`
  - `interface WellKnownDocument { frame: string; keys: JsonWebKey[] }`
  - `wellKnownDocument(publicJwks: JsonWebKey[], framePath?: string): WellKnownDocument`
  - `parseWellKnown(json: unknown): WellKnownDocument` (throws `TypeError` on shape errors)
  - `selectEncryptionKey(doc: WellKnownDocument): { kid: string; jwk: JsonWebKey }` (first usable P-256 `use: "enc"` key with a `kid`)
  - `runInit(options: { outDir: string; privateKeyPath: string; kid: string; frameAncestors: string; distDir: string }): Promise<string[]>` (returns written paths)
  - `bin/koschei.ts` subcommands: `init`, `doctor` (doctor wired in Task 8)

- [ ] **Step 1: Write the failing tests**

`tests/keys.test.ts`:
```ts
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
    expect(() => selectEncryptionKey({ frame: '/f', keys: [{ kty: 'EC', crv: 'P-384', x: 'a', y: 'b', kid: 'k', use: 'enc' }] })).toThrow(TypeError);
    expect(() => selectEncryptionKey({ frame: '/f', keys: [{ kty: 'EC', crv: 'P-256', x: 'a', y: 'b', use: 'enc' }] })).toThrow(TypeError);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/keys.test.ts`
Expected: FAIL, cannot find `../src/server/keys.ts`.

- [ ] **Step 3: Implement keys**

`src/server/keys.ts`:
```ts
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
```

- [ ] **Step 4: Implement `runInit` and the CLI entry**

`src/server/init.ts`:
```ts
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { DEFAULT_FRAME_PATH, generateRecipientKey, wellKnownDocument } from './keys.ts';

export interface InitOptions {
  outDir: string;
  privateKeyPath: string;
  kid: string;
  frameAncestors: string;
  distDir: string;
}

export async function runInit(options: InitOptions): Promise<string[]> {
  const pair = await generateRecipientKey(options.kid);
  const written: string[] = [];

  await writeFile(options.privateKeyPath, JSON.stringify(pair.privateJwk, null, 2) + '\n', { mode: 0o600 });
  written.push(options.privateKeyPath);

  const wellKnownPath = join(options.outDir, '.well-known', 'sealed-input');
  await mkdir(join(options.outDir, '.well-known'), { recursive: true });
  await writeFile(wellKnownPath, JSON.stringify(wellKnownDocument([pair.publicJwk]), null, 2) + '\n');
  written.push(wellKnownPath);

  const frameDir = join(options.outDir, 'sealed-input');
  await mkdir(frameDir, { recursive: true });
  for (const asset of ['frame.html', 'frame.js']) {
    const target = join(frameDir, asset);
    await writeFile(target, await readFile(join(options.distDir, asset)));
    written.push(target);
  }

  const headersPath = join(frameDir, 'HEADERS.txt');
  await writeFile(
    headersPath,
    [
      `# Send these response headers with ${DEFAULT_FRAME_PATH}:`,
      `Content-Security-Policy: frame-ancestors ${options.frameAncestors}`,
      '',
      '# Send this with /.well-known/sealed-input:',
      'Content-Type: application/json',
      `Access-Control-Allow-Origin: ${options.frameAncestors}`,
      '',
    ].join('\n'),
  );
  written.push(headersPath);
  return written;
}
```

`bin/koschei.ts`:
```ts
#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { runInit } from '../src/server/init.ts';

const [command, ...rest] = process.argv.slice(2);

function usage(): never {
  process.stderr.write(
    [
      'usage:',
      '  koschei init   [--out public] [--private ./koschei-private.jwk] [--kid <kid>] [--frame-ancestors <origin>] [--dist dist]',
      '  koschei doctor <action-url> [--private ./koschei-private.jwk] [--page <embedding-origin>]',
      '',
    ].join('\n'),
  );
  process.exit(2);
}

if (command === 'init') {
  const { values } = parseArgs({
    args: rest,
    options: {
      out: { type: 'string', default: 'public' },
      private: { type: 'string', default: './koschei-private.jwk' },
      kid: { type: 'string', default: new Date().toISOString().slice(0, 7) },
      'frame-ancestors': { type: 'string', default: 'https://www.example.com' },
      dist: { type: 'string', default: 'dist' },
    },
  });
  const written = await runInit({
    outDir: values.out,
    privateKeyPath: values.private,
    kid: values.kid,
    frameAncestors: values['frame-ancestors'],
    distDir: values.dist,
  });
  for (const path of written) process.stdout.write(`wrote ${path}\n`);
  process.stdout.write(`\nKeep ${values.private} out of the browser and out of git.\n`);
} else if (command === 'doctor') {
  const { runDoctorCli } = await import('../src/server/doctor.ts');
  process.exit(await runDoctorCli(rest));
} else {
  usage();
}
```

The `doctor` branch imports a module that does not exist until Task 8. Until then, `koschei doctor` fails with a module-not-found error; that is acceptable and expected.

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx vitest run tests/keys.test.ts`
Expected: PASS, 4 tests.

Run: `npm run typecheck`
Expected: one error, `Cannot find module '../src/server/doctor.ts'` in `bin/koschei.ts`. Acceptable until Task 8; every other file must type-check clean.

- [ ] **Step 6: Commit**

```bash
git add src/server/keys.ts src/server/init.ts bin/koschei.ts tests/keys.test.ts
git commit -m "feat: recipient key generation, well-known document, and koschei init"
```

---

### Task 5: Frame protocol and the sealed frame

**Files:**
- Create: `src/frame/protocol.ts`
- Create: `src/frame/frame.ts`
- Create: `src/frame/frame.html`
- Create: `scripts/build.ts`
- Test: `tests/protocol.test.ts`

**Interfaces:**
- Consumes: `sealValue` from `src/seal.ts`; `canonicalAction`, `Slot` from `src/envelope.ts`; `suite` from `src/hpke.ts`; `parseWellKnown`, `selectEncryptionKey` from `src/server/keys.ts`
- Produces (protocol, shared with the element in Task 6):
  - `type SealedErrorReason = 'recipient-unreachable' | 'recipient-invalid' | 'frame-blocked' | 'no-form-action' | 'insecure-action' | 'insecure-context'`
  - `interface Constraints { required: boolean; pattern?: string; minlength?: number; maxlength?: number }`
  - `interface FieldUi { placeholder?: string; inputmode?: string; autocomplete?: string; label?: string }`
  - `type ToFrame = { type: 'sealed-input:init'; action: string; name: string; constraints: Constraints; ui: FieldUi } | { type: 'sealed-input:constraints'; constraints: Constraints } | { type: 'sealed-input:reset' } | { type: 'sealed-input:disabled'; disabled: boolean } | { type: 'sealed-input:focus' }`
  - `type FromFrame = { type: 'sealed-input:ready'; kid: string } | { type: 'sealed-input:error'; reason: SealedErrorReason } | { type: 'sealed-input:value'; envelope: string; empty: boolean; valid: boolean } | { type: 'sealed-input:focus-change'; focused: boolean }`
  - `validateValue(value: string, constraints: Constraints): boolean`
  - `class FieldState { constraints; frozen; value; applyConstraints(c): boolean; input(value): void; reset(): void; isValid(): boolean }`
  - `isToFrameMessage(data: unknown): data is ToFrame`, `isFromFrameMessage(data: unknown): data is FromFrame`
- Produces (build): `dist/frame.js`, `dist/frame.html`, `dist/sealed-input.js` (the last one once Task 6 exists; the script skips missing entries with a warning)

- [ ] **Step 1: Write the failing tests**

`tests/protocol.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { FieldState, isFromFrameMessage, isToFrameMessage, validateValue } from '../src/frame/protocol.ts';

describe('validateValue', () => {
  it('honors required, minlength, maxlength, and the HTML pattern semantics', () => {
    expect(validateValue('', { required: true })).toBe(false);
    expect(validateValue('', { required: false, pattern: '\\d+' })).toBe(true);
    expect(validateValue('12', { required: false, minlength: 3 })).toBe(false);
    expect(validateValue('1234', { required: false, maxlength: 3 })).toBe(false);
    expect(validateValue('123-45-6789', { required: true, pattern: '\\d{3}-?\\d{2}-?\\d{4}' })).toBe(true);
    expect(validateValue('123-45-678', { required: true, pattern: '\\d{3}-?\\d{2}-?\\d{4}' })).toBe(false);
    expect(validateValue('x123-45-6789', { required: true, pattern: '\\d{3}-?\\d{2}-?\\d{4}' })).toBe(false);
  });
  it('treats an invalid pattern as no pattern, like browsers do', () => {
    expect(validateValue('abc', { required: false, pattern: '(' })).toBe(true);
  });
});

describe('FieldState freezes constraints on first input', () => {
  it('accepts constraint changes before input and ignores them after', () => {
    const state = new FieldState({ required: true, pattern: '^1.*' });
    expect(state.applyConstraints({ required: true, pattern: '^2.*' })).toBe(true);
    state.input('2x');
    expect(state.isValid()).toBe(true);
    expect(state.applyConstraints({ required: true, pattern: '^9.*' })).toBe(false);
    expect(state.isValid()).toBe(true);
    state.reset();
    expect(state.value).toBe('');
    expect(state.applyConstraints({ required: true, pattern: '^9.*' })).toBe(true);
  });
});

describe('message guards', () => {
  it('accepts well-formed messages and rejects junk', () => {
    expect(isToFrameMessage({ type: 'sealed-input:init', action: 'https://a/b', name: 'n', constraints: { required: true }, ui: {} })).toBe(true);
    expect(isToFrameMessage({ type: 'sealed-input:reset' })).toBe(true);
    expect(isToFrameMessage({ type: 'sealed-input:init' })).toBe(false);
    expect(isToFrameMessage('sealed-input:init')).toBe(false);
    expect(isFromFrameMessage({ type: 'sealed-input:value', envelope: 'sealed1.k.a.b', empty: false, valid: true })).toBe(true);
    expect(isFromFrameMessage({ type: 'sealed-input:error', reason: 'made-up' })).toBe(false);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/protocol.test.ts`
Expected: FAIL, cannot find `../src/frame/protocol.ts`.

- [ ] **Step 3: Implement the protocol module**

`src/frame/protocol.ts`:
```ts
export type SealedErrorReason =
  | 'recipient-unreachable'
  | 'recipient-invalid'
  | 'frame-blocked'
  | 'no-form-action'
  | 'insecure-action'
  | 'insecure-context';

export const SEALED_ERROR_REASONS: readonly SealedErrorReason[] = [
  'recipient-unreachable',
  'recipient-invalid',
  'frame-blocked',
  'no-form-action',
  'insecure-action',
  'insecure-context',
];

export interface Constraints {
  required: boolean;
  pattern?: string;
  minlength?: number;
  maxlength?: number;
}

export interface FieldUi {
  placeholder?: string;
  inputmode?: string;
  autocomplete?: string;
  label?: string;
}

export type ToFrame =
  | { type: 'sealed-input:init'; action: string; name: string; constraints: Constraints; ui: FieldUi }
  | { type: 'sealed-input:constraints'; constraints: Constraints }
  | { type: 'sealed-input:reset' }
  | { type: 'sealed-input:disabled'; disabled: boolean }
  | { type: 'sealed-input:focus' };

export type FromFrame =
  | { type: 'sealed-input:ready'; kid: string }
  | { type: 'sealed-input:error'; reason: SealedErrorReason }
  | { type: 'sealed-input:value'; envelope: string; empty: boolean; valid: boolean }
  | { type: 'sealed-input:focus-change'; focused: boolean };

export function compilePattern(pattern: string): RegExp | null {
  // HTML anchors the pattern and compiles it with the 'v' flag; a pattern that
  // fails to compile is ignored, matching browser behavior.
  try {
    return new RegExp(`^(?:${pattern})$`, 'v');
  } catch {
    return null;
  }
}

export function validateValue(value: string, constraints: Constraints): boolean {
  if (value.length === 0) return !constraints.required;
  if (constraints.minlength !== undefined && value.length < constraints.minlength) return false;
  if (constraints.maxlength !== undefined && value.length > constraints.maxlength) return false;
  if (constraints.pattern !== undefined) {
    const regex = compilePattern(constraints.pattern);
    if (regex && !regex.test(value)) return false;
  }
  return true;
}

export class FieldState {
  frozen = false;
  value = '';
  constructor(public constraints: Constraints) {}

  // Returns false when the change was ignored because the field is frozen.
  applyConstraints(constraints: Constraints): boolean {
    if (this.frozen) return false;
    this.constraints = constraints;
    return true;
  }

  input(value: string): void {
    this.frozen = true;
    this.value = value;
  }

  reset(): void {
    this.frozen = false;
    this.value = '';
  }

  isValid(): boolean {
    return validateValue(this.value, this.constraints);
  }
}

function isObject(data: unknown): data is Record<string, unknown> {
  return typeof data === 'object' && data !== null;
}

function isConstraints(data: unknown): data is Constraints {
  return (
    isObject(data) &&
    typeof data.required === 'boolean' &&
    (data.pattern === undefined || typeof data.pattern === 'string') &&
    (data.minlength === undefined || typeof data.minlength === 'number') &&
    (data.maxlength === undefined || typeof data.maxlength === 'number')
  );
}

export function isToFrameMessage(data: unknown): data is ToFrame {
  if (!isObject(data) || typeof data.type !== 'string') return false;
  switch (data.type) {
    case 'sealed-input:init':
      return typeof data.action === 'string' && typeof data.name === 'string' && isConstraints(data.constraints) && isObject(data.ui);
    case 'sealed-input:constraints':
      return isConstraints(data.constraints);
    case 'sealed-input:reset':
    case 'sealed-input:focus':
      return true;
    case 'sealed-input:disabled':
      return typeof data.disabled === 'boolean';
    default:
      return false;
  }
}

export function isFromFrameMessage(data: unknown): data is FromFrame {
  if (!isObject(data) || typeof data.type !== 'string') return false;
  switch (data.type) {
    case 'sealed-input:ready':
      return typeof data.kid === 'string';
    case 'sealed-input:error':
      return typeof data.reason === 'string' && (SEALED_ERROR_REASONS as readonly string[]).includes(data.reason);
    case 'sealed-input:value':
      return typeof data.envelope === 'string' && typeof data.empty === 'boolean' && typeof data.valid === 'boolean';
    case 'sealed-input:focus-change':
      return typeof data.focused === 'boolean';
    default:
      return false;
  }
}
```

- [ ] **Step 4: Run protocol tests to verify they pass**

Run: `npx vitest run tests/protocol.test.ts`
Expected: PASS, 4 tests.

- [ ] **Step 5: Implement the frame**

`src/frame/frame.html`:
```html
<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sealed input</title>
<style>
  html, body { margin: 0; padding: 0; background: transparent; }
  body { font: 16px system-ui, sans-serif; }
  input {
    box-sizing: border-box; width: 100%; height: 100%; margin: 0;
    font: inherit; padding: 4px 6px; border: 1px solid #767676; border-radius: 3px; background: #fff; color: #000;
  }
  input:disabled { background: #f2f2f2; color: #6f6f6f; }
  input[data-unavailable] { border-style: dashed; }
</style>
<body>
<input type="text" disabled data-unavailable aria-label="Sealed input, unavailable" spellcheck="false">
<script type="module" src="./frame.js"></script>
</body>
</html>
```

`src/frame/frame.ts`:
```ts
import { canonicalAction, type Slot } from '../envelope.ts';
import { suite } from '../hpke.ts';
import { sealValue } from '../seal.ts';
import { parseWellKnown, selectEncryptionKey } from '../server/keys.ts';
import { FieldState, isToFrameMessage, type FromFrame, type SealedErrorReason } from './protocol.ts';

const input = document.querySelector('input') as HTMLInputElement;

let parentOrigin: string | null = null;
let slot: Slot | null = null;
let recipient: { kid: string; publicKey: CryptoKey } | null = null;
let state: FieldState | null = null;
let sealSequence = 0;

function post(message: FromFrame): void {
  if (parentOrigin === null) return;
  window.parent.postMessage(message, parentOrigin);
}

function fail(reason: SealedErrorReason): void {
  input.disabled = true;
  input.toggleAttribute('data-unavailable', true);
  post({ type: 'sealed-input:error', reason });
}

async function loadRecipient(): Promise<{ kid: string; publicKey: CryptoKey }> {
  const response = await fetch('/.well-known/sealed-input', { credentials: 'omit', cache: 'no-store' });
  if (!response.ok) throw new Error('recipient-unreachable');
  const doc = parseWellKnown(await response.json());
  const { kid, jwk } = selectEncryptionKey(doc);
  const { kid: _kid, use: _use, ...importable } = jwk as JsonWebKey & { kid?: string; use?: string };
  return { kid, publicKey: await suite.kem.importKey('jwk', importable, true) };
}

async function publishValue(): Promise<void> {
  if (!state || !recipient || !slot) return;
  const sequence = ++sealSequence;
  const value = state.value;
  const valid = state.isValid();
  if (value.length === 0) {
    post({ type: 'sealed-input:value', envelope: '', empty: true, valid });
    return;
  }
  const envelope = await sealValue({ value, kid: recipient.kid, recipientPublicKey: recipient.publicKey, slot });
  // A newer keystroke may have sealed while we awaited; only the latest wins.
  if (sequence !== sealSequence) return;
  post({ type: 'sealed-input:value', envelope, empty: false, valid });
}

async function handleInit(message: Extract<import('./protocol.ts').ToFrame, { type: 'sealed-input:init' }>): Promise<void> {
  let action: URL;
  try {
    action = new URL(message.action);
  } catch {
    return fail('recipient-invalid');
  }
  // The frame seals only to its own origin's key. A page cannot redirect the seal.
  if (action.origin !== location.origin) return fail('recipient-invalid');

  try {
    recipient = await loadRecipient();
  } catch (error) {
    return fail(error instanceof Error && error.message === 'recipient-unreachable' ? 'recipient-unreachable' : 'recipient-invalid');
  }

  slot = { origin: parentOrigin as string, action: canonicalAction(action.href), name: message.name };
  state = new FieldState(message.constraints);

  input.placeholder = message.ui.placeholder ?? '';
  if (message.ui.inputmode) input.inputMode = message.ui.inputmode;
  input.autocomplete = (message.ui.autocomplete ?? 'off') as AutoFill;
  input.setAttribute('aria-label', message.ui.label ?? 'Sealed input');
  input.removeAttribute('data-unavailable');
  input.disabled = false;
  post({ type: 'sealed-input:ready', kid: recipient.kid });
}

window.addEventListener('message', (event: MessageEvent) => {
  if (event.source !== window.parent) return;
  if (parentOrigin === null) parentOrigin = event.origin;
  else if (event.origin !== parentOrigin) return;
  if (!isToFrameMessage(event.data)) return;

  switch (event.data.type) {
    case 'sealed-input:init':
      void handleInit(event.data);
      break;
    case 'sealed-input:constraints':
      if (state && state.applyConstraints(event.data.constraints)) void publishValue();
      break;
    case 'sealed-input:reset':
      if (state) {
        state.reset();
        input.value = '';
        void publishValue();
      }
      break;
    case 'sealed-input:disabled':
      if (recipient) input.disabled = event.data.disabled;
      break;
    case 'sealed-input:focus':
      input.focus();
      break;
  }
});

input.addEventListener('input', () => {
  if (!state) return;
  state.input(input.value);
  void publishValue();
});
input.addEventListener('focus', () => post({ type: 'sealed-input:focus-change', focused: true }));
input.addEventListener('blur', () => post({ type: 'sealed-input:focus-change', focused: false }));
```

- [ ] **Step 6: Write the build script**

`scripts/build.ts`:
```ts
import { build } from 'esbuild';
import { copyFile, mkdir, access } from 'node:fs/promises';

const entries: Array<{ entry: string; out: string }> = [
  { entry: 'src/frame/frame.ts', out: 'dist/frame.js' },
  { entry: 'src/element/sealed-input.ts', out: 'dist/sealed-input.js' },
];

await mkdir('dist', { recursive: true });
for (const { entry, out } of entries) {
  try {
    await access(entry);
  } catch {
    process.stderr.write(`skip ${entry} (not present yet)\n`);
    continue;
  }
  await build({ entryPoints: [entry], outfile: out, bundle: true, format: 'esm', target: 'es2022', sourcemap: true, minify: false });
  process.stdout.write(`built ${out}\n`);
}
await copyFile('src/frame/frame.html', 'dist/frame.html');
process.stdout.write('copied dist/frame.html\n');
```

- [ ] **Step 7: Build and type-check**

Run: `npm run build`
Expected: `built dist/frame.js`, `skip src/element/sealed-input.ts (not present yet)`, `copied dist/frame.html`.

Run: `npm run typecheck`
Expected: only the pre-existing `doctor.ts` error from Task 4. If `AutoFill` is not a known type in the installed `lib.dom.d.ts`, change the cast to `as unknown as HTMLInputElement['autocomplete']`.

- [ ] **Step 8: Commit**

```bash
git add src/frame/protocol.ts src/frame/frame.ts src/frame/frame.html scripts/build.ts tests/protocol.test.ts
git commit -m "feat: sealed frame with frozen-constraint protocol and esbuild bundle"
```

---

### Task 6: Recipient discovery and the `<sealed-input>` element

**Files:**
- Create: `src/element/recipient.ts`
- Create: `src/element/sealed-input.ts`
- Test: `tests/recipient.test.ts`

**Interfaces:**
- Consumes: `parseWellKnown`, `selectEncryptionKey` from `src/server/keys.ts`; protocol types and guards from `src/frame/protocol.ts`
- Produces:
  - `isPotentiallyTrustworthy(url: URL): boolean`
  - `class RecipientError extends Error { reason: SealedErrorReason }`
  - `interface RecipientInfo { recipientOrigin: string; frameUrl: string; kid: string }`
  - `discoverRecipient(actionUrl: string, fetchImpl?: typeof fetch): Promise<RecipientInfo>`
  - `resolveFormAction(form: HTMLFormElement | null): { action: URL } ` (throws `RecipientError('no-form-action')` when absent)
  - Custom element `sealed-input` (class `SealedInputElement`), registered on import if not already defined. Custom states `ready` and `error` via `ElementInternals.states`.

- [ ] **Step 1: Write the failing tests**

`tests/recipient.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { discoverRecipient, isPotentiallyTrustworthy, RecipientError } from '../src/element/recipient.ts';

const doc = {
  frame: '/sealed-input/frame.html',
  keys: [{ kty: 'EC', crv: 'P-256', x: 'a', y: 'b', kid: 'k1', use: 'enc' }],
};

function fakeFetch(handler: (url: string, init?: RequestInit) => Response): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => handler(String(input), init)) as typeof fetch;
}

describe('isPotentiallyTrustworthy', () => {
  it('accepts https and loopback http only', () => {
    expect(isPotentiallyTrustworthy(new URL('https://api.example.com/x'))).toBe(true);
    expect(isPotentiallyTrustworthy(new URL('http://localhost:4781/x'))).toBe(true);
    expect(isPotentiallyTrustworthy(new URL('http://app.localhost/x'))).toBe(true);
    expect(isPotentiallyTrustworthy(new URL('http://127.0.0.1/x'))).toBe(true);
    expect(isPotentiallyTrustworthy(new URL('http://[::1]/x'))).toBe(true);
    expect(isPotentiallyTrustworthy(new URL('http://api.example.com/x'))).toBe(false);
    expect(isPotentiallyTrustworthy(new URL('ftp://localhost/x'))).toBe(false);
  });
});

describe('discoverRecipient', () => {
  it('fetches the well-known from the action origin with credentials omitted and resolves the frame', async () => {
    let seen: { url: string; init?: RequestInit } | null = null;
    const info = await discoverRecipient(
      'https://api.example.com/enroll?x=1',
      fakeFetch((url, init) => {
        seen = { url, init };
        return new Response(JSON.stringify(doc), { headers: { 'content-type': 'application/json' } });
      }),
    );
    expect(seen).toMatchObject({ url: 'https://api.example.com/.well-known/sealed-input', init: { mode: 'cors', credentials: 'omit' } });
    expect(info).toEqual({ recipientOrigin: 'https://api.example.com', frameUrl: 'https://api.example.com/sealed-input/frame.html', kid: 'k1' });
  });

  it('rejects insecure actions before fetching', async () => {
    await expect(discoverRecipient('http://api.example.com/enroll', fakeFetch(() => new Response('')))).rejects.toMatchObject({ reason: 'insecure-action' });
  });

  it('maps network and shape failures to reasons', async () => {
    await expect(discoverRecipient('https://a.example/x', fakeFetch(() => new Response('', { status: 404 })))).rejects.toMatchObject({ reason: 'recipient-unreachable' });
    await expect(discoverRecipient('https://a.example/x', fakeFetch(() => { throw new TypeError('network'); }))).rejects.toMatchObject({ reason: 'recipient-unreachable' });
    await expect(discoverRecipient('https://a.example/x', fakeFetch(() => new Response('<html>', { headers: { 'content-type': 'text/html' } })))).rejects.toMatchObject({ reason: 'recipient-invalid' });
    await expect(discoverRecipient('https://a.example/x', fakeFetch(() => new Response(JSON.stringify({ frame: 'https://other.example/f', keys: doc.keys }), { headers: { 'content-type': 'application/json' } })))).rejects.toMatchObject({ reason: 'recipient-invalid' });
    await expect(discoverRecipient('https://a.example/x', fakeFetch(() => new Response(JSON.stringify({ frame: '/f', keys: [] }), { headers: { 'content-type': 'application/json' } })))).rejects.toBeInstanceOf(RecipientError);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/recipient.test.ts`
Expected: FAIL, cannot find `../src/element/recipient.ts`.

- [ ] **Step 3: Implement recipient discovery**

`src/element/recipient.ts`:
```ts
import { parseWellKnown, selectEncryptionKey } from '../server/keys.ts';
import type { SealedErrorReason } from '../frame/protocol.ts';

export class RecipientError extends Error {
  constructor(
    public readonly reason: SealedErrorReason,
    message: string,
  ) {
    super(message);
    this.name = 'RecipientError';
  }
}

export interface RecipientInfo {
  recipientOrigin: string;
  frameUrl: string;
  kid: string;
}

// Mirrors the platform's "potentially trustworthy URL": https, or http on loopback.
export function isPotentiallyTrustworthy(url: URL): boolean {
  if (url.protocol === 'https:') return true;
  if (url.protocol !== 'http:') return false;
  const host = url.hostname;
  return host === 'localhost' || host.endsWith('.localhost') || host === '127.0.0.1' || host === '[::1]';
}

export function resolveFormAction(form: HTMLFormElement | null): { action: URL } {
  if (!form) throw new RecipientError('no-form-action', '<sealed-input> must be inside a <form>');
  const attribute = form.getAttribute('action');
  if (attribute === null || attribute.trim() === '') {
    throw new RecipientError('no-form-action', 'the owning <form> must declare an action');
  }
  try {
    return { action: new URL(attribute, document.baseURI) };
  } catch {
    throw new RecipientError('no-form-action', 'the form action is not a valid URL');
  }
}

export async function discoverRecipient(actionUrl: string, fetchImpl: typeof fetch = fetch): Promise<RecipientInfo> {
  const action = new URL(actionUrl);
  if (!isPotentiallyTrustworthy(action)) {
    throw new RecipientError('insecure-action', 'the form action must be https (or loopback http)');
  }
  const recipientOrigin = action.origin;

  let response: Response;
  try {
    response = await fetchImpl(`${recipientOrigin}/.well-known/sealed-input`, { mode: 'cors', credentials: 'omit', cache: 'no-store' });
  } catch {
    throw new RecipientError('recipient-unreachable', 'could not fetch /.well-known/sealed-input');
  }
  if (!response.ok) throw new RecipientError('recipient-unreachable', `well-known returned ${response.status}`);
  if (!(response.headers.get('content-type') ?? '').startsWith('application/json')) {
    throw new RecipientError('recipient-invalid', 'well-known is not application/json');
  }

  let kid: string;
  let frameUrl: URL;
  try {
    const doc = parseWellKnown(await response.json());
    kid = selectEncryptionKey(doc).kid;
    frameUrl = new URL(doc.frame, recipientOrigin);
  } catch {
    throw new RecipientError('recipient-invalid', 'well-known is malformed');
  }
  if (frameUrl.origin !== recipientOrigin) {
    throw new RecipientError('recipient-invalid', 'well-known.frame must be same-origin with the recipient');
  }
  return { recipientOrigin, frameUrl: frameUrl.href, kid };
}
```

- [ ] **Step 4: Run recipient tests to verify they pass**

Run: `npx vitest run tests/recipient.test.ts`
Expected: PASS, 4 tests.

- [ ] **Step 5: Implement the element**

`src/element/sealed-input.ts`:
```ts
import { isFromFrameMessage, type Constraints, type FieldUi, type SealedErrorReason, type ToFrame } from '../frame/protocol.ts';
import { discoverRecipient, RecipientError, resolveFormAction } from './recipient.ts';

const UNAVAILABLE_MESSAGE = 'This field is unavailable.';
const INVALID_MESSAGE = 'Please match the requested format.';
const UI_ATTRIBUTES = ['placeholder', 'inputmode', 'autocomplete', 'aria-label'] as const;
const CONSTRAINT_ATTRIBUTES = ['required', 'pattern', 'minlength', 'maxlength'] as const;

export class SealedInputElement extends HTMLElement {
  static formAssociated = true;
  static observedAttributes = ['disabled', ...CONSTRAINT_ATTRIBUTES, ...UI_ATTRIBUTES];

  #internals: ElementInternals;
  #root: ShadowRoot;
  #iframe: HTMLIFrameElement | null = null;
  #recipientOrigin: string | null = null;
  #envelope = '';
  #ready = false;
  #started = false;
  #onMessage = (event: MessageEvent) => this.#handleMessage(event);

  constructor() {
    super();
    this.#internals = this.attachInternals();
    this.#root = this.attachShadow({ mode: 'closed', delegatesFocus: true });
    this.#root.innerHTML = `
      <style>
        :host { display: inline-block; width: 20ch; height: 2em; vertical-align: middle; }
        iframe { border: 0; width: 100%; height: 100%; display: block; }
      </style>`;
    this.#markUnavailable();
  }

  get value(): string {
    return this.#envelope;
  }
  set value(_value: string) {
    throw new DOMException('sealed-input value cannot be set by script', 'InvalidStateError');
  }
  get form(): HTMLFormElement | null {
    return this.#internals.form;
  }
  get name(): string {
    return this.getAttribute('name') ?? '';
  }
  get type(): string {
    return 'sealed-input';
  }
  get validity(): ValidityState {
    return this.#internals.validity;
  }
  get validationMessage(): string {
    return this.#internals.validationMessage;
  }
  get willValidate(): boolean {
    return this.#internals.willValidate;
  }
  checkValidity(): boolean {
    return this.#internals.checkValidity();
  }
  reportValidity(): boolean {
    return this.#internals.reportValidity();
  }

  connectedCallback(): void {
    window.addEventListener('message', this.#onMessage);
    if (!this.#started) {
      this.#started = true;
      void this.#start();
    }
  }

  disconnectedCallback(): void {
    window.removeEventListener('message', this.#onMessage);
  }

  attributeChangedCallback(name: string): void {
    if (!this.#ready) return;
    if (name === 'disabled') this.#post({ type: 'sealed-input:disabled', disabled: this.hasAttribute('disabled') });
    else if ((CONSTRAINT_ATTRIBUTES as readonly string[]).includes(name)) this.#post({ type: 'sealed-input:constraints', constraints: this.#constraints() });
  }

  formResetCallback(): void {
    this.#post({ type: 'sealed-input:reset' });
  }

  formDisabledCallback(disabled: boolean): void {
    this.#post({ type: 'sealed-input:disabled', disabled });
  }

  #constraints(): Constraints {
    const number = (attribute: string) => {
      const raw = this.getAttribute(attribute);
      return raw === null ? undefined : Number.parseInt(raw, 10);
    };
    return {
      required: this.hasAttribute('required'),
      pattern: this.getAttribute('pattern') ?? undefined,
      minlength: number('minlength'),
      maxlength: number('maxlength'),
    };
  }

  #ui(): FieldUi {
    return {
      placeholder: this.getAttribute('placeholder') ?? undefined,
      inputmode: this.getAttribute('inputmode') ?? undefined,
      autocomplete: this.getAttribute('autocomplete') ?? undefined,
      label: this.getAttribute('aria-label') ?? this.#labelText() ?? undefined,
    };
  }

  #labelText(): string | null {
    const labels = this.#internals.labels;
    return labels.length > 0 ? (labels[0] as HTMLLabelElement).textContent?.trim() ?? null : null;
  }

  #markUnavailable(): void {
    this.#envelope = '';
    this.#internals.setFormValue(null);
    this.#internals.setValidity({ customError: true }, UNAVAILABLE_MESSAGE);
  }

  #fail(reason: SealedErrorReason): void {
    this.#ready = false;
    this.#markUnavailable();
    this.#internals.states.delete('ready');
    this.#internals.states.add('error');
    this.dispatchEvent(new CustomEvent('sealed-error', { bubbles: true, composed: true, detail: { reason } }));
  }

  async #start(): Promise<void> {
    if (!window.isSecureContext) return this.#fail('insecure-context');
    try {
      const { action } = resolveFormAction(this.#internals.form);
      const info = await discoverRecipient(action.href);
      this.#recipientOrigin = info.recipientOrigin;
      const iframe = document.createElement('iframe');
      iframe.src = info.frameUrl;
      iframe.referrerPolicy = 'origin';
      iframe.title = this.#ui().label ?? 'Sealed input';
      iframe.addEventListener('load', () => {
        this.#post({ type: 'sealed-input:init', action: action.href, name: this.name, constraints: this.#constraints(), ui: this.#ui() });
      });
      iframe.addEventListener('error', () => this.#fail('frame-blocked'));
      this.#iframe = iframe;
      this.#root.append(iframe);
    } catch (error) {
      this.#fail(error instanceof RecipientError ? error.reason : 'recipient-invalid');
    }
  }

  #post(message: ToFrame): void {
    if (!this.#iframe?.contentWindow || !this.#recipientOrigin) return;
    this.#iframe.contentWindow.postMessage(message, this.#recipientOrigin);
  }

  #handleMessage(event: MessageEvent): void {
    if (!this.#iframe || event.source !== this.#iframe.contentWindow || event.origin !== this.#recipientOrigin) return;
    if (!isFromFrameMessage(event.data)) return;
    const message = event.data;
    switch (message.type) {
      case 'sealed-input:ready':
        this.#ready = true;
        this.#internals.states.delete('error');
        this.#internals.states.add('ready');
        this.#envelope = '';
        this.#internals.setFormValue('');
        this.#internals.setValidity(this.hasAttribute('required') ? { customError: true } : {}, INVALID_MESSAGE);
        if (this.hasAttribute('disabled')) this.#post({ type: 'sealed-input:disabled', disabled: true });
        this.dispatchEvent(new CustomEvent('sealed-ready', { bubbles: true, composed: true, detail: { kid: message.kid } }));
        break;
      case 'sealed-input:error':
        this.#fail(message.reason);
        break;
      case 'sealed-input:value':
        this.#envelope = message.envelope;
        this.#internals.setFormValue(message.envelope);
        this.#internals.setValidity(message.valid ? {} : { customError: true }, INVALID_MESSAGE);
        this.dispatchEvent(new InputEvent('input', { bubbles: true, composed: true, data: null, inputType: '' }));
        break;
      case 'sealed-input:focus-change':
        if (!message.focused) this.dispatchEvent(new Event('change', { bubbles: true }));
        break;
    }
  }
}

if (!customElements.get('sealed-input')) {
  customElements.define('sealed-input', SealedInputElement);
}
```

- [ ] **Step 6: Build and type-check**

Run: `npm run build`
Expected: `built dist/frame.js`, `built dist/sealed-input.js`, `copied dist/frame.html`.

Run: `npm run typecheck`
Expected: only the pre-existing `doctor.ts` error. If `ElementInternals.states` is missing from the installed DOM lib, add `declare global { interface ElementInternals { readonly states: Set<string>; } }` at the top of `sealed-input.ts`.

- [ ] **Step 7: Commit**

```bash
git add src/element/recipient.ts src/element/sealed-input.ts tests/recipient.test.ts
git commit -m "feat: <sealed-input> form-associated element with recipient discovery"
```

---

### Task 7: Two-origin demo and Playwright end-to-end proof

**Files:**
- Create: `demo/serve.ts`
- Create: `demo/index.html`
- Create: `demo/app.js`
- Create: `playwright.config.ts`
- Test: `e2e/sealed-input.spec.ts`

**Interfaces:**
- Consumes: `unseal`, `UnsealError` from `src/server/unseal.ts`; `generateRecipientKey`, `wellKnownDocument` from `src/server/keys.ts`; `dist/*` from `npm run build`
- Produces:
  - `startServers(options: { pagePort: number; recipientPort: number }): Promise<{ close(): Promise<void>; pageOrigin: string; recipientOrigin: string }>` (exported for the doctor tests in Task 8)
  - Recipient routes: `GET /.well-known/sealed-input`, `GET /sealed-input/frame.html`, `GET /sealed-input/frame.js`, `POST /enroll` (urlencoded; returns `{ ok: true, last4 }` or `400 { ok: false, code }`)
  - Page routes: `GET /` (demo page with CSP), `GET /sealed-input.js`, `GET /app.js`

- [ ] **Step 1: Install Chromium for Playwright**

Run: `npx playwright install chromium`
Expected: downloads and exits 0.

- [ ] **Step 2: Write the demo servers**

`demo/serve.ts`:
```ts
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { generateRecipientKey, wellKnownDocument } from '../src/server/keys.ts';
import { unseal, UnsealError } from '../src/server/unseal.ts';

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, '..', 'dist');

export interface DemoServers {
  close(): Promise<void>;
  pageOrigin: string;
  recipientOrigin: string;
}

function log(event: Record<string, unknown>): void {
  process.stderr.write(JSON.stringify({ time: new Date().toISOString(), ...event }) + '\n');
}

function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    request.on('data', (chunk: Buffer) => (body += chunk.toString('utf8')));
    request.on('end', () => resolve(body));
    request.on('error', reject);
  });
}

function send(response: ServerResponse, status: number, body: string | Buffer, headers: Record<string, string>): void {
  response.writeHead(status, headers);
  response.end(body);
}

export async function startServers(options: { pagePort: number; recipientPort: number }): Promise<DemoServers> {
  const pageOrigin = `http://localhost:${options.pagePort}`;
  const recipientOrigin = `http://localhost:${options.recipientPort}`;
  const key = await generateRecipientKey('demo');
  const wellKnown = JSON.stringify(wellKnownDocument([key.publicJwk]));
  const expect = { origin: pageOrigin, action: `${recipientOrigin}/enroll`, name: 'ssn' };

  const recipient = createServer(async (request, response) => {
    const url = new URL(request.url ?? '/', recipientOrigin);
    const cors = { 'Access-Control-Allow-Origin': pageOrigin, Vary: 'Origin' };
    if (request.method === 'OPTIONS') return send(response, 204, '', { ...cors, 'Access-Control-Allow-Methods': 'POST', 'Access-Control-Allow-Headers': 'content-type' });
    if (url.pathname === '/.well-known/sealed-input') return send(response, 200, wellKnown, { ...cors, 'Content-Type': 'application/json' });
    if (url.pathname === '/sealed-input/frame.html') {
      return send(response, 200, await readFile(join(dist, 'frame.html')), { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': `frame-ancestors ${pageOrigin}` });
    }
    if (url.pathname === '/sealed-input/frame.js') return send(response, 200, await readFile(join(dist, 'frame.js')), { 'Content-Type': 'text/javascript' });
    if (url.pathname === '/enroll' && request.method === 'POST') {
      const form = new URLSearchParams(await readBody(request));
      const fieldName = form.has('ssn') ? 'ssn' : [...form.keys()][0] ?? 'ssn';
      try {
        const ssn = await unseal(form.get(fieldName) ?? '', { privateKey: key.privateJwk, expect: { ...expect, name: fieldName }, onEvent: log });
        return send(response, 200, JSON.stringify({ ok: true, last4: ssn.slice(-4) }), { ...cors, 'Content-Type': 'application/json' });
      } catch (error) {
        if (error instanceof UnsealError) return send(response, 400, JSON.stringify({ ok: false, code: error.code }), { ...cors, 'Content-Type': 'application/json' });
        log({ event: 'demo.enroll.error', message: error instanceof Error ? error.message : String(error) });
        return send(response, 500, JSON.stringify({ ok: false }), { ...cors, 'Content-Type': 'application/json' });
      }
    }
    send(response, 404, 'not found', { 'Content-Type': 'text/plain' });
  });

  const page = createServer(async (request, response) => {
    const url = new URL(request.url ?? '/', pageOrigin);
    if (url.pathname === '/') {
      const html = (await readFile(join(here, 'index.html'), 'utf8')).replaceAll('__RECIPIENT__', recipientOrigin);
      const csp = [`default-src 'self'`, `script-src 'self'`, `style-src 'self' 'unsafe-inline'`, `frame-src ${recipientOrigin}`, `form-action ${recipientOrigin}`, `connect-src ${recipientOrigin}`].join('; ');
      return send(response, 200, html, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': csp });
    }
    if (url.pathname === '/sealed-input.js') return send(response, 200, await readFile(join(dist, 'sealed-input.js')), { 'Content-Type': 'text/javascript' });
    if (url.pathname === '/app.js') return send(response, 200, await readFile(join(here, 'app.js')), { 'Content-Type': 'text/javascript' });
    if (url.pathname === '/insecure') {
      const html = (await readFile(join(here, 'index.html'), 'utf8')).replaceAll('__RECIPIENT__', 'http://api.example.invalid');
      return send(response, 200, html, { 'Content-Type': 'text/html; charset=utf-8' });
    }
    send(response, 404, 'not found', { 'Content-Type': 'text/plain' });
  });

  await new Promise<void>((resolve) => recipient.listen(options.recipientPort, resolve));
  await new Promise<void>((resolve) => page.listen(options.pagePort, resolve));
  log({ event: 'demo.listening', pageOrigin, recipientOrigin });

  return {
    pageOrigin,
    recipientOrigin,
    close: async () => {
      await new Promise<void>((resolve) => recipient.close(() => resolve()));
      await new Promise<void>((resolve) => page.close(() => resolve()));
    },
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  await startServers({ pagePort: 4780, recipientPort: 4781 });
}
```

`demo/index.html`:
```html
<!doctype html>
<html lang="en">
<meta charset="utf-8">
<title>sealed-input demo</title>
<style>
  body { font: 16px system-ui, sans-serif; max-width: 40rem; margin: 2rem auto; padding: 0 1rem; }
  label { display: block; margin: 1rem 0 .25rem; }
  input, sealed-input { width: 24ch; }
  pre { background: #f4f4f4; padding: .75rem; overflow: auto; }
</style>
<body>
<h1>sealed-input demo</h1>
<form id="enroll" method="post" action="__RECIPIENT__/enroll">
  <label>Full name <input name="name" autocomplete="name" required value="Ada Lovelace"></label>
  <label>Social Security number
    <sealed-input name="ssn" required inputmode="numeric" pattern="\d{3}-?\d{2}-?\d{4}" autocomplete="off" aria-label="Social Security number"></sealed-input>
  </label>
  <button>Enroll</button>
</form>
<h2>What page script can see</h2>
<pre id="observed">waiting for sealed-ready…</pre>
<h2>Server response</h2>
<pre id="response">not submitted</pre>
<script type="module" src="/sealed-input.js"></script>
<script type="module" src="/app.js"></script>
</body>
</html>
```

`demo/app.js`:
```js
const form = document.getElementById('enroll');
const field = form.querySelector('sealed-input');
const observed = document.getElementById('observed');
const responseBox = document.getElementById('response');

function render(extra = '') {
  observed.textContent = [
    `sealed-input.value = ${JSON.stringify(field.value)}`,
    `FormData.get('ssn') = ${JSON.stringify(new FormData(form).get('ssn'))}`,
    `checkValidity() = ${field.checkValidity()}`,
    extra,
  ].join('\n');
}

field.addEventListener('sealed-ready', () => render('state: ready'));
field.addEventListener('sealed-error', (event) => render(`state: error (${event.detail.reason})`));
field.addEventListener('input', () => render('state: ready'));

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!form.checkValidity()) return form.reportValidity();
  const body = new URLSearchParams(new FormData(form));
  const response = await fetch(form.action, { method: 'POST', body });
  responseBox.textContent = `${response.status} ${await response.text()}`;
});
```

- [ ] **Step 3: Write the Playwright config and the failing e2e tests**

`playwright.config.ts`:
```ts
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: 'e2e',
  timeout: 30_000,
  use: { baseURL: 'http://localhost:4780', browserName: 'chromium' },
  webServer: { command: 'npm run build && node demo/serve.ts', port: 4780, reuseExistingServer: false, timeout: 60_000 },
});
```

`e2e/sealed-input.spec.ts`:
```ts
import { expect, test, type Frame, type Page } from '@playwright/test';

const RECIPIENT = 'http://localhost:4781';
const SSN = '123-45-6789';

async function sealedFrame(page: Page): Promise<Frame> {
  await expect.poll(() => page.frames().some((f) => f.url().startsWith(`${RECIPIENT}/sealed-input/frame.html`))).toBe(true);
  return page.frames().find((f) => f.url().startsWith(`${RECIPIENT}/sealed-input/frame.html`)) as Frame;
}

async function waitReady(page: Page): Promise<void> {
  await expect.poll(() => page.locator('sealed-input').evaluate((el) => el.matches(':state(ready)'))).toBe(true);
}

async function typeSsn(page: Page): Promise<void> {
  const frame = await sealedFrame(page);
  await frame.locator('input').pressSequentially(SSN);
  await expect.poll(() => page.locator('sealed-input').evaluate((el: HTMLElement & { value: string }) => el.value.startsWith('sealed1.'))).toBe(true);
}

test('the page only ever sees an envelope', async ({ page }) => {
  await page.goto('/');
  await waitReady(page);
  await typeSsn(page);
  const seen = await page.evaluate(() => {
    const form = document.getElementById('enroll') as HTMLFormElement;
    const field = form.querySelector('sealed-input') as HTMLElement & { value: string };
    return { value: field.value, formData: new FormData(form).get('ssn'), valid: form.checkValidity(), html: document.documentElement.outerHTML };
  });
  expect(seen.value).toMatch(/^sealed1\.demo\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  expect(seen.formData).toBe(seen.value);
  expect(seen.valid).toBe(true);
  expect(seen.value).not.toContain('6789');
  expect(seen.html).not.toContain(SSN);
});

test('setting .value throws InvalidStateError', async ({ page }) => {
  await page.goto('/');
  await waitReady(page);
  const error = await page.locator('sealed-input').evaluate((el: HTMLElement & { value: string }) => {
    try {
      el.value = 'x';
      return null;
    } catch (e) {
      return (e as DOMException).name;
    }
  });
  expect(error).toBe('InvalidStateError');
});

test('constraints freeze on first input so validity is not a page-driven oracle', async ({ page }) => {
  await page.goto('/');
  await waitReady(page);
  await typeSsn(page);
  const field = page.locator('sealed-input');
  expect(await field.evaluate((el: HTMLElement & { checkValidity(): boolean }) => el.checkValidity())).toBe(true);
  await field.evaluate((el) => el.setAttribute('pattern', '^9.*'));
  await page.waitForTimeout(200);
  expect(await field.evaluate((el: HTMLElement & { checkValidity(): boolean }) => el.checkValidity())).toBe(true);
  expect(await field.evaluate((el: HTMLElement & { validity: ValidityState }) => el.validity.patternMismatch)).toBe(false);
});

test('the recipient opens the envelope for the right slot and rejects the wrong one', async ({ page, request }) => {
  await page.goto('/');
  await waitReady(page);
  await typeSsn(page);
  await page.getByRole('button', { name: 'Enroll' }).click();
  await expect(page.locator('#response')).toContainText('200');
  await expect(page.locator('#response')).toContainText('"last4":"6789"');

  const envelope = await page.locator('sealed-input').evaluate((el: HTMLElement & { value: string }) => el.value);
  const replay = await request.post(`${RECIPIENT}/enroll`, { form: { card: envelope } });
  expect(replay.status()).toBe(400);
  expect(await replay.json()).toEqual({ ok: false, code: 'open-failed' });
});

test('fails closed when the action origin is not trustworthy', async ({ page }) => {
  await page.goto('/insecure');
  await expect.poll(() => page.locator('sealed-input').evaluate((el) => el.matches(':state(error)'))).toBe(true);
  const state = await page.evaluate(() => {
    const form = document.getElementById('enroll') as HTMLFormElement;
    const field = form.querySelector('sealed-input') as HTMLElement & { value: string };
    return { value: field.value, valid: form.checkValidity(), observed: document.getElementById('observed')?.textContent ?? '' };
  });
  expect(state.value).toBe('');
  expect(state.valid).toBe(false);
  expect(state.observed).toContain('insecure-action');
});
```

- [ ] **Step 4: Run the e2e suite**

Run: `npm run e2e`
Expected: all 5 tests PASS. Playwright starts `node demo/serve.ts` itself.

Debugging notes if a test fails:
- `:state(ready)` never true: open `http://localhost:4780/` in Chromium with `npm run demo` running and read the `#observed` box; a `sealed-error` reason there tells you which discovery step failed. Check the recipient's stderr for the structured `demo.listening` event.
- Frame never appears: `frame-ancestors` header on `/sealed-input/frame.html` must name `http://localhost:4780` exactly.
- `open-failed` on the happy path: the slot differs. The frame uses `MessageEvent.origin` (`http://localhost:4780`), `canonicalAction(action.href)` (`http://localhost:4781/enroll`), and `name` (`ssn`). Compare with `expect` in `demo/serve.ts`.

- [ ] **Step 5: Commit**

```bash
git add demo/serve.ts demo/index.html demo/app.js playwright.config.ts e2e/sealed-input.spec.ts
git commit -m "feat: two-origin demo and end-to-end proof of the sealed round trip"
```

---

### Task 8: `koschei doctor`

**Files:**
- Create: `src/server/doctor.ts`
- Test: `tests/doctor.test.ts`

**Interfaces:**
- Consumes: `parseWellKnown`, `selectEncryptionKey` from `src/server/keys.ts`; `startServers` from `demo/serve.ts` (tests only)
- Produces:
  - `interface DoctorCheck { name: string; ok: boolean; detail: string; hint?: string }`
  - `runDoctor(options: { actionUrl: string; privateKeyPath?: string; pageOrigin?: string; fetchImpl?: typeof fetch }): Promise<DoctorCheck[]>`
  - `formatDoctor(checks: DoctorCheck[]): string`
  - `runDoctorCli(args: string[]): Promise<number>` (exit code 0 when every check passes, 1 otherwise)

- [ ] **Step 1: Write the failing tests**

`tests/doctor.test.ts`:
```ts
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startServers, type DemoServers } from '../demo/serve.ts';
import { formatDoctor, runDoctor } from '../src/server/doctor.ts';

let servers: DemoServers;
const PAGE = 4790;
const RECIPIENT = 4791;

beforeAll(async () => {
  servers = await startServers({ pagePort: PAGE, recipientPort: RECIPIENT });
});
afterAll(async () => {
  await servers.close();
});

describe('doctor', () => {
  it('passes every check against the demo recipient and page', async () => {
    const checks = await runDoctor({ actionUrl: `${servers.recipientOrigin}/enroll`, pageOrigin: servers.pageOrigin });
    expect(checks.map((c) => [c.name, c.ok])).toEqual([
      ['well-known reachable', true],
      ['well-known parses', true],
      ['frame loads with frame-ancestors', true],
      ['WebCrypto available', true],
      ['page CSP form-action', true],
      ['page CSP frame-src', true],
    ]);
    expect(formatDoctor(checks)).toContain('✓ well-known reachable');
  });

  it('reports a mismatched private key with a hint', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'koschei-'));
    const keyPath = join(dir, 'wrong.jwk');
    const wrong = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    await writeFile(keyPath, JSON.stringify({ ...(await crypto.subtle.exportKey('jwk', wrong.privateKey)), kid: 'demo', use: 'enc' }));
    const checks = await runDoctor({ actionUrl: `${servers.recipientOrigin}/enroll`, privateKeyPath: keyPath });
    const keyCheck = checks.find((c) => c.name === 'private key matches published kid');
    expect(keyCheck?.ok).toBe(false);
    expect(keyCheck?.hint).toMatch(/kid/);
  });

  it('reports an unreachable recipient and stops early', async () => {
    const checks = await runDoctor({ actionUrl: 'http://localhost:1/enroll' });
    expect(checks[0]).toMatchObject({ name: 'well-known reachable', ok: false });
    expect(checks).toHaveLength(1);
  });

  it('flags a page without the CSP directives', async () => {
    const checks = await runDoctor({
      actionUrl: `${servers.recipientOrigin}/enroll`,
      pageOrigin: servers.pageOrigin,
      fetchImpl: (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === `${servers.pageOrigin}/`) return new Response('<html>', { headers: { 'content-type': 'text/html' } });
        return fetch(input, init);
      }) as typeof fetch,
    });
    expect(checks.find((c) => c.name === 'page CSP form-action')).toMatchObject({ ok: false });
    expect(checks.find((c) => c.name === 'page CSP form-action')?.hint).toContain('form-action');
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/doctor.test.ts`
Expected: FAIL, cannot find `../src/server/doctor.ts`.

- [ ] **Step 3: Implement doctor**

`src/server/doctor.ts`:
```ts
import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { parseWellKnown, selectEncryptionKey, type WellKnownDocument } from './keys.ts';

export interface DoctorCheck {
  name: string;
  ok: boolean;
  detail: string;
  hint?: string;
}

export interface DoctorOptions {
  actionUrl: string;
  privateKeyPath?: string;
  pageOrigin?: string;
  fetchImpl?: typeof fetch;
}

function cspDirective(header: string | null, directive: string): string | null {
  if (!header) return null;
  for (const part of header.split(';')) {
    const [name, ...values] = part.trim().split(/\s+/);
    if (name === directive) return values.join(' ');
  }
  return null;
}

// Checks run in the order they most often fail; a failure that makes later
// checks meaningless stops the run.
export async function runDoctor(options: DoctorOptions): Promise<DoctorCheck[]> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const checks: DoctorCheck[] = [];
  const action = new URL(options.actionUrl);
  const recipientOrigin = action.origin;

  let response: Response;
  try {
    response = await fetchImpl(`${recipientOrigin}/.well-known/sealed-input`, { credentials: 'omit', cache: 'no-store' });
  } catch (error) {
    checks.push({ name: 'well-known reachable', ok: false, detail: `${recipientOrigin}/.well-known/sealed-input: ${error instanceof Error ? error.message : String(error)}`, hint: 'Serve /.well-known/sealed-input from the action origin (koschei init writes it).' });
    return checks;
  }
  const contentType = response.headers.get('content-type') ?? '';
  const reachable = response.ok && contentType.startsWith('application/json');
  checks.push({ name: 'well-known reachable', ok: reachable, detail: `${response.status}, ${contentType || 'no content-type'}`, ...(reachable ? {} : { hint: 'Return 200 with Content-Type: application/json.' }) });
  if (!reachable) return checks;

  let doc: WellKnownDocument;
  let kid: string;
  let frameUrl: URL;
  try {
    doc = parseWellKnown(await response.json());
    kid = selectEncryptionKey(doc).kid;
    frameUrl = new URL(doc.frame, recipientOrigin);
    if (frameUrl.origin !== recipientOrigin) throw new TypeError('frame is not same-origin with the recipient');
    checks.push({ name: 'well-known parses', ok: true, detail: `${doc.keys.length} key(s), kid=${kid}, frame=${doc.frame}` });
  } catch (error) {
    checks.push({ name: 'well-known parses', ok: false, detail: error instanceof Error ? error.message : String(error), hint: 'Needs { frame: "<same-origin path>", keys: [ { kty: "EC", crv: "P-256", x, y, kid, use: "enc" } ] }.' });
    return checks;
  }

  try {
    const frameResponse = await fetchImpl(frameUrl.href, { credentials: 'omit', cache: 'no-store' });
    const ancestors = cspDirective(frameResponse.headers.get('content-security-policy'), 'frame-ancestors');
    const ok = frameResponse.ok && ancestors !== null;
    checks.push({ name: 'frame loads with frame-ancestors', ok, detail: `${frameResponse.status}, frame-ancestors ${ancestors ?? 'missing'}`, ...(ok ? {} : { hint: `Send Content-Security-Policy: frame-ancestors <embedding origin> with ${doc.frame}.` }) });
  } catch (error) {
    checks.push({ name: 'frame loads with frame-ancestors', ok: false, detail: error instanceof Error ? error.message : String(error), hint: `Serve ${doc.frame} from the recipient origin.` });
  }

  if (options.privateKeyPath) {
    try {
      const privateJwk = JSON.parse(await readFile(options.privateKeyPath, 'utf8')) as JsonWebKey & { kid?: string };
      const published = doc.keys.find((key) => (key as { kid?: string }).kid === privateJwk.kid);
      const matches = published !== undefined && published.x === privateJwk.x && published.y === privateJwk.y;
      checks.push({ name: 'private key matches published kid', ok: matches, detail: `local kid=${privateJwk.kid ?? 'none'}, published kids=${doc.keys.map((k) => (k as { kid?: string }).kid).join(',')}`, ...(matches ? {} : { hint: 'The private JWK kid, x, and y must match a key in the well-known. Re-run koschei init or publish the matching public key.' }) });
    } catch (error) {
      checks.push({ name: 'private key matches published kid', ok: false, detail: error instanceof Error ? error.message : String(error), hint: 'Pass --private <path to the JWK koschei init wrote>.' });
    }
  }

  const webcrypto = typeof crypto?.subtle?.deriveBits === 'function';
  checks.push({ name: 'WebCrypto available', ok: webcrypto, detail: webcrypto ? 'crypto.subtle present (ECDH, HKDF, AES-GCM)' : 'crypto.subtle missing', ...(webcrypto ? {} : { hint: 'Run on Node 20+.' }) });

  if (options.pageOrigin) {
    try {
      const pageResponse = await fetchImpl(`${options.pageOrigin}/`, { credentials: 'omit', cache: 'no-store' });
      const csp = pageResponse.headers.get('content-security-policy');
      for (const directive of ['form-action', 'frame-src']) {
        const value = cspDirective(csp, directive);
        const ok = value !== null && value.split(/\s+/).includes(recipientOrigin);
        checks.push({ name: `page CSP ${directive}`, ok, detail: value === null ? `${directive} missing` : `${directive} ${value}`, ...(ok ? {} : { hint: `Add \`${directive} ${recipientOrigin}\` to the page's Content-Security-Policy so a script cannot ${directive === 'form-action' ? 'retarget the form' : 'swap in another frame'}.` }) });
      }
    } catch (error) {
      checks.push({ name: 'page CSP form-action', ok: false, detail: error instanceof Error ? error.message : String(error), hint: 'Pass --page <embedding origin> that serves the form.' });
    }
  }

  return checks;
}

export function formatDoctor(checks: DoctorCheck[]): string {
  return checks
    .map((check) => `${check.ok ? '✓' : '!'} ${check.name}  ${check.detail}${check.hint && !check.ok ? `\n    -> ${check.hint}` : ''}`)
    .join('\n');
}

export async function runDoctorCli(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: { private: { type: 'string' }, page: { type: 'string' } },
  });
  const actionUrl = positionals[0];
  if (!actionUrl) {
    process.stderr.write('usage: koschei doctor <action-url> [--private path] [--page origin]\n');
    return 2;
  }
  const checks = await runDoctor({ actionUrl, privateKeyPath: values.private, pageOrigin: values.page });
  process.stdout.write(formatDoctor(checks) + '\n');
  return checks.every((check) => check.ok) ? 0 : 1;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/doctor.test.ts`
Expected: PASS, 4 tests. (Requires `dist/` from `npm run build`; the demo servers read it.)

Run: `npm run typecheck`
Expected: exit 0, no errors anywhere now that `doctor.ts` exists.

Run: `npm test`
Expected: all unit suites PASS.

- [ ] **Step 5: Try the CLI end to end**

In one terminal: `npm run demo`
In another:
```bash
node bin/koschei.ts doctor http://localhost:4781/enroll --page http://localhost:4780
```
Expected: six `✓` lines, exit 0. Then `node bin/koschei.ts init --out /tmp/koschei-init-check --private /tmp/koschei-init-check.jwk --frame-ancestors http://localhost:4780` writes five files and prints the private-key warning.

- [ ] **Step 6: Commit**

```bash
git add src/server/doctor.ts tests/doctor.test.ts
git commit -m "feat: koschei doctor checks recipient, frame, key, and page CSP in failure order"
```

---

### Task 9: Spec amendment, README status, and closing verification

**Files:**
- Modify: `docs/specs/explainer.md` (Recipient discovery bullets; Global Constraints "secure" definition)
- Modify: `README.md` (status paragraph; `init` output matches Task 4; note on running)

- [ ] **Step 1: Amend the explainer for potentially trustworthy origins**

In `docs/specs/explainer.md`, under "Recipient discovery", replace the bullet beginning `If the form has no `action`, or the resolved action is not `https:`` with:

```markdown
- If the form has no `action`, or the resolved action is not a potentially
  trustworthy URL (`https:`, or `http:` on `localhost`, `*.localhost`,
  `127.0.0.1`, `[::1]`, matching the platform's definition), the document
  fails to load or parse, or `frame` is not same-origin with the recipient, the
  control is disabled and dispatches `sealed-error`. There is no fallback to
  plaintext.
```

Also update the `sealed-error` row's `insecure-action` meaning if it is described anywhere as "not https". Search: `grep -n 'https:' docs/specs/explainer.md`.

Also, under "Polyfill-specific limitations", replace the **Styling** bullet with:

```markdown
- **Styling.** The page cannot style the frame's input. v1 of the polyfill
  ships a fixed system-font look and accepts no theme; a constrained theme
  object (font, color, size) is the obvious follow-up and the same compromise
  every hosted field makes.
```

- [ ] **Step 2: Update the README status and run instructions**

In `README.md`, replace the paragraph beginning `This is a polyfill and an explainer for a primitive the platform does not have.` with:

```markdown
This is a polyfill and an explainer for a primitive the platform does not have.
Status: working prototype. `npm test` runs the unit suites including the RFC 9180
known-answer tests; `npm run e2e` runs the two-origin browser proof; `npm run demo`
serves the page on `http://localhost:4780` and the recipient on
`http://localhost:4781`. The API below is the proposal; if it does not read well
here, the crypto does not matter.
```

Update the `koschei init` output block in README to list the five files Task 4 writes (private key, well-known, `frame.html`, `frame.js`, `HEADERS.txt`).

If the Task 2 sender-side KAT had to be weakened, add one sentence under "Dependencies (planned)" saying so and naming the discrepancy.

- [ ] **Step 3: Full verification**

Run, each unpiped, and check each exit status:
```bash
npm run typecheck; echo "typecheck exit=$?"
npm test; echo "unit exit=$?"
npm run build; echo "build exit=$?"
npm run e2e; echo "e2e exit=$?"
```
Expected: four `exit=0` lines. Do not claim completion on any other output.

- [ ] **Step 4: Commit**

```bash
git add docs/specs/explainer.md README.md
git commit -m "docs: potentially-trustworthy origins in the spec, prototype status in the README"
```
