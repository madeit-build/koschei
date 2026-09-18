# koschei

A form field the page cannot read.

`<sealed-input>` looks and behaves like `<input>`, but the value is encrypted in
the browser to a key published by the form's destination, before any script on the
page can touch it. Page JavaScript, npm dependencies, browser extensions, session
replay, the CDN, the WAF, and the APM agent all see ciphertext. Only the backend
holding the private key sees the value.

This is a polyfill and an explainer for a primitive the platform does not have.
Status: pre-code. The API below is the proposal; if it does not read well here,
the crypto does not matter.

## Usage

### 1. Set up the recipient

```sh
npx koschei init
```

```
Wrote private key  ->  ./koschei-private.jwk          (keep this out of the browser and out of git)
Wrote well-known   ->  ./public/.well-known/sealed-input
Wrote sealed frame ->  ./public/sealed-input/frame.html
```

Serve both static files from the same origin as your form's `action`. The
well-known names the frame and carries one P-256 public key with a `kid`:

```json
{
  "frame": "/sealed-input/frame.html",
  "keys": [ { "kid": "2026-09", "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "use": "enc" } ]
}
```

The frame is where keystrokes land and sealing happens. It lives on the
recipient's origin on purpose: that origin sees the plaintext after decryption
anyway, so hosting the frame there adds no new party. Never serve it from a
third-party CDN. Send `Content-Security-Policy: frame-ancestors https://www.example.com`
with it so only your site can embed it.

### 2. Mark the field

```html
<script type="module" src="https://cdn.example/koschei.js"></script>

<form method="post" action="https://api.example.com/enroll">
  <label>Full name <input name="name" autocomplete="name" required></label>

  <label>Social Security number
    <sealed-input name="ssn" required
                  inputmode="numeric"
                  pattern="\d{3}-?\d{2}-?\d{4}"
                  autocomplete="off"></sealed-input>
  </label>

  <button>Enroll</button>
</form>
```

That is the whole client integration. No key on the page, no SDK init, no
`data-` attributes. The element reads the form's `action`, fetches
`https://api.example.com/.well-known/sealed-input`, loads the recipient's frame,
and every keystroke is sealed inside that frame to the recipient's key. Host the
loader script yourself with Subresource Integrity; it is ordinary page code.

Native form behavior keeps working:

```js
form.checkValidity();        // true/false, evaluated inside the sealed boundary
form.requestSubmit();        // posts ssn=<envelope> like any other field
new FormData(form).get('ssn') // "sealed1.2026-09.BGx…"  (ciphertext, safe to read)
```

### 3. Open it on the server

```js
import { unseal } from 'koschei/server';
import { readFile } from 'node:fs/promises';

const privateKey = JSON.parse(await readFile(process.env.KOSCHEI_PRIVATE_KEY_PATH, 'utf8'));

app.post('/enroll', async (req, res) => {
  const ssn = await unseal(req.body.ssn, {
    privateKey,
    expect: {
      origin: 'https://www.example.com',
      action: 'https://api.example.com/enroll',
      name: 'ssn',
    },
  });
  // ssn is plaintext here and only here.
});
```

`unseal` rejects, with a reason code, anything sealed for a different origin,
action, or field name. A ciphertext lifted from one site's form will not open on
another's, and a ciphertext for `ssn` will not open as `card`.

### 4. Check the setup

```sh
npx koschei doctor https://api.example.com/enroll
```

```
✓ https://api.example.com/.well-known/sealed-input  reachable, 200, application/json
✓ well-known parses, 1 key, kid=2026-09, P-256, use=enc, frame=/sealed-input/frame.html (same-origin)
✓ frame loads, sends frame-ancestors https://www.example.com
✓ private key at ./koschei-private.jwk matches kid=2026-09
✓ WebCrypto available in this runtime (ECDH, HKDF, AES-GCM)
! Content-Security-Policy on https://www.example.com has no form-action directive
    -> add `form-action https://api.example.com` so a script cannot retarget the form
! Content-Security-Policy on https://www.example.com has no frame-src directive
    -> add `frame-src https://api.example.com` so a script cannot swap in another frame
```

Checks run in the order they most often fail.

## The API, as proposed

### `<sealed-input>`

Form-associated custom element (`static formAssociated = true`). Participates in
`FormData`, constraint validation, `form.reset()`, and `disabled` via
`ElementInternals`.

| Surface | Behavior |
|---|---|
| `name`, `required`, `disabled`, `autocomplete`, `placeholder`, `inputmode` | Same meaning as `<input>`. |
| `pattern`, `minlength`, `maxlength` | Same meaning as `<input>`, evaluated inside the sealed boundary. Frozen once the user starts typing, so the page cannot change the pattern and re-read validity to binary-search the value. |
| `.value` (get) | The current **envelope** string, or `""` if empty. Never the plaintext. |
| `.value` (set) | Throws `InvalidStateError`. The page cannot seed a value it is not allowed to read. |
| `.validity`, `.validationMessage`, `.checkValidity()`, `.reportValidity()` | Work. One `customError` bit, never which constraint failed. The message is generic (`"Please match the requested format."`), never echoes input. |
| `input`, `change` events | Fire, with `data` and `inputType` absent. Enough for "has the user typed anything" UX. |
| `keydown`, `keyup`, `keypress`, `beforeinput`, `compositionupdate` | Do not fire on the page. |
| `selectionStart`, `selectionEnd`, `setSelectionRange()` | Absent. |
| `sealed-ready` event | Fires once the recipient key is fetched and verified. Before this the field is disabled. |
| `sealed-error` event | Fires with `reason` (`recipient-unreachable`, `recipient-invalid`, `frame-blocked`, `no-form-action`, `insecure-action`, `insecure-context`). The field stays disabled. Fail closed. |

### Envelope

```
sealed1 . <kid> . <base64url(enc)> . <base64url(ciphertext)>
```

- `sealed1` version tag.
- `kid` from the well-known JWK Set, so the server can rotate keys.
- `enc` is the HPKE encapsulated key, `ciphertext` the HPKE-sealed value.
- HPKE (RFC 9180) single-shot, base mode, suite
  `DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM`. Same suite ISO 18013-7
  mandates for mdoc responses; nothing beyond baseline WebCrypto is needed.
- `info` = `"sealed-input/1"`.
- `aad` = `"<embedding origin>\n<action URL, no query or fragment>\n<field name>"`.
  The embedding origin is taken from the browser (the frame's `MessageEvent.origin`),
  not from anything the page can set.
- Plaintext is length-prefixed and zero-padded to a multiple of 32 bytes, so the
  envelope reveals length only to a 32-byte bucket.

### `unseal(envelope, { privateKey, expect })` (server)

Returns the plaintext string. Throws `UnsealError` with `code`:
`bad-envelope`, `unknown-kid`, `open-failed`. An AEAD failure cannot say *which*
part of the slot was wrong, so `open-failed` covers origin, action, and name
mismatches as well as a corrupted envelope. Every rejection emits one structured
log event with the code, the `kid`, the expected slot (none of which are
secrets), and what to check next. It never logs the envelope, the key, or the
plaintext.

## What it defends against, and what it does not

Three questions, answered separately, so nobody reads "sealed" as "authenticated."

- **Identity: who is the caller?** The embedding origin, as reported by the
  browser, plus the form's action and field name. That triple is what the AAD binds.
- **Authentication: what proves it?** Successful AEAD open under the destination's
  private key proves the bytes were sealed *in a browser, for this origin, action,
  and field*. It proves nothing about which user typed them. Sessions, CSRF tokens,
  and login are still your job.
- **Authorization: what may they do?** Entirely the server's. `unseal` returns a
  string; what happens next is application logic.

| Adversary | Outcome |
|---|---|
| Third-party script on the page (analytics, session replay, tag manager) | Sees ciphertext. Cannot read the frame's DOM. |
| Compromised first-party dependency, reading fields (Magecart-style) | Sees ciphertext. Cannot call `.value` for plaintext. This is the headline case. |
| Compromised first-party dependency, active | Can retarget the form or frame only if `form-action` / `frame-src` CSP are missing. Can insert a decoy field (below). |
| Browser extension with content-script access | Sees ciphertext in the page. Can read the sealed frame's DOM if it also has host permission for the recipient origin. A native implementation closes this. |
| Page changes `pattern` and re-reads validity to probe the value | Blocked. Constraints freeze on first input; validity is one bit. |
| TLS-terminating edge, CDN, WAF, APM, request logging | Sees ciphertext. |
| Replay of a captured envelope to another origin or form | `open-failed`. AEAD rejects the wrong slot. |
| Attacker who controls the destination origin's well-known | Game over, by definition: they are the recipient. |
| **Decoy field.** XSS inserts a plain `<input>` styled to look like ours and the user types into it | **Not prevented, made costlier.** Passive readers (the common case) are eliminated outright; a decoy is an active, visible attack that still needs an exfil path CSP allows. Natively, a `sealed-fields` CSP directive seals the decoy too. Same residual hole as every hosted-fields product. |
| **Replay to the same form.** Same envelope posted twice to the same action | **Not defended by the envelope.** Idempotency and nonces are the server's job, as with any form. |

## Why these choices

- **No key on the page.** If the page declares the recipient key, an injected
  script declares a different one. Discovering the key from the `action` origin
  means substituting the key requires substituting the destination, and
  `form-action` CSP already exists for that. This is the direct answer to the
  objection that killed the 2014 `writeonly` proposal
  (see [docs/research/prior-art.md](docs/research/prior-art.md)).
- **Encrypt, do not hide.** `writeonly` only blocked DOM reads and was rejected in
  one WebAppSec call because the value was still plaintext at the edge and in the
  renderer. Ciphertext from the first keystroke has an answer for every hop.
- **`.value` returns the envelope, not an exception.** Reading ciphertext is
  harmless and keeps `FormData`, `fetch` bodies, and every form library working
  unchanged. Setting `.value` throws, because seeding a value is a read in disguise.
- **Cross-origin iframe in the polyfill, served by the recipient.** It stands in
  for the renderer-side isolation a native implementation gets for free. It is
  the same architecture Stripe, Evervault, VGS, and Basis Theory ship, except the
  frame lives on the origin that will decrypt the value anyway, so no vendor ever
  holds plaintext.
- **A new element, not `<input type="sealed">`.** An unknown `type` falls back to
  `text` and renders a plaintext field in old browsers. An unknown element renders
  nothing the user can type into. Fail closed, all the way down to the markup.
- **One ciphersuite, no negotiation.** Fewer knobs, and reviewers can point at
  ISO 18013-7's existing analysis.

## Non-goals

- Real renderer heap isolation. Needs browser changes. The explainer says what a
  native `<sealedinput>` would do differently.
- Key management and rotation beyond `kid` selection. `init` gets you one key;
  rotating it is your deployment's concern.
- Production hardening of the polyfill. It is a reference, not a product.
- Defending against a compromised destination.
- Preventing decoy fields. Making them costlier, yes; preventing them, no.

## Dependencies (planned)

- [`@hpke/core`](https://github.com/dajiaji/hpke-js): RFC 9180 on top of WebCrypto,
  runs in browsers and Node unchanged, so the client seal and the server unseal use
  the same library. Chosen over hand-rolled ECDH + HKDF + AES-GCM so the envelope is
  a standard construction with published test vectors.
- No framework. The element is vanilla so the polyfill reads as a spec sketch, not
  as a component library.

## Repo layout (planned)

```
docs/
  research/prior-art.md     what exists, what stalled, why
  specs/explainer.md        WICG-template explainer (next)
src/
  element/                  <sealed-input> and the sealed frame
  frame/                    the sealed frame document, served by the recipient
  server/                   unseal(), init, doctor
demo/                       reference server + page proving the round trip
```
