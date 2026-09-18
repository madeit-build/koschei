# Sealed form fields

**Explainer, draft.** Follows the [WICG explainer template](https://github.com/WICG/proposals/blob/main/explainer-template.md).

## Authors

- Matt deClercq

## Participate

- Repository: this repo (issues welcome once published)
- Prior-art survey: [docs/research/prior-art.md](../research/prior-art.md)

## Introduction

There is no declarative way for a web page to say "this value is not for me."

TLS protects a form value between the browser and the first server that
terminates the connection. WebAuthn removed passwords from the authentication
path. Neither touches *sensitive data submission*: a card number, a Social
Security number, a medical answer, an API key pasted into a settings page, or a
password on a fallback path. Today that value is readable by every script on the
page from the first keystroke, and is plaintext in the request handler, the CDN,
the WAF, the APM trace, and the access log.

This explainer proposes a form control whose value is encrypted in the browser to
a public key published by the form's destination, before page script can read it.
The page, and everything between the page and the private key holder, handles
ciphertext. We call the control a *sealed field*, the ciphertext an *envelope*,
and the key holder the *recipient*.

The proposal is deliberately narrow. It addresses confidentiality of a submitted
value against the page's own dependencies and infrastructure. It does not
authenticate the user, does not replace TLS, and does not attempt to be a PAKE.

## Goals

1. **Page script never holds the plaintext.** No DOM API returns it, no event
   carries it.
2. **Ciphertext from the first keystroke.** Every hop after the browser, including
   the site's own edge and observability stack, sees only the envelope.
3. **Recipient is the destination, not a value the page declares.** Substituting
   the key must require substituting the destination, so existing CSP governs it.
4. **Envelopes are bound to the slot they were sealed in.** An envelope sealed on
   one origin, for one action, for one field name, opens nowhere else.
5. **Ordinary forms keep working.** `FormData`, `requestSubmit()`, constraint
   validation, `reset()`, `disabled`, and every form library that reads
   `.value` as an opaque string.
6. **Zero user-visible key handling.** Users see a text field. Nothing else.
7. **Adoption cost is one tag on the page.** No SDK initialization, no key on
   the page, no pre-render round trip.
8. **No new trusted party.** The only origin that ever holds plaintext is the
   one that would hold it after decryption anyway.
9. **Fails closed.** An unsupported browser, an unreachable recipient, or a
   misconfiguration yields a disabled field, never a plaintext one.

## Non-goals

- **Authentication.** A sealed field proves the value was sealed in a browser for
  this origin, action, and name. It proves nothing about who typed it. Sessions,
  CSRF tokens, and WebAuthn remain the answer for identity.
- **Password hashing, PAKEs, OPAQUE.** Those change what the server *stores*.
  This proposal changes what the page and the network *see*. Both can coexist.
- **Protection against a compromised recipient.** If the destination origin's
  private key is stolen or its well-known document is rewritten, the recipient
  is the attacker by definition.
- **Preventing decoy fields.** An injected script can insert an ordinary
  `<input>` styled to look like the sealed one and hope the user types into it.
  This is not prevented. It is made costlier and more detectable, and the
  remaining gap is bounded by CSP. See
  [The decoy field, directly](#the-decoy-field-directly).
- **Replay to the same slot.** The same envelope posted twice to the same action
  opens twice. Idempotency and nonces are the server's responsibility, exactly as
  for an ordinary form.
- **Sender authentication.** HPKE base mode is used. Anyone holding the public
  key can produce a valid envelope for any slot, exactly as anyone can submit an
  ordinary form. Envelopes prove context, not provenance.
- **Renderer heap isolation in the polyfill.** A userland implementation can
  only approximate isolation with a cross-origin frame. See
  [What a native implementation does differently](#what-a-native-implementation-does-differently).

## Use cases

- **Payment card entry without a PSP iframe.** A merchant who is willing to be
  the recipient (or who runs their own vault) declares the vault origin as the
  form action and publishes its key. The card is ciphertext from keystroke to
  vault. Today this requires embedding a vendor's frame and letting the vendor
  hold the key. (Whether this changes PCI DSS scoping is a question for the
  compliance body, not this document.)
- **Government and healthcare identifiers.** SSN, tax ID, insurance member ID,
  diagnosis fields. High regulatory cost, no PSP-style vendor ecosystem, and
  therefore almost always plaintext in the page and in logs today.
- **API keys and secrets in settings pages.** A user pastes a third-party API key
  into a SaaS integrations form. The SaaS wants to store it encrypted and never
  see it in a log line or an error report.
- **Passwords on fallback and recovery paths.** WebAuthn covers the happy path.
  Password reset, enterprise directory bridges, and "sign in another way" still
  post plaintext.
- **Third-party-heavy pages.** Any form on a page that also loads a tag manager,
  session replay, A/B testing, or chat widget. The 2017 Princeton session-replay
  study found unredacted passwords, SSNs, and card numbers captured before
  submit on 400+ top sites.

## Proposed API

### Markup

```html
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

**A new element, not a new `type`.** An unknown `type` on `<input>` falls back to
`text`, so `<input type="sealed">` in a browser without support would silently
render a plaintext field. An unknown element renders as an inert inline box the
user cannot type into. The native proposal is therefore also a new element
(`<sealedinput>` or similar), so that unsupported browsers fail closed. The
polyfill uses the same shape for the same reason.

### Trust boundary

Two origins participate.

- The **embedding origin** owns the page and the form. It runs the page's
  scripts, dependencies, and extensions. It is the party we defend against.
- The **recipient origin** is the origin of the form's resolved `action`. It
  publishes the public key and holds the private key. It sees plaintext after
  decryption regardless, so it is already trusted with the value.

The polyfill's sealed frame is **served by the recipient origin**. The frame is
where keystrokes land and where sealing happens; putting it on the recipient adds
no party that does not already see the value. It must never be served from a
third-party CDN or a polyfill vendor's origin, which would make that vendor a
plaintext recipient and recreate the hosted-fields problem this proposal exists
to remove. The page-side loader script is ordinary page code and may be hosted
anywhere, with Subresource Integrity.

Each side controls the other with existing CSP:

- The recipient's frame document sends
  `Content-Security-Policy: frame-ancestors <embedding origins>` so only
  approved sites can seal to it.
- The embedding page's CSP carries `frame-src <recipient origin>` and
  `form-action <recipient origin>` so a compromised script cannot swap in a
  different frame or a different destination.

### Recipient discovery

The control reads the owning form's resolved `action` URL, takes its origin, and
loads `<origin>/.well-known/sealed-input`. The response is JSON:

```json
{
  "frame": "/sealed-input/frame.html",
  "keys": [
    { "kid": "2026-09", "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "use": "enc" }
  ]
}
```

- `frame` is a same-origin path to the sealed frame document. The polyfill loads
  it in an `<iframe>`. The frame itself fetches `keys` same-origin, so no key
  material ever passes through the page.
- Must be served over HTTPS with `Content-Type: application/json`.
- The page-side fetch of the document is `cors`, `credentials: omit`.
- Multiple keys are allowed; the frame uses the first key with `use: "enc"` and
  a supported curve. `kid` is carried in the envelope so the recipient can rotate.
- If the form has no `action`, or the resolved action is not a potentially
  trustworthy URL (`https:`, or `http:` on `localhost`, `*.localhost`,
  `127.0.0.1`, `[::1]`, matching the platform's definition), the document
  fails to load or parse, or `frame` is not same-origin with the recipient, the
  control is disabled and dispatches `sealed-error`. There is no fallback to
  plaintext.

### Element surface

`<sealed-input>` is a form-associated custom element (`formAssociated = true`)
using `ElementInternals` for form value and validity.

| Member | Behavior |
|---|---|
| `name`, `required`, `disabled`, `autocomplete`, `placeholder`, `inputmode`, `form` | Same as `<input>`. |
| `pattern`, `minlength`, `maxlength` | Same meaning as `<input>`, evaluated inside the sealed boundary. **Frozen** once the field first receives input; later changes are ignored until the field is reset (see [Validation is a one-bit oracle](#validation-is-a-one-bit-oracle)). |
| `value` getter | Current envelope string, or `""`. Never plaintext. |
| `value` setter | Throws `InvalidStateError`. |
| `validity`, `validationMessage`, `checkValidity()`, `reportValidity()` | Work. `validity` exposes a single `customError` flag, not which constraint failed. `validationMessage` is generic and never echoes input. |
| `input`, `change` | Dispatched. `InputEvent.data` and `inputType` are `null`. |
| `keydown`, `keyup`, `keypress`, `beforeinput`, `compositionstart/update/end`, `paste` | Not dispatched to the page. |
| `selectionStart`, `selectionEnd`, `setSelectionRange()`, `select()` | Not present. |
| `focus()`, `blur()`, `focus`/`blur` events | Work via `delegatesFocus`. |
| `sealed-ready` (event) | Recipient frame loaded and key verified. Field enabled. |
| `sealed-error` (event) | `detail.reason` ∈ `recipient-unreachable`, `recipient-invalid`, `frame-blocked`, `no-form-action`, `insecure-action`, `insecure-context`. Field stays disabled. |

### Envelope

```
sealed1 . <kid> . <base64url(enc)> . <base64url(ct)>
```

- `sealed1`: format version.
- `kid`: from the recipient's key set.
- `enc`, `ct`: HPKE (RFC 9180) single-shot, base mode, suite
  `DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM`.
- `info` = `"sealed-input/1"`.
- `aad` = the *slot*: `<embedding origin> "\n" <action URL without query or fragment> "\n" <field name>`.
- Plaintext = `uint16 length || UTF-8 value || zero padding` to a multiple of
  32 bytes, so the envelope reveals length only to a 32-byte bucket.

The embedding origin is the origin of the document that owns the form, as
determined by the browser (in the polyfill: `MessageEvent.origin` on the message
from the embedding page to the sealed frame, which page script cannot forge). The
action URL is `new URL(form.action).origin + .pathname`; `search` and `hash` are
dropped, so envelopes are valid across query variations of the same path by
design. The field name is the control's `name` attribute.

The recipient does not parse the slot out of the envelope. It reconstructs the
slot from its own expectations and attempts `Open`. A wrong slot fails
authentication and yields no plaintext.

### Recipient library

```js
import { unseal } from 'koschei/server';

const ssn = await unseal(envelope, {
  privateKey,                                   // JWK, P-256, matching kid
  expect: {
    origin: 'https://www.example.com',          // or an array
    action: 'https://api.example.com/enroll',   // absolute, no query
    name:   'ssn',
  },
});
```

Throws `UnsealError` with `code` ∈ `bad-envelope`, `unknown-kid`, `open-failed`.
Origin, action, and name mismatches are all the same AEAD failure and cannot be
told apart from a corrupted envelope, so they share `open-failed`. When
`expect.origin` is an array the library attempts `Open` once per origin. Every
rejection emits one structured log event carrying the code, the `kid`, and the
expected slot, so "why did that not open" is answerable without adding code. The
envelope, the key, and the plaintext are never logged.

### Tooling

- `koschei init`: generates a P-256 keypair, writes the private JWK to a file,
  and writes the recipient's static assets: `.well-known/sealed-input` and the
  sealed frame document with its `frame-ancestors` header hint.
- `koschei doctor <action-url>`: checks, in order, that the well-known is
  reachable over HTTPS with the right content type, that it parses and contains
  a usable key and a same-origin `frame`, that the frame loads and sends
  `frame-ancestors`, that the local private key matches a published `kid`, that
  the runtime has the WebCrypto primitives, and that the embedding origin's CSP
  has `frame-src` and `form-action` naming the recipient.

## Key scenarios

### Ordinary form post

User types into the sealed field. Each `input` re-seals the current text inside
the recipient's frame; the envelope crosses to the page by `postMessage` and
becomes the form value via `ElementInternals.setFormValue()`. User clicks submit.
The browser posts `ssn=sealed1.2026-09.…` with the other fields. The server calls
`unseal`. Nothing on the page ever read the plaintext.

### SPA with `fetch`

```js
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const body = new FormData(form);        // ssn is already an envelope
  await fetch(form.action, { method: 'POST', body });
});
```

No change from an ordinary form. `FormData.get('ssn')` returns the envelope.

### Validation

```js
if (!form.checkValidity()) form.reportValidity();
```

`pattern`, `minlength`, `maxlength`, and `required` are evaluated inside the
sealed boundary. The frame reports one bit; the control calls
`ElementInternals.setValidity({ customError: true }, genericMessage)` or clears
it. The page learns "valid" or "invalid," never why in terms of the content.

### Key rotation

Recipient publishes a second key in the key set with a new `kid`, deploys the new
private key alongside the old, and after a grace period removes the old key from
the set. Envelopes carry `kid`; `unseal` selects the private key by it.

### Recipient unavailable

The well-known or frame fails to load. The control dispatches `sealed-error`
with `reason: "recipient-unreachable"`, stays disabled, and shows a generic
unavailable state. Because it is `disabled` and `required`, `checkValidity()` is
false and the form does not submit. Fail closed.

This is a deliberate availability trade: the recipient's static hosting is now on
the critical path for every form that seals to it. The alternative, falling back
to plaintext, defeats the proposal.

## Detailed design discussion

### Why the recipient is discovered, not declared

The 2014 `writeonly` proposal was met with: an injected script can insert its own
form with its own target, so what does hiding the value buy? The same objection
applies to any design where the page declares the recipient key: the injected
script declares its own.

Deriving the recipient from the form's `action` origin makes the key a property
of the destination. To seal to an attacker's key, the attacker must change where
the form posts and which frame is loaded, and `form-action` plus `frame-src`
already exist to prevent exactly that. The proposal adds no new trust decision;
it reuses ones sites are already expected to make.

### Why the frame is served by the recipient

Any cross-origin frame isolates the keystrokes from the page. The question is
whose origin. A third-party polyfill or CDN origin would see plaintext, and the
proposal would have reinvented hosted fields with a different vendor. The
recipient origin sees plaintext after `unseal` regardless, so hosting the frame
there introduces no new party. It also means the frame seals only to its own
origin's key: there is no configuration the page can pass that redirects the
seal, because the frame does not take the key from the page.

The recipient controls who may embed its frame with `frame-ancestors`, which is
browser-enforced and replaces any application-level allowlist.

### Why the slot is authenticated, not carried

Putting `origin`, `action`, and `name` *inside* the envelope as readable fields
and checking them server-side would work until a verifier forgets to check, or
loosens the check to a wildcard. This is the well-known failure mode of JWT
`aud`. Placing the slot in the AEAD's additional authenticated data makes the
check impossible to skip: a recipient that expects the wrong slot cannot
decrypt. Wrong context produces no plaintext to misuse.

This is the same construction ISO 18013-7 uses for mdoc responses over the
Digital Credentials API, where the `SessionTranscript` (verifier origin, client
id, nonce) is the HPKE `aad`.

### Why the origin comes from the browser

If page script could assert its own origin into the slot, a phishing page would
assert the victim's. The browser is the only party that knows which origin it
actually loaded. In the polyfill this is `MessageEvent.origin` on the sealed
frame's side; natively it is the document's origin. The page asserts nothing.

### Why `.value` returns ciphertext instead of throwing

`writeonly` made `value` throw. That breaks every form library, every
`FormData`-based `fetch`, and every test that reads a field. The envelope is
ciphertext; reading it is harmless. Returning it keeps the ecosystem working
unchanged and lets adoption be one tag. Setting `.value` throws because seeding
a value is a read in disguise (the page could seed a known value and observe
validity).

### Validation is a one-bit oracle

Constraint validation necessarily tells the page one bit about the content. That
bit must not be queryable at will. If the page could change `pattern` to `^1`
and read `validity`, then `^2`, and so on, it would binary-search the value one
character at a time.

Mitigations, all required:

- `pattern`, `minlength`, and `maxlength` are read when the field first receives
  input and frozen until `form.reset()` or the element is disconnected. Changing
  them afterward is a no-op. Reconnecting the element creates a fresh frame with
  an empty value.
- `validity` exposes a single `customError` flag. `patternMismatch`, `tooShort`,
  and `tooLong` are never set individually.
- Validity is re-evaluated only on user input inside the frame, never on
  attribute change from the page.

What remains is one bit per user keystroke against a fixed pattern the page
chose before the user typed. That is the same bit an ordinary `<input pattern>`
exposes and is acceptable.

### Why one ciphersuite

Negotiation adds attack surface and a decision for integrators. The chosen suite
needs only baseline WebCrypto (ECDH P-256, HKDF-SHA256, AES-GCM), is the suite
ISO 18013-7 mandates, and has published HPKE test vectors. A `sealed2` version
tag exists for the day P-256 is not enough.

### Why re-seal on every `input`

Sealing only on submit would leave plaintext in the frame until then, and would
make `.value` inconsistent with the field state. One HPKE seal per keystroke is
sub-millisecond on any device that can run a browser. The envelope for a partial
value is valid ciphertext and useless to a reader. Padding to 32-byte buckets
keeps the envelope from tracking length character by character; the per-keystroke
`input` event still reveals keystroke count and cadence to the page, as any
field does.

### The decoy field, directly

The strongest objection to any field-level protection, raised against
`writeonly` in 2014 and 2015: if a script can inject markup, it can inject a
plain `<input>` that looks like the sealed one, and the user types into that.
Three answers, in order of weight.

**The threat model is passive readers, and that is most of the real world.**
Session replay, analytics, tag managers, and extensions do not render decoys.
They read `input.value` and ship it. The British Airways skimmer was 22 lines
that read existing fields. Readers are silent, which is why attackers prefer
them. Sealing eliminates the passive class entirely. A decoy is an active
attack: it must render convincing UI and keep it convincing across the site's
own redesigns, and it is visible to DOM-integrity monitoring and to users in a
way a `.value` read never is.

**The exfiltration channel is already CSP's problem.** A decoy still has to get
the value off the page. `connect-src`, `form-action`, `img-src`, and
`frame-src` bound where bytes can go. With sealing in place, an attacker needs a
decoy *and* an exfiltration path inside the allowlist. Neither alone suffices.

**A policy directive can seal the decoy too.** `writeonly` came with a
`form-writeonly` CSP directive keyed on `autocomplete` tokens. The same companion
belongs here and is the half that actually addresses decoys:

```
Content-Security-Policy: sealed-fields cc-number cc-csc current-password
```

The browser applies policy, not markup: an injected `<input autocomplete="cc-number">`
is sealed to the form's recipient like any other. The attacker must omit the
autocomplete hint, which also disables autofill for the decoy, which is a tell.
This does not close the gap. It narrows it to "a plain field with no autofill
that the user types a card number into anyway," which is a phishing problem, not
a platform one. CSP cannot be polyfilled; this directive is part of the native
proposal only, and is one of the strongest arguments for going native.

We do not claim to solve client-side skimming. We claim to remove the silent
majority of it and to leave the loud minority bounded by controls that already
exist.

### Polyfill-specific limitations

Honest list of what the iframe stand-in costs. Each is fixed by a native
implementation.

- **Autofill and password managers.** Browsers scope autofill to the frame's
  origin. Saved passwords for `www.example.com` will not fill a frame on
  `api.example.com`. The `shared-autofill` permissions policy (shipped for PSP
  frames) can be delegated to the frame for payment fields, but credential
  autofill has no equivalent. The password use cases are therefore weaker in the
  polyfill than natively.
- **Labels and accessibility.** `<label for>` does not cross a frame boundary.
  The element delegates focus and forwards its accessible name into the frame by
  `postMessage`, but assistive technology sees an iframe containing a text field,
  not a labeled control in the page's form. Native gets this for free.
- **Styling.** The page cannot style the frame's input. v1 of the polyfill
  ships a fixed system-font look and accepts no theme; a constrained theme
  object (font, color, size) is the obvious follow-up and the same compromise
  every hosted field makes.
- **Extensions.** A content script with host permission for the recipient origin
  can read the frame. A native implementation keeps the plaintext out of any
  content script's reach.
- **The `postMessage` seam.** The frame trusts the page for the action path and
  field name in the slot. A compromised page can only mislabel a slot; it cannot
  change the recipient key, and the origin line is browser-supplied. Mislabeling
  produces an envelope for a slot the attacker could have obtained by letting the
  user submit normally. No gain.
- **Storage in the frame.** The frame must not use cookies or storage. The
  recipient is already a party the user has a relationship with, but the frame
  should not become a tracking surface.

## Security boundary

This proposal defends against **script and everything downstream of the
browser**: page JavaScript, dependencies, extensions' content scripts (natively),
the TLS-terminating edge, and the recipient's own logs. It does not defend
against a compromised renderer process. Neither does any existing form control,
Content Security Policy, or Trusted Types; the platform's security features
assume an intact renderer, and this one is held to the same bar, not a higher
one.

The specification does not say where a user agent keeps the plaintext before
sealing. A UA **may** implement trusted-path input, in which the process that
first receives keystrokes seals them and hands the renderer only ciphertext and
a character count, so that a renderer memory disclosure cannot recover the
value. Ladybird's topology, where one process brokers both key events and the
final frame, is an existence proof that a real engine's shape can support this
(see [docs/research/native-feasibility-ladybird.md](../research/native-feasibility-ladybird.md),
"Beyond v1"). Chromium's and WebKit's topologies differ, and the cost there is
theirs to judge. Nothing in the API surface changes between the two
implementation strategies.

## What a native implementation does differently

The polyfill's cross-origin iframe is a stand-in. A native `<sealedinput>` would:

- Keep the plaintext in the browser process, or in a renderer-side allocation
  the page's JS heap cannot address. No content script, no dependency, no frame
  boundary to argue about.
- Remove the `postMessage` seam and the recipient-hosted frame entirely. The
  recipient publishes only a key set.
- Use HPKE from the engine's own crypto library (Chrome and Firefox already ship
  HPKE for ECH and Oblivious HTTP), removing the polyfill's dependency and the
  possibility of a substituted crypto library.
- Enforce the `sealed-fields` CSP directive.
- Pad envelopes and coalesce `input` events if the platform decides length and
  cadence leakage matter.
- Integrate with the platform's secure input mode so keystrokes into a sealed
  field are hidden from other processes, as password fields already are on
  macOS.
- Restore autofill, labels, and styling as first-class, since the control is an
  ordinary form control to the browser.

## Considered alternatives

| Alternative | Why not |
|---|---|
| **`writeonly` attribute** (Mike West, 2014) | Hid the value from the DOM but never encrypted. Plaintext at the edge, in the renderer, and in logs. Rejected by WebAppSec in one call. Ours encrypts. |
| **`<input type="sealed">`** | Unknown `type` degrades to `text`, so unsupported browsers would render plaintext fields. A new element degrades to nothing. |
| **Hosted fields / PSP iframes** (Stripe, Braintree, Evervault, VGS, Basis Theory) | Same architecture as the polyfill, but the vendor is the recipient. Works only for verticals with a vendor ecosystem. Ours makes the destination the recipient. |
| **Polyfill frame on a shared or CDN origin** | Makes the polyfill host a plaintext recipient. Recreates the hosted-fields problem. |
| **Client-side hashing** (HTML Server Relief, 2015) | `H(password)` is the password. Replayable. Solves KDF cost, not confidentiality from the page. |
| **PAKEs / OPAQUE in the browser** | Changes what the server stores; requires protocol negotiation and a provisioning step. Solves database secrecy, not page-side or edge-side exposure. Complementary, not competing. |
| **WebAuthn** | Binds a *signature* to origin to prove who. We bind *confidentiality* to origin to control who can read. Different primitive; WebAuthn does nothing for a card number. |
| **Payment Request `basic-card`** | Removed in Chrome 100 because a merchant receiving raw PAN is outside PCI SAQ A. Confirms the platform retreated from handling sensitive data natively rather than solving it. |
| **Recipient key as an element attribute** | XSS declares its own key. Discovery from the action origin routes the attack through `form-action` and `frame-src`, existing controls. |
| **Session nonce in the slot** | Would make envelopes single-use and session-bound (a full `SessionTranscript`). Requires a pre-render round trip, changing integration from "add a tag" to "add a tag and an endpoint." Left to the server's existing CSRF/idempotency layer. Revisit if adoption data says the round trip is acceptable. |
| **Tokenization instead of encryption** | Requires the recipient to run a synchronous vault the browser calls before submit. Encryption needs only a static public key and works offline until submit. |
| **Per-constraint validity flags** | Turns validation into a multi-bit, page-driven oracle. One frozen bit is enough for UX. |
| **COWL-style labels** | Solves the general information-flow problem and stalled for it. This proposal is the narrow case that does not need a new confinement model. |

## Open questions

- **Derived, declared signals.** Card forms want brand detection from the first
  digits to show a logo. Any signal derived from the plaintext leaks bits. A
  possible shape: the recipient's key set declares a small closed set of
  derivations (`card-brand`) the frame may report, each with a documented
  entropy cost. Not in the first version.
- **`input` event granularity.** Per-keystroke events reveal count and cadence.
  Coalescing to empty/non-empty transitions plus `change` would remove that at
  some UX cost. Native can decide; the polyfill emits per keystroke for now.
- **Nonce in the slot.** See alternatives. The trade is single-use envelopes
  versus a pre-render round trip.
- **Same-document forms.** A form with no `action` posts to the page's own URL.
  The recipient is then the embedding origin, which is fine, but it means the
  page's own origin must publish a key set. Worth a worked example.

## Stakeholder feedback and opposition

- **Historical.** Daniel Veditz (Mozilla) "argued against [write-only form
  elements] for 10 years" (WebAppSec, 2014-10-28). Tab Atkins and Anne van
  Kesteren both raised form retargeting and decoy fields. This proposal answers
  retargeting via `form-action` and `frame-src`, and addresses decoys directly
  above.
- **Expected.** Payment vendors have a commercial interest in the iframe status
  quo. Browser vendors have prioritized authentication. The constituency for the
  non-payment, non-auth case (identifiers, secrets, health data) has had no
  champion.
- **Developer demand.** Not yet gathered directly. The market signal is in the
  prior-art survey, §4: four independent vendors sell the iframe workaround, and
  every PCI-scoped merchant on the web uses one. The `writeonly` proposal died
  for want of this evidence, so it is the gap to close before public posting.
- **Positive precedent.** Chrome shipped the Digital Credentials API with
  HPKE-encrypted responses the page cannot read (2025). Apple Pay JS has returned
  merchant-encrypted tokens to page script for a decade. The shape is accepted;
  only the generalization is new.

## Security and privacy considerations

Three questions, answered separately.

**Identity: who is the caller?** The embedding origin, the form action, and the
field name, together forming the slot. All three are determined by the browser
or by markup the browser parsed, none by page script.

**Authentication: what proves it?** A successful HPKE `Open` under the recipient's
private key proves the envelope was sealed for that slot by a party holding the
recipient's public key. Since the public key is public, this proves *context*,
not *user identity* or *provenance*. It is not an authentication mechanism and
must not be treated as one.

**Authorization: what may they do?** Entirely the recipient's. `unseal` returns a
string.

### Threat table

| Adversary | Outcome |
|---|---|
| Third-party script on the page | Ciphertext only. Cannot read the sealed boundary. |
| Compromised first-party dependency, passive read | Ciphertext only. This is the headline case and the one the British Airways skimmer represents. |
| Compromised first-party dependency, active | Can retarget the form or frame only if `form-action` / `frame-src` are absent. Can insert a decoy field; see the decoy section. Can mislabel the slot; no gain. |
| Browser extension with content-script access | Ciphertext in the page. **Polyfill:** can read the frame if it also has host permission for the recipient origin. **Native:** cannot. |
| TLS-terminating edge, CDN, WAF, APM, logs | Ciphertext only. |
| Cross-slot replay (different origin, action, or name) | AEAD failure. No plaintext. |
| Same-slot replay | Opens. Server-side idempotency required, as for any form. |
| Forged envelope from an attacker holding the public key | Opens, containing whatever the attacker sealed. Equivalent to submitting a form. Not new. |
| Page-driven validation oracle | Blocked by frozen constraints and a single validity bit. |
| Compromised recipient key or well-known | Total. Out of scope by definition. |
| Recipient fingerprinting users via frame load or well-known fetch | Mitigated: fetch is `credentials: omit`; frame must not use storage; page sets `referrerpolicy="origin"` on the iframe. The recipient learns that *some* visitor on an allowed origin loaded a form. |
| Length and timing side channels | Envelope length reveals plaintext length to a 32-byte bucket. `input` events reveal keystroke count and cadence, as any field does. Native may pad further and coalesce. |
| Denial of service against the recipient's static hosting | Sealed fields become disabled; forms do not submit. Fail closed by design; see availability note. |

### Privacy

- The well-known fetch is credential-less. The frame load carries `Referer`
  limited to origin. Together they reveal to the recipient that a form on an
  allowed origin was rendered, nothing more.
- No new persistent identifier is created. The frame uses no storage.
- The control does not participate in autofill by default (`autocomplete="off"`
  in examples); if it did, the autofilled value would be sealed like typed input.

### Self-review questionnaire highlights

- *Does this expose PII?* No; it removes exposure.
- *New cross-origin state?* None.
- *Does it enable fingerprinting?* The well-known fetch and frame load are the
  only network activity, both uncredentialed and origin-scoped.
- *Secure contexts only?* Yes. `sealed-error: insecure-context` otherwise.
- *Impact on `Permissions-Policy`?* `shared-autofill` may be delegated to the
  frame for payment fields. Nothing new proposed.

## References

- Write-only Form Elements, Mike West, 2014: https://mikewest.github.io/credentialmanagement/writeonly/
- WebAppSec minutes, 2014-10-28: https://www.w3.org/2014/10/28-webappsec-minutes.html
- WebAppSec minutes, 2015-10-28: https://www.w3.org/2011/webappsec/minutes/2015-10-28-webappsec-minutes.html
- RFC 9180, Hybrid Public Key Encryption: https://www.rfc-editor.org/rfc/rfc9180
- OpenID for Verifiable Presentations 1.0: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- Digital Credentials API shipped: https://developer.chrome.com/blog/digital-credentials-api-shipped
- No boundaries: session-replay scripts, Princeton CITP, 2017: https://blog.citp.princeton.edu/2017/11/15/no-boundaries-exfiltration-of-personal-data-by-session-replay-scripts/
- Sunsetting `basic-card`, Chromium, 2021: https://blog.chromium.org/2021/10/sunsetting-basic-card-payment-method-in.html
- Full survey: [docs/research/prior-art.md](../research/prior-art.md)
