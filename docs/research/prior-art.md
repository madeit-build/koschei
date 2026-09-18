# Prior art: sealed / opaque form values on the web platform

Research pass, 2026-09-17. Question: has anyone tried to give the web a form field
whose value the page cannot read and that reaches the backend encrypted? What
exists, what stalled, and was it a technical objection or a missing champion?

Short answer: one serious native attempt (2014), killed in a single working-group
call. It aimed at DOM opacity, never at encryption, so it could not answer "what
about the network, the edge, and the renderer's own memory." Everything since has
been userland iframes sold by payments vendors. Two shipped native APIs (Apple Pay
JS, Digital Credentials API) already hand the page ciphertext it cannot open, which
is the exact shape we want, just not for arbitrary fields.

## 1. Direct ancestors: native proposals

### 1.1 Write-only Form Elements (Mike West, Google, Sept-Oct 2014)

The closest thing to our idea that ever reached a spec draft.

- Proposal thread: [Write-only input fields](https://discourse.wicg.io/t/write-only-input-fields/598/), 2014-09-03.
- Spec draft: [Write-only Form Elements](https://mikewest.github.io/credentialmanagement/writeonly/), 2014-10-15.

Mechanism: a boolean `writeonly` attribute on `<input>` and `<form>`, plus a CSP
directive `form-writeonly` keyed on `autocomplete` tokens (`current-password`,
`cc-number`, ...). Once the internal "write-only value flag" is set it can never be
cleared, even if the attribute is removed. With the flag set:

- `value`, `valueAsNumber`, `valueAsDate`, `selectionStart`, `selectionEnd` throw `InvalidStateError`
- `keydown`, `keyup`, `keypress` do not fire
- the element is barred from constraint validation
- `FormData` built from the form is "opaque": `.get()` returns null, bytes only
  materialize inside `XMLHttpRequest.send()` / `fetch()` `Request` construction

The security considerations section is where it gets interesting for us. It admits
the renderer process still holds the plaintext, and proposes the browser's
privileged parent process fill the field with a *nonce* and swap in the real
credential at the network layer. That is heap isolation by process boundary. It is
also as far as the draft goes: **no encryption to a recipient key anywhere.** The
value is hidden from script, then travels in the clear past TLS termination.

Objections on the record:

- Tab Atkins, 2014-09-03: "If someone can do content-injection, can't they insert
  a full form... with the target of their choosing?" and the attacker can just
  remove the attribute. West: `form-action` CSP mitigates the retarget; the flag is
  sticky so removing the attribute does nothing.
- [WebAppSec teleconference, 2014-10-28](https://www.w3.org/2014/10/28-webappsec-minutes.html):
  Tanvi Vyas raised write-only passwords alongside password-manager extraction
  attacks (citing [Automated Password Extraction Attack on Modern Password Managers](https://arxiv.org/pdf/1309.1416v1.pdf)
  and [Silver et al., USENIX Security 2014](https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/silver)).
  Daniel Veditz (Mozilla): "argued against it for 10 years." Brad Hill, chair:
  **"write only form elements will not be done."** No action items.
- [WebAppSec teleconference, 2015-10-28](https://www.w3.org/2011/webappsec/minutes/2015-10-28-webappsec-minutes.html):
  mkwst: proposed "a write-only attribute on form fields a while back, was no
  interest expressed at the time." annevk asked for "an opt-in upgrade to a
  hardened model" for password inputs, then listed the same two holes: XSS can
  retarget the form, or "inject a new, non-opaque field and convince user to type
  into that instead." No next steps.

Verdict: **both**. There was a real technical objection (opacity without
encryption leaves the network path and renderer memory exposed, and does nothing
against a decoy field), and there was no champion (Google's own author reported no
interest; Mozilla's security lead had opposed the idea for a decade). The
technical objection is answerable. The decoy-field attack is not answerable by any
field-level primitive, native or userland, and hosted-fields vendors live with it
today.

### 1.2 HTML Server Relief: client-side password hashing (stuartpb, 2015)

[Thread](https://discourse.wicg.io/t/html-server-relief-password-input-attributes-for-client-side-hashing/793/).
Attributes `crypt`, `work`, `salt` to derive a key in the browser so the server
compares a cheap hash. Different goal (offload KDF cost, not hide the value from
the page). Author later pivoted to "passwordless by default." Stalled, no
champion, no implementer.

### 1.3 `encrypted` / `algorithm` attributes on password inputs (2022)

[Thread](https://discourse.wicg.io/t/new-attribute-as-encrypted-and-algorithm-for-password-type-input-field/5849/).
Browser generates an RSA pair per password and stores the private key locally.
Rejected on threat-model grounds in one reply ("the password in the end still has
to be some text value... transmitted over the wire", "if an attacker has local
code executing, all bets are off"). Author conceded. Useful mostly as a warning:
a proposal that cannot say precisely *who* the recipient is and *what* the
attacker can already do gets dismissed in one message.

### 1.4 Adjacent WICG threads, not examined in depth

- [`<input type="credentials" accept="Ed25519">` and form signing](https://discourse.wicg.io/t/input-type-credentials-accept-ed25519-and-form-signing/3316):
  signing, not confidentiality.
- [Public key authentication in browsers](https://discourse.wicg.io/t/public-key-authentication-in-browsers/4616/):
  authentication, later subsumed by WebAuthn.

## 2. The isolation side: prior art for "the page never holds the bytes"

### 2.1 COWL, Confinement with Origin Web Labels (W3C WebAppSec, 2015-2017)

[Spec](https://www.w3.org/TR/COWL) · [Repo](https://github.com/w3c/webappsec-cowl) · [Project site](https://cowl.ws/).
Label-based mandatory access control for browsing contexts: data carries
confidentiality labels naming the origins it is secret to, and a context that
reads labeled data is confined from communicating anywhere that would leak it.
Reached Working Draft, then stalled (editor's draft unmaintained, repo archival).
Jonathan Knezevic proposed COWL labels as the alternative to `writeonly` in the
2015 thread. Verdict: no champion, plus implementation cost. It is the only
platform-level design that addresses the renderer-heap problem rather than the
DOM-API problem, which is why our polyfill's cross-origin iframe is a crude COWL.

### 2.2 `<keygen>` (removed from HTML, 2017)

[Removing `<keygen>` · whatwg/html#2079](https://github.com/whatwg/html/issues/2079) ·
[Blink intent to deprecate](https://groups.google.com/a/chromium.org/g/blink-dev/c/pX5NbX0Xack) ·
[Mozilla bug 1315460](https://bugzilla.mozilla.org/show_bug.cgi?id=1315460).
Form-integrated key generation for client certificates. Removed because it
"modified the device-wide store outside the browsers' and origins' security
models" and the client-cert UX was "inherently user-hostile." Lesson for us: any
proposal that reaches outside the origin model, or asks the user to manage keys,
dies. Ours must stay inside the origin model with zero user-visible key handling.

## 3. Native APIs that already hand the page ciphertext

These are the strongest precedent. The platform *has* shipped "page receives a
blob only the backend can open," twice, each time scoped to one vertical.

### 3.1 Apple Pay JS

The `PKPaymentToken` returned to page JavaScript is encrypted by Apple's servers to
the merchant's certificate: `EC_v1` = ECDH over P-256, NIST SP 800-56A KDF, AES-GCM,
with an ECDSA signature over `ephemeralPublicKey || data || transactionId`.
Decryption requires the merchant private key, which lives server-side. Page script
handles ciphertext, forwards it, done. (See e.g. [apple-pay-decrypt](https://github.com/samcorcos/apple-pay-decrypt)
and Apple's forum thread on the [v2 token format](https://developer.apple.com/forums/thread/808677).)

### 3.2 Digital Credentials API + OpenID4VP `direct_post.jwt` (shipped in Chrome, 2025)

[Chrome announcement](https://developer.chrome.com/blog/digital-credentials-api-shipped) ·
[OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
The wallet encrypts the presentation to the verifier's public key supplied in the
request's `client_metadata`; ISO 18013-7 mandates HPKE single-shot with
AES-128-GCM. The relying party's page JS receives a JWE it cannot read and posts it
to the backend, which decrypts with the private key. This is our envelope flow,
with a wallet in place of a keyboard.

### 3.3 Payment Request API `basic-card` (sunset, Chrome 100, 2022)

[Chromium blog](https://blog.chromium.org/2021/10/sunsetting-basic-card-payment-method-in.html).
Browser-native raw card entry was removed because a merchant receiving raw PAN via
the API falls outside PCI SAQ A, so nobody could use it without a PSP anyway. The
platform's answer to "handle sensitive data natively" was to *retreat* and let
iframes from PSPs own it. That retreat is why every hosted-fields product exists.

## 4. Userland: hosted fields and client-side encryption products

All of these are the same architecture: a cross-origin iframe owned by the vendor,
WebCrypto or a vendor SDK inside it, a vendor-held key, and a token or ciphertext
handed back to the page.

| Product | Model | Key holder |
|---|---|---|
| [Evervault Inputs](https://docs.evervault.com/products/inputs) | Client-side encryption via WebCrypto in an iframe ([Evervault Encryption](https://docs.evervault.com/security/evervault-encryption)) | Evervault |
| [VGS Collect](https://go.basistheory.com/compare/very-good-security) | Tokenization; iframe fields, vault-side storage | VGS |
| [Basis Theory Elements](https://go.basistheory.com/evervault-alternative) | Tokenization; PCI L1 vault, token returned | Basis Theory |
| Stripe Elements, [Braintree Hosted Fields](https://developer.paypal.com/braintree/docs/guides/payment-request/overview) | Tokenization; PSP iframe | PSP |

Evervault is the closest in spirit (encryption rather than tokenization) and the
one whose docs read most like an explainer for what we are building. The
difference: in every product above the recipient is the *vendor*, chosen for you.
Ours makes the recipient the destination origin's own published key.

## 5. Evidence for the threat model

Three incidents, one per adversary class in the problem statement.

- **Third-party script on the page.** Princeton CITP, 2017,
  [No boundaries: Exfiltration of personal data by session-replay scripts](https://blog.citp.princeton.edu/2017/11/15/no-boundaries-exfiltration-of-personal-data-by-session-replay-scripts/):
  seven replay vendors, 400+ top sites, unredacted passwords, SSNs and card numbers
  captured *before submit*. Follow-up, 2018:
  [No boundaries for credentials](https://blog.citp.princeton.edu/?p=13616).
- **Compromised first-party dependency.** British Airways, 2018
  ([Securonix](https://www.securonix.com/resources/british-airways-breach-magecart-formgrabbing-supply-chain-attack-detection/),
  [Huntress](https://www.huntress.com/threat-library/data-breach/british-airways-data-breach)):
  22 lines added to Modernizr.js read card fields on the payment page and beaconed
  to `baways.com`. 380,000+ records. WAF and server never saw it; the read happened
  in the DOM.
- **Browser extension.** Cyberhaven, 2024-12-25
  ([Sekoia](https://blog.sekoia.io/targeted-supply-chain-attack-against-chrome-browser-extensions/),
  [SecurityWeek](https://www.securityweek.com/cyberhaven-chrome-extension-hack-linked-to-widening-supply-chain-campaign/)):
  developer phished, malicious version published, 30+ extensions and 2.6M users in
  the wider campaign. Extensions with `<all_urls>` content scripts read any input.

Not one of these adversaries is stopped by TLS, and the first two are not stopped
by DOM opacity either if the decoy-field trick is available. All three are stopped
by the value being ciphertext from the first keystroke onward.

## 6. Platform crypto readiness

- WebCrypto today: ECDH P-256, HKDF-SHA256, AES-GCM are universal. X25519 has
  shipped in all engines but arrived late (Chrome 133).
- [Modern Algorithms in the Web Cryptography API](https://wicg.github.io/webcrypto-modern-algos/)
  (WICG draft): adds `encapsulateKey/Bits` and `decapsulateKey/Bits`, ML-KEM and
  hybrid KEMs (MLKEM768-P256, MLKEM768-X25519), ChaCha20-Poly1305, AES-OCB, SHA-3,
  Argon2. **Does not add HPKE itself.** So a native `<input type=sealed>` would
  need HPKE in the engine (Chrome and Firefox both already ship HPKE internally for
  ECH and OHTTP, so the code exists; the API does not).
- Polyfill path: [`@hpke/core`](https://github.com/dajiaji/hpke-js) (dajiaji),
  RFC 9180 on top of WebCrypto, all ciphersuites, browsers + Node + Deno. Suite
  choice `DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM` matches ISO 18013-7
  and needs nothing beyond baseline WebCrypto.

## 7. Verdict

**Why it stalled: no champion, with a technical objection that was never answered
because the one proposal aimed at the wrong layer.**

1. The 2014 proposal hid the value from the DOM. It did not encrypt. So the
   working group correctly asked "and then what, it's plaintext at the edge and in
   the renderer," and closed it in one call.
2. The two loudest constituencies solved their problem elsewhere: payments went to
   PSP iframes after `basic-card` died, authentication went to WebAuthn by
   deleting the secret. Nobody was left to push for SSNs, API keys, health data,
   and the long tail of "sensitive but not a card."
3. Where the platform did ship "page gets ciphertext" (Apple Pay JS, Digital
   Credentials API), it was vertical-specific and driven by a wallet vendor, not
   generalized to `<input>`.

## 8. What this means for the design

- **Encrypt, do not merely hide.** Opacity alone was rejected in 2014 and would be
  again. The envelope must be ciphertext to a key the page never holds.
- **Recipient = destination origin, discovered, not declared.** If the page
  supplies the key, an XSS attacker supplies their own. Fetch the recipient key
  from the form `action`'s origin (`/.well-known/...`) so substituting the key
  requires substituting the destination, which `form-action` CSP already governs.
  This collapses Tab Atkins' retarget objection into an existing control.
- **Bind origin and destination into the AAD.** A ciphertext lifted from one site
  or one form must fail to open anywhere else. This is what ISO 18013-7 does with
  the session transcript.
- **Name the decoy-field attack as out of scope, up front.** Every hosted-fields
  product has the same hole. Say so in the explainer before a reviewer does.
- **Stay inside the origin model, zero user key management.** `<keygen>` is the
  cautionary tale.
- **Reuse a shipped ciphersuite.** Same suite as mdoc / ISO 18013-7 removes a
  bikeshed and lets reviewers point at existing security analysis.
- **Keep the form-associated ergonomics.** `writeonly` kept `FormData` and
  submission working; anything that breaks `form.submit()` or `checkValidity()`
  is a non-starter for adoption.
- **Position the iframe as a stand-in for COWL-style confinement**, and say what
  a native implementation would get for free (renderer-side isolation, no
  postMessage seam, HPKE without a polyfill).
