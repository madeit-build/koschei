# Proposal: sealed form fields (a field whose value the page cannot read)

_Draft for WICG Discourse, category "APIs". Everything here argues from
[the explainer](../specs/explainer.md); anything in this post that is not in
the explainer is a bug in the post._

---

There is no declarative way for a web page to say "this value is not for me."

TLS protects a form value between the browser and the first server that
terminates the connection. WebAuthn took passwords out of the authentication
path. Neither touches sensitive data _submission_: a card number, a national ID,
a medical answer, an API key pasted into a settings page. Today that value is
readable by every script on the page from the first keystroke, and it is
plaintext in the request handler, the CDN, the WAF, the APM trace, and the
access log. The British Airways skimmer was 22 lines that read `input.value`.

We are proposing a form control whose value is encrypted in the browser, to a
public key published by the form's destination, before page script can read it.
The page and everything between it and the private-key holder handle
ciphertext. We call the control a **sealed field**, the ciphertext an
**envelope**, and the key holder the **recipient**.

## The whole integration

```html
<form method="post" action="https://api.example.com/enroll">
  <label>Full name <input name="name" autocomplete="name" required></label>

  <label>Social Security number
    <sealed-input name="ssn" required inputmode="numeric"
                  pattern="\d{3}-?\d{2}-?\d{4}"></sealed-input>
  </label>

  <button>Enroll</button>
</form>
```

No key on the page, no SDK init, no `data-` attributes. The element reads the
form's `action`, fetches `https://api.example.com/.well-known/sealed-input`
(a JWK Set), and seals every edit to that key. `FormData`, `requestSubmit()`,
constraint validation, `reset()`, and every form library that treats `.value`
as an opaque string keep working. `.value` returns the envelope. The server
opens it with one call that also checks the envelope was sealed _for this
origin, this action, and this field name_; a ciphertext lifted from one site
opens nowhere else.

A companion CSP directive seals plain inputs by `autocomplete` field name, so
policy rather than markup decides what is sealed:

```
Content-Security-Policy: sealed-fields cc-number cc-csc current-password
```

## What it defends against, stated plainly

**In scope:** page JavaScript, first- and third-party dependencies, extension
content scripts (natively), session replay and analytics, the TLS-terminating
edge, and the recipient's own logs and traces. Passive readers, which is what
almost every real skimmer is, see ciphertext and nothing else.

**Out of scope, on purpose:** a compromised renderer process, and the recipient
itself. The recipient sees plaintext after decryption regardless; this adds no
party that would not already hold the value. On the renderer: no existing form
control, CSP, or Trusted Types defends against a compromised renderer either. The explainer sketches a
trusted-path variant where the process that first receives keystrokes seals
them, and shows one engine whose topology already supports it. The API surface
is identical either way.

**The decoy field.** This is the objection that killed `writeonly` in 2014: a
script that can inject markup can inject a plain `<input>` next to the sealed
one. Three answers, in order of weight. The threat model is passive readers,
and a decoy is an active attack that must render convincing UI and stay
convincing across the site's redesigns, visible to DOM-integrity monitoring in
a way a `.value` read never is. A decoy still has to exfiltrate, and
`connect-src`/`form-action`/`img-src` already bound where bytes can go. And the
`sealed-fields` directive seals the decoy too, unless the attacker omits the
`autocomplete` hint, which disables autofill for it, which is a tell. We do not
claim to solve client-side skimming. We claim to remove its silent majority and
leave the loud minority bounded by controls that already exist.

## What we built, and what it showed

Ideas in this space have mostly arrived as ideas. We wanted the room to have
artifacts to argue with, so there are two implementations of the same envelope
format, and one server that opens both.

**A polyfill** (`<sealed-input>`, a form-associated custom element). Sealing
happens in an iframe served by the recipient origin, never a CDN or a polyfill
vendor, so no new plaintext party appears. HPKE (RFC 9180, DHKEM P-256 /
HKDF-SHA256 / AES-128-GCM) via WebCrypto. A two-origin browser suite drives the
whole path. It is honest about what an iframe cannot do: extensions running in
the page's world, and anything that needs the engine's cooperation.

**A native implementation in Ladybird**, as a 13-patch series against a
current checkout. `<sealedinput>` plus the `sealed-fields` directive, HPKE in
the engine's own crypto library, `form-action` applied at key discovery so
retargeting the form cannot redirect the seal. The plaintext is a C++ member
and a UA-shadow text node; no IDL surface returns it. Two engine Text tests
cover the element path and the header-delivered directive path, and a headless
run produced envelopes for both that the polyfill's server opened unchanged.

The native work is where we learned the most, and the deviations list in the
feasibility memo is the part we would most like reviewed. A partial list of
plaintext channels we had to close after the first pass: `cloneNode`, a `type`
switch, `paste` events, detach-and-reinsert, `document.execCommand("undo")`
(script could replay the user's last edit and read the validity bit), and the
editing history surviving a `name` or form-`action` change, so the user's own
Ctrl+Z would have resealed old plaintext under a new slot and a new recipient
key. Every one of those now has a line in the expected test output. If you
know of a channel we missed, that list is the place to point.

## What we are asking the room for

1. **Developer demand, directly.** `writeonly` died partly for want of it. Our
   evidence so far is indirect: four independent vendors sell the iframe
   workaround for card data, and every PCI-scoped merchant uses one. The
   constituency for the non-payment, non-auth case (identifiers, secrets,
   health data) has never had a champion. If you have shipped a hosted-fields
   integration, or wanted to and could not because your data has no vendor
   ecosystem, we want to hear it here.
2. **The decoy argument.** Is the three-part answer above sufficient for
   WebAppSec, or is `sealed-fields` load-bearing enough that the element
   without the directive should not ship?
3. **Open design questions** in the explainer: derived, declared signals
   (card-brand detection leaks bits; a closed set the recipient declares?),
   `input` event granularity (per-keystroke reveals count and cadence), and
   whether a per-render nonce in the slot is worth the pre-render round trip
   it costs.
4. **Engine feedback** from anyone who knows Chromium's or WebKit's input
   topology. The Ladybird series shows the hooks exist in one engine; we would
   like to know where the shape is wrong for the others.

## Links

- Repository, explainer, polyfill, patch series, and prior-art survey:
  https://github.com/madeit-build/koschei
- Explainer: `docs/specs/explainer.md`
- Native feasibility memo, with the deviations list: `docs/research/native-feasibility-ladybird.md`
- Prior art (2014 `writeonly` through Digital Credentials 2025): `docs/research/prior-art.md`

Positive precedent for the shape: Chrome shipped the Digital Credentials API
with HPKE-encrypted responses the page cannot read, and Apple Pay JS has
returned merchant-encrypted tokens to page script for a decade. The shape is
accepted; only the generalization is new.
