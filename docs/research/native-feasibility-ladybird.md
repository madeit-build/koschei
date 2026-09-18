# Native feasibility: `<sealedinput>` in Ladybird

Spike, 2026-09-18. Question: can we build a second demo that implements the
sealed field _natively_ in an open-source engine, to show what the polyfill
structurally cannot, and produce envelopes the same `unseal` opens?

**Verdict: yes, and it is smaller than it sounds.** A demo that types into a native control, seals in-engine with HPKE, submits the
envelope through the normal form path, and is opened by the koschei reference
server roughly t-shirt sizes at a medium. Every integration point exists in Ladybird today and is spec-shaped
enough that the patch reads like the explainer's processing model.

Engine: Ladybird `master` at `1010a932` (shallow clone), macOS, AppKit chrome.
Process model: `WebContent` (renderer, one per tab), `RequestServer`,
`ImageDecoder`, `Compositor`, `WebWorker`. Read-only survey; no engine code
written in this spike.

## Integration map

Paths are relative to the Ladybird checkout. Line numbers are at `1010a932`.

| Explainer section                       | Where it lands                                                                                                                                                                                                                                                                                                                                      | What changes                                                                                                                                                                                                                                                                                                        |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| New element (not a new `type`)          | `Libraries/LibWeb/HTML/TagNames.h:79` (`__ENUMERATE_HTML_TAG`), `Libraries/LibWeb/DOM/ElementFactory.cpp:383` (`REGISTER_HTML_ELEMENT`), `Libraries/LibWeb/idl_files.cmake:274` (`libweb_js_bindings`)                                                                                                                                              | Add `sealedinput`, new `HTML/HTMLSealedInputElement.{h,cpp,idl}`. `HTMLOutputElement` is the size template: 201 lines across three files.                                                                                                                                                                           |
| Keystrokes never reach JS               | `Libraries/LibWeb/HTML/FormAssociatedElement.h:280-308` (`FormAssociatedTextControlElement`: `handle_insert`, `handle_delete`, `relevant_value`, `did_edit_text_node`); caller is `Libraries/LibWeb/Page/EventHandler.cpp:1462,1263`                                                                                                                | Implement the mixin. Plaintext lives in a C++ member. The IDL `value` getter returns the envelope; there is no getter for the plaintext, so LibJS never allocates a string containing it.                                                                                                                           |
| Rendering                               | `Libraries/LibWeb/HTML/HTMLInputElement.cpp:~1200-1290` (`create_text_input_shadow_tree`)                                                                                                                                                                                                                                                           | Borrow ~100 lines of the UA shadow tree pattern (inner text element, `DOM::Text` node, placeholder). Not exposed to script: `Element::open_shadow_root()` (`DOM/Element.cpp:2805`) returns null for UA trees.                                                                                                       |
| Envelope submitted like any field       | `Libraries/LibWeb/HTML/FormControlInfrastructure.cpp:111` (`construct_entry_list`), field loop at `:176-215`                                                                                                                                                                                                                                        | One new branch: if field is a `sealedinput`, `create_entry(name, envelope)`. Same shape as the existing `select` / checkbox / file branches.                                                                                                                                                                        |
| HPKE in-engine                          | `Libraries/LibCrypto/Curves/SECPxxxr1.h:161-190` (`SECP256r1::generate_private_key`, `generate_public_key`, `compute_coordinate`), `Libraries/LibCrypto/Hash/HKDF.h:28` (`derive_key(salt, ikm, info, len)`), `Libraries/LibCrypto/Cipher/AES.h:50-60` (`AESGCMCipher::encrypt(plaintext, iv, aad, taglen)`), `AK/Random.h:21` (`fill_with_random`) | All primitives exist, OpenSSL-backed. RFC 9180 composition (`LabeledExtract`, `LabeledExpand`, `Encap`, `KeySchedule`, `Seal`) is ~150 lines in a new `LibCrypto/HPKE.{h,cpp}`. RFC 9180 Appendix A.3 is _exactly_ our suite (DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM), so test vectors are ready-made. |
| Recipient discovery                     | `Libraries/LibWeb/HTML/HTMLLinkElement.cpp:507-541` as the pattern (`Fetch::Infrastructure::Request::create`, `FetchAlgorithms::Input::process_response_consume_body`, `Fetch::Fetching::fetch`)                                                                                                                                                    | On insertion, resolve owning form's `action`, fetch `<origin>/.well-known/sealed-input` with mode `cors`, credentials `omit`, parse JWK `x`/`y` into a `SECPxxxr1Point`. Disabled until the key arrives; disabled forever on failure. Fail closed.                                                                  |
| `form-action` enforcement               | `Libraries/LibWeb/ContentSecurityPolicy/Directives/FormActionDirective.cpp` (38 lines, `pre_navigation_check`)                                                                                                                                                                                                                                      | Already implemented. The demo inherits it for free, which is one of the points.                                                                                                                                                                                                                                     |
| `sealed-fields` CSP directive (stretch) | `Libraries/LibWeb/ContentSecurityPolicy/Directives/Names.h:19` (`__ENUMERATE_DIRECTIVE_NAME`), `DirectiveFactory.cpp:55`                                                                                                                                                                                                                            | New `SealedFieldsDirective` is the easy half (~40 lines by analogy). The hard half is making `HTMLInputElement` consult the policy on its `autocomplete` token and switch behavior, which touches a 4,129-line file. Stretch goal, not v1.                                                                          |
| Proving it                              | `Tests/LibWeb/Text/input/` (existing `form-*.html`, `FormData-*.html`), `Libraries/LibWeb/Internals/Internals.idl:60` (`internals.sendText(target, text)`), `./Meta/ladybird.py test`                                                                                                                                                               | A Text test types a known string with `sendText`, asserts `value.startsWith("sealed1.")`, `!value.includes(typed)`, and that `new FormData(form).get(name)` is the envelope. Then the end-to-end: Ladybird against the koschei demo server, `unseal` opens it.                                                      |

## What this demo proves that the polyfill cannot

1. **No JS-reachable plaintext, by construction.** The only copy is a C++ member
   on the element plus the `DOM::Text` node in a UA shadow tree that
   `open_shadow_root()` hides. No IDL surface returns it. This is "there is no
   object to leak," not "we chose not to expose it."
2. **No `postMessage` seam, no recipient-hosted frame.** The recipient publishes
   a key set. The explainer's trust-boundary section shrinks to one origin.
3. **HPKE from the engine's own crypto.** Not substitutable by page script.
4. **Fail-closed markup, photographed.** The same HTML renders a working control
   in Ladybird and an inert box in Chrome without the polyfill.
5. **`form-action` enforced where CSP lives**, not by a doctor command.
6. **One server, two clients.** Byte-compatible `sealed1` envelopes from the
   polyfill and from Ladybird, opened by the same `unseal`. This is the artifact
   a spec reviewer actually wants.

## What it does not prove

- **Renderer memory isolation.** In v1 the plaintext exists inside the
  `WebContent` process, as a `Utf16String` member and as a `DOM::Text` node in
  the UA shadow tree. That is the same place `<input type=password>` keeps it
  today (`HTMLInputElement.cpp:1270-1272`; `set_is_password_input` only affects
  painting). v1 defends against *script*: no IDL surface, no JS-heap object. It
  does not defend against a renderer memory disclosure (use-after-free read,
  speculative-execution gadget, compromised `WebContent`). Neither does any
  existing form control, CSP, or Trusted Types; the platform's security features
  assume an intact renderer. See [Beyond v1](#beyond-v1-trusted-path-input) for
  what would.
- **Extension threat.** Ladybird has no extension system, so the polyfill's
  weakest row cannot be demonstrated either way here. The argument stays
  architectural.
- **Autofill and password-manager integration.** Ladybird has neither yet.

## Beyond v1: trusted-path input

An earlier draft of this memo said keeping plaintext out of the renderer "would
mean moving sealing into `RequestServer`." That was the wrong process. Mike
West's 2014 nonce-substitution design (privileged process fills the field with a
nonce, network layer swaps in the real value) only works for *autofilled*
values, which never had to pass through the renderer. A *typed* value enters the
renderer at the keyboard, so a network-layer fix is too late. `RequestServer`
terminates TLS (curl, in-process) and receives the request body as a finished
`ByteBuffer` in `start_request`; it never needs to change, because in every
design here `WebContent` only ever submits ciphertext.

Ladybird's actual topology, from the IPC definitions at `1010a932`:

```
UI process  --key_event-->  Compositor  --key_event-->  WebContent
WebContent  --update_display_list-->  Compositor  -->  pixels
WebContent  --start_request(body)-->  RequestServer  --TLS-->  network
```

`WebContent` receives key events from the Compositor
(`Services/WebContent/ConnectionFromClient.cpp:448`,
`m_compositor_connection->on_key_event`), and does not paint: it ships a display
list to the Compositor (`Services/Compositor/CompositorWebContentServer.ipc:36`),
which owns the final frame. One privileged process already sits on both the
input path and the output path. That is the pair a trusted input surface needs,
and most engines would have to add a process or an IPC channel to get it.

The architecture: when a sealed field has focus, the Compositor stops forwarding
its keystrokes. It accumulates the plaintext, seals per keystroke, and sends
`WebContent` the envelope plus a character count. `WebContent` holds ciphertext
and a number.

| Slice | What it needs | What it proves | Rough cost |
|---|---|---|---|
| **v2, masked only** | Focus tracking across the Compositor boundary; a `sealed_input_*` IPC pair; Compositor-side HPKE (reuses v1's `LibCrypto/HPKE`); `WebContent` renders N bullets from the count | Plaintext never enters the renderer for password, SSN, CSC, and any other masked field. A compromised `WebContent` cannot read it. | ~1 week |
| **v3, visible text** | Compositor paints the characters into the field's rectangle as an overlay it owns, matching the renderer's font and layout; IME/composition routed to the Compositor; accessibility tree for text that is not in the renderer | Same guarantee for card numbers and anything shown as typed. A trusted display surface, the same idea as Android Protected Confirmation. | Weeks. Real browser work. |

Closing the last hole (a compromised renderer naming a wrong recipient key) means
the Compositor fetches the well-known itself via `RequestServer` for the action
origin `WebContent` names, plus `--site-isolation` so one site's renderer cannot
name another site's action. Both mechanisms exist in this codebase.

**This is not required for the proposal and should not be built speculatively.**
Chromium's input path is browser process to renderer with no compositor seam;
WebKit differs again. A trusted-path demo in Ladybird is evidence that *an*
engine's shape supports it, not that Chromium's does, and a reviewer from either
would say so. It belongs in the explainer as a "UA may" implementation note with
this topology as the existence proof. Build the v2 slice only if a named
reviewer asks to see it.

## Effort estimate

| Piece                                                                                           | Days          |
| ----------------------------------------------------------------------------------------------- | ------------- |
| `LibCrypto/HPKE` with RFC 9180 A.3 test vectors passing                                         | 1             |
| `HTMLSealedInputElement`: registration, IDL, text-control mixin, shadow tree, entry-list branch | 1.5           |
| Well-known fetch, JWK parse, fail-closed state machine                                          | 0.5           |
| Text test + end-to-end against the koschei demo server                                          | 0.5           |
| Build and iteration overhead (first build is long; incremental is fine with ccache)             | 0.5           |
| **Total for v1**                                                                                | **~4**        |
| `sealed-fields` CSP directive including `HTMLInputElement` hook                                 | +1.5, stretch |

## Risks

- **Master moves fast.** Pin to `1010a932`. Keep the work as a patch series in
  the koschei repo (`native/ladybird/*.patch`) against the pinned commit, not as
  a long-lived fork. Rebasing is a cost we pay once, at the end, if we want to
  show it against current master.
- **vcpkg.** The build doc warns that vcpkg failures surface as "Unable to find
  Ninja." First build on this machine is in progress; numbers below.
- **C++ surface area.** `HTMLInputElement.cpp` is 4,129 lines. We borrow from
  it, we do not modify it (except for the stretch directive).
- **Ergonomics we cannot test here.** Labels, styling, and autofill behave
  natively by definition, so the demo will look _better_ than the polyfill in
  ways that are not the polyfill's fault. Say so in the write-up.

## Recommendation

Go, as its own bounded task, sequenced **after** the polyfill's Node crypto layer
lands and freezes the `sealed1` byte format. The native demo's entire value is
envelope compatibility, and you cannot target a moving format. It can run in
parallel with the polyfill's DOM work; the only shared resources are CPU and disk
during builds.

Deliverables of that task: the patch series, a Text test in Ladybird's own
format, a screenshot pair (Ladybird vs. Chrome-without-polyfill), and a recorded
`unseal` of a Ladybird-produced envelope by the koschei server.

## Build on this machine

Ladybird `1010a932`, macOS (Darwin 25.6, Apple Silicon), Apple clang 21, Homebrew
toolchain (`autoconf autoconf-archive automake ccache cmake libtool nasm ninja
pkg-config rustup`), `./Meta/ladybird.py build`, ccache enabled, release preset.

| Stage                          | Wall clock      | Result                                             |
| ------------------------------ | --------------- | -------------------------------------------------- |
| vcpkg dependencies (first run) | 735 s           | Completed, then CMake configure failed: no `cargo` |
| Engine build (vcpkg cached)    | 2947 s (49 min) | `rc=0`, `Build/release/bin/Ladybird.app`           |
| **Total to a running binary**  | **~61 min**     | 13 GB in `Build/`                                  |

Gotchas hit, so the next person does not:

- **Rust is a hard prerequisite.** `LibJS` builds a Rust crate; `rust-toolchain.toml`
  pins `1.98.0`. The build doc says so in one sentence and it is easy to miss.
- **Homebrew's `rustup` does not populate `~/.cargo/bin`.** The `cargo`/`rustc`
  proxies live in `$(brew --prefix rustup)/bin`. Put that on `PATH` before
  building, then `rustup toolchain install 1.98.0` (or let the toolchain file
  trigger it).
- **Headless runs use the main binary, not `test-web`.**
  `Ladybird.app/Contents/MacOS/Ladybird --headless=text <url>` dumps rendered
  text; `--headless=screenshot --screenshot-path <png>` captures. `test-web` is
  the suite runner and requires `--test-path`.
- **GNU userland on this Mac.** The shell here resolves `sed`/`date` to GNU
  versions (Nix), so BSD-only flags fail. Irrelevant to Ladybird, relevant to
  anyone scripting around it on this machine.

### Baseline probe: what the engine does with `<sealedinput>` today

[`assets/sealed-probe.html`](assets/sealed-probe.html) puts a plain `<input>`
and a `<sealedinput>` in one form and prints what script can see. Ladybird
`1010a932`, `--headless=text`:

```
constructor=HTMLUnknownElement
is-form-control=false
has-value-prop=false
formdata-has-ssn=false
formdata-plain=typed-plaintext
```

Screenshot: [`assets/ladybird-sealedinput-unknown.png`](assets/ladybird-sealedinput-unknown.png).

This is the fail-closed baseline the explainer argues for. An unsupported engine
renders the sealed field as nothing: no control, no value, no entry in the
submission. The plain field beside it submits its plaintext as usual. After the
patch, the same page should print `constructor=HTMLSealedInputElement`,
`is-form-control=true`, `formdata-has-ssn=true`, and a `value` that starts with
`sealed1.` and does not contain the typed text. That before/after pair is the
demo's first screenshot.
