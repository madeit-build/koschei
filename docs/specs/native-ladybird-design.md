# Native `<sealedinput>` in Ladybird: design

Design for the second demo: a native implementation of sealed fields in the
Ladybird engine, byte-compatible with the polyfill's `sealed1` envelope and
opened by the same `unseal`. Companion to
[docs/research/native-feasibility-ladybird.md](../research/native-feasibility-ladybird.md)
(integration map, build notes) and [docs/specs/explainer.md](explainer.md)
(the binding spec for behavior).

## Decisions

1. **Patch series, not a fork.** Work happens on a branch of a local Ladybird
   checkout pinned at `1010a932`. The deliverable in this repo is
   `native/ladybird/*.patch` (`git format-patch` output) plus a script that
   applies, builds, and runs the demo against a checkout the user supplies.
   Rebasing onto newer Ladybird is a cost paid once, at the end, if ever.
2. **One core, two entry points.** A new `LibWeb/HTML/SealedField.{h,cpp}`
   owns recipient discovery, HPKE sealing, the envelope, frozen constraints,
   and one-bit validity. `<sealedinput>` is a thin element that owns a
   `SealedField` unconditionally. The `sealed-fields` CSP directive attaches a
   `SealedField` to an ordinary `<input>` whose `autocomplete` token the
   directive names. Same mechanism, two opt-ins.
3. **Guards, not logic, in `HTMLInputElement.cpp`.** Every change to the
   existing input element is a one-line `if (m_sealed_field) ...` delegate.
   The set of guards is the explainer's Element surface table, row by row
   (see the hook table below). A row with no hook is an over-promise; a hook
   with no row is scope creep.
4. **Tag name `<sealedinput>`.** Hyphenated names are reserved for author
   custom elements, so a UA cannot ship `<sealed-input>`. The demo gets a
   `/native` page variant; same recipient, same `unseal`.
5. **Proof artifact.** The recipient's structured log line
   `sealed-input.unseal outcome=ok` for an envelope Ladybird produced, plus a
   screenshot. The log is the assertion; the screenshot is the exhibit.
6. **Tests at two speeds.** Both paths are covered by Ladybird Text tests: the
   runner serves any test with a `.headers` sidecar over HTTP from its echo
   server, so the directive test carries a real `Content-Security-Policy`
   header. The HTTP run against the demo remains the cross-client proof.
7. **HPKE in LibCrypto, one suite.** `LibCrypto/HPKE.{h,cpp}` implements
   RFC 9180 single-shot base mode for `DHKEM(P-256, HKDF-SHA256),
   HKDF-SHA256, AES-128-GCM` on top of the existing `SECP256r1`, `HKDF`, and
   `AESGCMCipher`, with the Appendix A.3.1 vectors as a `TestSuite`.
8. **Out of scope, stated.** Renderer-memory isolation (plaintext stays in
   `WebContent`, as `type=password` does today); IME/composition edge cases
   beyond "composition text is not forwarded to script"; autofill; the
   Compositor trusted-path design from the memo.

## The hook table

Each row of the explainer's Element surface becomes exactly one guard.

| Explainer row | File | Guard |
|---|---|---|
| `value` getter returns the envelope | `HTMLInputElement.cpp` `value()` | `if (m_sealed_field) return m_sealed_field->envelope();` |
| `value` setter throws `InvalidStateError` | `HTMLInputElement.cpp` `set_value()` | `if (m_sealed_field) return WebIDL::InvalidStateError::create(realm(), "sealed field value cannot be set by script"_string);` |
| Re-seal on every input | `HTMLInputElement.cpp` `did_edit_text_node()` | `if (m_sealed_field) m_sealed_field->reseal(m_value);` |
| `input`/`change` fire with `data` null | `HTMLInputElement.cpp` `did_edit_text_node()` | pass `{}` instead of `data` when sealed |
| `keydown`/`keyup`/`keypress` not dispatched | `Page/EventHandler.cpp` keyboard dispatch | skip script dispatch when the target's input is sealed; UA default action still runs |
| `beforeinput`/`compositionupdate` not dispatched | `Page/EventHandler.cpp` / `FormAssociatedElement.cpp` | same guard at the input-event dispatch |
| `selectionStart`/`selectionEnd` absent | `HTMLInputElement.cpp` selection getters | return `0` when sealed |
| `setSelectionRange()`/`select()`/`setRangeText()` absent | `HTMLInputElement.cpp` | no-op when sealed |
| Constraints frozen on first input | `SealedField` | snapshot `pattern`/`minlength`/`maxlength`/`required` on first `reseal` |
| Validity is one bit | `HTMLInputElement.cpp` constraint checks | `if (m_sealed_field) return m_sealed_field->is_invalid();` in the aggregate, individual flags false |
| Attach by policy | `HTMLInputElement.cpp` `form_associated_element_was_inserted()` | `m_sealed_field = SealedField::create_if_policy_applies(*this);` |
| Fail closed until ready | `SealedField` | disabled until the well-known fetch completes and the key imports |
| `sealed-ready` / `sealed-error` | `SealedField` | dispatched on the owning element |
| Entry list carries the envelope | none | the generic branch already reads `value()` |

Added during implementation, beyond the explainer's original Element surface table:

| Explainer row | File | Guard |
|---|---|---|
| `textInput` not dispatched | `Page/EventHandler.cpp` legacy `textInput` dispatch | `if (sealed_input_for(*focused_area)) return EventResult::Accepted;` |
| Composition events not dispatched | `HTML/LocalNavigable.cpp` | `focused_area_is_sealed_input(document)` guards composition dispatch |
| `getSelection().toString()` returns empty for a sealed field | `HTMLInputElement.cpp` `selected_text_for_stringifier()` | `if (m_sealed_field) return {};` |
| Paste ignored until ready | `Page/EventHandler.cpp` `insert_pasted_content()` | `if (sealed_input_is_not_ready(*target)) return EventResult::Handled;` |
| `selectionDirection` bindings guarded | `FormAssociatedElement.cpp` `set_selection_direction_binding()` | `if (is_sealed_text_control()) return {};` |

## Envelope compatibility

Identical to the polyfill: `sealed1.<kid>.<base64url(enc)>.<base64url(ct)>`;
plaintext `uint16 BE length || UTF-8 || zero pad` to 32 bytes; `info` =
`sealed-input/1`; `aad` = `<document origin>\n<action origin+pathname>\n<name>`.
The document origin is the element's node document origin, taken from the
engine, never from markup. The action is the owning form's resolved action.

## What this proves that the polyfill cannot

- No `postMessage` seam and no recipient-hosted frame: the recipient publishes
  a key set and nothing else.
- HPKE from the engine's own crypto library.
- Key events never reach script (the polyfill relies on the frame boundary).
- The `sealed-fields` directive seals a decoy `<input autocomplete=...>` the
  page did not opt in, which no userland approach can do.
- Fail-closed markup: the same page renders a working control natively and an
  inert box in an engine without support.

## Deliverables

- `native/ladybird/0001-*.patch` … `000N-*.patch` against `1010a932`
- `native/ladybird/apply-and-build.sh` and `native/ladybird/run-demo.sh`
  (take `LADYBIRD_DIR`; never assume a path)
- Demo routes `/native` and `/native-directive` in `demo/serve.ts`
- Ladybird Text test under `Tests/LibWeb/Text/input/HTML/sealedinput-*.html`
  (inside the patch series)
- `docs/research/assets/ladybird-native.png` and
  `docs/research/assets/ladybird-native-directive.png` (the two "after"
  screenshots, element path and directive path), alongside the existing
  `ladybird-sealedinput-unknown.png` "before", and the captured `unseal` log
  lines in the memo
