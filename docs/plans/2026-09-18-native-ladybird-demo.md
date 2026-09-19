# Native `<sealedinput>` in Ladybird Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A patch series against Ladybird `1010a932` that adds HPKE to LibCrypto, a shared `SealedField` core, a native `<sealedinput>` element, and a `sealed-fields` CSP directive, proven by Ladybird Text tests and by the koschei demo recipient opening an envelope Ladybird produced.

**Architecture:** `LibCrypto/HPKE` implements RFC 9180 single-shot base mode for one suite on top of the existing P-256, HMAC-SHA256, and AES-GCM primitives. `LibWeb/HTML/SealedField` (a `GC::Cell`) owns recipient discovery, sealing, the envelope, frozen constraints, and one-bit validity. `HTMLInputElement` gains a `GC::Ptr<SealedField>` and one-line guards at each row of the explainer's Element surface table; `<sealedinput>` is an `HTMLInputElement` subclass that attaches a `SealedField` unconditionally; the directive attaches one to an ordinary `<input>` whose `autocomplete` token it names. The koschei repo receives the exported patches, apply/build/run scripts, two demo routes, and the proof.

**Tech Stack:** Ladybird at `1010a932` (C++23, CMake, vcpkg, OpenSSL-backed LibCrypto), Ladybird `test-web` Text tests served by the Python echo server, koschei demo server (Node 26, `demo/serve.ts`), Playwright not used.

**Spec:** `docs/specs/native-ladybird-design.md` (decisions, hook table), `docs/specs/explainer.md` (behavior, binding), `docs/research/native-feasibility-ladybird.md` (integration map, build notes).

## Global Constraints

- Two working directories. **Engine work** happens in the Ladybird checkout `$LADYBIRD_DIR` (on this machine `~/code/scratch/ladybird`), on branch `koschei-sealedinput` cut from `1010a932`; every engine task ends with a commit there. **Repo work** happens in the koschei worktree `koschei-worktrees/native-ladybird-demo` on branch `native-ladybird-demo`. Never confuse the two; every step says which.
- Engine build environment: `export PATH="/opt/homebrew/opt/rustup/bin:/opt/homebrew/opt/ccache/libexec:/opt/homebrew/bin:$PATH"` before any `./Meta/ladybird.py` call. Incremental builds take minutes, not the initial hour. Build output is `Build/release/bin/`.
- Envelope must be byte-compatible with the polyfill: `sealed1.<kid>.<base64url(enc)>.<base64url(ct)>`, no padding; `kid` matches `^[A-Za-z0-9_-]{1,64}$`; plaintext `uint16 BE length || UTF-8 || zero pad` to a multiple of 32; HPKE `info` = `sealed-input/1`; `aad` = `<document origin>\n<action origin + pathname>\n<field name>`; suite `DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM`, base mode, sequence number 0; `ct` = AEAD ciphertext followed by the 16-byte tag.
- The document origin comes from `element.document().origin().serialize()`. The action comes from the owning form, parsed against the document; `search` and `hash` dropped. A form action that is not potentially trustworthy (`SecureContexts::is_url_potentially_trustworthy`) fails with `insecure-action`.
- Well-known: `GET <action origin>/.well-known/sealed-input`, mode CORS, credentials omit; JSON `{ "frame": string, "keys": [JWK] }`; the first key with `kty: "EC"`, `crv: "P-256"`, `use: "enc"`, string `x`/`y`, and a `kid` matching the pattern is used. `frame` is ignored natively.
- Fail closed: until the well-known is fetched and the key imports, a sealed field ignores insertions and its `value` is `""`. Failure reasons are exactly `recipient-unreachable`, `recipient-invalid`, `no-form-action`, `insecure-action`, `insecure-context`; `sealed-error` is a `CustomEvent` whose `detail` is `{ reason }`; `sealed-ready` is a plain `Event`. Both bubble.
- Constraints (`required`, `pattern`, `minlength`, `maxlength`) snapshot on the first non-empty reseal and stay frozen until the field is reset or removed. Validity is one bit, surfaced as `customError` via `set_custom_validity` with the message `Please match the requested format.`; every other `suffering_from_*` returns false for a sealed field.
- No secrets in logs: no `dbgln` of plaintext, envelopes, or key material. Error `dbgln`s name the reason and the origin only.
- Ladybird code style: 4-space indent, `m_` members, `Utf16String` for DOM strings, spec-step comments where a spec exists, `ErrorOr<T>` and `TRY` in LibCrypto, `GC::Ref`/`GC::Ptr` for cells. Run `./Meta/check-style.py` on touched files before each engine commit if it exists; otherwise match surrounding formatting.
- API drift is expected. The C++ in this plan was written against the headers at `1010a932` but not compiled. When a name or signature does not compile, fix it to the nearest real API without changing behavior, and note the substitution in the task report. Do not paper over a compile error by deleting a guard.
- Tasks 5 and 6 need `demo/serve.ts` from PR #1 (`sealed-input-polyfill`). Before starting Task 5, confirm PR #1 is merged and rebase `native-ladybird-demo` onto `origin/main`. If it is not merged, stop and report; do not cherry-pick.
- Repo-relative paths only in anything committed to either repository. Never commit `Build/`, `dist/`, `public/`, or a private key.

---

### Task 1: HPKE in LibCrypto with RFC 9180 A.3.1 known answers

**Where:** Ladybird checkout.

**Files:**
- Create: `Libraries/LibCrypto/HPKE.h`, `Libraries/LibCrypto/HPKE.cpp`
- Modify: `Libraries/LibCrypto/CMakeLists.txt` (add `HPKE.cpp` to the sources list, alphabetically near `Hash/HKDF.cpp`)
- Create: `Tests/LibCrypto/TestHPKE.cpp`
- Modify: `Tests/LibCrypto/CMakeLists.txt` (add `TestHPKE.cpp` to `TEST_SOURCES`)

**Interfaces:**
- Produces (namespace `Crypto::HPKE`):
  - `struct KeyPair { UnsignedBigInteger private_key; ByteBuffer public_key; }` (public key is the 65-byte uncompressed point)
  - `struct Sealed { ByteBuffer enc; ByteBuffer ciphertext; }`
  - `ErrorOr<KeyPair> derive_key_pair(ReadonlyBytes ikm)` (RFC 9180 §7.1.3 for P-256)
  - `ErrorOr<KeyPair> generate_key_pair()`
  - `ErrorOr<Sealed> seal(ReadonlyBytes recipient_public_key, ReadonlyBytes info, ReadonlyBytes aad, ReadonlyBytes plaintext, Optional<ReadonlyBytes> ephemeral_ikm = {})`
  - `ErrorOr<ByteBuffer> open(UnsignedBigInteger const& recipient_private_key, ReadonlyBytes recipient_public_key, ReadonlyBytes enc, ReadonlyBytes info, ReadonlyBytes aad, ReadonlyBytes ciphertext)`

- [ ] **Step 1: Branch the engine checkout**

```bash
cd "$LADYBIRD_DIR"
git status --short | wc -l        # expect 0
git checkout -b koschei-sealedinput 1010a932
```

- [ ] **Step 2: Write the failing test**

`Tests/LibCrypto/TestHPKE.cpp`:
```cpp
/*
 * RFC 9180 Appendix A.3.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, Base mode.
 */

#include <AK/Hex.h>
#include <LibCrypto/HPKE.h>
#include <LibTest/TestCase.h>

static ByteBuffer hex(StringView text)
{
    return MUST(decode_hex(text));
}

static auto const info = hex("4f6465206f6e2061204772656369616e2055726e"sv);
static auto const ikmE = hex("4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e"sv);
static auto const pkEm = hex("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"sv);
static auto const ikmR = hex("668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550"sv);
static auto const pkRm = hex("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0"sv);
static auto const skRm = hex("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2"sv);
static auto const pt = hex("4265617574792069732074727574682c20747275746820626561757479"sv);
static auto const aad = hex("436f756e742d30"sv);
static auto const ct = hex("5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434"sv);

TEST_CASE(derive_key_pair_matches_pkRm)
{
    auto kp = TRY_OR_FAIL(Crypto::HPKE::derive_key_pair(ikmR));
    EXPECT_EQ(kp.public_key.bytes(), pkRm.bytes());
    EXPECT_EQ(TRY_OR_FAIL(Crypto::Curves::SECPxxxr1Point::scalar_to_bytes(kp.private_key, 32)).bytes(), skRm.bytes());
}

TEST_CASE(seal_reproduces_enc_and_ct_with_vector_ikmE)
{
    auto sealed = TRY_OR_FAIL(Crypto::HPKE::seal(pkRm, info, aad, pt, ikmE.bytes()));
    EXPECT_EQ(sealed.enc.bytes(), pkEm.bytes());
    EXPECT_EQ(sealed.ciphertext.bytes(), ct.bytes());
}

TEST_CASE(open_recovers_vector_plaintext)
{
    auto kp = TRY_OR_FAIL(Crypto::HPKE::derive_key_pair(ikmR));
    auto opened = TRY_OR_FAIL(Crypto::HPKE::open(kp.private_key, pkRm, pkEm, info, aad, ct));
    EXPECT_EQ(opened.bytes(), pt.bytes());
}

TEST_CASE(open_rejects_wrong_aad)
{
    auto kp = TRY_OR_FAIL(Crypto::HPKE::derive_key_pair(ikmR));
    auto wrong_aad = hex("436f756e742d31"sv);
    EXPECT(Crypto::HPKE::open(kp.private_key, pkRm, pkEm, info, wrong_aad, ct).is_error());
}

TEST_CASE(round_trip_with_fresh_keys)
{
    auto kp = TRY_OR_FAIL(Crypto::HPKE::generate_key_pair());
    auto sealed = TRY_OR_FAIL(Crypto::HPKE::seal(kp.public_key, "sealed-input/1"sv.bytes(), "slot"sv.bytes(), "hello"sv.bytes()));
    EXPECT_EQ(sealed.enc.size(), 65u);
    auto opened = TRY_OR_FAIL(Crypto::HPKE::open(kp.private_key, kp.public_key, sealed.enc, "sealed-input/1"sv.bytes(), "slot"sv.bytes(), sealed.ciphertext));
    EXPECT_EQ(opened.bytes(), "hello"sv.bytes());
}
```

Add `TestHPKE.cpp` to `Tests/LibCrypto/CMakeLists.txt` `TEST_SOURCES` (alphabetical, after `TestHMAC.cpp`).

- [ ] **Step 3: Run to verify it fails**

```bash
./Meta/ladybird.py build 2>&1 | tail -5
```
Expected: compile error, `LibCrypto/HPKE.h` not found.

- [ ] **Step 4: Implement**

`Libraries/LibCrypto/HPKE.h`:
```cpp
/*
 * RFC 9180 Hybrid Public Key Encryption, single-shot base mode, one suite:
 * DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM. Used by sealed form fields.
 */

#pragma once

#include <AK/ByteBuffer.h>
#include <AK/Error.h>
#include <AK/Optional.h>
#include <LibCrypto/BigInt/UnsignedBigInteger.h>

namespace Crypto::HPKE {

struct KeyPair {
    UnsignedBigInteger private_key;
    ByteBuffer public_key; // 65-byte uncompressed SEC1 point
};

struct Sealed {
    ByteBuffer enc;        // 65-byte encapsulated ephemeral public key
    ByteBuffer ciphertext; // AEAD ciphertext followed by the 16-byte tag
};

ErrorOr<KeyPair> derive_key_pair(ReadonlyBytes ikm);
ErrorOr<KeyPair> generate_key_pair();

// ephemeral_ikm exists for test vectors only; production callers must not pass it.
ErrorOr<Sealed> seal(ReadonlyBytes recipient_public_key, ReadonlyBytes info, ReadonlyBytes aad, ReadonlyBytes plaintext, Optional<ReadonlyBytes> ephemeral_ikm = {});
ErrorOr<ByteBuffer> open(UnsignedBigInteger const& recipient_private_key, ReadonlyBytes recipient_public_key, ReadonlyBytes enc, ReadonlyBytes info, ReadonlyBytes aad, ReadonlyBytes ciphertext);

}
```

`Libraries/LibCrypto/HPKE.cpp`:
```cpp
#include <AK/Random.h>
#include <LibCrypto/Authentication/HMAC.h>
#include <LibCrypto/Cipher/AES.h>
#include <LibCrypto/Curves/SECPxxxr1.h>
#include <LibCrypto/HPKE.h>
#include <LibCrypto/Hash/HashManager.h>

namespace Crypto::HPKE {

static constexpr size_t Nh = 32;      // HKDF-SHA256 output
static constexpr size_t Nsecret = 32; // DHKEM(P-256) shared secret
static constexpr size_t Nk = 16;      // AES-128-GCM key
static constexpr size_t Nn = 12;      // AES-GCM nonce
static constexpr size_t Nt = 16;      // AES-GCM tag
static constexpr size_t Npk = 65;     // uncompressed P-256 point

// suite_id values from RFC 9180 §4.1 and §5.1: "KEM" || I2OSP(kem_id, 2) and "HPKE" || kem_id || kdf_id || aead_id.
static constexpr u8 kem_suite_id[] = { 'K', 'E', 'M', 0x00, 0x10 };
static constexpr u8 hpke_suite_id[] = { 'H', 'P', 'K', 'E', 0x00, 0x10, 0x00, 0x01, 0x00, 0x01 };
static constexpr u8 version_label[] = { 'H', 'P', 'K', 'E', '-', 'v', '1' };

static ErrorOr<ByteBuffer> concat(std::initializer_list<ReadonlyBytes> parts)
{
    size_t total = 0;
    for (auto part : parts)
        total += part.size();
    auto out = TRY(ByteBuffer::create_uninitialized(total));
    size_t offset = 0;
    for (auto part : parts) {
        out.overwrite(offset, part.data(), part.size());
        offset += part.size();
    }
    return out;
}

// HKDF-Extract(salt, ikm) = HMAC-SHA256(salt, ikm). An empty salt means Nh zero bytes (RFC 5869 §2.2).
static ErrorOr<ByteBuffer> hkdf_extract(ReadonlyBytes salt, ReadonlyBytes ikm)
{
    u8 zeros[Nh] = {};
    Authentication::HMAC hmac(Hash::HashKind::SHA256, salt.is_empty() ? ReadonlyBytes { zeros, Nh } : salt);
    return hmac.process(ikm);
}

// HKDF-Expand(prk, info, L) per RFC 5869 §2.3.
static ErrorOr<ByteBuffer> hkdf_expand(ReadonlyBytes prk, ReadonlyBytes info, size_t length)
{
    auto out = TRY(ByteBuffer::create_uninitialized(0));
    ByteBuffer previous;
    for (u8 counter = 1; out.size() < length; ++counter) {
        Authentication::HMAC hmac(Hash::HashKind::SHA256, prk);
        hmac.update(previous.bytes());
        hmac.update(info);
        hmac.update(ReadonlyBytes { &counter, 1 });
        previous = hmac.digest();
        TRY(out.try_append(previous.bytes()));
    }
    return out.slice(0, length);
}

static ErrorOr<ByteBuffer> labeled_extract(ReadonlyBytes salt, ReadonlyBytes suite_id, StringView label, ReadonlyBytes ikm)
{
    auto labeled_ikm = TRY(concat({ { version_label, sizeof(version_label) }, suite_id, label.bytes(), ikm }));
    return hkdf_extract(salt, labeled_ikm);
}

static ErrorOr<ByteBuffer> labeled_expand(ReadonlyBytes prk, ReadonlyBytes suite_id, StringView label, ReadonlyBytes info, size_t length)
{
    u8 length_bytes[2] = { static_cast<u8>(length >> 8), static_cast<u8>(length & 0xff) };
    auto labeled_info = TRY(concat({ { length_bytes, 2 }, { version_label, sizeof(version_label) }, suite_id, label.bytes(), info }));
    return hkdf_expand(prk, labeled_info, length);
}

static ReadonlyBytes kem_id() { return { kem_suite_id, sizeof(kem_suite_id) }; }
static ReadonlyBytes hpke_id() { return { hpke_suite_id, sizeof(hpke_suite_id) }; }

static UnsignedBigInteger p256_order()
{
    // Group order n of secp256r1.
    return MUST(UnsignedBigInteger::from_base(16, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"sv));
}

// RFC 9180 §7.1.3, DeriveKeyPair for P-256: rejection-sample a scalar in [1, n-1].
ErrorOr<KeyPair> derive_key_pair(ReadonlyBytes ikm)
{
    Curves::SECP256r1 curve;
    auto dkp_prk = TRY(labeled_extract({}, kem_id(), "dkp_prk"sv, ikm));
    auto order = p256_order();
    for (u32 counter = 0; counter < 256; ++counter) {
        u8 counter_byte = static_cast<u8>(counter);
        auto candidate = TRY(labeled_expand(dkp_prk, kem_id(), "candidate"sv, { &counter_byte, 1 }, 32));
        candidate[0] &= 0xff; // bitmask for P-256 is 0xff
        auto scalar = UnsignedBigInteger::import_data(candidate.bytes());
        if (scalar.is_zero() || scalar >= order)
            continue;
        auto point = TRY(curve.generate_public_key(scalar));
        return KeyPair { move(scalar), TRY(point.to_uncompressed()) };
    }
    return Error::from_string_literal("HPKE DeriveKeyPair exhausted 256 candidates");
}

ErrorOr<KeyPair> generate_key_pair()
{
    Curves::SECP256r1 curve;
    auto scalar = TRY(curve.generate_private_key());
    auto point = TRY(curve.generate_public_key(scalar));
    return KeyPair { move(scalar), TRY(point.to_uncompressed()) };
}

// RFC 9180 §4.1 ExtractAndExpand over the DH x-coordinate with kem_context = enc || pkRm.
static ErrorOr<ByteBuffer> kem_shared_secret(Curves::SECPxxxr1Point const& dh, ReadonlyBytes enc, ReadonlyBytes pkRm)
{
    auto dh_bytes = TRY(Curves::SECPxxxr1Point::scalar_to_bytes(dh.x, 32));
    auto eae_prk = TRY(labeled_extract({}, kem_id(), "eae_prk"sv, dh_bytes));
    auto kem_context = TRY(concat({ enc, pkRm }));
    return labeled_expand(eae_prk, kem_id(), "shared_secret"sv, kem_context, Nsecret);
}

struct KeyAndNonce {
    ByteBuffer key;
    ByteBuffer base_nonce;
};

// RFC 9180 §5.1 KeySchedule, mode_base, no PSK, sequence number 0 so nonce == base_nonce.
static ErrorOr<KeyAndNonce> key_schedule(ReadonlyBytes shared_secret, ReadonlyBytes info)
{
    auto psk_id_hash = TRY(labeled_extract({}, hpke_id(), "psk_id_hash"sv, {}));
    auto info_hash = TRY(labeled_extract({}, hpke_id(), "info_hash"sv, info));
    u8 mode_base = 0x00;
    auto key_schedule_context = TRY(concat({ { &mode_base, 1 }, psk_id_hash, info_hash }));
    auto secret = TRY(labeled_extract(shared_secret, hpke_id(), "secret"sv, {}));
    auto key = TRY(labeled_expand(secret, hpke_id(), "key"sv, key_schedule_context, Nk));
    auto base_nonce = TRY(labeled_expand(secret, hpke_id(), "base_nonce"sv, key_schedule_context, Nn));
    return KeyAndNonce { move(key), move(base_nonce) };
}

ErrorOr<Sealed> seal(ReadonlyBytes recipient_public_key, ReadonlyBytes info, ReadonlyBytes aad, ReadonlyBytes plaintext, Optional<ReadonlyBytes> ephemeral_ikm)
{
    if (recipient_public_key.size() != Npk)
        return Error::from_string_literal("HPKE recipient public key must be a 65-byte uncompressed point");
    Curves::SECP256r1 curve;
    auto pkR = TRY(Curves::SECPxxxr1Point::from_uncompressed(recipient_public_key));
    if (!TRY(curve.is_valid_point(pkR)))
        return Error::from_string_literal("HPKE recipient public key is not on P-256");

    auto ephemeral = ephemeral_ikm.has_value() ? TRY(derive_key_pair(*ephemeral_ikm)) : TRY(generate_key_pair());
    auto dh = TRY(curve.compute_coordinate(ephemeral.private_key, pkR));
    auto shared_secret = TRY(kem_shared_secret(dh, ephemeral.public_key, recipient_public_key));
    auto schedule = TRY(key_schedule(shared_secret, info));

    Cipher::AESGCMCipher aead(schedule.key);
    auto encrypted = TRY(aead.encrypt(plaintext, schedule.base_nonce, aad, Nt));
    auto ciphertext = TRY(concat({ encrypted.ciphertext, encrypted.tag }));
    return Sealed { move(ephemeral.public_key), move(ciphertext) };
}

ErrorOr<ByteBuffer> open(UnsignedBigInteger const& recipient_private_key, ReadonlyBytes recipient_public_key, ReadonlyBytes enc, ReadonlyBytes info, ReadonlyBytes aad, ReadonlyBytes ciphertext)
{
    if (enc.size() != Npk || recipient_public_key.size() != Npk)
        return Error::from_string_literal("HPKE enc and recipient public key must be 65-byte uncompressed points");
    if (ciphertext.size() < Nt)
        return Error::from_string_literal("HPKE ciphertext shorter than the tag");
    Curves::SECP256r1 curve;
    auto pkE = TRY(Curves::SECPxxxr1Point::from_uncompressed(enc));
    if (!TRY(curve.is_valid_point(pkE)))
        return Error::from_string_literal("HPKE enc is not on P-256");

    auto dh = TRY(curve.compute_coordinate(recipient_private_key, pkE));
    auto shared_secret = TRY(kem_shared_secret(dh, enc, recipient_public_key));
    auto schedule = TRY(key_schedule(shared_secret, info));

    Cipher::AESGCMCipher aead(schedule.key);
    auto body = ciphertext.slice(0, ciphertext.size() - Nt);
    auto tag = ciphertext.slice(ciphertext.size() - Nt, Nt);
    return aead.decrypt(body, schedule.base_nonce, aad, tag);
}

}
```

Add `HPKE.cpp` to `Libraries/LibCrypto/CMakeLists.txt` sources.

- [ ] **Step 5: Build and run the test**

```bash
./Meta/ladybird.py build 2>&1 | grep -E "error|warning: unused|HPKE" | head -20
./Build/release/bin/TestHPKE
```
Expected: 5 test cases pass. If `UnsignedBigInteger::from_base` or `>=` does not exist under those names, use the nearest real API (`from_base(16, ...)` may be `from_base(StringView, u16)`; comparison may be `operator<`); record the substitution.

- [ ] **Step 6: Commit (engine)**

```bash
git add Libraries/LibCrypto/HPKE.h Libraries/LibCrypto/HPKE.cpp Libraries/LibCrypto/CMakeLists.txt Tests/LibCrypto/TestHPKE.cpp Tests/LibCrypto/CMakeLists.txt
git commit -m "LibCrypto: Add single-suite HPKE (DHKEM P-256, HKDF-SHA256, AES-128-GCM) with RFC 9180 A.3.1 tests"
```

---

### Task 2: `SealedField` core

**Where:** Ladybird checkout.

**Files:**
- Create: `Libraries/LibWeb/HTML/SealedField.h`, `Libraries/LibWeb/HTML/SealedField.cpp`
- Modify: `Libraries/LibWeb/CMakeLists.txt` (add `HTML/SealedField.cpp` after `HTML/SelectedFile.cpp` or alphabetically)
- Modify: `Libraries/LibWeb/Forward.h` (forward-declare `class SealedField;` in `Web::HTML`)

**Interfaces:**
- Consumes: `Crypto::HPKE::seal`; `HTMLInputElement` accessors `document()`, `form()`, `name()`, `get_attribute(...)`, `has_attribute(...)`, `set_custom_validity(Utf16String&)`, `dispatch_event(...)`
- Produces (namespace `Web::HTML`):
  - `class SealedField final : public GC::Cell`
  - `static GC::Ref<SealedField> create(JS::Realm&, HTMLInputElement&)`
  - `static GC::Ptr<SealedField> create_if_policy_applies(JS::Realm&, HTMLInputElement&)`
  - `void start()` (resolves action, checks trustworthiness, fetches the well-known)
  - `void reseal(Utf16View plaintext)`
  - `Utf16String const& envelope() const`
  - `bool is_ready() const`, `bool has_failed() const`
  - `void reset()` (clears envelope and unfreezes constraints)
  - `static bool document_policy_seals_autocomplete_token(DOM::Document const&, Utf16View token)`

- [ ] **Step 1: Write the header**

`Libraries/LibWeb/HTML/SealedField.h`:
```cpp
/*
 * The shared core behind <sealedinput> and the sealed-fields CSP directive: recipient discovery,
 * HPKE sealing, the sealed1 envelope, frozen constraints, and one-bit validity.
 * Behavior is specified by koschei docs/specs/explainer.md.
 */

#pragma once

#include <AK/ByteBuffer.h>
#include <AK/Utf16String.h>
#include <LibGC/CellAllocator.h>
#include <LibGC/Ptr.h>
#include <LibJS/Heap/Cell.h>
#include <LibWeb/Forward.h>

namespace Web::HTML {

class SealedField final : public GC::Cell {
    GC_CELL(SealedField, GC::Cell);
    GC_DECLARE_ALLOCATOR(SealedField);

public:
    static GC::Ref<SealedField> create(JS::Realm&, HTMLInputElement&);
    static GC::Ptr<SealedField> create_if_policy_applies(JS::Realm&, HTMLInputElement&);
    static bool document_policy_seals_autocomplete_token(DOM::Document const&, Utf16View token);

    virtual ~SealedField() override = default;

    void start();
    void reseal(Utf16View plaintext);
    void reset();

    Utf16String const& envelope() const { return m_envelope; }
    bool is_ready() const { return m_ready; }
    bool has_failed() const { return m_failed; }

private:
    SealedField(HTMLInputElement&);
    virtual void visit_edges(Visitor&) override;

    struct Constraints {
        bool required { false };
        Optional<Utf16String> pattern;
        Optional<u32> minlength;
        Optional<u32> maxlength;
    };

    void fail(StringView reason);
    void become_ready(String kid, ByteBuffer recipient_public_key);
    void process_well_known(ReadonlyBytes body);
    void freeze_constraints_if_needed();
    bool constraints_satisfied(Utf16View plaintext) const;
    void update_validity(Utf16View plaintext);

    GC::Ref<HTMLInputElement> m_element;
    GC::Ptr<Fetch::Infrastructure::FetchController> m_fetch_controller;

    String m_kid;
    ByteBuffer m_recipient_public_key;
    ByteBuffer m_slot_aad;
    Utf16String m_envelope;

    bool m_ready { false };
    bool m_failed { false };
    bool m_frozen { false };
    Constraints m_constraints;
};

}
```

- [ ] **Step 2: Write the implementation**

`Libraries/LibWeb/HTML/SealedField.cpp`:
```cpp
#include <AK/Base64.h>
#include <AK/JsonObject.h>
#include <AK/JsonValue.h>
#include <LibCrypto/HPKE.h>
#include <LibRegex/Regex.h>
#include <LibWeb/DOM/CustomEvent.h>
#include <LibWeb/DOM/Document.h>
#include <LibWeb/DOM/Event.h>
#include <LibWeb/Fetch/Fetching/Fetching.h>
#include <LibWeb/Fetch/Infrastructure/FetchAlgorithms.h>
#include <LibWeb/Fetch/Infrastructure/FetchController.h>
#include <LibWeb/Fetch/Infrastructure/HTTP/Requests.h>
#include <LibWeb/Fetch/Infrastructure/HTTP/Responses.h>
#include <LibWeb/HTML/AttributeNames.h>
#include <LibWeb/HTML/HTMLFormElement.h>
#include <LibWeb/HTML/HTMLInputElement.h>
#include <LibWeb/HTML/PolicyContainers.h>
#include <LibWeb/HTML/Scripting/Environments.h>
#include <LibWeb/HTML/SealedField.h>
#include <LibWeb/ContentSecurityPolicy/Policy.h>
#include <LibWeb/ContentSecurityPolicy/PolicyList.h>
#include <LibWeb/ContentSecurityPolicy/Directives/Directive.h>
#include <LibWeb/SecureContexts/AbstractOperations.h>

namespace Web::HTML {

GC_DEFINE_ALLOCATOR(SealedField);

static constexpr StringView envelope_version = "sealed1"sv;
static constexpr StringView hpke_info = "sealed-input/1"sv;
static constexpr StringView well_known_path = "/.well-known/sealed-input"sv;
static constexpr StringView invalid_message = "Please match the requested format."sv;
static constexpr StringView directive_name = "sealed-fields"sv;
static constexpr size_t pad_block = 32;

static bool is_valid_kid(StringView kid)
{
    if (kid.is_empty() || kid.length() > 64)
        return false;
    for (auto ch : kid) {
        if (!(is_ascii_alphanumeric(ch) || ch == '_' || ch == '-'))
            return false;
    }
    return true;
}

GC::Ref<SealedField> SealedField::create(JS::Realm& realm, HTMLInputElement& element)
{
    return realm.create<SealedField>(element);
}

// The sealed-fields directive names autocomplete tokens; an <input> whose autocomplete attribute's last
// token is listed gets a SealedField as if it were a <sealedinput>. Enforced policies only.
bool SealedField::document_policy_seals_autocomplete_token(DOM::Document const& document, Utf16View token)
{
    if (token.is_empty())
        return false;
    for (auto const& policy : document.policy_container()->csp_list->policies()) {
        if (policy->disposition() != ContentSecurityPolicy::Policy::Disposition::Enforce)
            continue;
        auto directive = policy->get_directive_by_name(Utf16View { directive_name });
        if (!directive)
            continue;
        for (auto const& value : directive->value()) {
            if (value.equals_ignoring_ascii_case(token))
                return true;
        }
    }
    return false;
}

GC::Ptr<SealedField> SealedField::create_if_policy_applies(JS::Realm& realm, HTMLInputElement& element)
{
    auto autocomplete = element.get_attribute(AttributeNames::autocomplete);
    if (!autocomplete.has_value())
        return nullptr;
    // autocomplete may carry section/contact tokens before the field name; the field name is last.
    auto tokens = autocomplete->split_view(' ');
    if (tokens.is_empty())
        return nullptr;
    if (!document_policy_seals_autocomplete_token(element.document(), tokens.last()))
        return nullptr;
    return create(realm, element);
}

SealedField::SealedField(HTMLInputElement& element)
    : m_element(element)
{
}

void SealedField::visit_edges(Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_element);
    visitor.visit(m_fetch_controller);
}

void SealedField::fail(StringView reason)
{
    m_failed = true;
    m_ready = false;
    m_envelope = {};
    dbgln("SealedField: {} for field '{}' in {}", reason, m_element->name(), m_element->document().origin().serialize());

    auto& realm = m_element->realm();
    DOM::CustomEventInit init {};
    init.bubbles = true;
    auto detail = JS::Object::create(realm, realm.intrinsics().object_prototype());
    MUST(detail->create_data_property("reason"_fly_string, JS::PrimitiveString::create(realm.vm(), reason)));
    init.detail = detail;
    m_element->dispatch_event(DOM::CustomEvent::create(realm, "sealed-error"_fly_string, init));
}

void SealedField::start()
{
    auto& document = m_element->document();

    // 1. The document must be a secure context; loopback http counts, per the trustworthiness rules.
    if (!SecureContexts::is_url_potentially_trustworthy(document.url()))
        return fail("insecure-context"sv);

    // 2. The owning form and its action decide the recipient origin.
    auto const* form = m_element->form();
    if (!form)
        return fail("no-form-action"sv);
    auto action_attribute = form->get_attribute(AttributeNames::action);
    if (!action_attribute.has_value() || action_attribute->trim_ascii_whitespace().is_empty())
        return fail("no-form-action"sv);
    auto action = document.encoding_parse_url(action_attribute->to_utf8_but_should_be_ported_to_utf16());
    if (!action.has_value())
        return fail("no-form-action"sv);
    if (!SecureContexts::is_url_potentially_trustworthy(*action))
        return fail("insecure-action"sv);

    // 3. The slot binds the envelope to this origin, this action (origin + path), and this field name.
    auto slot = MUST(String::formatted("{}\n{}{}\n{}",
        document.origin().serialize(),
        action->origin().serialize(),
        action->serialize_path(),
        m_element->name().to_utf8_but_should_be_ported_to_utf16()));
    m_slot_aad = MUST(ByteBuffer::copy(slot.bytes()));

    // 4. Fetch the recipient's key set: CORS mode, no credentials, from the action origin.
    auto well_known_url = MUST(URL::Parser::basic_parse(MUST(String::formatted("{}{}", action->origin().serialize(), well_known_path))));
    auto& realm = m_element->realm();
    auto request = Fetch::Infrastructure::Request::create(realm.vm());
    request->set_url(*well_known_url);
    request->set_client(&document.relevant_settings_object());
    request->set_mode(Fetch::Infrastructure::Request::Mode::CORS);
    request->set_credentials_mode(Fetch::Infrastructure::Request::CredentialsMode::Omit);
    request->set_destination(Fetch::Infrastructure::Request::Destination::Empty);

    Fetch::Infrastructure::FetchAlgorithms::Input fetch_algorithms_input {};
    fetch_algorithms_input.process_response_consume_body = [this](auto response, auto body_bytes) {
        m_fetch_controller = nullptr;
        response = response->unsafe_response();
        if (!Fetch::Infrastructure::is_ok_status(response->status()))
            return fail("recipient-unreachable"sv);
        body_bytes.visit(
            [&](ByteBuffer const& bytes) { process_well_known(bytes.bytes()); },
            [&](auto const&) { fail("recipient-unreachable"sv); });
    };
    m_fetch_controller = Fetch::Fetching::fetch(realm, request, Fetch::Infrastructure::FetchAlgorithms::create(realm.vm(), move(fetch_algorithms_input)));
}

// Parse { "keys": [ JWK, ... ] } and import the first usable EC P-256 encryption key.
void SealedField::process_well_known(ReadonlyBytes body)
{
    auto json = JsonValue::from_string(StringView { body });
    if (json.is_error() || !json.value().is_object())
        return fail("recipient-invalid"sv);
    auto keys = json.value().as_object().get_array("keys"sv);
    if (!keys.has_value())
        return fail("recipient-invalid"sv);

    for (auto const& entry : keys->values()) {
        if (!entry.is_object())
            continue;
        auto const& key = entry.as_object();
        if (key.get_string("kty"sv) != "EC"sv || key.get_string("crv"sv) != "P-256"sv || key.get_string("use"sv) != "enc"sv)
            continue;
        auto kid = key.get_string("kid"sv);
        auto x = key.get_string("x"sv);
        auto y = key.get_string("y"sv);
        if (!kid.has_value() || !x.has_value() || !y.has_value() || !is_valid_kid(*kid))
            continue;
        auto x_bytes = decode_base64url(*x);
        auto y_bytes = decode_base64url(*y);
        if (x_bytes.is_error() || y_bytes.is_error() || x_bytes.value().size() != 32 || y_bytes.value().size() != 32)
            continue;
        auto point = MUST(ByteBuffer::create_uninitialized(65));
        point[0] = 0x04;
        point.overwrite(1, x_bytes.value().data(), 32);
        point.overwrite(33, y_bytes.value().data(), 32);
        return become_ready(*kid, move(point));
    }
    fail("recipient-invalid"sv);
}

void SealedField::become_ready(String kid, ByteBuffer recipient_public_key)
{
    m_kid = move(kid);
    m_recipient_public_key = move(recipient_public_key);
    m_ready = true;
    m_failed = false;
    DOM::EventInit init {};
    init.bubbles = true;
    m_element->dispatch_event(DOM::Event::create(m_element->realm(), "sealed-ready"_fly_string, init));
}

void SealedField::freeze_constraints_if_needed()
{
    if (m_frozen)
        return;
    m_frozen = true;
    m_constraints.required = m_element->has_attribute(AttributeNames::required);
    m_constraints.pattern = m_element->get_attribute(AttributeNames::pattern);
    if (auto value = m_element->get_attribute(AttributeNames::minlength); value.has_value())
        m_constraints.minlength = value->to_number<u32>();
    if (auto value = m_element->get_attribute(AttributeNames::maxlength); value.has_value())
        m_constraints.maxlength = value->to_number<u32>();
}

// Same semantics as the polyfill's validateValue: HTML anchors the pattern and compiles it with the
// v flag; a pattern that fails to compile is ignored.
bool SealedField::constraints_satisfied(Utf16View plaintext) const
{
    if (plaintext.is_empty())
        return !m_constraints.required;
    auto length = plaintext.length_in_code_points();
    if (m_constraints.minlength.has_value() && length < *m_constraints.minlength)
        return false;
    if (m_constraints.maxlength.has_value() && length > *m_constraints.maxlength)
        return false;
    if (m_constraints.pattern.has_value()) {
        auto anchored = Utf16String::formatted("^(?:{})$", *m_constraints.pattern);
        Regex<ECMA262> regex(anchored.to_utf8_but_should_be_ported_to_utf16(), ECMAScriptFlags::UnicodeSets);
        if (regex.parser_result.error == regex::Error::NoError && !regex.match(plaintext.to_utf8_but_should_be_ported_to_utf16()).success)
            return false;
    }
    return true;
}

void SealedField::update_validity(Utf16View plaintext)
{
    Utf16String message = constraints_satisfied(plaintext) ? Utf16String {} : Utf16String::from_utf8(invalid_message);
    m_element->set_custom_validity(message);
}

// Plaintext is length-prefixed and zero-padded to 32 bytes so the envelope reveals length only to a bucket.
static ErrorOr<ByteBuffer> pad_plaintext(String const& utf8)
{
    auto bytes = utf8.bytes();
    if (bytes.size() > 0xffff)
        return Error::from_string_literal("sealed value exceeds 65535 bytes");
    auto total = ((2 + bytes.size() + pad_block - 1) / pad_block) * pad_block;
    auto out = TRY(ByteBuffer::create_zeroed(total));
    out[0] = static_cast<u8>(bytes.size() >> 8);
    out[1] = static_cast<u8>(bytes.size() & 0xff);
    out.overwrite(2, bytes.data(), bytes.size());
    return out;
}

void SealedField::reseal(Utf16View plaintext)
{
    if (!m_ready)
        return;
    if (!plaintext.is_empty())
        freeze_constraints_if_needed();
    update_validity(plaintext);
    if (plaintext.is_empty()) {
        m_envelope = {};
        return;
    }
    auto padded = pad_plaintext(plaintext.to_utf8_but_should_be_ported_to_utf16());
    if (padded.is_error())
        return fail("recipient-invalid"sv);
    auto sealed = Crypto::HPKE::seal(m_recipient_public_key, hpke_info.bytes(), m_slot_aad, padded.value());
    if (sealed.is_error())
        return fail("recipient-invalid"sv);
    auto enc = MUST(encode_base64url(sealed.value().enc, AK::OmitPadding::Yes));
    auto ct = MUST(encode_base64url(sealed.value().ciphertext, AK::OmitPadding::Yes));
    m_envelope = Utf16String::from_utf8(MUST(String::formatted("{}.{}.{}.{}", envelope_version, m_kid, enc, ct)));
}

void SealedField::reset()
{
    m_envelope = {};
    m_frozen = false;
    m_constraints = {};
    Utf16String no_message;
    m_element->set_custom_validity(no_message);
}

}
```

Add `HTML/SealedField.cpp` to `Libraries/LibWeb/CMakeLists.txt` and `class SealedField;` to the `Web::HTML` block of `Libraries/LibWeb/Forward.h`.

- [ ] **Step 3: Build**

```bash
./Meta/ladybird.py build 2>&1 | grep -E "error" | head -30
```
Expected: no errors. Likely drift points and their nearest real APIs: `Document::encoding_parse_url` (may be `parse_url`), `DOM::CustomEventInit` field names, `Fetch::Infrastructure::FetchAlgorithms::create` signature (`create(vm, input)` vs `create(input)`), `Utf16View::to_number<u32>`, `Regex<ECMA262>` constructor (may take `ByteString`), `String::formatted` on `Utf16String`. Fix each to the real name; keep the behavior.

- [ ] **Step 4: Commit (engine)**

```bash
git add Libraries/LibWeb/HTML/SealedField.h Libraries/LibWeb/HTML/SealedField.cpp Libraries/LibWeb/CMakeLists.txt Libraries/LibWeb/Forward.h
git commit -m "LibWeb: Add SealedField, the shared core for sealed form fields"
```

No test in this task; Tasks 3 and 4 exercise it end to end through `<sealedinput>`.

---

### Task 3: Hooks in `HTMLInputElement`, the text-control selection API, and the event handler

**Where:** Ladybird checkout.

**Files:**
- Modify: `Libraries/LibWeb/HTML/HTMLInputElement.h` (`final` removed; constructor `protected`; member; three accessors)
- Modify: `Libraries/LibWeb/HTML/HTMLInputElement.cpp` (guards listed below; `visit_edges`)
- Modify: `Libraries/LibWeb/HTML/FormAssociatedElement.h` and `.cpp` (`virtual bool is_sealed_text_control() const { return false; }` on `FormAssociatedTextControlElement`; guards in `select`, `selection_start`, `selection_end`, `set_selection_range`, `set_range_text`)
- Modify: `Libraries/LibWeb/Page/EventHandler.cpp` (guard in `fire_keyboard_event`; guard before `handle_insert`)

**Interfaces:**
- Consumes: `SealedField` from Task 2
- Produces: `HTMLInputElement::sealed_field() const -> GC::Ptr<SealedField>`; `HTMLInputElement::attach_sealed_field()` (protected; used by Task 4's subclass); `FormAssociatedTextControlElement::is_sealed_text_control()`

- [ ] **Step 1: Header changes**

In `HTMLInputElement.h`: change `class WEB_API HTMLInputElement final` to `class WEB_API HTMLInputElement`; move the constructor declaration `HTMLInputElement(DOM::Document&, DOM::QualifiedName);` from `private:` to a `protected:` section together with a new `void attach_sealed_field();`; add under `public:`:
```cpp
    GC::Ptr<SealedField> sealed_field() const { return m_sealed_field; }
    virtual bool is_sealed_text_control() const override { return !!m_sealed_field; }
```
and under `private:` members:
```cpp
    GC::Ptr<SealedField> m_sealed_field;
```
Include `<LibWeb/HTML/SealedField.h>` in the `.cpp`, forward-declare via `Forward.h` in the header.

- [ ] **Step 2: Guards in `HTMLInputElement.cpp`**

Each is a one- or two-line insertion; comments name the explainer row.

`visit_edges`: `visitor.visit(m_sealed_field);`

`value()` (`:708`), first line of the function:
```cpp
    // Sealed fields expose the envelope, never the plaintext (explainer: Element surface, value getter).
    if (m_sealed_field)
        return m_sealed_field->envelope();
```

`set_value(Utf16View)` (`:784`), first line:
```cpp
    // Seeding a value is a read in disguise (explainer: value setter throws).
    if (m_sealed_field)
        return WebIDL::InvalidStateError::create(realm(), "A sealed field's value cannot be set by script"_string);
```

`did_edit_text_node` (`:606`): before `user_interaction_did_change_input_value(input_type, data);`:
```cpp
    if (m_sealed_field) {
        // Re-seal every edit; input events carry no data for sealed fields.
        m_sealed_field->reseal(m_value);
        user_interaction_did_change_input_value(input_type, {});
        return;
    }
```

`beforeinput`: grep `FormAssociatedElement.cpp` and `HTMLInputElement.cpp` for `beforeinput`. Wherever a `beforeinput` `InputEvent` is created for a text control, pass an empty `data` when `is_sealed_text_control()` is true, with the comment `// Sealed fields never hand typed text to script.` If no `beforeinput` dispatch exists at `1010a932`, say so in the report; the keyboard guard in Step 4 already covers `keydown`/`keyup`/`keypress`.

`form_associated_element_was_inserted()` (`:2244`), at the end:
```cpp
    // The sealed-fields CSP directive can turn an ordinary <input> into a sealed field by autocomplete token.
    if (!m_sealed_field) {
        if (auto sealed = SealedField::create_if_policy_applies(realm(), *this))
            m_sealed_field = sealed;
    }
    if (m_sealed_field && !m_sealed_field->is_ready() && !m_sealed_field->has_failed())
        m_sealed_field->start();
```

New protected method:
```cpp
void HTMLInputElement::attach_sealed_field()
{
    m_sealed_field = SealedField::create(realm(), *this);
}
```

`form_associated_element_was_removed(DOM::Node*)`: add at the end `if (m_sealed_field) m_sealed_field->reset();` (a removed field starts over on reinsertion; `start()` runs again from the insertion hook because `is_ready()` is preserved, so reset only clears the envelope and constraints).

`reset_algorithm()` (the form reset path; find `void HTMLInputElement::reset_algorithm()`): add `if (m_sealed_field) m_sealed_field->reset();` after the value is cleared.

Validity, each existing override gets a first line `if (m_sealed_field) return false;`: `suffering_from_being_missing`, `suffering_from_a_type_mismatch`, `suffering_from_a_pattern_mismatch`, `suffering_from_an_underflow`, `suffering_from_an_overflow`, `suffering_from_a_step_mismatch`, `suffering_from_bad_input`. Add overrides for `suffering_from_being_too_long` and `suffering_from_being_too_short` that return `false` when sealed and otherwise call the base. The one bit is `customError`, set by `SealedField::update_validity`.

- [ ] **Step 3: Selection API guards in `FormAssociatedElement.cpp`**

In `FormAssociatedTextControlElement::select()`, `set_selection_range(...)`, and both `set_range_text(...)` overloads, first line: `if (is_sealed_text_control()) return {};`. In `selection_start()` and `selection_end()`: `if (is_sealed_text_control()) return 0;`. In `selection_start_binding()` / `selection_end_binding()`: `if (is_sealed_text_control()) return 0u;` (they return `Optional<UnsignedLong>`).

- [ ] **Step 4: Event handler guards in `EventHandler.cpp`**

Add a file-local helper near the top:
```cpp
// A sealed <input> (see HTML::SealedField) keeps keystrokes away from script: keyboard events are not
// dispatched to the page, and typing is ignored until the recipient key has arrived.
static HTML::HTMLInputElement* sealed_input_for(DOM::Node& node)
{
    auto* input = as_if<HTML::HTMLInputElement>(node);
    if (input && input->sealed_field())
        return input;
    return nullptr;
}
```

In `fire_keyboard_event` (`:2120`), inside `if (GC::Ptr focused_area = document->focused_area())` after the `NavigableContainer` block and before the event is created:
```cpp
        if (auto* sealed = sealed_input_for(*focused_area)) {
            (void)sealed;
            return EventResult::Accepted; // default action proceeds; script never sees the key
        }
```

In `handle_keydown`, immediately before each `target->handle_insert(...)` call (`:1462` and `:1471`), guard on readiness. `target` is an `InputEventsTarget&`; resolve it through the text-control mixin:
```cpp
            if (auto* text_control = as_if<HTML::FormAssociatedTextControlElement>(*target)) {
                if (auto* sealed = sealed_input_for(text_control->form_associated_element_to_html_element()); sealed && !sealed->sealed_field()->is_ready())
                    return EventResult::Handled;
            }
```
If `as_if` cannot cast an `InputEventsTarget` to the mixin, use the existing `is<HTML::FormAssociatedTextControlElement>(target)` check the file already performs at `:1400` and `static_cast` after it.

- [ ] **Step 5: Build**

```bash
./Meta/ladybird.py build 2>&1 | grep -E "error" | head -30
```
Expected: clean. Then a quick smoke that nothing regressed for ordinary inputs:
```bash
./Build/release/bin/test-web --test-path Tests/LibWeb --filter "*input*" 2>&1 | tail -5
```
Expected: same pass count as before the change (run the same command on `1010a932` first if you need the baseline; record both numbers).

- [ ] **Step 6: Commit (engine)**

```bash
git add Libraries/LibWeb/HTML/HTMLInputElement.h Libraries/LibWeb/HTML/HTMLInputElement.cpp Libraries/LibWeb/HTML/FormAssociatedElement.h Libraries/LibWeb/HTML/FormAssociatedElement.cpp Libraries/LibWeb/Page/EventHandler.cpp
git commit -m "LibWeb: Route sealed inputs through SealedField (value, events, selection, validity)"
```

---

### Task 4: `<sealedinput>` element and Text tests

**Where:** Ladybird checkout.

**Files:**
- Create: `Libraries/LibWeb/HTML/HTMLSealedInputElement.h`, `.cpp`, `.idl`
- Modify: `Libraries/LibWeb/HTML/TagNames.h` (add `__ENUMERATE_HTML_TAG(sealedinput, "sealedinput")` alphabetically)
- Modify: `Libraries/LibWeb/DOM/ElementFactory.cpp` (interface-name switch at `:216` gets `if (html_element_interface_name == Utf16View { "HTMLSealedInputElement"sv }) return FixedArray<Utf16FlyString>::create({ HTML::TagNames::sealedinput });` and the registration list gets `REGISTER_HTML_ELEMENT(sealedinput, HTMLSealedInputElement);`; include the header)
- Modify: `Libraries/LibWeb/idl_files.cmake` (add `libweb_js_bindings(HTML/HTMLSealedInputElement)` after `HTML/HTMLScriptElement`)
- Modify: `Libraries/LibWeb/CMakeLists.txt` (add `HTML/HTMLSealedInputElement.cpp`)
- Create: `Tests/LibWeb/Text/input/wpt-import/.well-known/sealed-input` and `sealed-input.headers` (fixture; served by the echo server at the origin root)
- Create: `Tests/LibWeb/Text/input/HTML/sealedinput-envelope.html`, `.html.headers`, and `Tests/LibWeb/Text/expected/HTML/sealedinput-envelope.txt`
- Create: `Tests/LibWeb/Text/input/HTML/sealed-fields-directive.html`, `.html.headers`, and `Tests/LibWeb/Text/expected/HTML/sealed-fields-directive.txt`

**Interfaces:**
- Consumes: `HTMLInputElement::attach_sealed_field()` (Task 3)
- Produces: `Web::HTML::HTMLSealedInputElement`, IDL `interface HTMLSealedInputElement : HTMLInputElement`

- [ ] **Step 1: Element**

`HTMLSealedInputElement.h`:
```cpp
/*
 * <sealedinput>: an input whose value is always sealed. Non-void; authors write </sealedinput>.
 */

#pragma once

#include <LibWeb/HTML/HTMLInputElement.h>

namespace Web::HTML {

class HTMLSealedInputElement final : public HTMLInputElement {
    WEB_WRAPPABLE(HTMLSealedInputElement, HTMLInputElement);
    GC_DECLARE_ALLOCATOR(HTMLSealedInputElement);

public:
    virtual ~HTMLSealedInputElement() override;

private:
    HTMLSealedInputElement(DOM::Document&, DOM::QualifiedName);
    virtual void initialize(JS::Realm&) override;
    virtual void form_associated_element_was_inserted() override;
};

}
```

`HTMLSealedInputElement.cpp`:
```cpp
#include <LibWeb/Bindings/HTMLSealedInputElementPrototype.h>
#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/HTML/HTMLSealedInputElement.h>
#include <LibWeb/HTML/SealedField.h>

namespace Web::HTML {

GC_DEFINE_ALLOCATOR(HTMLSealedInputElement);

HTMLSealedInputElement::HTMLSealedInputElement(DOM::Document& document, DOM::QualifiedName qualified_name)
    : HTMLInputElement(document, move(qualified_name))
{
}

HTMLSealedInputElement::~HTMLSealedInputElement() = default;

void HTMLSealedInputElement::initialize(JS::Realm& realm)
{
    WEB_SET_PROTOTYPE_FOR_INTERFACE(HTMLSealedInputElement);
    Base::initialize(realm);
}

void HTMLSealedInputElement::form_associated_element_was_inserted()
{
    if (!sealed_field())
        attach_sealed_field();
    // The base hook starts the SealedField when it is present and not yet ready.
    HTMLInputElement::form_associated_element_was_inserted();
}

}
```

`HTMLSealedInputElement.idl`:
```
#import <HTML/HTMLInputElement.idl>

// A sealed form field: value is HPKE-sealed to the form action's published key; script sees only the envelope.
// Proposal: koschei docs/specs/explainer.md
[Exposed=Window]
interface HTMLSealedInputElement : HTMLInputElement {
    [HTMLConstructor] constructor();
};
```

If `HTMLInputElement::initialize` is `private` and `Base::initialize` will not compile from the subclass, make it `protected` in the header (one-word change) and note it.

- [ ] **Step 2: Fixture well-known**

`Tests/LibWeb/Text/input/wpt-import/.well-known/sealed-input` (the RFC 9180 A.3.1 recipient key, so any envelope can be opened offline with `skRm` if ever needed):
```json
{
  "frame": "/unused-natively",
  "keys": [
    { "kid": "rfc-a3-1", "kty": "EC", "crv": "P-256", "use": "enc",
      "x": "_owZzgkFGR68KYqSRXklMfJvDOziRgY56Lw5y39waoI",
      "y": "anebTPlpuKDlOcf2L7PTCtaqj4DjDx0Siq_WiiznLqA" }
  ]
}
```
`Tests/LibWeb/Text/input/wpt-import/.well-known/sealed-input.headers`:
```
Content-Type: application/json
Access-Control-Allow-Origin: *
```

- [ ] **Step 3: Element Text test**

`Tests/LibWeb/Text/input/HTML/sealedinput-envelope.html.headers` (its presence makes the runner serve the test over HTTP from a unique `*.localhost` origin, which is potentially trustworthy):
```
X-Koschei-Test: serve-over-http
```

`Tests/LibWeb/Text/input/HTML/sealedinput-envelope.html`:
```html
<!DOCTYPE html>
<form action="/submit" method="post">
    <input name="plain" value="typed-plaintext">
    <sealedinput name="ssn" required pattern="\d{3}-?\d{2}-?\d{4}"></sealedinput>
</form>
<script src="../include.js"></script>
<script>
    promiseTest(async () => {
        const form = document.forms[0];
        const el = form.querySelector("sealedinput");
        println(`constructor=${el.constructor.name}`);
        println(`is-form-control=${form.elements.namedItem("ssn") === el}`);

        await new Promise(resolve => el.addEventListener("sealed-ready", resolve, { once: true }));
        println("sealed-ready fired");

        let keydowns = 0;
        el.addEventListener("keydown", () => keydowns++);
        let inputData = "unset";
        el.addEventListener("input", e => { inputData = e.data; });

        el.focus();
        internals.sendText(el, "123-45-6789");

        const envelope = el.value;
        println(`value-prefix=${envelope.startsWith("sealed1.rfc-a3-1.")}`);
        println(`value-parts=${envelope.split(".").length}`);
        println(`value-leaks-digits=${envelope.includes("6789")}`);
        println(`formdata-equals-value=${new FormData(form).get("ssn") === envelope}`);
        println(`plain-still-plain=${new FormData(form).get("plain")}`);
        println(`keydowns-seen-by-script=${keydowns}`);
        println(`input-data=${inputData}`);
        println(`selectionStart=${el.selectionStart} selectionEnd=${el.selectionEnd}`);
        println(`valid=${el.checkValidity()} patternMismatch=${el.validity.patternMismatch} customError=${el.validity.customError}`);

        el.setAttribute("pattern", "^9.*");
        internals.sendKey(el, "Backspace");
        internals.sendText(el, "9");
        println(`valid-after-pattern-change-and-retype=${el.checkValidity()}`);
        println(`value-changed-after-retype=${el.value !== envelope}`);

        try {
            el.value = "x";
            println("setter-threw=false");
        } catch (e) {
            println(`setter-threw=${e.name}`);
        }

        form.reset();
        println(`value-after-reset=${JSON.stringify(el.value)} valid-after-reset=${el.checkValidity()}`);
    });
</script>
```

`Tests/LibWeb/Text/expected/HTML/sealedinput-envelope.txt`:
```
constructor=HTMLSealedInputElement
is-form-control=true
sealed-ready fired
value-prefix=true
value-parts=4
value-leaks-digits=false
formdata-equals-value=true
plain-still-plain=typed-plaintext
keydowns-seen-by-script=0
input-data=null
selectionStart=0 selectionEnd=0
valid=true patternMismatch=false customError=false
valid-after-pattern-change-and-retype=true
value-changed-after-retype=true
setter-threw=InvalidStateError
value-after-reset="" valid-after-reset=false
```

- [ ] **Step 4: Directive Text test**

`Tests/LibWeb/Text/input/HTML/sealed-fields-directive.html.headers`:
```
Content-Security-Policy: sealed-fields cc-number
```

`Tests/LibWeb/Text/input/HTML/sealed-fields-directive.html`:
```html
<!DOCTYPE html>
<form action="/submit" method="post">
    <input name="card" autocomplete="cc-number">
    <input name="memo" autocomplete="off">
</form>
<script src="../include.js"></script>
<script>
    promiseTest(async () => {
        const form = document.forms[0];
        const card = form.elements.namedItem("card");
        const memo = form.elements.namedItem("memo");
        println(`card-constructor=${card.constructor.name}`);

        await new Promise(resolve => card.addEventListener("sealed-ready", resolve, { once: true }));
        println("sealed-ready fired on the policy-sealed input");

        card.focus();
        internals.sendText(card, "4111111111111111");
        memo.focus();
        internals.sendText(memo, "gift");

        println(`card-value-prefix=${card.value.startsWith("sealed1.rfc-a3-1.")}`);
        println(`card-leaks=${card.value.includes("4111")}`);
        println(`memo-plain=${memo.value}`);
        println(`formdata-card-equals-value=${new FormData(form).get("card") === card.value}`);
        try {
            card.value = "x";
            println("card-setter-threw=false");
        } catch (e) {
            println(`card-setter-threw=${e.name}`);
        }
        memo.value = "ok";
        println(`memo-setter-works=${memo.value}`);
    });
</script>
```

`Tests/LibWeb/Text/expected/HTML/sealed-fields-directive.txt`:
```
card-constructor=HTMLInputElement
sealed-ready fired on the policy-sealed input
card-value-prefix=true
card-leaks=false
memo-plain=gift
formdata-card-equals-value=true
card-setter-threw=InvalidStateError
memo-setter-works=ok
```

- [ ] **Step 5: Build and run the two tests**

```bash
./Meta/ladybird.py build 2>&1 | grep -E "error" | head -30
./Build/release/bin/test-web --test-path Tests/LibWeb --filter "*sealed*" --verbose 2>&1 | tail -25
```
Expected: 2 passed. If the actual output differs only in a line you can justify from engine behavior (for example `input-data=null` printing as `input-data=` because `e.data` is `""` rather than `null`), fix the engine to match the expected file, not the other way round: the expected file is the spec. Two exceptions are allowed and must be reported: `keydowns-seen-by-script` may be `0` for a reason other than the guard if `internals.sendText` bypasses `fire_keyboard_event`; confirm by temporarily removing the guard and observing the count, then restore it. The `.well-known` fetch is same-origin from the test's point of view but still CORS mode; if the runner's static handler rejects the dotfile directory, move the fixture to `wpt-import/well-known-sealed-input/` and add a one-line rewrite in `Tests/LibWeb/Fixtures/http-test-server.py` `_request_target` mapping `/.well-known/sealed-input` to it, and report that.

- [ ] **Step 6: Run the broader Text suites once**

```bash
./Build/release/bin/test-web --test-path Tests/LibWeb --filter "*input*" 2>&1 | tail -3
./Build/release/bin/test-web --test-path Tests/LibWeb --filter "*form*" 2>&1 | tail -3
```
Expected: no new failures against the baseline recorded in Task 3.

- [ ] **Step 7: Commit (engine)**

```bash
git add Libraries/LibWeb/HTML/HTMLSealedInputElement.h Libraries/LibWeb/HTML/HTMLSealedInputElement.cpp Libraries/LibWeb/HTML/HTMLSealedInputElement.idl Libraries/LibWeb/HTML/TagNames.h Libraries/LibWeb/DOM/ElementFactory.cpp Libraries/LibWeb/idl_files.cmake Libraries/LibWeb/CMakeLists.txt Tests/LibWeb/Text/input/wpt-import/.well-known Tests/LibWeb/Text/input/HTML/sealedinput-envelope.html Tests/LibWeb/Text/input/HTML/sealedinput-envelope.html.headers Tests/LibWeb/Text/expected/HTML/sealedinput-envelope.txt Tests/LibWeb/Text/input/HTML/sealed-fields-directive.html Tests/LibWeb/Text/input/HTML/sealed-fields-directive.html.headers Tests/LibWeb/Text/expected/HTML/sealed-fields-directive.txt
git commit -m "LibWeb: Add <sealedinput> and the sealed-fields CSP directive, with Text tests"
```

---

### Task 5: Demo routes, scripts, and the exported patch series

**Where:** koschei worktree (`native-ladybird-demo`), after confirming PR #1 is merged and rebasing onto `origin/main`.

**Files:**
- Create: `native/ladybird/README.md`, `native/ladybird/apply-and-build.sh`, `native/ladybird/run-demo.sh`
- Create: `native/ladybird/0001-*.patch` … `0004-*.patch` (exported from the engine branch)
- Create: `demo/native.html`, `demo/native.js`
- Modify: `demo/serve.ts` (routes `/native`, `/native-directive`, `/native.js`; CSP for the directive page)

**Interfaces:**
- Consumes: `startServers`, `renderPage`-style helpers, and `pageCsp` in `demo/serve.ts` from PR #1; `POST /enroll` accepting a dynamic field name
- Produces: `GET /native` (page with `<sealedinput name="ssn">`), `GET /native-directive` (page with `<input name="card" autocomplete="cc-number">` and CSP `sealed-fields cc-number`), `GET /native.js`

- [ ] **Step 1: Precondition**

```bash
cd <koschei worktree native-ladybird-demo>
git fetch origin && git log --oneline origin/main | head -3      # must include the polyfill commits
git rebase origin/main
ls demo/serve.ts                                                  # must exist
```
If `demo/serve.ts` is absent, stop and report BLOCKED: PR #1 is not merged.

- [ ] **Step 2: Export the patch series**

```bash
mkdir -p native/ladybird
git -C "$LADYBIRD_DIR" format-patch 1010a932..koschei-sealedinput -o "$(pwd)/native/ladybird"
ls native/ladybird/*.patch      # expect 4 files
```

- [ ] **Step 3: Scripts**

`native/ladybird/apply-and-build.sh`:
```bash
#!/usr/bin/env bash
# Apply the koschei patch series to a Ladybird checkout pinned at 1010a932 and build it.
# Usage: LADYBIRD_DIR=/path/to/ladybird native/ladybird/apply-and-build.sh
set -euo pipefail
: "${LADYBIRD_DIR:?set LADYBIRD_DIR to a Ladybird checkout}"
here="$(cd "$(dirname "$0")" && pwd)"
cd "$LADYBIRD_DIR"
if [ "$(git rev-parse HEAD)" != "$(git rev-parse 1010a932^{commit})" ]; then
  echo "expected HEAD at 1010a932; got $(git rev-parse --short HEAD). Check out 1010a932 first." >&2
  exit 1
fi
git checkout -q -b koschei-sealedinput
git am "$here"/*.patch
export PATH="/opt/homebrew/opt/rustup/bin:/opt/homebrew/opt/ccache/libexec:/opt/homebrew/bin:$PATH"
./Meta/ladybird.py build
./Build/release/bin/TestHPKE
./Build/release/bin/test-web --test-path Tests/LibWeb --filter "*sealed*"
```

`native/ladybird/run-demo.sh`:
```bash
#!/usr/bin/env bash
# Run the koschei demo recipient and page, drive Ladybird headless at /native and /native-directive,
# and save screenshots. The proof is the recipient's `sealed-input.unseal` log lines on stderr.
# Usage: LADYBIRD_DIR=/path/to/ladybird native/ladybird/run-demo.sh
set -euo pipefail
: "${LADYBIRD_DIR:?set LADYBIRD_DIR to a built Ladybird checkout}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="${OUT_DIR:-$root/docs/research/assets}"
mkdir -p "$out"
cd "$root"
npm run build >/dev/null
node demo/serve.ts 2> "$out/native-demo.log" &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT
sleep 1
bin="$LADYBIRD_DIR/Build/release/bin/Ladybird.app/Contents/MacOS/Ladybird"
[ -x "$bin" ] || bin="$LADYBIRD_DIR/Build/release/bin/Ladybird"
for page in native native-directive; do
  timeout 60 "$bin" --headless=screenshot --screenshot-delay 5 --temporary-profile --expose-internals-object \
    --window-width 720 --window-height 320 --screenshot-path "$out/ladybird-$page.png" "http://localhost:4780/$page"
done
echo "--- unseal outcomes ---"
grep -o '"event":"sealed-input.unseal","outcome":"[a-z-]*"' "$out/native-demo.log" || { echo "no unseal events logged" >&2; exit 1; }
grep -q '"outcome":"ok"' "$out/native-demo.log"
```
`chmod +x` both.

- [ ] **Step 4: Demo page and routes**

`demo/native.html` (uses the same `__RECIPIENT__` and `__EXTRA_ATTRS__` placeholders as `index.html`, plus `__FIELD__` for the field markup and `__NAME__` for its name):
```html
<!doctype html>
<html lang="en">
<meta charset="utf-8">
<title>sealed-input native demo</title>
<style>
  body { font: 16px system-ui, sans-serif; max-width: 40rem; margin: 2rem auto; padding: 0 1rem; }
  label { display: block; margin: 1rem 0 .25rem; }
  input, sealedinput { width: 24ch; }
  pre { background: #f4f4f4; padding: .75rem; overflow: auto; }
</style>
<body>
<h1>native sealed field</h1>
<form id="enroll" method="post" action="__RECIPIENT__/enroll">
  <label>Full name <input name="name" autocomplete="name" required value="Ada Lovelace"></label>
  <label>Sensitive value __FIELD__</label>
  <button>Enroll</button>
</form>
<h2>What page script can see</h2>
<pre id="observed">waiting…</pre>
<h2>Server response</h2>
<pre id="response">not submitted</pre>
<script src="/native.js" data-field="__NAME__"></script>
</body>
</html>
```

`demo/native.js`:
```js
// Drives the native page: when Ladybird exposes `internals`, types a fixed value and submits, so a
// headless run produces an unseal log line on the recipient without a human at the keyboard.
const fieldName = document.currentScript.dataset.field;
const form = document.getElementById('enroll');
const field = form.elements.namedItem(fieldName);
const observed = document.getElementById('observed');
const responseBox = document.getElementById('response');
const TYPED = fieldName === 'card' ? '4111111111111111' : '123-45-6789';

function render(state) {
  observed.textContent = [
    `constructor = ${field.constructor.name}`,
    `${fieldName}.value = ${JSON.stringify(field.value)}`,
    `FormData.get('${fieldName}') = ${JSON.stringify(new FormData(form).get(fieldName))}`,
    `checkValidity() = ${form.checkValidity()}`,
    `state: ${state}`,
  ].join('\n');
}

async function submit() {
  const body = new URLSearchParams(new FormData(form));
  const response = await fetch(form.action, { method: 'POST', body });
  responseBox.textContent = `${response.status} ${await response.text()}`;
}

field.addEventListener('sealed-error', (event) => render(`error (${event.detail.reason})`));
field.addEventListener('sealed-ready', async () => {
  render('ready');
  if (!globalThis.internals) return;
  field.focus();
  internals.sendText(field, TYPED);
  render('typed via internals');
  await submit();
});
form.addEventListener('submit', (event) => { event.preventDefault(); void submit(); });
```

In `demo/serve.ts`, add to the page server (next to `/`):
```ts
      if (url.pathname === '/native') {
        const html = (await readFile(join(here, 'native.html'), 'utf8'))
          .replaceAll('__RECIPIENT__', recipientOrigin)
          .replaceAll('__FIELD__', '<sealedinput name="ssn" required inputmode="numeric" pattern="\\d{3}-?\\d{2}-?\\d{4}"></sealedinput>')
          .replaceAll('__NAME__', 'ssn');
        return send(response, 200, html, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': pageCsp(recipientOrigin) });
      }
      if (url.pathname === '/native-directive') {
        const html = (await readFile(join(here, 'native.html'), 'utf8'))
          .replaceAll('__RECIPIENT__', recipientOrigin)
          .replaceAll('__FIELD__', '<input name="card" autocomplete="cc-number" inputmode="numeric">')
          .replaceAll('__NAME__', 'card');
        return send(response, 200, html, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': `${pageCsp(recipientOrigin)}; sealed-fields cc-number` });
      }
      if (url.pathname === '/native.js') return send(response, 200, await readFile(join(here, 'native.js')), { 'Content-Type': 'text/javascript' });
```
`/enroll` already accepts `card` as the field name (PR #1's dynamic detection).

- [ ] **Step 5: Verify the repo side without Ladybird**

```bash
npm run typecheck; echo "typecheck exit=$?"
npm test; echo "unit exit=$?"
npm run demo & sleep 1; curl -s -o /dev/null -w '%{http_code}\n' http://localhost:4780/native; curl -s -D - -o /dev/null http://localhost:4780/native-directive | grep -i 'sealed-fields'; kill %1
```
Expected: `exit=0` twice, `200`, and a CSP header line containing `sealed-fields cc-number`.

- [ ] **Step 6: `native/ladybird/README.md`**

```markdown
# Native `<sealedinput>` for Ladybird

Patch series against Ladybird `1010a932`. See `docs/specs/native-ladybird-design.md`.

    LADYBIRD_DIR=~/code/scratch/ladybird native/ladybird/apply-and-build.sh   # ~1 h cold, minutes warm
    LADYBIRD_DIR=~/code/scratch/ladybird native/ladybird/run-demo.sh          # writes docs/research/assets/ladybird-*.png and native-demo.log

`run-demo.sh` exits non-zero unless the recipient logged at least one `sealed-input.unseal` with `outcome: ok`.
```

- [ ] **Step 7: Commit (repo)**

```bash
git add native/ demo/native.html demo/native.js demo/serve.ts
git commit -m "feat: native Ladybird demo routes, patch series, and apply/run scripts"
```

---

### Task 6: Proof run and write-up

**Where:** both. Engine must be built with the series applied (it is, on `koschei-sealedinput`).

**Files:**
- Create: `docs/research/assets/ladybird-native.png`, `docs/research/assets/ladybird-native-directive.png`, `docs/research/assets/native-demo.log` (scrubbed: keep only `sealed-input.unseal` and `demo.listening` lines)
- Modify: `docs/research/native-feasibility-ladybird.md` (Results section), `docs/specs/native-ladybird-design.md` (decision 6 revised: directive is Text-testable via `.headers`), `README.md` (one paragraph pointing at `native/ladybird/`)

- [ ] **Step 1: Run the proof**

```bash
LADYBIRD_DIR="$LADYBIRD_DIR" native/ladybird/run-demo.sh; echo "proof exit=$?"
```
Expected: two PNGs written, `--- unseal outcomes ---` followed by at least two `"outcome":"ok"` lines (one per page), `exit=0`. If `/native-directive` yields no unseal line, check the page's CSP header reached the document (`internals` can dump it: add a temporary `println(document.policyContainer)` is not available; instead confirm with `curl -D -`) and that `autocomplete="cc-number"` is the last token.

- [ ] **Step 2: Scrub the log and view the screenshots**

```bash
grep -E '"event":"(sealed-input.unseal|demo.listening)"' docs/research/assets/native-demo.log > /tmp/scrubbed && mv /tmp/scrubbed docs/research/assets/native-demo.log
```
Open both PNGs and confirm the `#observed` block shows a `sealed1.` value and the response block shows `200 {"ok":true,"last4":...}`.

- [ ] **Step 3: Write results into the memo**

Append to `docs/research/native-feasibility-ladybird.md`:
```markdown
## Results

Patch series `native/ladybird/0001..0004` against `1010a932`. `TestHPKE` reproduces RFC 9180
A.3.1 `enc` and `ct` from the vector `ikmE` and opens the vector ciphertext. Two Ladybird Text
tests pass under `test-web`: `sealedinput-envelope` (element path) and
`sealed-fields-directive` (header-delivered CSP, served by the echo server). The koschei demo
recipient opened envelopes produced by Ladybird for both `/native` and `/native-directive`:

    <paste the two `sealed-input.unseal` ... "outcome":"ok" lines from assets/native-demo.log>

Screenshots: `assets/ladybird-native.png`, `assets/ladybird-native-directive.png`. Compare with
`assets/ladybird-sealedinput-unknown.png` (before).

Deviations from the explainer that a native implementer should know: the field is not `disabled`
while waiting for the key; it ignores insertions instead. `<sealedinput>` is non-void. Renderer
memory still holds the plaintext (see Beyond v1).
```

Revise design decision 6 in `docs/specs/native-ladybird-design.md` to: "Both paths are covered by Ladybird Text tests: the runner serves any test with a `.headers` sidecar over HTTP from its echo server, so the directive test carries a real `Content-Security-Policy` header. The HTTP run against the demo remains the cross-client proof."

Add to `README.md` under the status paragraph: "A native implementation for Ladybird lives in `native/ladybird/` as a patch series; `docs/research/native-feasibility-ladybird.md` has the results."

- [ ] **Step 4: Final verification**

```bash
npm run typecheck; echo "typecheck exit=$?"
npm test; echo "unit exit=$?"
git status --short          # only the intended files
```
Then in the engine checkout:
```bash
git -C "$LADYBIRD_DIR" format-patch 1010a932..koschei-sealedinput --stdout | diff -q - <(cat native/ladybird/*.patch) && echo "patch series matches engine branch"
```
If the engine branch gained fix-up commits during Tasks 5 and 6, re-export the series (`rm native/ladybird/*.patch` then Task 5 Step 2) so the repo carries what actually ran.

- [ ] **Step 5: Commit (repo)**

```bash
git add docs/research/native-feasibility-ladybird.md docs/research/assets/ladybird-native.png docs/research/assets/ladybird-native-directive.png docs/research/assets/native-demo.log docs/specs/native-ladybird-design.md README.md native/ladybird
git commit -m "docs: native Ladybird demo results, screenshots, and unseal proof"
```
