# rustssm

A Rust-based software HSM exposing a PKCS#11 (Cryptoki) interface, in the
spirit of [SoftHSM](https://github.com/opendnssec/SoftHSMv2). Builds a
`cdylib` (`librustssm.so`) that PKCS#11 clients load directly.

## Status

Implemented (and exercised by the rust-cryptoki test suite):

- Slot/token management: `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`,
  `C_InitToken`, `C_GetInfo`
- Sessions and authentication: open/close sessions, session info, SO/user
  login, `C_InitPIN`, `C_SetPIN`. Private objects (`CKA_PRIVATE` true) are
  enforced per PKCS#11 §4.4: until the normal user is logged in they are
  excluded from `C_FindObjects` and cannot be created or accessed by handle
  (`CKR_USER_NOT_LOGGED_IN`); public objects are unrestricted. Secret and
  private keys default to `CKA_PRIVATE` true (so they need a login to use),
  public keys to false — set the attribute explicitly to override
- Usage flags are enforced: initializing an operation with a key whose flag
  (`CKA_SIGN`, `CKA_VERIFY`, `CKA_ENCRYPT`, `CKA_DECRYPT`, `CKA_WRAP`,
  `CKA_UNWRAP`) is false fails with `CKR_KEY_FUNCTION_NOT_PERMITTED`. A flag
  omitted from the creation template defaults to true, matching SoftHSM —
  usage is opt-out, not opt-in. (`CKA_SENSITIVE` defaults to true, where
  SoftHSM says false; `CKA_EXTRACTABLE` and `CKA_DERIVE` default to false)
- Key generation: `CKM_GENERIC_SECRET_KEY_GEN`, `CKM_AES_KEY_GEN`,
  `CKM_RSA_PKCS_KEY_PAIR_GEN`, `CKM_EC_KEY_PAIR_GEN` (P-256)
- Sign/verify: `CKM_RSA_PKCS`, `CKM_ECDSA`, `CKM_SHA256_HMAC` (single-part)
- Encrypt/decrypt: `CKM_AES_GCM` (single-part; 96- or 256-bit IV; 128-bit
  tag), `CKM_AES_ECB`, `CKM_AES_CBC`, `CKM_AES_CBC_PAD` (single-part; all AES
  key sizes; the unpadded modes require block-aligned input)
- Key wrapping: `CKM_AES_KEY_WRAP_PAD`
- Object creation/search: `C_CreateObject` (secret keys via `CKA_VALUE`, RSA
  public keys via raw `CKA_MODULUS`/`CKA_PUBLIC_EXPONENT`, P-256 EC private
  keys via `CKA_VALUE`; token-managed read-only attributes like `CKA_UNIQUE_ID`
  in a template are rejected),
  `C_CopyObject` (duplicates key material; template overrides follow the
  set-attribute rules),
  `C_FindObjects*` (matching any combination of stored attributes),
  `C_DestroyObject`
- Attribute readback: `C_GetAttributeValue` serves the object's stored
  template plus token-synthesized/derived attributes (`CKA_CLASS`,
  `CKA_KEY_TYPE`, `CKA_MODULUS`, `CKA_MODULUS_BITS`, `CKA_PUBLIC_EXPONENT`,
  `CKA_EC_POINT`, `CKA_EC_PARAMS`, `CKA_ID`, `CKA_LABEL`, boolean usage flags,
  …)
- Attribute modification: `C_SetAttributeValue` updates modifiable
  attributes (usage/policy flags, label, id); identity and key-material
  attributes are rejected as read-only, unknown types as invalid. Both set
  and copy enforce the one-way guarantees: a sensitive key cannot be made
  non-sensitive, a non-extractable key cannot be made extractable
- `C_GenerateRandom` / `C_SeedRandom`

Token objects and token state (label, initialized flag, and salted-hashed
SO/user PINs) are persisted in a SQLite database (`rustssm.db` in the working
directory; override with `RUSTSSM_DATABASE_URL`, either a plain path or a
`sqlite://path` URL — namespaced so it can't clash with a host process's own
`DATABASE_URL`), so a restarted module keeps its tokens and accepts the
same PINs. Session objects (`CKA_TOKEN` false) live in process memory only,
like SoftHSM's: they are visible to all of the process's sessions, destroyed
when the session that created them closes, and cannot outlive the process —
short-lived key material never touches disk, and processes sharing one
database cannot interfere with each other's session objects.

Set `RUSTSSM_LOG=debug` (or `error`/`warn`/`info`/`trace`) to log all calls
and error returns to stderr, including the resolved database path.

Error policy: expected failures return `CK_RV` codes; panics indicate broken
internal invariants and deliberately abort the host process (crash-only) —
see the module docs in `src/lib.rs`.

Not implemented: `C_CreateObject` for RSA private keys, `CKA_VALUE` readback of
secret keys (treated as sensitive), digests, multipart operations, RSA
encryption, EdDSA, and mechanisms not listed above. Unsupported calls return
`CKR_FUNCTION_NOT_SUPPORTED` / `CKR_MECHANISM_INVALID`. See [TODO.md](TODO.md)
for the roadmap.

Wrapped-key format: `C_WrapKey` with `CKM_AES_KEY_WRAP_PAD` wraps an EC private
key's raw 32-byte scalar, whereas SoftHSM wraps a PKCS#8 `PrivateKeyInfo`.
Wrap/unwrap round-trips within rustssm are consistent, but a key wrapped by one
implementation cannot be unwrapped by the other — do not migrate persisted
wrapped keys between rustssm and SoftHSM.

## Provisioning a token

The `rustssm-util` binary provisions tokens directly in the store — a rough
analogue of `softhsm2-util` — so an operator can prepare a token a client logs
into at startup, without going through the PKCS#11 API. It is gated behind the
`cli` feature so a default build (and the cdylib) never pulls in `clap`:

```sh
cargo build --release --features cli   # builds target/release/rustssm-util

# Initialize a token on the first free slot, set the user PIN:
rustssm-util --database /path/to/rustssm.db init-token \
    --free --label "my token" --so-pin <SO_PIN> --user-pin <USER_PIN>

# List slots and their token state:
rustssm-util --database /path/to/rustssm.db show-slots

# Import a raw AES key (the file's bytes are the key) as a secret-key object.
# --id is optional and hex-encoded, matching `softhsm2-util --id`:
rustssm-util --database /path/to/rustssm.db import \
    --aes ./wrapping.key --label wrapping_key --id 6b6579 \
    --user-pin <USER_PIN> --token "my token"
```

`init-token` selects a slot with one of `--free`, `--slot <N>` or
`--token <LABEL>`. The `--database` path (or `RUSTSSM_DATABASE_URL`) must match the one
the loaded module uses. Initializing a token destroys any objects already in
the store, and — as with the PKCS#11 API — PINs are stored as salted hashes,
never in plaintext.

## Building

Requires `libclang` for bindgen.

```sh
cargo build --release   # produces target/release/librustssm.so
```

## Testing

`cargo test` runs both suites:

- **Unit tests** exercise the `Hsm` domain layer directly against an
  in-memory store (`src/hsm_tests.rs`).
- **`tests/pkcs11.rs`** is a self-contained integration test: it loads the
  built `cdylib` with `libloading`, obtains the dispatch table from
  `C_GetFunctionList`, and drives a full lifecycle (init → token → session →
  login → keygen → sign/verify → encrypt → teardown) plus error cases
  through the real FFI boundary — covering pointer parsing, the output-buffer
  protocol, and `CK_RV` mapping.

For broader mechanism coverage, the [rust-cryptoki](https://github.com/parallaxsecond/rust-cryptoki)
test suite can be run against the built module:

```sh
cd ../rust-cryptoki
TEST_PKCS11_MODULE=$PWD/../rustssm/target/release/librustssm.so \
TEST_PRETEND_LIBRARY=softhsm \
cargo test -p cryptoki --test basic -- --test-threads=1
```

`TEST_PRETEND_LIBRARY=softhsm` makes the suite expect Cryptoki 2.40 behavior
(rustssm exposes the 2.40 function list). Tests covering unimplemented
mechanisms fail with clean PKCS#11 errors; a failing test that panics before
calling `C_Finalize` leaves the library initialized, which cascades into the
`is_initialized_test`/`test_clone_initialize` tests (they pass when run in
isolation).
