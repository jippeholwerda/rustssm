# rustssm

A Rust-based software HSM exposing a PKCS#11 (Cryptoki) interface, in the
spirit of [SoftHSM](https://github.com/opendnssec/SoftHSMv2). Builds a
`cdylib` (`librustssm.so`) that PKCS#11 clients load directly.

## Status

Implemented (and exercised by the rust-cryptoki test suite):

- Slot/token management: `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`,
  `C_InitToken`, `C_GetInfo`
- Sessions and authentication: open/close sessions, session info, SO/user
  login, `C_InitPIN`, `C_SetPIN`
- Key generation: `CKM_GENERIC_SECRET_KEY_GEN`, `CKM_RSA_PKCS_KEY_PAIR_GEN`,
  `CKM_EC_KEY_PAIR_GEN` (P-256)
- Sign/verify: `CKM_RSA_PKCS`, `CKM_ECDSA`, `CKM_SHA256_HMAC` (single-part)
- Encryption: `CKM_AES_GCM` (single-part, 96-bit IV, 128-bit tag)
- Key wrapping: `CKM_AES_KEY_WRAP_PAD`
- Object search (`C_FindObjects*`, by label/private), `C_DestroyObject`
- `C_GenerateRandom` / `C_SeedRandom`

Objects are persisted in a SQLite database (`rustssm.db` in the working
directory; override with `DATABASE_URL`, either a plain path or a
`sqlite://path` URL).

Set `RUSTSSM_LOG=debug` (or `error`/`warn`/`info`/`trace`) to log all calls
and error returns to stderr, including the resolved database path.

Error policy: expected failures return `CK_RV` codes; panics indicate broken
internal invariants and deliberately abort the host process (crash-only) —
see the module docs in `src/lib.rs`.

Not implemented: `C_CreateObject`/`C_CopyObject`, attribute storage/readback
(only `CKA_EC_POINT` of P-256 public keys), digests, multipart operations,
decryption, AES key generation, EdDSA, and mechanisms not listed above.
Unsupported calls return `CKR_FUNCTION_NOT_SUPPORTED` /
`CKR_MECHANISM_INVALID`. See [TODO.md](TODO.md) for the roadmap.

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
