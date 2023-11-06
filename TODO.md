# TODO

Current baseline (2026-07-02): rust-cryptoki `basic.rs` suite scores
**31 passed / 45 failed / 2 ignored** against rustssm (with
`TEST_PRETEND_LIBRARY=softhsm`). All failures are missing functionality, not
bugs; each item below names the tests it unlocks.

## 1. Make every rust-cryptoki test pass

### Object management (biggest unlock, ~14 tests)

- [ ] `C_CreateObject` — import objects from templates (AES keys via
      `CKA_VALUE`, RSA public keys via `CKA_MODULUS`/`CKA_PUBLIC_EXPONENT`).
      Must enforce `CKR_SESSION_READ_ONLY` for token objects in RO sessions,
      and reject read-only attributes (`CKA_UNIQUE_ID`, validation flags) with
      `CKR_ATTRIBUTE_TYPE_INVALID`.
      → `aes_cbc_encrypt`, `aes_cbc_pad_encrypt`, `aes_gcm_with_aad`,
      `ro_rw_session_test`, `import_export`, `unique_id`, `validation`,
      `aes_cmac_sign`, `aes_cmac_verify`, `ekdf_aes_cbc_encrypt_data`
- [ ] Attribute storage and readback — persist each object's template
      (class, key type, label, `CKA_ID`, value, modulus/exponent, boolean
      flags like `SENSITIVE`/`EXTRACTABLE`, a generated `CKA_UNIQUE_ID`) and
      serve it from `C_GetAttributeValue`. `C_FindObjects` must then match on
      arbitrary template attributes (`CKA_ID`, class, key type), not only
      label/private. Currently only `CKA_EC_POINT` of P-256 public keys works.
      → `get_attributes_test`, `get_attribute_info_test`,
      `aes_key_attributes_test`, `session_find_objects`,
      `session_objecthandle_iterator`, `import_export`
- [ ] `C_CopyObject` → `session_copy_object`
- [ ] `C_SetAttributeValue` → `update_attributes_key`

### Key generation mechanisms

- [ ] `CKM_AES_KEY_GEN` — single most-referenced mechanism in the suite
      (22 uses). → `wrap_and_unwrap_key`, `session_find_objects`,
      `session_objecthandle_iterator`, `aes_key_attributes_test`,
      `encrypt_decrypt*`, `derive_key*`, …
- [ ] `CKM_EC_EDWARDS_KEY_PAIR_GEN` + `CKM_EDDSA` (Ed25519 and Ed448,
      including `EddsaParams` schemes)
      → `sign_verify_eddsa`, `sign_verify_eddsa_with_ed25519_schemes`,
      `sign_verify_eddsa_with_ed448_schemes`
- [ ] `CKM_SHA{1,224,256,384,512}_KEY_GEN`
      → `sha256_digest_multipart_with_key`, HMAC tests below

### Encrypt / decrypt

- [ ] Decryption in general: `C_DecryptInit`, `C_Decrypt` (currently
      `CKR_FUNCTION_NOT_SUPPORTED` stubs)
- [ ] `CKM_AES_ECB`, `CKM_AES_CBC`, `CKM_AES_CBC_PAD`
      → `aes_cbc_encrypt`, `aes_cbc_pad_encrypt`, `wrap_and_unwrap_key`
- [ ] `CKM_RSA_PKCS` encrypt/decrypt and `CKM_RSA_PKCS_OAEP`
      → `encrypt_decrypt`, `encrypt_decrypt_single_part`,
      `rsa_pkcs_oaep_empty`, `rsa_pkcs_oaep_with_data`,
      `wrap_and_unwrap_key_oaep`
- [ ] Multipart encryption: `C_EncryptUpdate`/`C_EncryptFinal` and decrypt
      counterparts → `encrypt_decrypt_multipart`,
      `encrypt_decrypt_multipart_already_initialized`
- [ ] AES-GCM: IV lengths other than 96 bits and tag lengths other than 128
      (rustssm currently rejects both)

### Sign / verify

- [ ] `CKM_SHA256_RSA_PKCS` plus multipart `C_SignUpdate`/`C_SignFinal`/
      `C_VerifyUpdate`/`C_VerifyFinal`
      → `sign_verify_multipart`, `sign_verify_multipart_not_initialized`,
      `sign_verify_multipart_already_initialized`, `sign_verify_single_part`
- [ ] `CKM_SHA{1,224,384,512}_HMAC` (SHA-256 HMAC already works)
      → `sign_verify_sha{1,224,384,512}_hmac`
- [ ] `CKM_AES_CMAC` → `aes_cmac_sign`, `aes_cmac_verify`

### Digests

- [ ] `C_DigestInit`, `C_Digest`, `C_DigestUpdate`, `C_DigestKey`,
      `C_DigestFinal` with `CKM_SHA256`
      → all six `sha256_digest*` tests, and `is_fn_supported_test`
      (asserts `C_DigestFinal` is non-null)

### Key derivation

- [ ] `C_DeriveKey` with `CKM_ECDH1_DERIVE` → `derive_key`
- [ ] `CKM_AES_CBC_ENCRYPT_DATA` → `ekdf_aes_cbc_encrypt_data`
- [ ] `CKM_CONCATENATE_{BASE_AND_KEY,BASE_AND_DATA,DATA_AND_BASE}`,
      `CKM_XOR_BASE_AND_DATA`, `CKM_EXTRACT_KEY_FROM_KEY`, and the
      SP800-108 KBKDFs (counter/feedback/double-pipeline) — the
      `derive_key_*`/`kbkdf_*` tests currently pass *vacuously* because they
      skip under the softhsm pretend flag; real support is needed for a green
      run without `TEST_PRETEND_LIBRARY=softhsm`

### PKCS#11 3.0 surface (only needed without the softhsm pretend flag)

- [ ] `C_GetInterfaceList`/`C_GetInterface` with `CK_FUNCTION_LIST_3_0`,
      message-based encryption (`C_MessageEncryptInit` etc.), and Cryptoki
      3.0 in `C_GetInfo`
      → `is_fn_supported_test` (3.0 assertions), `get_info_test` (3.x path),
      `encrypt_decrypt_gcm_message_no_aad`,
      `encrypt_decrypt_gcm_message_with_aad`

### Not rustssm bugs (no action)

- `is_initialized_test` / `test_clone_initialize` fail in full-suite runs
  only because earlier failing tests panic without calling `C_Finalize`,
  which leaves the library initialized. Both pass in isolation and will pass
  once the rest of the suite is green.

## 2. Support nl-wallet `wallet_core/lib/hsm`

Based on `Pkcs11Hsm`/`Pkcs11Client` in
`/home/jippeh/Code/nl-wallet/wallet_core/lib/hsm/src/service.rs`. What
already works against rustssm:

- `C_Initialize`, `get_slots_with_initialized_token` (rustssm reports
  `CKF_TOKEN_INITIALIZED`), the r2d2-cryptoki session pool (RW session +
  user login per pooled session; the pool tolerates
  `CKR_USER_ALREADY_LOGGED_IN`, `test_on_check_out` uses `C_GetSessionInfo`)
- `generate_generic_secret_key` (`CKM_GENERIC_SECRET_KEY_GEN`)
- `generate_signing_key_pair` / `generate_session_signing_key_pair`
  (`CKM_EC_KEY_PAIR_GEN`, P-256)
- `find_objects` on `[Private, Label]`, `destroy_object`
- `get_verifying_key` (`C_GetAttributeValue` of `CKA_EC_POINT` as DER octet
  string)
- `sign`/`verify` with `CKM_ECDSA` (prehashed) and `CKM_SHA256_HMAC`
- `wrap_key`/`unwrap_signing_key` with `CKM_AES_KEY_WRAP_PAD`

TODOs, roughly in dependency order:

- [ ] **`CKM_AES_KEY_GEN`** — `generate_aes_encryption_key` creates the
      AES-256 encryption/wrapping keys everything else depends on. (Same item
      as in section 1.)
- [ ] **AES-GCM decrypt** — `decrypt()` needs `C_DecryptInit`/`C_Decrypt`
      for `CKM_AES_GCM`; rustssm only implements the encrypt direction.
- [ ] **AES-GCM with 32-byte IVs** — nl-wallet passes
      `random_bytes(32)` as IV; rustssm currently requires exactly 12 bytes.
      Implement the GCM spec's GHASH-based IV processing for arbitrary IV
      lengths (the `aes-gcm` crate supports non-96-bit nonce sizes via its
      `NonceSize` type parameter).
- [ ] **Persistent token state** — PINs, label, and the initialized flag
      live only in memory; objects alone are persisted in SQLite. nl-wallet
      assumes a pre-initialized token it can log into at startup
      (`hsm.toml`: `user_pin`), so token state must survive process
      restarts. Includes storing PIN hashes rather than plaintext.
- [ ] **Token-init tooling** — an equivalent of `softhsm2-util
      --init-token` so an operator can initialize the token and set the user
      PIN outside the wallet process.
- [ ] **Session-object lifecycle** — nl-wallet creates session keys with
      `Token(false)` (`generate_session_signing_key_pair`, unwrapped signing
      keys) and relies on the HSM cleaning them up; rustssm ignores
      `CKA_TOKEN` and persists everything to the database. Store session
      objects in memory (or delete on session close) so they don't leak into
      the token store. Also relevant: their PVW-5862 notes assume session
      objects die with the session.
- [ ] **Validate `CKA_EC_PARAMS`** — nl-wallet passes the P-256 OID
      explicitly; rustssm ignores the attribute and silently assumes P-256.
      Reject other curves with `CKR_CURVE_NOT_SUPPORTED`.
- [ ] **ECDSA verify via private-key handle** — the `Pkcs11Client::verify`
      trait method allows `SigningMechanism::Ecdsa256` with a private-key
      handle (today nl-wallet only verifies HMACs). `C_VerifyInit` with
      `CKM_ECDSA` on a private key handle should derive the public key
      instead of failing.
- [ ] **Attribute storage for unwrapped keys** — `unwrap_signing_key` passes
      a template (`CKA_CLASS`, `CKA_KEY_TYPE`, `CKA_TOKEN`, `CKA_PRIVATE`);
      rustssm stores only the key bytes. Fine for the immediate
      unwrap-then-sign flow, but attribute-aware `find_objects`/
      `C_GetAttributeValue` (section 1) should include these objects.
- [ ] Point nl-wallet at rustssm for integration testing: set
      `library_path` in `wallet_core/lib/hsm/hsm.toml` to
      `.../rustssm/target/release/librustssm.so` (it currently points at
      SoftHSM) and run the `hsm_test`-gated tests in
      `wallet_core/lib/hsm/tests/hsm.rs`.

Critical path for nl-wallet: AES key generation → GCM decrypt → arbitrary
GCM IV length → persistent token state. Critical path for the rust-cryptoki
suite: `C_CreateObject` + attribute storage → AES key generation → digests →
multipart operations.
