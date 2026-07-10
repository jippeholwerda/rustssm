# TODO

Current baseline (2026-07-08): rust-cryptoki `basic.rs` suite scores
**40 passed / 36 failed / 2 ignored** against rustssm (with
`TEST_PRETEND_LIBRARY=softhsm`). All failures are missing functionality, not
bugs; each item below names the tests it unlocks. (`CKM_AES_KEY_GEN` unlocked
`session_find_objects` and `session_objecthandle_iterator`; attribute
storage/readback then unlocked `get_attributes_test`,
`generate_generic_secret_key`, `import_export`, and `aes_key_attributes_test`;
`C_SetAttributeValue` unlocked `update_attributes_key`; create-time read-only
attribute rejection unlocked `unique_id`; `C_CopyObject` unlocked
`session_copy_object`; from the 2026-07-02 baseline of 31/45.)

## 1. Make every rust-cryptoki test pass

### Object management (biggest unlock, ~14 tests)

- [~] `C_CreateObject` — secret keys (`CKO_SECRET_KEY` via `CKA_VALUE`),
      RSA public keys (metadata-only, via raw `CKA_MODULUS`/
      `CKA_PUBLIC_EXPONENT`), and P-256 EC private keys (`CKO_PRIVATE_KEY` +
      `CKK_EC` with `CKA_VALUE` = the scalar; stored like a generated EC
      private key, findable by label and usable to sign) are implemented and
      enforce `CKR_SESSION_READ_ONLY` for token objects in RO sessions; a
      template carrying a token-managed read-only attribute (`CKA_UNIQUE_ID`,
      `CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE`,
      `CKA_KEY_GEN_MECHANISM`) is rejected with `CKR_ATTRIBUTE_TYPE_INVALID`
      (SoftHSM-compatible; the same guard covers `C_GenerateKey(Pair)` and
      `C_UnwrapKey`). Validated against `p11tool --write --secret-key`,
      `pkcs11-tool --write-object --type privkey` (import + sign), and the
      `import_export`/`unique_id` tests. Still TODO: RSA private keys.
      → `aes_cbc_encrypt`, `aes_cbc_pad_encrypt`, `validation`,
      `aes_cmac_sign`, `aes_cmac_verify`, `ekdf_aes_cbc_encrypt_data`
- [x] Attribute storage and readback — each object persists its full typed
      attribute list (the template merged with token-synthesized class/key
      type and derived modulus/exponent/EC point), served from
      `C_GetAttributeValue` and matched by `C_FindObjects` on any combination
      of attributes. `CKA_START_DATE`/`CKA_END_DATE`/`CKA_ALLOWED_MECHANISMS`
      report present-but-empty. `CKA_VALUE` of a secret key stays unavailable
      (sensitive). → `get_attributes_test`, `aes_key_attributes_test`,
      `generate_generic_secret_key`, `import_export`, `session_find_objects`,
      `session_objecthandle_iterator`, `unique_id`. Remaining readback gap:
      `get_attribute_info_test` (needs `CKA_MODULUS` on a generated private key
      + sensitivity reporting).
- [x] `C_CopyObject` → `session_copy_object`. Duplicates the source's key
      material into a new object; the template overrides attributes under the
      `C_SetAttributeValue` rules (identity/key-material read-only,
      untracked/token-managed invalid) plus the one-way guarantees that
      `CKA_SENSITIVE` may not go true→false and `CKA_EXTRACTABLE` false→true.
- [x] `C_SetAttributeValue` → `update_attributes_key`, `unique_id`. Updates
      modifiable attributes (usage/policy flags, label, id); rejects
      identity/key-material attributes as `CKR_ATTRIBUTE_READ_ONLY` and
      untracked/token-managed types as `CKR_ATTRIBUTE_TYPE_INVALID`; token
      objects require a R/W session.

### Key generation mechanisms

- [x] `CKM_AES_KEY_GEN` — single most-referenced mechanism in the suite
      (22 uses). Generates a 128/192/256-bit key from `CKA_VALUE_LEN`.
      Most of the referencing tests also need `C_CreateObject`/attribute
      storage before they go green. → `wrap_and_unwrap_key`,
      `session_find_objects`,
      `session_objecthandle_iterator`, `aes_key_attributes_test`,
      `encrypt_decrypt*`, `derive_key*`, …
- [ ] `CKM_EC_EDWARDS_KEY_PAIR_GEN` + `CKM_EDDSA` (Ed25519 and Ed448,
      including `EddsaParams` schemes)
      → `sign_verify_eddsa`, `sign_verify_eddsa_with_ed25519_schemes`,
      `sign_verify_eddsa_with_ed448_schemes`
- [ ] `CKM_SHA{1,224,256,384,512}_KEY_GEN`
      → `sha256_digest_multipart_with_key`, HMAC tests below

### Encrypt / decrypt

- [x] Decryption plumbing: `C_DecryptInit`/`C_Decrypt` now dispatch (no
      longer `CKR_FUNCTION_NOT_SUPPORTED` stubs); AES-GCM decrypt is
      implemented. Other mechanisms (RSA, AES-CBC/ECB below) still need their
      decrypt arms.
- [ ] `CKM_AES_ECB`, `CKM_AES_CBC`, `CKM_AES_CBC_PAD`
      → `aes_cbc_encrypt`, `aes_cbc_pad_encrypt`, `wrap_and_unwrap_key`
- [ ] `CKM_RSA_PKCS` encrypt/decrypt and `CKM_RSA_PKCS_OAEP`
      → `encrypt_decrypt`, `encrypt_decrypt_single_part`,
      `rsa_pkcs_oaep_empty`, `rsa_pkcs_oaep_with_data`,
      `wrap_and_unwrap_key_oaep`
- [ ] Multipart encryption: `C_EncryptUpdate`/`C_EncryptFinal` and decrypt
      counterparts → `encrypt_decrypt_multipart`,
      `encrypt_decrypt_multipart_already_initialized`
- [ ] AES-GCM: tag lengths other than 128 bits (rustssm still requires 128).
      IV lengths: 96-bit and 256-bit (32-byte) are supported; other lengths
      are rejected with `CKR_MECHANISM_PARAM_INVALID`.

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

- [x] **`CKM_AES_KEY_GEN`** — `generate_aes_encryption_key` creates the
      AES-256 encryption/wrapping keys everything else depends on. (Same item
      as in section 1.)
- [x] **AES-GCM decrypt** — `decrypt()` uses `C_DecryptInit`/`C_Decrypt`
      for `CKM_AES_GCM` (auth-tag failure → `CKR_ENCRYPTED_DATA_INVALID`,
      short ciphertext → `CKR_ENCRYPTED_DATA_LEN_RANGE`). Still 12-byte IV
      only (next item).
- [x] **AES-GCM with 32-byte IVs** — nl-wallet passes `random_bytes(32)` as
      IV. `read_mechanism` now accepts 12- or 32-byte IVs; `signing.rs`
      dispatches on `(key_len, iv_len)` to a concrete `AesGcm<Aes*, U32>` via
      a generic `gcm_encrypt`/`gcm_decrypt` helper (nonce size is a
      compile-time type parameter, so each IV length needs its own type).
- [x] **Persistent token state** — per-slot label, initialized flag and PIN
      hashes now persist in a `token` table alongside the objects. `initialize`
      hydrates the in-memory slots from the store, so a restarted process sees
      the same tokens and accepts the same PINs. PINs are stored as salted
      SHA-256 (`PinHash`), never plaintext. (A stolen DB already exposes the
      keys, so this is hygiene, not a slow-KDF defence; layer Argon2 if that
      changes.)
- [x] **Token-init tooling (Tier 1)** — the `rustssm-util` binary (`src/bin`,
      backed by `src/admin.rs`, gated behind the `cli` feature so the cdylib
      never pulls clap) covers the `softhsm2-util` roles the nl-wallet devenv
      uses: `show-slots`, `init-token` (`--free`/`--slot`/`--token`), and
      `import --aes` (raw AES key from a file → labelled secret key). It drives
      the same `Hsm` init_token/init_pin/import path as the PKCS#11 API. (Crate
      is now `cdylib` + `rlib` so the binary can link it.)
- [x] **Token-init tooling (Tier 2)** — the devenv's `p11tool` calls run
      *through the module*. `--list-token-urls` and `--login --write
      --secret-key` both work against rustssm now (secret-key `C_CreateObject`
      landed and was validated with real `p11tool 3.8.13`). Decision: keep the
      honest `model = "rustssm"`; the devenv's `grep 'model=SoftHSM%20v2'` must
      change to `model=rustssm` (a one-line edit on the nl-wallet side).
      Remaining nicety (own item below): `p11tool` can't *display* a created
      object's label/type because `C_GetAttributeValue` only serves
      `CKA_EC_POINT` — functionally fine, since nl-wallet finds keys by label
      via `C_FindObjects`, which works.
- [x] **Session-object lifecycle** — nl-wallet creates session keys with
      `Token(false)` (`generate_session_signing_key_pair`, unwrapped signing
      keys) and relies on the HSM cleaning them up. Objects carry an
      `owner_session` column: `NULL` for token objects (persistent),
      otherwise the creating session's id. Session objects are deleted when
      that session closes (`C_CloseSession`) and every session object is
      purged on `C_Initialize`/`C_Finalize` (session ids don't survive a
      process, so any left behind is a crash orphan). Token objects
      (`CKA_TOKEN` true) are unaffected. Matches their PVW-5862 assumption
      that session objects die with the session.
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
- [x] Point nl-wallet at rustssm for integration testing: set `library_path`
      in `wallet_core/lib/hsm/hsm.toml` to
      `.../rustssm/target/release/librustssm.so`, provision a token whose user
      PIN matches the toml (`rustssm-util --database <db> init-token --free
      --label nl-wallet-test --so-pin <sopin> --user-pin 12345678`), then run
      with the module pointed at the same store:
      `RUSTSSM_DATABASE_URL=<db> cargo test -p hsm --features hsm_test --test hsm`.
      **All 5 cases pass** (`sign_sha256_hmac`, `sign_ecdsa`, `encrypt_decrypt`,
      `encrypt_decrypt_verifying_key`, `wrap_key_and_sign`) — exercises
      nl-wallet's `Pkcs11Hsm` + the r2d2-cryptoki session pool end-to-end.

Critical path for nl-wallet: AES key generation → GCM decrypt → arbitrary
GCM IV length → persistent token state. Critical path for the rust-cryptoki
suite: `C_CreateObject` + attribute storage → AES key generation → digests →
multipart operations.

## 3. Internals / tech debt

- [ ] **Switch persisted object records from postcard to CBOR** (ciborium).
      postcard encodes enums by discriminant index and struct fields
      positionally, with no names or framing — so reordering/inserting a
      variant in the now-persisted `Attribute`/`ObjectClass`/`KeyType` enums (or
      adding an `ObjectRecord` field) silently misreads previously-stored
      objects. postcard's niche (embedded / `no_std` / serial wire) does not
      match a desktop HSM persisting into local SQLite; CBOR is self-describing
      and tolerant of schema evolution. Scope is isolated to the object BLOB
      (token state already lives in typed SQL columns). While doing it, collapse
      the double serialization (key material is postcard'd, then the wrapping
      `ObjectRecord` is postcard'd again). Interim mitigation if deferred: a
      stored format-version guard plus an append-only rule for those enums.

## 4. Code review findings (2026-07-09)

Ranked; being worked one at a time.

- [x] **Single-slot module** — collapsed the slot map from four slots to one.
      PKCS#11 stays slot-addressed (`SlotId`), but there is exactly one token,
      which is all nl-wallet uses (it takes the first initialized token). This
      removes the cross-slot object wipe: `init_token`'s store-wide `clear()`
      can now only affect that one token's objects, so no `slot_id` column on
      `object` is needed. `SlotSelector::Free`/`--free` still resolves to slot 0
      when uninitialized.
- [ ] **`C_InitToken` must verify the SO PIN on re-init** — `init_token`
      currently accepts any PIN and re-initializes. Spec §5.6: re-initializing
      an initialized token requires the supplied PIN to match the existing SO
      PIN, else `CKR_PIN_INCORRECT`. Three-line guard against `slot.so_pin`.
- [ ] **`attr_bool`/`attr_ulong` bounds** — they dereference `pValue` without
      checking `ulValueLen`; a `CK_ULONG` attr with `ulValueLen = 1` causes an
      8-byte out-of-bounds read. Check the length matches `size_of` and reject
      (or map to `Attribute::Unknown`). The FFI layer's own validation contract.
- [ ] **Populate `FUNCTION_LIST` stubs** — `C_GetMechanismList`,
      `C_CloseAllSessions`, `C_Digest*`, `C_GetObjectSize`, … are `None` (null C
      function pointers). Real C clients (p11-kit, pkcs11-tool, OpenSSL) call
      `C_GetMechanismList` unconditionally and segfault on null; rust-cryptoki
      null-checks, which is why we haven't been bitten. Add stubs returning
      `CKR_FUNCTION_NOT_SUPPORTED` (or implement where cheap).
- [ ] **`unwrap_key` should merge attributes** — it is the only object-creating
      path that skips `merge_attributes`, so an `Unknown` template attribute
      gets persisted and (since `Unknown == Unknown`) later matches unrelated
      search templates. `merge_attributes(attributes, vec![])` fixes it and
      makes the path consistent with `create_object`.
- [ ] **`import_secret_key` should set `KeyType(Aes)`** — an imported AES key is
      not findable by a `KeyType` template the way a generated one is.
- [ ] **Login enforcement — decide and act** — private objects
      (`CKA_PRIVATE` true) are findable/usable without `C_Login`; only PIN
      management is login-gated. nl-wallet always logs in, so no impact.
      Either enforce `CKR_USER_NOT_LOGGED_IN` on private-object access or
      document the deviation in the README error-policy section.
- [ ] **`CKM_RSA_PKCS` uses the wrong padding** — it is implemented as
      `CKM_SHA256_RSA_PKCS` (`pkcs1v15::SigningKey::<Sha256>` hashes + embeds
      DigestInfo). Raw `CKM_RSA_PKCS` must pad the data as given, no hashing.
      Self-consistent internally (own tests pass), breaks external interop.
      No nl-wallet impact (no RSA). Fix via the `rsa` crate's unprefixed path.
- [ ] **`CKA_VALUE` of a sensitive key** returns `CKR_ATTRIBUTE_TYPE_INVALID`;
      spec wants `CKR_ATTRIBUTE_SENSITIVE` (`ulValueLen` already set to
      `CK_UNAVAILABLE_INFORMATION`).
- [ ] **README: wrapped-key portability** — `C_WrapKey` wraps the raw 32-byte
      EC scalar, while SoftHSM wraps a PKCS#8 `PrivateKeyInfo`; wrapped keys are
      not portable between the two implementations. Worth a README line.
