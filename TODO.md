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
      `import_export`/`unique_id` tests. RSA private key import: decided
      2026-07-15 not to implement until a consumer appears — no test in any
      suite imports one (the suite's two RSA `create_object` templates are
      public keys), nl-wallet is EC/AES/HMAC-only, and the devenv provisioning
      imports AES/EC only; it would add attribute variants and `CKA_PRIVATE_
      EXPONENT`/prime parsing that nothing exercises.
      → `aes_cbc_encrypt`, `aes_cbc_pad_encrypt`, `validation`,
      `aes_cmac_sign`, `aes_cmac_verify`, `ekdf_aes_cbc_encrypt_data`
      (these create AES keys via `C_CreateObject` but still fail on their
      CBC/CMAC/EKDF mechanisms)
- [x] Attribute storage and readback — each object persists its full typed
      attribute list (the template merged with token-synthesized class/key
      type and derived modulus/exponent/EC point), served from
      `C_GetAttributeValue` and matched by `C_FindObjects` on any combination
      of attributes. `CKA_START_DATE`/`CKA_END_DATE`/`CKA_ALLOWED_MECHANISMS`
      report present-but-empty. `CKA_VALUE` of a secret key stays unavailable
      (sensitive). → `get_attributes_test`, `aes_key_attributes_test`,
      `generate_generic_secret_key`, `import_export`, `session_find_objects`,
      `session_objecthandle_iterator`, `unique_id`. Readback gap closed
      2026-07-15 → `get_attribute_info_test`: a generated RSA private key now
      also stores the pair's `CKA_MODULUS`/`CKA_PUBLIC_EXPONENT`/
      `CKA_MODULUS_BITS`, and the RSA private-key components
      (`CKA_PRIVATE_EXPONENT`, primes, CRT parameters) report
      `CKR_ATTRIBUTE_SENSITIVE` — keyed on the attribute type alone, the same
      deliberate imprecision as `CKA_VALUE` (see section 4). Baseline 44 → 45.
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
      keys) and relies on the HSM cleaning them up. Session objects are
      destroyed when the creating session closes and die with the process,
      matching their PVW-5862 assumption; token objects (`CKA_TOKEN` true)
      are unaffected. (Originally implemented as an `owner_session` column in
      the store with purges on `C_Initialize`/`C_Finalize`; superseded
      2026-07-15 by the in-memory session-object store — see the
      multi-process entry in section 4.)
- [x] **Validate `CKA_EC_PARAMS`** — nl-wallet passes the P-256 OID
      explicitly; rustssm now validates it rather than silently assuming
      P-256. A supplied `CKA_EC_PARAMS` naming a curve other than secp256r1
      is rejected with `CKR_CURVE_NOT_SUPPORTED` (`HsmError::CurveNotSupported`)
      at both EC entry points: `create_object` (EC private-key import) and
      `generate_key_pair` (`EcKeyPairGen`, validated on both halves). An
      omitted `CKA_EC_PARAMS` is still fine — the P-256 OID is injected by
      `merge_attributes` at write time. Covered by
      `create_ec_private_key_rejects_unsupported_curve`,
      `create_ec_private_key_accepts_explicit_p256_params`,
      `generate_key_pair_rejects_unsupported_curve`, and
      `generate_key_pair_accepts_explicit_p256_params`.
- [x] **ECDSA verify via private-key handle** — the `Pkcs11Client::verify`
      trait method allows `SigningMechanism::Ecdsa256` with a private-key
      handle (today nl-wallet only verifies HMACs). `C_VerifyInit` with
      `CKM_ECDSA` on a private key handle now derives the public key from the
      stored scalar instead of failing: the Ecdsa arm first tries to read the
      handle as a `VerifyingKey` (public-key handle), and on failure falls
      back to reading the raw scalar, constructing a `SigningKey`, and
      deriving its `VerifyingKey`. A DB error on the first attempt
      propagates immediately; only a deserialization mismatch triggers the
      fallback. Covered by `ecdsa_verify_via_private_key_handle_derives_public_key`
      (signs with the private key, verifies with the private-key handle,
      and confirms tampered signatures are still rejected).
- [x] **Attribute storage for unwrapped keys** — `unwrap_signing_key` passes
      a template (`CKA_CLASS`, `CKA_KEY_TYPE`, `CKA_TOKEN`, `CKA_PRIVATE`);
      rustssm now persists the full template like every other object-creating
      path: `unwrap_key` runs its template through `merge_attributes`, so the
      class/key-type/token/private flags (plus materialized class defaults)
      are stored and served by `C_GetAttributeValue`/`C_FindObjects`. Covered
      by `unwrap_drops_untracked_template_attributes` (proves an unwrapped key
      is findable by its label).
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

- [ ] **SQL pre-filter for object search** (decided 2026-07-10: keep the scan
      until the numbers say otherwise). `ObjectStore::search` is a full-table
      scan: it selects every row, postcard-decodes each record, and matches
      the template in Rust. Measured (release, in-memory, template
      `[Private, Label]`): ~20µs per search at 100 objects, ~190µs at 1,000,
      ~1.9ms at 10,000 — linear, and the scan holds the store `Mutex`, so at
      large n it also serializes concurrent operations. At the intended scale
      (a handful of named token keys; bulk keys live outside the HSM as
      wrapped blobs) this is immaterial. If a store is ever expected to hold
      thousands of objects: keep the Rust match as the single source of truth
      and add a conservative SQL pre-filter — when the template carries a
      `Label`, narrow with `where label = ?` plus an index on `label`, then
      decode and Rust-verify only the candidates. Prerequisite: store `NULL`
      in the `label` column for unlabelled objects instead of
      `random_string(16)` (`indexed_columns`) — the column becomes
      load-bearing, and a wrong value would cause false negatives. Do NOT
      move full template matching into SQL (attribute table / JSON1): that
      duplicates the matching semantics in a second encoding that must agree
      with `Attribute` equality forever, and a divergence returns the wrong
      key handle. Note: since the search scan doesn't use SQL, this raised
      "why SQLite at all?" — see the storage-mechanism decision below.

- [x] **Keep SQLite as the storage mechanism** (decided 2026-07-13; no code
      change). With search matching in Rust and records as opaque CBOR blobs,
      SQLite is not used as a relational database — and that is fine: it is
      used as a transactional, multi-process-safe file format ("SQLite
      competes with `fopen()`"). What it earns its keep with, and what a
      single-CBOR-file store would have to hand-roll: (1) torn-write
      impossibility under the crash-only policy — a panic may abort
      mid-mutation at any time, and WAL journaling is what makes that stance
      safe; a flat file needs the full temp+fsync+rename+dir-fsync dance on
      every write, done perfectly, in a key store where corruption is the
      worst outcome; (2) cross-process locking and visibility —
      `rustssm-util` writes to a store a loaded module reads, and the
      SoftHSM-style deployment has several processes sharing one store;
      read-modify-rewrite of a single file gives lost updates without
      flock+reload machinery that would amount to a worse database;
      (3) never-reused monotonic handles via `AUTOINCREMENT` rowids;
      (4) per-object deletes, `sqlite3` inspectability, and the documented
      label pre-filter escalation path. The SQL surface is seven short
      statements in one file, and `ObjectStore`'s API is storage-agnostic, so
      the decision is reversible if single-process access ever becomes
      guaranteed. Two nits this analysis surfaced are filed in section 4
      (non-transactional `generate_key_pair` writes; `C_Initialize` session
      purge vs. multi-process).

- [x] **Switch persisted object records from postcard to CBOR** (ciborium).
      postcard encoded enums by discriminant index and struct fields
      positionally, with no names or framing — so reordering/inserting a
      variant in the persisted `Attribute`/`ObjectClass`/`KeyType` enums (or
      adding an `ObjectRecord` field) silently misread previously-stored
      objects. The object blob is now a **version byte** (`0x01`) followed by
      one self-describing CBOR document: struct fields and enum variants are
      encoded by *name* (pinned by `records_encode_attribute_variants_by_name`),
      so schema evolution is tolerated (pinned by
      `record_decoding_tolerates_unknown_fields`, which decodes a record
      carrying a field from "the future"), and an unknown version byte or a
      pre-CBOR blob fails loudly with `ObjectStoreError::UnsupportedFormat`
      rather than being misread (pinned by
      `unknown_record_format_is_rejected_loudly`). The double serialization is
      collapsed: the typed key material is embedded in the same CBOR document
      (`NewObjectRecord<T>` on the write path, `material: ciborium::Value` on
      the read path, decoded into its concrete key type on demand by
      `ObjectParts::material`). Scope stayed isolated to the object BLOB
      (token state lives in typed SQL columns). **Deliberate format break, no
      migration**: there are no live rustssm stores (same call as the
      `owner_session` column); existing test/devenv DBs must be re-provisioned
      — the rust-cryptoki and nl-wallet suites were re-run against fresh
      stores (44/32 and 5/5, both unchanged). postcard is dropped from
      Cargo.toml; ciborium added.

- [x] **Richer error logging at the FFI boundary.** `ck()` now logs
      `C_Sign returned CKR_DATA_LEN_RANGE (0x00000021)` instead of the bare
      hex: `rv_name` in `lib.rs` maps every code rustssm produces (the
      `rv_from` mapping plus the FFI layer's direct returns) to its `CKR_*`
      name, with `"CKR_?"` + the hex for anything else. The deliberate
      logging convention stands: the domain layer is log-free except
      `object_store` (device/DB failures, surfaced via the `warn!` in
      `rv_from`); the FFI layer owns return-code logging. Domain
      input-rejection reasons (e.g. *why* a sign was `DataLenRange`) are
      still not logged because the crypto traits return `Option`/`bool` and
      discard the reason — surfacing those would be a separate logging-policy
      change. Covered by
      `rv_name_maps_known_codes_and_tolerates_unknown_ones` and verified
      rendered through the `.so` (`RUSTSSM_LOG=debug` on the FFI test).

## 4. Code review findings (2026-07-09)

Ranked; being worked one at a time.

- [x] **Single-slot module** — collapsed the slot map from four slots to one.
      PKCS#11 stays slot-addressed (`SlotId`), but there is exactly one token,
      which is all nl-wallet uses (it takes the first initialized token). This
      removes the cross-slot object wipe: `init_token`'s store-wide `clear()`
      can now only affect that one token's objects, so no `slot_id` column on
      `object` is needed. `SlotSelector::Free`/`--free` still resolves to slot 0
      when uninitialized.
- [x] **`C_InitToken` must verify the SO PIN on re-init** — `init_token` now
      rejects a re-init of an already-initialized token unless the supplied SO
      PIN matches the stored one (`CKR_PIN_INCORRECT`); a fresh token still
      accepts any PIN as its new SO PIN. The check runs before `store.clear()`,
      so a wrong PIN cannot destroy objects (covered by
      `reinit_token_with_wrong_so_pin_is_rejected_and_keeps_objects`).
- [x] **`attr_bool`/`attr_ulong` bounds** — both now return `Option` and yield
      `None` when `ulValueLen` doesn't match the scalar's width (`CK_BBOOL` = 1,
      `CK_ULONG` = 8), mapped to `Attribute::Unknown` at the call sites like the
      existing `attr_bytes` path. Closes the out-of-bounds read of an undersized
      buffer. Covered by `ulong_attribute_with_short_length_is_unknown_not_oob`,
      `bool_attribute_with_wrong_length_is_unknown`, and a positive control.
- [x] **Populate `FUNCTION_LIST` stubs** — the 26 previously-`None` entries
      (`C_GetMechanismList`, `C_CloseAllSessions`, `C_Digest*`, `C_GetObjectSize`,
      the multipart/recover/dual operations, `C_DeriveKey`, …) are now real
      function pointers. A `not_supported_stubs!` macro generates one
      correctly-typed stub per entry returning `CKR_FUNCTION_NOT_SUPPORTED`; the
      compiler checks each signature against its `CK_FUNCTION_LIST` field on
      assignment. Guards C clients (p11-kit, pkcs11-tool, OpenSSL) that call
      these unconditionally against a null-pointer crash. Covered by
      `function_list_is_fully_populated` and
      `stubbed_function_returns_not_supported_rather_than_crashing`. (When a real
      implementation lands for one of these, it replaces its stub.)
- [x] **`unwrap_key` should merge attributes** — now runs its template through
      `merge_attributes(attributes, vec![])` like every other object-creating
      path, so `Unknown`/`Unsupported`/`Value` attributes are dropped rather than
      persisted (a stored `Unknown` would spuriously match search templates).
      Covered by `unwrap_drops_untracked_template_attributes`.
- [x] **`import_secret_key` should set `KeyType(Aes)`** — imported AES keys now
      carry `CKA_KEY_TYPE = AES`, so they are findable by a `KeyType` template
      exactly like a generated AES key. Covered by the extended
      `import_aes_key_stores_a_usable_key`.
- [x] **Login enforcement** — private objects (`CKA_PRIVATE` true) are now
      gated per PKCS#11 §4.4: a session not logged in as the normal user has
      them excluded from `C_FindObjects` and is refused creating or accessing
      one by handle (`CKR_USER_NOT_LOGGED_IN`); public objects are unrestricted.
      Enforced in the domain layer: `logged_in_as_user` captures the slot's
      login state *before* the session lock (the lock order is slot→session),
      then `require_login_for_private`/`require_object_access` gate creation and
      handle access, and `ObjectStore::search` filters private rows. nl-wallet
      is unaffected (it logs in per pooled session). Covered by
      `private_objects_are_inaccessible_without_login`,
      `creating_a_private_object_requires_login`, and
      `search_excludes_private_objects_when_not_permitted`.
- [x] **`CKM_RSA_PKCS` uses the wrong padding** — now signs/verifies with
      `Pkcs1v15Sign::new_unprefixed()`, padding the data as given (PKCS#1 v1.5
      block type 01, no hashing/DigestInfo) instead of the old
      `CKM_SHA256_RSA_PKCS` behaviour. `Sign::sign` returns `Option` (like
      `Encrypt`/`Decrypt`); oversized input maps to `CKR_DATA_LEN_RANGE`.
      Covered by `rsa_pkcs_pads_raw_data_and_rejects_oversized_input` (the
      oversized-input rejection is a discriminator the old hashing path could
      not satisfy).
- [x] **`CKA_VALUE` of a sensitive key** now returns `CKR_ATTRIBUTE_SENSITIVE`
      (with `ulValueLen = CK_UNAVAILABLE_INFORMATION`) in `C_GetAttributeValue`,
      distinct from `CKR_ATTRIBUTE_TYPE_INVALID` for an attribute the object
      genuinely lacks. Covered in the FFI test (`pkcs11_end_to_end`).
- [x] **README: wrapped-key portability** — documented that `C_WrapKey`
      (`CKM_AES_KEY_WRAP_PAD`) wraps the raw 32-byte EC scalar while SoftHSM
      wraps a PKCS#8 `PrivateKeyInfo`, so wrapped keys are not portable between
      the two implementations (round-trips within rustssm are fine).
- [x] **Materialize default attributes at write time** — `merge_attributes`
      (the single write path) now appends class-keyed boolean defaults for the
      attributes a template omits, via `default_boolean_attributes(class)`, so
      the stored list is complete and `ObjectStore::search` stays a plain
      presence-plus-equality match (a template like `CKA_PRIVATE = false` or
      `CKA_SIGN = false` now matches an object whose template never set it, as
      against SoftHSM). Defaults (SoftHSM-like, chosen 2026-07-10): `CKA_TOKEN`
      and `CKA_DERIVE` false everywhere (spec-fixed); `CKA_PRIVATE` true for
      private/secret keys and false for public keys; key material sensitive and
      non-extractable by default; usage flags opt-in (false). Consequence:
      generated private/secret keys are now private objects, so §4.4 login
      enforcement bites them — the concurrency test logs its token in and the
      "public" objects in the login tests set `CKA_PRIVATE=false` explicitly.
      `copy_object` inherits the source's already-materialized list, so it needs
      no change. Covered by `write_paths_materialize_class_default_booleans`.
- [x] **Creation login check reads effective privacy** — follow-up to the
      above. The §4.4 creation check now gates on the *effective* `CKA_PRIVATE`
      (explicit template value, else the class default) via
      `require_login_to_create`/`effective_private`, so a not-logged-in session
      can no longer create a key that is private only by its class default and
      then find it unusable — it is refused up front with
      `CKR_USER_NOT_LOGGED_IN`, matching SoftHSM (which applies the default
      before the check). Wired into `create_object`, `generate_key`,
      `generate_key_pair`, and `unwrap_key`; by-handle access and `copy_object`
      already read the object's complete stored list, so they keep
      `require_login_for_private`. The read-only-session tests now log the token
      in first so the RO rejection (not login) is what fires. Covered by the
      extended `creating_a_private_object_requires_login`.
- [x] **Reject duplicate attribute types in templates** — a creation template
      carrying the same attribute type twice is now rejected with
      `CKR_TEMPLATE_INCONSISTENT` at every object-creating entry point
      (`create_object`, `generate_key(_pair)`, `unwrap_key`, `copy_object`) via
      `reject_duplicate_attribute_types`, which runs right after
      `reject_unsupported_attributes`. This enforces the one-attribute-per-type
      invariant that `set_object_attributes` already assumed when it does
      retain-then-push, so readback stays single-valued and search cannot match
      either of two conflicting values. `Unknown`/`Unsupported` attributes (no
      readable type) are skipped by the check, matching how
      `reject_unsupported_attributes` already handles `Unsupported`. Covered by
      `create_object_rejects_duplicate_attribute_types`,
      `generate_key_rejects_duplicate_attribute_types`,
      `generate_key_pair_rejects_duplicate_attribute_types`,
      `unwrap_key_rejects_duplicate_attribute_types`,
      `copy_object_rejects_duplicate_attribute_types`, and a positive control
      (`duplicate_attribute_types_check_allows_distinct_types`).
- [x] **Search template with an untracked attribute must match nothing —
      explicitly** — `ObjectStore::search` now returns an empty result when
      the template contains an `Attribute::Unknown`, before scanning any rows.
      Previously matching relied on no object ever *storing* an `Unknown`
      (true by construction — every object-creating path runs
      `merge_attributes`, which drops them — but only by convention). Making
      the semantics explicit means a future write path that forgets to merge
      cannot silently turn two different unrecognized attributes into a
      wildcard match of each other. Covered by
      `search_template_with_unknown_matches_nothing` (stores an `Unknown`
      directly via the store-level `write` to prove the guard, not just the
      construction invariant, is what blocks the match) and the existing
      `unwrap_drops_untracked_template_attributes` hsm-level test.
- [x] **Witness-type refactor (Template / CanonicalAttributes / SessionContext)**
      — parse-don't-validate: `Template::new` validates an application-supplied
      attribute list (rejects `Unsupported` and duplicate attribute types in
      one place), and `Template::merge` is the sole producer of
      `CanonicalAttributes`, the only attribute list a session will persist — so
      an object-creating path that skips validation or the merge does not
      compile, rather than silently storing an unnormalized list. `SessionContext`
      captures a session and a snapshot of its slot's login state under one
      brief slot read lock; `ctx.object()` does one store read (attributes +
      material) with §4.4 enforced, replacing the scattered `logged_in_as_user`
      + `get_session` + `require_object_access` + `read_handle` pattern. Every
      session-scoped entry point starts with `session_context`, which also
      restores spec behavior: operations on an uninitialized HSM return
      `NotInitialized` (the half-done refactor had regressed this to
      `SessionNotFound` because `logged_in_as_user` didn't call
      `ensure_initialized`). `apply_attribute_updates` shares the
      `C_SetAttributeValue`/`C_CopyObject` update loop; `store_read_error`
      replaces the repeated `SessionError`-to-`HsmError` match. `import_secret_key`
      now delegates to `create_object` (the drift fix — previously it built its
      own template and skipped `Template::merge`, so imported keys lacked class
      defaults like `CKA_SENSITIVE`). `verify_init`'s ECDSA arm does one
      `ctx.object` read and tries `material::<VerifyingKey>()` then falls back
      to the scalar, instead of up to three separate reads. Covered by
      `imported_key_carries_class_defaults` (CKA_SENSITIVE reads back true,
      findable by a Sensitive(true) template) and the full existing suite (121
      tests).
- [x] **`CKA_VALUE` readback on objects that never carry a value** — decided
      2026-07-15: won't fix. The `C_GetAttributeValue` branch in `lib.rs` keys
      on the *attribute type*: any object lacking a stored `Value` reports
      `CKR_ATTRIBUTE_SENSITIVE`, including objects that never have one (a
      metadata-only RSA public key), where spec-precise behavior would be
      `CKR_ATTRIBUTE_TYPE_INVALID`. Both codes follow the same output
      convention (`ulValueLen = CK_UNAVAILABLE_INFORMATION`), so every client
      treats them identically as "unavailable"; erring toward "sensitive" is
      the harmless direction, and the fix would thread a per-class "carries
      `CKA_VALUE`" notion through the readback path — complexity buying a
      distinction nothing observes. Revisit only if a client ever
      programmatically distinguishes the two codes.
- [x] **Usage flags are not enforced — decide and document** — resolved
      2026-07-15 the compliant way, after measuring SoftHSM 2.6.1 (probe via
      rust-cryptoki against the nix-store module): SoftHSM *enforces* the
      flags (`CKR_KEY_FUNCTION_NOT_PERMITTED` on explicit false) but
      *defaults omitted flags to true* — EC private key: Sign/Decrypt/Unwrap
      true, Derive false, Sensitive false, Extractable false; AES secret key:
      Sign/Verify/Encrypt/Decrypt/Wrap/Unwrap true, Derive/Sensitive/
      Extractable false. The spec makes these defaults token-specific, so
      nl-wallet's templates were never out of spec — they rely on permissive
      defaults, and the wrapped-then-unwrapped key demonstrably gets
      `CKA_SIGN = true` from the unwrap template's defaults on SoftHSM (flags
      don't travel in the wrapped blob). rustssm now does the same: usage-flag
      class defaults flipped to true (`CKA_SENSITIVE` stays true — safe-side
      deviation from SoftHSM; `CKA_EXTRACTABLE`/`CKA_DERIVE` stay false), and
      all six operation entry points enforce via `check_key_usage`
      (sign/verify/encrypt/decrypt init + wrap/unwrap key), new
      `HsmError::KeyFunctionNotPermitted` → `CKR_KEY_FUNCTION_NOT_PERMITTED`.
      Enforcement blocks only an explicitly-false stored flag; an absent flag
      (one the class doesn't define) never blocks, which keeps ECDSA
      verify-via-private-key-handle working (private keys carry no
      `CKA_VERIFY`). Covered by `operations_reject_keys_that_opt_out_of_usage`
      and `unwrapped_key_gets_the_unwrap_templates_usage_defaults`; README
      documents the policy. rust-cryptoki baseline unchanged, nl-wallet 5/5
      (including `wrap_key_and_sign`).
- [x] **`C_SetAttributeValue` skips the one-way guarantees** — the set path
      now enforces the same one-way guarantees as `C_CopyObject`:
      `CKA_SENSITIVE` true→false and `CKA_EXTRACTABLE` false→true are rejected
      with `CKR_ATTRIBUTE_READ_ONLY` (matching SoftHSM). With both callers
      enforcing, the `enforce_one_way` flag on `apply_attribute_updates` was
      dead and removed. Covered by
      `set_object_attributes_enforces_one_way_guarantees`; the rust-cryptoki
      `update_attributes_key` test (the suite's main `C_SetAttributeValue`
      consumer) still passes and the suite baseline is unchanged.
- [x] **`generate_key_pair` writes the two halves without a transaction** —
      fixed with `ObjectStore::write_pair` (both `INSERT`s inside one
      transaction) routed through `Session::write_object_pair`, used by both
      `generate_key_pair` arms. When both halves are token objects the write
      is transactional, so a crash-only abort between them can no longer leave
      an orphaned single key; mixed and session pairs write independently, as
      at most one half reaches the store and an in-memory half dies with the
      process regardless of order. Covered by `write_pair_persists_both_halves`
      (store) and `generate_token_key_pair_persists_both_halves` (hsm);
      rust-cryptoki baseline unchanged, nl-wallet suite 5/5.
- [x] **`C_Initialize` purges *all* session objects — a single-process
      assumption** — fixed by moving session objects to an in-memory
      per-slot store (`SessionObjects` in `session.rs`), matching SoftHSM
      semantics. Session objects never touch SQLite: handles are partitioned
      from store rowids by bit 63 (compile-time-asserted 64-bit
      `CK_OBJECT_HANDLE`; store rowids are positive `i64`, so no collision is
      possible), `Session` routes every read/write/copy/delete by handle bit
      or `CKA_TOKEN`, and `C_FindObjects` merges the store scan with the
      in-memory matches under the same template/§4.4/`Unknown` semantics
      (shared `matches_template` in `attribute.rs`). Consequences: the
      cross-process purge and the session-id collision are both
      unrepresentable (each process's session objects live in its own
      memory); crash orphans are impossible by construction, so
      `purge_session_objects`/`delete_session_objects`/the `owner_session`
      column are all deleted; short-lived key material (unwrapped signing
      keys) never reaches disk; and multi-process store sharing is now safe
      for session objects — the devenv-swap blocker is gone. `C_CopyObject`
      remains the one way to change token-ness (a copy is a new object with
      a new handle, and can cross the memory/store boundary in either
      direction); `C_SetAttributeValue` rejects `CKA_TOKEN` as
      `CKR_ATTRIBUTE_READ_ONLY`, since a handle cannot switch stores in
      place. Covered by
      `session_objects_live_in_memory_with_partitioned_handles`,
      `closing_a_session_destroys_only_its_session_objects`,
      `copy_object_moves_across_the_token_boundary`,
      `set_object_attributes_rejects_token_changes`, and the pre-existing
      `session_objects_do_not_survive_a_restart` (which now passes for a
      stronger reason: the "ephemeral" key never existed on disk). Verified:
      130 local tests, rust-cryptoki 44/32 (unchanged; `session_copy_object`,
      `session_find_objects`, `session_objecthandle_iterator`,
      `update_attributes_key` all still green), nl-wallet 5/5 (including
      `wrap_key_and_sign`, the full session-object lifecycle through the
      r2d2 pool).
