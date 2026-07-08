use aes_gcm::aead::Aead;
use aes_gcm::aead::Payload;
use aes_gcm::aes::cipher::consts::U32;
use aes_gcm::aes::Aes256;
use aes_gcm::Aes256Gcm;
use aes_gcm::AesGcm;
use aes_gcm::KeyInit;
use aes_gcm::Nonce;

use super::*;
use crate::attribute::Attribute;
use crate::attribute::AttributeType;
use crate::mechanism::Mechanism;
use crate::object_store::ObjectStore;
use crate::pin::Pin;
use crate::session::SessionState;
use crate::slot::SlotId;
use crate::slot::UserType;

const SO_PIN: &str = "so-pin-123456";
const USER_PIN: &str = "user-pin-123456";
const SLOT: SlotId = SlotId(0);

fn hsm() -> Hsm {
    let hsm = Hsm::with_store(ObjectStore::in_memory().unwrap());
    hsm.initialize().unwrap();
    hsm
}

/// An initialized HSM with an initialized token and a set user PIN,
/// mirroring what `softhsm2-util --init-token` would produce.
fn hsm_with_token() -> Hsm {
    let hsm = hsm();
    hsm.init_token(&SLOT, Pin::new(SO_PIN), Some(String::from("test token")))
        .unwrap();

    let session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();
    hsm.login(session, UserType::So, Pin::new(SO_PIN)).unwrap();
    hsm.init_pin(session, Pin::new(USER_PIN)).unwrap();
    hsm.close_session(session).unwrap();

    hsm
}

fn user_session(hsm: &Hsm) -> SessionId {
    let session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();
    hsm.login(session, UserType::User, Pin::new(USER_PIN)).unwrap();
    session
}

fn generate_secret_key(hsm: &Hsm, session: SessionId, length: u64, label: &str) -> ObjectId {
    hsm.generate_key(
        session,
        &Mechanism::GenericSecretKeyGen,
        vec![
            Attribute::ValueLen(length),
            Attribute::Label(String::from(label)),
            Attribute::Private(true),
        ],
    )
    .unwrap()
}

// ---- lifecycle ---------------------------------------------------------

#[test]
fn initialize_twice_is_rejected() {
    let hsm = hsm();
    assert!(matches!(hsm.initialize(), Err(HsmError::AlreadyInitialized)));
}

#[test]
fn finalize_without_initialize_is_rejected() {
    let hsm = Hsm::with_store(ObjectStore::in_memory().unwrap());
    assert!(matches!(hsm.finalize(), Err(HsmError::NotInitialized)));
}

#[test]
fn operations_require_initialization() {
    let hsm = Hsm::with_store(ObjectStore::in_memory().unwrap());
    assert!(matches!(hsm.slot_ids(), Err(HsmError::NotInitialized)));
    assert!(matches!(
        hsm.open_session(SLOT, SessionState::ReadWrite),
        Err(HsmError::NotInitialized)
    ));
}

#[test]
fn finalize_closes_sessions_and_logs_out() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    hsm.finalize().unwrap();
    hsm.initialize().unwrap();

    assert!(matches!(
        hsm.validate_session(session),
        Err(HsmError::SessionNotFound(_))
    ));
    assert_eq!(hsm.token_status(SLOT).unwrap().session_count, 0);
}

#[test]
fn slot_ids_are_stable_and_sorted() {
    let hsm = hsm();
    assert_eq!(hsm.slot_ids().unwrap(), vec![0, 1, 2, 3]);
}

// ---- token initialization ----------------------------------------------

#[test]
fn init_token_sets_status() {
    let hsm = hsm();
    hsm.init_token(&SLOT, Pin::new(SO_PIN), Some(String::from("my token")))
        .unwrap();

    let status = hsm.token_status(SLOT).unwrap();
    assert!(status.initialized);
    assert!(!status.user_pin_set);
    assert_eq!(status.label.as_deref(), Some("my token"));
}

#[test]
fn init_token_unknown_slot_is_rejected() {
    let hsm = hsm();
    assert!(matches!(
        hsm.init_token(&SlotId(99), Pin::new(SO_PIN), None),
        Err(HsmError::SlotNotFound(_))
    ));
}

#[test]
fn init_token_with_open_session_is_rejected() {
    let hsm = hsm_with_token();
    let _session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();

    assert!(matches!(
        hsm.init_token(&SLOT, Pin::new(SO_PIN), None),
        Err(HsmError::SessionExists(_))
    ));
}

#[test]
fn init_token_destroys_objects_and_resets_user_pin() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = generate_secret_key(&hsm, session, 32, "doomed");
    hsm.close_session(session).unwrap();

    hsm.init_token(&SLOT, Pin::new(SO_PIN), None).unwrap();

    assert!(!hsm.token_status(SLOT).unwrap().user_pin_set);
    let session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();
    assert!(!hsm.object_exists(session, key).unwrap());
}

#[test]
fn token_state_survives_a_restart() {
    let path = std::env::temp_dir().join(format!("rustssm-persist-{}.db", std::process::id()));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }

    // First boot: initialize the token and set the user PIN, then drop the
    // HSM (closing its database connection).
    {
        let hsm = Hsm::with_store(ObjectStore::at_path(&path).unwrap());
        hsm.initialize().unwrap();
        hsm.init_token(&SLOT, Pin::new(SO_PIN), Some(String::from("persisted")))
            .unwrap();

        let session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();
        hsm.login(session, UserType::So, Pin::new(SO_PIN)).unwrap();
        hsm.init_pin(session, Pin::new(USER_PIN)).unwrap();
    }

    // Second boot: a fresh HSM over the same database file must see the token
    // and accept the same PINs.
    {
        let hsm = Hsm::with_store(ObjectStore::at_path(&path).unwrap());
        hsm.initialize().unwrap();

        let status = hsm.token_status(SLOT).unwrap();
        assert!(status.initialized);
        assert!(status.user_pin_set);
        assert_eq!(status.label.as_deref(), Some("persisted"));

        let session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();
        hsm.login(session, UserType::User, Pin::new(USER_PIN)).unwrap();
        hsm.logout(session).unwrap();
        assert!(matches!(
            hsm.login(session, UserType::User, Pin::new("wrong")),
            Err(HsmError::PinIncorrect)
        ));

        // PINs are persisted as hashes, never as plaintext.
        let tokens = hsm.object_store().unwrap().load_tokens().unwrap();
        let record = tokens.iter().find(|token| token.slot_id == SLOT.0).unwrap();
        assert_ne!(record.so_pin_hash, SO_PIN);
        assert_ne!(record.user_pin_hash.as_deref(), Some(USER_PIN));
    }

    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

// ---- sessions ------------------------------------------------------------

#[test]
fn open_session_unknown_slot_is_rejected() {
    let hsm = hsm();
    assert!(matches!(
        hsm.open_session(SlotId(99), SessionState::ReadWrite),
        Err(HsmError::SlotNotFound(_))
    ));
}

#[test]
fn close_session_twice_is_rejected() {
    let hsm = hsm_with_token();
    let session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();

    hsm.close_session(session).unwrap();
    assert!(matches!(hsm.close_session(session), Err(HsmError::SessionNotFound(_))));
}

#[test]
fn closing_last_session_logs_out() {
    let hsm = hsm_with_token();
    let first = user_session(&hsm);
    let second = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();

    // Login state is per token: the second session sees the user login.
    assert_eq!(hsm.session_info(second).unwrap().user, Some(UserType::User));

    hsm.close_session(first).unwrap();
    assert_eq!(hsm.session_info(second).unwrap().user, Some(UserType::User));

    hsm.close_session(second).unwrap();
    let third = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();
    assert_eq!(hsm.session_info(third).unwrap().user, None);
}

#[test]
fn session_info_reflects_state_and_user() {
    let hsm = hsm_with_token();

    let ro_session = hsm.open_session(SLOT, SessionState::ReadOnly).unwrap();
    let info = hsm.session_info(ro_session).unwrap();
    assert_eq!(info.slot_id, SLOT.0);
    assert!(!info.read_write);
    assert_eq!(info.user, None);

    hsm.login(ro_session, UserType::User, Pin::new(USER_PIN)).unwrap();
    assert_eq!(hsm.session_info(ro_session).unwrap().user, Some(UserType::User));

    let rw_session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();
    assert!(hsm.session_info(rw_session).unwrap().read_write);
}

#[test]
fn read_only_session_cannot_be_opened_while_so_is_logged_in() {
    let hsm = hsm_with_token();
    let session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();
    hsm.login(session, UserType::So, Pin::new(SO_PIN)).unwrap();

    assert!(matches!(
        hsm.open_session(SLOT, SessionState::ReadOnly),
        Err(HsmError::SessionReadOnlyExists)
    ));
}

// ---- authentication --------------------------------------------------------

#[test]
fn login_with_wrong_pin_is_rejected() {
    let hsm = hsm_with_token();
    let session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();

    assert!(matches!(
        hsm.login(session, UserType::So, Pin::new("wrong")),
        Err(HsmError::PinIncorrect)
    ));
    assert!(matches!(
        hsm.login(session, UserType::User, Pin::new("wrong")),
        Err(HsmError::PinIncorrect)
    ));
}

#[test]
fn login_twice_is_rejected() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    assert!(matches!(
        hsm.login(session, UserType::User, Pin::new(USER_PIN)),
        Err(HsmError::UserAlreadyLoggedIn)
    ));
    assert!(matches!(
        hsm.login(session, UserType::So, Pin::new(SO_PIN)),
        Err(HsmError::UserAnotherAlreadyLoggedIn)
    ));
}

#[test]
fn user_login_requires_initialized_pin() {
    let hsm = hsm();
    hsm.init_token(&SLOT, Pin::new(SO_PIN), None).unwrap();
    let session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();

    assert!(matches!(
        hsm.login(session, UserType::User, Pin::new(USER_PIN)),
        Err(HsmError::UserPinNotInitialized)
    ));
}

#[test]
fn so_login_is_blocked_by_read_only_session() {
    let hsm = hsm_with_token();
    let _ro_session = hsm.open_session(SLOT, SessionState::ReadOnly).unwrap();
    let rw_session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();

    assert!(matches!(
        hsm.login(rw_session, UserType::So, Pin::new(SO_PIN)),
        Err(HsmError::SessionReadOnlyExists)
    ));
}

#[test]
fn logout_without_login_is_rejected() {
    let hsm = hsm_with_token();
    let session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();

    assert!(matches!(hsm.logout(session), Err(HsmError::UserNotLoggedIn)));
}

#[test]
fn init_pin_requires_so_in_read_write_session() {
    let hsm = hsm_with_token();

    let session = user_session(&hsm);
    assert!(matches!(
        hsm.init_pin(session, Pin::new("newpin")),
        Err(HsmError::UserNotLoggedIn)
    ));
    hsm.close_session(session).unwrap();

    let ro_session = hsm.open_session(SLOT, SessionState::ReadOnly).unwrap();
    assert!(matches!(
        hsm.init_pin(ro_session, Pin::new("newpin")),
        Err(HsmError::UserNotLoggedIn)
    ));
}

#[test]
fn set_pin_changes_the_pin_of_the_logged_in_user() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    hsm.set_pin(session, Pin::new(USER_PIN), Pin::new("new-user-pin"))
        .unwrap();
    hsm.logout(session).unwrap();

    assert!(matches!(
        hsm.login(session, UserType::User, Pin::new(USER_PIN)),
        Err(HsmError::PinIncorrect)
    ));
    hsm.login(session, UserType::User, Pin::new("new-user-pin")).unwrap();
}

#[test]
fn set_pin_with_wrong_old_pin_is_rejected() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    assert!(matches!(
        hsm.set_pin(session, Pin::new("wrong"), Pin::new("new")),
        Err(HsmError::PinIncorrect)
    ));
}

#[test]
fn set_pin_requires_read_write_session() {
    let hsm = hsm_with_token();
    let session = hsm.open_session(SLOT, SessionState::ReadOnly).unwrap();

    assert!(matches!(
        hsm.set_pin(session, Pin::new(USER_PIN), Pin::new("new")),
        Err(HsmError::SessionReadOnly)
    ));
}

// ---- key generation -------------------------------------------------------

#[test]
fn generate_generic_secret_key_roundtrip() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    let key = generate_secret_key(&hsm, session, 32, "secret");
    assert!(hsm.object_exists(session, key).unwrap());
}

#[test]
fn generate_aes_key_produces_usable_key() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    for length in [16, 24, 32] {
        let key = hsm
            .generate_key(
                session,
                &Mechanism::AesKeyGen,
                vec![Attribute::ValueLen(length), Attribute::Label(String::from("aes"))],
            )
            .unwrap();

        let key_bytes: Vec<u8> = hsm.object_store().unwrap().read(&key).unwrap();
        assert_eq!(key_bytes.len(), length as usize);
    }
}

#[test]
fn generate_aes_key_rejects_non_aes_lengths() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    for length in [0, 8, 20, 64] {
        assert!(matches!(
            hsm.generate_key(session, &Mechanism::AesKeyGen, vec![Attribute::ValueLen(length)]),
            Err(HsmError::AttributeValueInvalid)
        ));
    }
}

#[test]
fn generate_aes_key_requires_value_length() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    assert!(matches!(
        hsm.generate_key(session, &Mechanism::AesKeyGen, vec![]),
        Err(HsmError::TemplateIncomplete)
    ));
}

#[test]
fn generated_aes_key_encrypts_under_gcm() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    let key = hsm
        .generate_key(session, &Mechanism::AesKeyGen, vec![Attribute::ValueLen(32)])
        .unwrap();

    let mechanism = Mechanism::AesGcm {
        initialization_vector: vec![0x24; 12],
        additional_authenticated_data: vec![],
    };
    hsm.encrypt_init(session, &mechanism, key).unwrap();
    let ciphertext = hsm.encrypt(session, b"secret payload").unwrap();

    assert_eq!(ciphertext.len(), b"secret payload".len() + AES_GCM_TAG_LENGTH);
}

#[test]
fn generate_key_requires_value_length() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    assert!(matches!(
        hsm.generate_key(session, &Mechanism::GenericSecretKeyGen, vec![]),
        Err(HsmError::TemplateIncomplete)
    ));
}

#[test]
fn generate_key_bounds_value_length() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    for length in [0, MAX_SECRET_KEY_LENGTH + 1] {
        assert!(matches!(
            hsm.generate_key(
                session,
                &Mechanism::GenericSecretKeyGen,
                vec![Attribute::ValueLen(length)],
            ),
            Err(HsmError::AttributeValueInvalid)
        ));
    }
}

#[test]
fn generate_key_rejects_wrong_mechanism() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    assert!(matches!(
        hsm.generate_key(session, &Mechanism::Ecdsa, vec![Attribute::ValueLen(32)]),
        Err(HsmError::MechanismInvalid)
    ));
}

#[test]
fn token_objects_cannot_be_created_in_read_only_session() {
    let hsm = hsm_with_token();
    let session = hsm.open_session(SLOT, SessionState::ReadOnly).unwrap();

    assert!(matches!(
        hsm.generate_key(
            session,
            &Mechanism::GenericSecretKeyGen,
            vec![Attribute::ValueLen(32), Attribute::Token(true)],
        ),
        Err(HsmError::SessionReadOnly)
    ));
}

#[test]
fn generate_rsa_key_pair_requires_modulus_bits() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    assert!(matches!(
        hsm.generate_key_pair(session, &Mechanism::RsaPkcsKeyPairGen, vec![], vec![]),
        Err(HsmError::TemplateIncomplete)
    ));
}

#[test]
fn generate_rsa_key_pair_bounds_modulus_bits() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    for bits in [0, MIN_RSA_MODULUS_BITS - 1, MAX_RSA_MODULUS_BITS + 1] {
        assert!(matches!(
            hsm.generate_key_pair(
                session,
                &Mechanism::RsaPkcsKeyPairGen,
                vec![Attribute::ModulusBits(bits)],
                vec![],
            ),
            Err(HsmError::AttributeValueInvalid)
        ));
    }
}

// ---- sign / verify ---------------------------------------------------------

#[test]
fn rsa_sign_verify_roundtrip() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    let (public_key, private_key) = hsm
        .generate_key_pair(
            session,
            &Mechanism::RsaPkcsKeyPairGen,
            vec![Attribute::ModulusBits(MIN_RSA_MODULUS_BITS)],
            vec![],
        )
        .unwrap();

    let data = b"data to sign";

    hsm.sign_init(session, &Mechanism::RsaPkcs, private_key).unwrap();
    assert_eq!(hsm.signature_length(session).unwrap(), MIN_RSA_MODULUS_BITS / 8);
    let signature = hsm.sign(session, data).unwrap();

    hsm.verify_init(session, &Mechanism::RsaPkcs, public_key).unwrap();
    hsm.verify(session, data, &signature).unwrap();
}

#[test]
fn ecdsa_sign_verify_roundtrip_and_tamper_detection() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    let (public_key, private_key) = hsm
        .generate_key_pair(session, &Mechanism::EcKeyPairGen, vec![], vec![])
        .unwrap();

    // CKM_ECDSA signs a message digest; use a 32-byte value.
    let digest = [0x5Au8; 32];

    hsm.sign_init(session, &Mechanism::Ecdsa, private_key.clone()).unwrap();
    assert_eq!(hsm.signature_length(session).unwrap(), 64);
    let signature = hsm.sign(session, &digest).unwrap();

    hsm.verify_init(session, &Mechanism::Ecdsa, public_key.clone()).unwrap();
    hsm.verify(session, &digest, &signature).unwrap();

    let mut tampered = signature.clone();
    tampered[0] ^= 0xFF;
    hsm.verify_init(session, &Mechanism::Ecdsa, public_key).unwrap();
    assert!(matches!(
        hsm.verify(session, &digest, &tampered),
        Err(HsmError::SignatureInvalid)
    ));
}

#[test]
fn hmac_sign_verify_roundtrip() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = generate_secret_key(&hsm, session, 32, "hmac key");

    let data = b"authenticated message";

    hsm.sign_init(session, &Mechanism::Sha256Hmac, key.clone()).unwrap();
    assert_eq!(hsm.signature_length(session).unwrap(), 32);
    let mac = hsm.sign(session, data).unwrap();

    hsm.verify_init(session, &Mechanism::Sha256Hmac, key.clone()).unwrap();
    hsm.verify(session, data, &mac).unwrap();

    hsm.verify_init(session, &Mechanism::Sha256Hmac, key).unwrap();
    assert!(matches!(
        hsm.verify(session, b"other message", &mac),
        Err(HsmError::SignatureInvalid)
    ));
}

#[test]
fn sign_without_init_is_rejected() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    assert!(matches!(
        hsm.signature_length(session),
        Err(HsmError::OperationNotInitialized)
    ));
    assert!(matches!(
        hsm.sign(session, b"data"),
        Err(HsmError::OperationNotInitialized)
    ));
}

#[test]
fn sign_init_twice_is_rejected() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = generate_secret_key(&hsm, session, 32, "hmac key");

    hsm.sign_init(session, &Mechanism::Sha256Hmac, key.clone()).unwrap();
    assert!(matches!(
        hsm.sign_init(session, &Mechanism::Sha256Hmac, key),
        Err(HsmError::OperationActive)
    ));
}

#[test]
fn verify_with_sign_operation_is_rejected() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = generate_secret_key(&hsm, session, 32, "hmac key");

    hsm.sign_init(session, &Mechanism::Sha256Hmac, key).unwrap();
    assert!(matches!(
        hsm.verify(session, b"data", b"signature"),
        Err(HsmError::OperationNotInitialized)
    ));
}

#[test]
fn sign_init_with_invalid_key_handle_is_rejected() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    assert!(matches!(
        hsm.sign_init(session, &Mechanism::Sha256Hmac, ObjectId::new(4242)),
        Err(HsmError::KeyHandleInvalid)
    ));
}

// ---- encryption ------------------------------------------------------------

#[test]
fn aes_gcm_encryption_matches_reference_implementation() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = generate_secret_key(&hsm, session, 32, "aes key");

    let key_bytes: Vec<u8> = hsm.object_store().unwrap().read(&key).unwrap();
    let iv = [0x42u8; 12];
    let aad = b"header".to_vec();
    let plaintext = b"attack at dawn";

    let mechanism = Mechanism::AesGcm {
        initialization_vector: iv.to_vec(),
        additional_authenticated_data: aad.clone(),
    };

    hsm.encrypt_init(session, &mechanism, key).unwrap();
    assert_eq!(
        hsm.encrypted_length(session, plaintext.len() as u64).unwrap(),
        plaintext.len() as u64 + AES_GCM_TAG_LENGTH as u64
    );
    let ciphertext = hsm.encrypt(session, plaintext).unwrap();

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).unwrap();
    let decrypted = cipher
        .decrypt(
            &Nonce::try_from(&iv[..]).unwrap(),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn aes_gcm_rejects_invalid_key_sizes() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = generate_secret_key(&hsm, session, 24, "wrong size");

    let mechanism = Mechanism::AesGcm {
        initialization_vector: vec![0; 12],
        additional_authenticated_data: vec![],
    };

    assert!(matches!(
        hsm.encrypt_init(session, &mechanism, key),
        Err(HsmError::KeySizeRange)
    ));
}

#[test]
fn aes_gcm_encrypt_decrypt_roundtrip() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = generate_secret_key(&hsm, session, 32, "aes key");

    let mechanism = Mechanism::AesGcm {
        initialization_vector: vec![0x42; 12],
        additional_authenticated_data: b"header".to_vec(),
    };
    let plaintext = b"attack at dawn";

    hsm.encrypt_init(session, &mechanism, key.clone()).unwrap();
    let ciphertext = hsm.encrypt(session, plaintext).unwrap();

    hsm.decrypt_init(session, &mechanism, key).unwrap();
    assert_eq!(
        hsm.decrypted_length(session, ciphertext.len() as u64).unwrap(),
        plaintext.len() as u64
    );
    let decrypted = hsm.decrypt(session, &ciphertext).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn aes_gcm_with_32_byte_iv_roundtrips_and_matches_reference() {
    // A 32-byte IV is processed by AES-GCM via GHASH rather than the 96-bit
    // fast path.
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = generate_secret_key(&hsm, session, 32, "aes key");
    let key_bytes: Vec<u8> = hsm.object_store().unwrap().read(&key).unwrap();

    let iv = [0x17u8; 32];
    let plaintext = b"attack at dawn";
    let mechanism = Mechanism::AesGcm {
        initialization_vector: iv.to_vec(),
        additional_authenticated_data: vec![],
    };

    hsm.encrypt_init(session, &mechanism, key.clone()).unwrap();
    let ciphertext = hsm.encrypt(session, plaintext).unwrap();

    // Cross-check against a reference AES-256-GCM with a 32-byte nonce.
    let reference = AesGcm::<Aes256, U32>::new_from_slice(&key_bytes).unwrap();
    let expected = reference
        .encrypt(
            &Nonce::<U32>::try_from(&iv[..]).unwrap(),
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .unwrap();
    assert_eq!(ciphertext, expected);

    // And decrypts back through the HSM.
    hsm.decrypt_init(session, &mechanism, key).unwrap();
    let decrypted = hsm.decrypt(session, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn aes_gcm_decrypt_detects_tampering() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = generate_secret_key(&hsm, session, 32, "aes key");

    let mechanism = Mechanism::AesGcm {
        initialization_vector: vec![0x42; 12],
        additional_authenticated_data: b"header".to_vec(),
    };

    hsm.encrypt_init(session, &mechanism, key.clone()).unwrap();
    let mut ciphertext = hsm.encrypt(session, b"attack at dawn").unwrap();
    ciphertext[0] ^= 0xFF;

    hsm.decrypt_init(session, &mechanism, key.clone()).unwrap();
    assert!(matches!(
        hsm.decrypt(session, &ciphertext),
        Err(HsmError::EncryptedDataInvalid)
    ));

    // Decrypting under the wrong AAD must also fail authentication.
    hsm.encrypt_init(session, &mechanism, key.clone()).unwrap();
    let ciphertext = hsm.encrypt(session, b"attack at dawn").unwrap();
    let wrong_aad = Mechanism::AesGcm {
        initialization_vector: vec![0x42; 12],
        additional_authenticated_data: b"other".to_vec(),
    };
    hsm.decrypt_init(session, &wrong_aad, key).unwrap();
    assert!(matches!(
        hsm.decrypt(session, &ciphertext),
        Err(HsmError::EncryptedDataInvalid)
    ));
}

#[test]
fn decrypt_rejects_ciphertext_shorter_than_tag() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = generate_secret_key(&hsm, session, 32, "aes key");

    let mechanism = Mechanism::AesGcm {
        initialization_vector: vec![0x42; 12],
        additional_authenticated_data: vec![],
    };
    hsm.decrypt_init(session, &mechanism, key).unwrap();

    assert!(matches!(
        hsm.decrypted_length(session, (AES_GCM_TAG_LENGTH - 1) as u64),
        Err(HsmError::EncryptedDataLenRange)
    ));
}

#[test]
fn decrypt_without_init_is_rejected() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    assert!(matches!(
        hsm.decrypted_length(session, 32),
        Err(HsmError::OperationNotInitialized)
    ));
    assert!(matches!(
        hsm.decrypt(session, b"data"),
        Err(HsmError::OperationNotInitialized)
    ));
}

#[test]
fn decrypt_init_rejects_invalid_key_size() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = generate_secret_key(&hsm, session, 24, "wrong size");

    let mechanism = Mechanism::AesGcm {
        initialization_vector: vec![0x42; 12],
        additional_authenticated_data: vec![],
    };
    assert!(matches!(
        hsm.decrypt_init(session, &mechanism, key),
        Err(HsmError::KeySizeRange)
    ));
}

#[test]
fn encrypt_init_rejects_non_encryption_mechanism() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = generate_secret_key(&hsm, session, 32, "aes key");

    assert!(matches!(
        hsm.encrypt_init(session, &Mechanism::Sha256Hmac, key),
        Err(HsmError::MechanismInvalid)
    ));
}

#[test]
fn encrypt_without_init_is_rejected() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    assert!(matches!(
        hsm.encrypted_length(session, 16),
        Err(HsmError::OperationNotInitialized)
    ));
    assert!(matches!(
        hsm.encrypt(session, b"data"),
        Err(HsmError::OperationNotInitialized)
    ));
}

// ---- wrap / unwrap -----------------------------------------------------------

#[test]
fn wrap_unwrap_roundtrip() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let wrapping_key = generate_secret_key(&hsm, session, 32, "kek");
    let key = generate_secret_key(&hsm, session, 32, "payload");

    let wrapped = hsm
        .wrap_key(session, &Mechanism::AesKeyWrapPad, wrapping_key.clone(), key)
        .unwrap();

    let unwrapped = hsm
        .unwrap_key(
            session,
            &Mechanism::AesKeyWrapPad,
            wrapping_key.clone(),
            &wrapped,
            vec![],
        )
        .unwrap();

    // AES-KWP is deterministic: wrapping the unwrapped key again must yield
    // the identical ciphertext.
    let rewrapped = hsm
        .wrap_key(session, &Mechanism::AesKeyWrapPad, wrapping_key, unwrapped)
        .unwrap();
    assert_eq!(wrapped, rewrapped);
}

#[test]
fn wrap_with_wrong_size_kek_is_rejected() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let wrapping_key = generate_secret_key(&hsm, session, 16, "short kek");
    let key = generate_secret_key(&hsm, session, 32, "payload");

    assert!(matches!(
        hsm.wrap_key(session, &Mechanism::AesKeyWrapPad, wrapping_key, key),
        Err(HsmError::WrappingKeySizeRange)
    ));
}

#[test]
fn wrap_with_invalid_handles_is_rejected() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = generate_secret_key(&hsm, session, 32, "payload");

    assert!(matches!(
        hsm.wrap_key(session, &Mechanism::AesKeyWrapPad, ObjectId::new(4242), key.clone()),
        Err(HsmError::WrappingKeyHandleInvalid)
    ));
    assert!(matches!(
        hsm.wrap_key(session, &Mechanism::AesKeyWrapPad, key, ObjectId::new(4242)),
        Err(HsmError::KeyHandleInvalid)
    ));
}

#[test]
fn unwrap_garbage_is_rejected() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let wrapping_key = generate_secret_key(&hsm, session, 32, "kek");

    assert!(matches!(
        hsm.unwrap_key(session, &Mechanism::AesKeyWrapPad, wrapping_key, &[0u8; 40], vec![],),
        Err(HsmError::WrappedKeyInvalid)
    ));
}

// ---- objects and search ------------------------------------------------------

#[test]
fn find_objects_by_label() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    generate_secret_key(&hsm, session, 32, "needle");
    generate_secret_key(&hsm, session, 32, "haystack");
    generate_secret_key(&hsm, session, 32, "needle");

    hsm.find_objects_init(session, vec![Attribute::Label(String::from("needle"))])
        .unwrap();
    let found = hsm.find_objects_next(session, 10).unwrap();
    hsm.find_objects_final(session).unwrap();

    assert_eq!(found.len(), 2);
}

#[test]
fn find_objects_respects_max_count_and_drains() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    for _ in 0..3 {
        generate_secret_key(&hsm, session, 32, "key");
    }

    hsm.find_objects_init(session, vec![Attribute::Label(String::from("key"))])
        .unwrap();
    assert_eq!(hsm.find_objects_next(session, 2).unwrap().len(), 2);
    assert_eq!(hsm.find_objects_next(session, 2).unwrap().len(), 1);
    assert_eq!(hsm.find_objects_next(session, 2).unwrap().len(), 0);
    hsm.find_objects_final(session).unwrap();
}

#[test]
fn find_objects_requires_active_search() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    assert!(matches!(
        hsm.find_objects_next(session, 1),
        Err(HsmError::OperationNotInitialized)
    ));
    assert!(matches!(
        hsm.find_objects_final(session),
        Err(HsmError::OperationNotInitialized)
    ));
}

#[test]
fn find_objects_init_twice_is_rejected() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    hsm.find_objects_init(session, vec![]).unwrap();
    assert!(matches!(
        hsm.find_objects_init(session, vec![]),
        Err(HsmError::OperationActive)
    ));
}

#[test]
fn create_secret_key_object_is_stored_and_usable() {
    use crate::attribute::ObjectClass;

    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    let key_bytes = vec![0x2Bu8; 32];
    let object = hsm
        .create_object(
            session,
            vec![
                Attribute::Class(ObjectClass::SecretKey),
                Attribute::Value(key_bytes.clone()),
                Attribute::Label(String::from("created")),
                Attribute::Token(true),
                Attribute::Private(true),
            ],
        )
        .unwrap();

    // Stored verbatim and usable as an AES key.
    let stored: Vec<u8> = hsm.object_store().unwrap().read(&object).unwrap();
    assert_eq!(stored, key_bytes);

    hsm.find_objects_init(session, vec![Attribute::Label(String::from("created"))])
        .unwrap();
    let found = hsm.find_objects_next(session, 10).unwrap();
    hsm.find_objects_final(session).unwrap();
    assert_eq!(found, vec![object]);
}

#[test]
fn create_object_rejects_bad_templates() {
    use crate::attribute::ObjectClass;

    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    // Missing CKA_CLASS.
    assert!(matches!(
        hsm.create_object(session, vec![Attribute::Value(vec![0u8; 32])]),
        Err(HsmError::TemplateIncomplete)
    ));
    // Secret key without CKA_VALUE.
    assert!(matches!(
        hsm.create_object(session, vec![Attribute::Class(ObjectClass::SecretKey)]),
        Err(HsmError::TemplateIncomplete)
    ));
    // Empty value.
    assert!(matches!(
        hsm.create_object(
            session,
            vec![Attribute::Class(ObjectClass::SecretKey), Attribute::Value(vec![])],
        ),
        Err(HsmError::AttributeValueInvalid)
    ));
    // Unsupported object class (parsed as Unknown).
    assert!(matches!(
        hsm.create_object(
            session,
            vec![Attribute::Class(ObjectClass::Unknown), Attribute::Value(vec![0u8; 32])],
        ),
        Err(HsmError::TemplateInconsistent)
    ));
}

#[test]
fn create_token_object_in_read_only_session_is_rejected() {
    use crate::attribute::ObjectClass;

    let hsm = hsm_with_token();
    let session = hsm.open_session(SLOT, SessionState::ReadOnly).unwrap();

    assert!(matches!(
        hsm.create_object(
            session,
            vec![
                Attribute::Class(ObjectClass::SecretKey),
                Attribute::Value(vec![0u8; 32]),
                Attribute::Token(true),
            ],
        ),
        Err(HsmError::SessionReadOnly)
    ));
}

#[test]
fn destroy_object_removes_it() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = generate_secret_key(&hsm, session, 32, "doomed");

    hsm.destroy_object(session, key.clone()).unwrap();

    assert!(!hsm.object_exists(session, key.clone()).unwrap());
    assert!(matches!(
        hsm.destroy_object(session, key),
        Err(HsmError::ObjectHandleInvalid)
    ));
}

#[test]
fn object_attribute_returns_ec_point_of_public_key() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    let (public_key, private_key) = hsm
        .generate_key_pair(session, &Mechanism::EcKeyPairGen, vec![], vec![])
        .unwrap();

    let Some(Attribute::EcPoint(der)) = hsm
        .object_attribute(session, public_key.clone(), AttributeType::EcPoint)
        .unwrap()
    else {
        panic!("public key should expose an EC point");
    };

    // DER octet string wrapping a 65-byte uncompressed SEC1 point.
    assert_eq!(der.len(), 67);
    assert_eq!(der[0], 0x04); // OCTET STRING tag
    assert_eq!(der[1], 65); // length
    assert_eq!(der[2], 0x04); // uncompressed point marker

    // The private key carries no EC point.
    assert_eq!(
        hsm.object_attribute(session, private_key.clone(), AttributeType::EcPoint)
            .unwrap(),
        None
    );

    // Synthesized class and key type are readable on both halves.
    assert_eq!(
        hsm.object_attribute(session, public_key, AttributeType::Class).unwrap(),
        Some(Attribute::Class(crate::attribute::ObjectClass::PublicKey))
    );
    assert_eq!(
        hsm.object_attribute(session, private_key, AttributeType::KeyType)
            .unwrap(),
        Some(Attribute::KeyType(crate::attribute::KeyType::Ec))
    );
}

#[test]
fn generated_aes_keys_are_searchable_by_synthesized_and_template_attributes() {
    use crate::attribute::KeyType;
    use crate::attribute::ObjectClass;

    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    // Three AES keys sharing a CKA_ID, plus one decoy with a different id.
    for label in ["a", "b", "c"] {
        hsm.generate_key(
            session,
            &Mechanism::AesKeyGen,
            vec![
                Attribute::Token(true),
                Attribute::ValueLen(32),
                Attribute::Label(String::from(label)),
                Attribute::Id(b"shared".to_vec()),
            ],
        )
        .unwrap();
    }
    hsm.generate_key(
        session,
        &Mechanism::AesKeyGen,
        vec![Attribute::ValueLen(16), Attribute::Id(b"other".to_vec())],
    )
    .unwrap();

    // Search by the token-synthesized class/key-type plus the template id.
    hsm.find_objects_init(
        session,
        vec![
            Attribute::Token(true),
            Attribute::Id(b"shared".to_vec()),
            Attribute::Class(ObjectClass::SecretKey),
            Attribute::KeyType(KeyType::Aes),
        ],
    )
    .unwrap();
    let found = hsm.find_objects_next(session, 10).unwrap();
    hsm.find_objects_final(session).unwrap();
    assert_eq!(found.len(), 3);

    // The synthesized class and key type read back on a found object.
    let key = found[0].clone();
    assert_eq!(
        hsm.object_attribute(session, key.clone(), AttributeType::Class)
            .unwrap(),
        Some(Attribute::Class(ObjectClass::SecretKey))
    );
    assert_eq!(
        hsm.object_attribute(session, key.clone(), AttributeType::KeyType)
            .unwrap(),
        Some(Attribute::KeyType(KeyType::Aes))
    );
    // A template attribute reads back verbatim.
    assert_eq!(
        hsm.object_attribute(session, key, AttributeType::Id).unwrap(),
        Some(Attribute::Id(b"shared".to_vec()))
    );
}

#[test]
fn generated_rsa_public_key_exposes_derived_attributes() {
    use crate::attribute::KeyType;
    use crate::attribute::ObjectClass;

    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    let (public_key, _private_key) = hsm
        .generate_key_pair(
            session,
            &Mechanism::RsaPkcsKeyPairGen,
            vec![
                Attribute::ModulusBits(2048),
                Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
            ],
            vec![],
        )
        .unwrap();

    assert_eq!(
        hsm.object_attribute(session, public_key.clone(), AttributeType::Class)
            .unwrap(),
        Some(Attribute::Class(ObjectClass::PublicKey))
    );
    assert_eq!(
        hsm.object_attribute(session, public_key.clone(), AttributeType::KeyType)
            .unwrap(),
        Some(Attribute::KeyType(KeyType::Rsa))
    );
    // The public exponent the caller supplied is preserved.
    assert_eq!(
        hsm.object_attribute(session, public_key.clone(), AttributeType::PublicExponent)
            .unwrap(),
        Some(Attribute::PublicExponent(vec![0x01, 0x00, 0x01]))
    );
    // The modulus is derived from the generated key: 2048 bits => 256 bytes.
    let Some(Attribute::Modulus(modulus)) = hsm
        .object_attribute(session, public_key, AttributeType::Modulus)
        .unwrap()
    else {
        panic!("public key should expose a modulus");
    };
    assert_eq!(modulus.len(), 256);
}

#[test]
fn set_object_attributes_updates_readable_value() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    let (_public_key, private_key) = hsm
        .generate_key_pair(
            session,
            &Mechanism::RsaPkcsKeyPairGen,
            vec![
                Attribute::ModulusBits(2048),
                Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
            ],
            vec![Attribute::Token(true), Attribute::Extractable(true)],
        )
        .unwrap();

    assert_eq!(
        hsm.object_attribute(session, private_key.clone(), AttributeType::Extractable)
            .unwrap(),
        Some(Attribute::Extractable(true))
    );

    hsm.set_object_attributes(session, private_key.clone(), vec![Attribute::Extractable(false)])
        .unwrap();

    assert_eq!(
        hsm.object_attribute(session, private_key, AttributeType::Extractable)
            .unwrap(),
        Some(Attribute::Extractable(false))
    );
}

#[test]
fn set_object_attributes_rejects_read_only_and_unknown() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = generate_secret_key(&hsm, session, 32, "target");

    // Identity/key-material attributes are read-only.
    assert!(matches!(
        hsm.set_object_attributes(session, key.clone(), vec![Attribute::ValueLen(16)]),
        Err(HsmError::AttributeReadOnly)
    ));
    // Untracked attribute types are invalid.
    assert!(matches!(
        hsm.set_object_attributes(session, key.clone(), vec![Attribute::Unknown]),
        Err(HsmError::AttributeTypeInvalid)
    ));

    // A rejected update leaves the object unchanged.
    assert_eq!(
        hsm.object_attribute(session, key, AttributeType::ValueLen).unwrap(),
        Some(Attribute::ValueLen(32))
    );
}

#[test]
fn set_object_attributes_on_token_object_needs_read_write_session() {
    let hsm = hsm_with_token();
    let rw = user_session(&hsm);
    let key = hsm
        .generate_key(
            rw,
            &Mechanism::AesKeyGen,
            vec![Attribute::ValueLen(32), Attribute::Token(true)],
        )
        .unwrap();

    // Login is per-slot and already established by `user_session`; a second
    // read-only session shares it.
    let ro = hsm.open_session(SLOT, SessionState::ReadOnly).unwrap();

    assert!(matches!(
        hsm.set_object_attributes(ro, key, vec![Attribute::Extractable(false)]),
        Err(HsmError::SessionReadOnly)
    ));
}

#[test]
fn operations_on_invalid_session_are_rejected() {
    let hsm = hsm_with_token();
    let bogus = SessionId(4242);

    assert!(matches!(hsm.session_info(bogus), Err(HsmError::SessionNotFound(_))));
    assert!(matches!(
        hsm.login(bogus, UserType::User, Pin::new(USER_PIN)),
        Err(HsmError::SessionNotFound(_))
    ));
    assert!(matches!(
        hsm.generate_key(bogus, &Mechanism::GenericSecretKeyGen, vec![]),
        Err(HsmError::SessionNotFound(_))
    ));
    assert!(matches!(hsm.sign(bogus, b"data"), Err(HsmError::SessionNotFound(_))));
}
