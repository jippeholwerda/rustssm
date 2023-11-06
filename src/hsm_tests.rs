use aes_gcm::aead::Aead;
use aes_gcm::aead::Payload;
use aes_gcm::Aes256Gcm;
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
            Nonce::from_slice(&iv),
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
fn attribute_value_returns_ec_point_of_public_key() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    let (public_key, private_key) = hsm
        .generate_key_pair(session, &Mechanism::EcKeyPairGen, vec![], vec![])
        .unwrap();

    let der = hsm
        .attribute_value(session, public_key, AttributeType::EcPoint)
        .unwrap();

    // DER octet string wrapping a 65-byte uncompressed SEC1 point.
    assert_eq!(der.len(), 67);
    assert_eq!(der[0], 0x04); // OCTET STRING tag
    assert_eq!(der[1], 65); // length
    assert_eq!(der[2], 0x04); // uncompressed point marker

    // The private key is stored as raw bytes and exposes no EC point.
    assert!(matches!(
        hsm.attribute_value(session, private_key, AttributeType::EcPoint),
        Err(HsmError::AttributeTypeInvalid)
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
