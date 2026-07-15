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
use crate::encryption::AES_GCM_TAG_LENGTH;
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

/// Like [`generate_secret_key`] but as a token object, for tests that read
/// the key material back through the persistent store.
fn generate_token_secret_key(hsm: &Hsm, session: SessionId, length: u64, label: &str) -> ObjectId {
    hsm.generate_key(
        session,
        &Mechanism::GenericSecretKeyGen,
        vec![
            Attribute::ValueLen(length),
            Attribute::Label(String::from(label)),
            Attribute::Private(true),
            Attribute::Token(true),
        ],
    )
    .unwrap()
}

// ---- concurrency -------------------------------------------------------

/// Hammers a single shared `Hsm` from many threads, each running full crypto
/// cycles (keygen → sign/verify or encrypt/decrypt → find → destroy) on its
/// own sessions with unique labels. Proves the module is safe under
/// concurrent access: every shared structure is behind a lock or atomic, so
/// concurrent FFI calls serialize internally rather than racing. Wrong
/// locking would surface here as a panic (poisoned lock), a wrong result, or
/// a database error.
#[test]
fn concurrent_sessions_from_many_threads_stay_correct() {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    let hsm = hsm_with_token();

    // Generated keys are private by default, so accessing them by handle
    // requires the normal user. Login is per-token, so one keep-alive session
    // logs the token in for every thread's sessions (§4.4).
    let login_session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();
    hsm.login(login_session, UserType::User, Pin::new(USER_PIN)).unwrap();

    const THREADS: usize = 12;
    const ITERATIONS: usize = 40;
    let completed = AtomicUsize::new(0);

    std::thread::scope(|scope| {
        for thread_id in 0..THREADS {
            let hsm = &hsm;
            let completed = &completed;
            scope.spawn(move || {
                for iteration in 0..ITERATIONS {
                    let session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();
                    let tag = format!("t{thread_id}-i{iteration}");
                    let data = tag.as_bytes();

                    if iteration % 2 == 0 {
                        // ECDSA sign/verify on a fresh key pair.
                        let (public, private) = hsm
                            .generate_key_pair(
                                session,
                                &Mechanism::EcKeyPairGen,
                                vec![Attribute::Label(format!("{tag}-pub"))],
                                vec![Attribute::Label(format!("{tag}-priv"))],
                            )
                            .unwrap();

                        hsm.sign_init(session, &Mechanism::Ecdsa, private.clone()).unwrap();
                        let signature = hsm.sign(session, data).unwrap();
                        hsm.verify_init(session, &Mechanism::Ecdsa, public.clone()).unwrap();
                        hsm.verify(session, data, &signature).unwrap();

                        // The unique label finds exactly this thread's key.
                        hsm.find_objects_init(session, vec![Attribute::Label(format!("{tag}-priv"))])
                            .unwrap();
                        let found = hsm.find_objects_next(session, 10).unwrap();
                        hsm.find_objects_final(session).unwrap();
                        assert_eq!(found, vec![private.clone()]);

                        hsm.destroy_object(session, public).unwrap();
                        hsm.destroy_object(session, private).unwrap();
                    } else {
                        // AES-GCM encrypt/decrypt round-trip.
                        let key = hsm
                            .generate_key(
                                session,
                                &Mechanism::AesKeyGen,
                                vec![Attribute::ValueLen(32), Attribute::Label(format!("{tag}-aes"))],
                            )
                            .unwrap();

                        let mechanism = Mechanism::AesGcm {
                            initialization_vector: vec![0x24; 12],
                            additional_authenticated_data: Vec::new(),
                        };
                        hsm.encrypt_init(session, &mechanism, key.clone()).unwrap();
                        let ciphertext = hsm.encrypt(session, data).unwrap();
                        hsm.decrypt_init(session, &mechanism, key.clone()).unwrap();
                        let plaintext = hsm.decrypt(session, &ciphertext).unwrap();
                        assert_eq!(plaintext, data);

                        hsm.destroy_object(session, key).unwrap();
                    }

                    hsm.close_session(session).unwrap();
                    completed.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });

    assert_eq!(completed.load(Ordering::Relaxed), THREADS * ITERATIONS);

    hsm.close_session(login_session).unwrap();
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
fn there_is_a_single_slot() {
    let hsm = hsm();
    assert_eq!(hsm.slot_ids().unwrap(), vec![0]);
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
fn reinit_token_with_wrong_so_pin_is_rejected_and_keeps_objects() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    // A token (persistent) object, so it outlives its creating session and
    // would only vanish if `init_token` actually wiped the store.
    let key = hsm
        .generate_key(
            session,
            &Mechanism::GenericSecretKeyGen,
            vec![
                Attribute::ValueLen(32),
                Attribute::Label(String::from("keep")),
                Attribute::Private(true),
                Attribute::Token(true),
            ],
        )
        .unwrap();
    hsm.close_session(session).unwrap();

    // Re-initializing an initialized token with the wrong SO PIN is refused...
    assert!(matches!(
        hsm.init_token(&SLOT, Pin::new("wrong-so-pin"), None),
        Err(HsmError::PinIncorrect)
    ));

    // ...and the token's objects and user PIN are left untouched.
    let session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();
    assert!(hsm.object_exists(session, key).unwrap());
    assert!(hsm.token_status(SLOT).unwrap().user_pin_set);
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
                vec![
                    Attribute::ValueLen(length),
                    Attribute::Label(String::from("aes")),
                    Attribute::Token(true),
                ],
            )
            .unwrap();

        let (_, material) = hsm.object_store().unwrap().read_parts(&key).unwrap();
        let key_bytes: Vec<u8> = material.deserialized().unwrap();
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

/// Creates an AES key with known material, for known-answer tests.
fn import_aes_key(hsm: &Hsm, session: SessionId, value: Vec<u8>) -> ObjectId {
    use crate::attribute::KeyType;
    use crate::attribute::ObjectClass;

    hsm.create_object(
        session,
        vec![
            Attribute::Class(ObjectClass::SecretKey),
            Attribute::KeyType(KeyType::Aes),
            Attribute::Value(value),
        ],
    )
    .unwrap()
}

#[test]
fn aes_ecb_roundtrips_across_key_sizes() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    // Two identical plaintext blocks: ECB (and only ECB) encrypts them to
    // identical ciphertext blocks.
    let plaintext = [0x5Au8; 32];

    for key_length in [16u64, 24, 32] {
        let key = hsm
            .generate_key(session, &Mechanism::AesKeyGen, vec![Attribute::ValueLen(key_length)])
            .unwrap();

        hsm.encrypt_init(session, &Mechanism::AesEcb, key.clone()).unwrap();
        assert_eq!(hsm.encrypted_length(session, 32).unwrap(), 32);
        let ciphertext = hsm.encrypt(session, &plaintext).unwrap();
        assert_eq!(ciphertext.len(), 32);
        assert_eq!(ciphertext[..16], ciphertext[16..]);

        hsm.decrypt_init(session, &Mechanism::AesEcb, key).unwrap();
        assert_eq!(hsm.decrypt(session, &ciphertext).unwrap(), plaintext);
    }
}

#[test]
fn aes_cbc_matches_known_vectors() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = import_aes_key(&hsm, session, vec![0; 16]);

    // AES-128-CBC, zero key, zero IV, two zero blocks (the vector the
    // rust-cryptoki suite asserts).
    let expected_cipher = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e, 0xf7, 0x95,
        0xbd, 0x4a, 0x52, 0xe2, 0x9e, 0xd7, 0x13, 0xd3, 0x13, 0xfa, 0x20, 0xe9, 0x8d, 0xbc,
    ];
    let cbc = Mechanism::AesCbc {
        initialization_vector: vec![0; 16],
    };
    hsm.encrypt_init(session, &cbc, key.clone()).unwrap();
    assert_eq!(hsm.encrypt(session, &[0; 32]).unwrap(), expected_cipher);

    hsm.decrypt_init(session, &cbc, key.clone()).unwrap();
    assert_eq!(hsm.decrypt(session, &expected_cipher).unwrap(), [0; 32]);

    // The padded variant appends one full PKCS#7 block to aligned input.
    let expected_pad_tail = [
        0x5c, 0x04, 0x76, 0x16, 0x75, 0x6f, 0xdc, 0x1c, 0x32, 0xe0, 0xdf, 0x6e, 0x8c, 0x59, 0xbb, 0x2a,
    ];
    let cbc_pad = Mechanism::AesCbcPad {
        initialization_vector: vec![0; 16],
    };
    hsm.encrypt_init(session, &cbc_pad, key.clone()).unwrap();
    assert_eq!(hsm.encrypted_length(session, 32).unwrap(), 48);
    let ciphertext = hsm.encrypt(session, &[0; 32]).unwrap();
    assert_eq!(ciphertext[..32], expected_cipher);
    assert_eq!(ciphertext[32..], expected_pad_tail);

    hsm.decrypt_init(session, &cbc_pad, key).unwrap();
    // The length query reports the upper bound; the operation strips the pad.
    assert_eq!(hsm.decrypted_length(session, 48).unwrap(), 48);
    assert_eq!(hsm.decrypt(session, &ciphertext).unwrap(), [0; 32]);
}

#[test]
fn aes_cbc_pad_roundtrips_unaligned_plaintext() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = hsm
        .generate_key(session, &Mechanism::AesKeyGen, vec![Attribute::ValueLen(32)])
        .unwrap();

    let plaintext = [0xC3u8; 20];
    let cbc_pad = Mechanism::AesCbcPad {
        initialization_vector: vec![0x11; 16],
    };

    hsm.encrypt_init(session, &cbc_pad, key.clone()).unwrap();
    assert_eq!(hsm.encrypted_length(session, 20).unwrap(), 32);
    let ciphertext = hsm.encrypt(session, &plaintext).unwrap();
    assert_eq!(ciphertext.len(), 32);

    hsm.decrypt_init(session, &cbc_pad, key).unwrap();
    assert_eq!(hsm.decrypt(session, &ciphertext).unwrap(), plaintext);
}

#[test]
fn unpadded_block_modes_reject_unaligned_input() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = hsm
        .generate_key(session, &Mechanism::AesKeyGen, vec![Attribute::ValueLen(16)])
        .unwrap();

    hsm.encrypt_init(session, &Mechanism::AesEcb, key.clone()).unwrap();
    assert!(matches!(hsm.encrypted_length(session, 20), Err(HsmError::DataLenRange)));
    assert!(matches!(hsm.encrypt(session, &[0; 20]), Err(HsmError::DataLenRange)));

    let cbc = Mechanism::AesCbc {
        initialization_vector: vec![0; 16],
    };
    hsm.decrypt_init(session, &cbc, key).unwrap();
    assert!(matches!(
        hsm.decrypted_length(session, 20),
        Err(HsmError::EncryptedDataLenRange)
    ));
}

#[test]
fn aes_cbc_pad_rejects_malformed_padding() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = import_aes_key(&hsm, session, vec![0; 16]);

    // A block whose plaintext ends in 0x00 is never valid PKCS#7: encrypt one
    // zero block without padding, then decrypt it with the padded mechanism.
    hsm.encrypt_init(
        session,
        &Mechanism::AesCbc {
            initialization_vector: vec![0; 16],
        },
        key.clone(),
    )
    .unwrap();
    let ciphertext = hsm.encrypt(session, &[0; 16]).unwrap();

    hsm.decrypt_init(
        session,
        &Mechanism::AesCbcPad {
            initialization_vector: vec![0; 16],
        },
        key,
    )
    .unwrap();
    assert!(matches!(
        hsm.decrypt(session, &ciphertext),
        Err(HsmError::EncryptedDataInvalid)
    ));
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
    // Log the token in (secret keys are private by default) so the read-only
    // rejection is what fires, not the §4.4 login check.
    let _authed = user_session(&hsm);
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
fn rsa_pkcs_pads_raw_data_and_rejects_oversized_input() {
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

    // CKM_RSA_PKCS pads the input as given (no hashing/DigestInfo), so a short
    // "digest" round-trips directly.
    let short = [0x11u8; 32];
    hsm.sign_init(session, &Mechanism::RsaPkcs, private_key.clone())
        .unwrap();
    let signature = hsm.sign(session, &short).unwrap();
    hsm.verify_init(session, &Mechanism::RsaPkcs, public_key).unwrap();
    hsm.verify(session, &short, &signature).unwrap();

    // Input longer than the modulus can PKCS#1-pad (k - 11 bytes) is rejected
    // with CKR_DATA_LEN_RANGE. The old digest-then-sign path would have hashed
    // this to 32 bytes and succeeded, so this pins down the raw padding.
    let oversized = vec![0x22u8; (MIN_RSA_MODULUS_BITS as usize / 8) - 10];
    hsm.sign_init(session, &Mechanism::RsaPkcs, private_key).unwrap();
    assert!(matches!(hsm.sign(session, &oversized), Err(HsmError::DataLenRange)));
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
fn generate_token_key_pair_persists_both_halves() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    // Both halves CKA_TOKEN true — the transactional store path.
    let (public_key, private_key) = hsm
        .generate_key_pair(
            session,
            &Mechanism::EcKeyPairGen,
            vec![Attribute::Token(true)],
            vec![Attribute::Token(true)],
        )
        .unwrap();

    // Both handles denote persistent store objects, and both are usable.
    assert!(!public_key.is_session_object());
    assert!(!private_key.is_session_object());

    let digest = [0x5Au8; 32];
    hsm.sign_init(session, &Mechanism::Ecdsa, private_key).unwrap();
    let signature = hsm.sign(session, &digest).unwrap();
    hsm.verify_init(session, &Mechanism::Ecdsa, public_key).unwrap();
    hsm.verify(session, &digest, &signature).unwrap();
}

#[test]
fn ecdsa_verify_via_private_key_handle_derives_public_key() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    let (_public_key, private_key) = hsm
        .generate_key_pair(session, &Mechanism::EcKeyPairGen, vec![], vec![])
        .unwrap();

    // Sign with the private key.
    let digest = [0x5Au8; 32];
    hsm.sign_init(session, &Mechanism::Ecdsa, private_key.clone()).unwrap();
    let signature = hsm.sign(session, &digest).unwrap();

    // Verify with the *private* key handle: verify_init derives the public
    // key from the stored scalar instead of failing.
    hsm.verify_init(session, &Mechanism::Ecdsa, private_key.clone())
        .unwrap();
    hsm.verify(session, &digest, &signature).unwrap();

    // Tampered signature is still rejected.
    let mut tampered = signature.clone();
    tampered[0] ^= 0xFF;
    hsm.verify_init(session, &Mechanism::Ecdsa, private_key).unwrap();
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
    let key = generate_token_secret_key(&hsm, session, 32, "aes key");

    let (_, material) = hsm.object_store().unwrap().read_parts(&key).unwrap();
    let key_bytes: Vec<u8> = material.deserialized().unwrap();
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
    let key = generate_token_secret_key(&hsm, session, 32, "aes key");
    let (_, material) = hsm.object_store().unwrap().read_parts(&key).unwrap();
    let key_bytes: Vec<u8> = material.deserialized().unwrap();

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
fn operations_reject_keys_that_opt_out_of_usage() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    // Usage flags default to true; an explicit false opts the key out of the
    // operation (CKR_KEY_FUNCTION_NOT_PERMITTED, as on SoftHSM).
    let no_sign = hsm
        .generate_key(
            session,
            &Mechanism::GenericSecretKeyGen,
            vec![Attribute::ValueLen(32), Attribute::Sign(false)],
        )
        .unwrap();
    assert!(matches!(
        hsm.sign_init(session, &Mechanism::Sha256Hmac, no_sign),
        Err(HsmError::KeyFunctionNotPermitted)
    ));

    let opted_out = hsm
        .generate_key(
            session,
            &Mechanism::AesKeyGen,
            vec![
                Attribute::ValueLen(32),
                Attribute::Encrypt(false),
                Attribute::Decrypt(false),
                Attribute::Wrap(false),
                Attribute::Unwrap(false),
            ],
        )
        .unwrap();
    let gcm = Mechanism::AesGcm {
        initialization_vector: vec![0x24; 12],
        additional_authenticated_data: vec![],
    };
    assert!(matches!(
        hsm.encrypt_init(session, &gcm, opted_out.clone()),
        Err(HsmError::KeyFunctionNotPermitted)
    ));
    assert!(matches!(
        hsm.decrypt_init(session, &gcm, opted_out.clone()),
        Err(HsmError::KeyFunctionNotPermitted)
    ));

    let payload = generate_secret_key(&hsm, session, 32, "payload");
    assert!(matches!(
        hsm.wrap_key(session, &Mechanism::AesKeyWrapPad, opted_out.clone(), payload.clone()),
        Err(HsmError::KeyFunctionNotPermitted)
    ));
    let wrapped = hsm
        .wrap_key(session, &Mechanism::AesKeyWrapPad, payload.clone(), payload)
        .unwrap();
    assert!(matches!(
        hsm.unwrap_key(session, &Mechanism::AesKeyWrapPad, opted_out, &wrapped, vec![]),
        Err(HsmError::KeyFunctionNotPermitted)
    ));
}

#[test]
fn unwrapped_key_gets_the_unwrap_templates_usage_defaults() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let wrapping_key = generate_secret_key(&hsm, session, 32, "kek");

    // Usage flags do not travel inside the wrapped blob: a Sign(false)
    // original unwrapped with a template that omits CKA_SIGN gets the default
    // true and may sign (matches SoftHSM's measured behavior).
    let (_public, private) = hsm
        .generate_key_pair(
            session,
            &Mechanism::EcKeyPairGen,
            vec![],
            vec![Attribute::Extractable(true), Attribute::Sign(false)],
        )
        .unwrap();
    assert!(matches!(
        hsm.sign_init(session, &Mechanism::Ecdsa, private.clone()),
        Err(HsmError::KeyFunctionNotPermitted)
    ));

    let wrapped = hsm
        .wrap_key(session, &Mechanism::AesKeyWrapPad, wrapping_key.clone(), private)
        .unwrap();
    let unwrapped = hsm
        .unwrap_key(
            session,
            &Mechanism::AesKeyWrapPad,
            wrapping_key,
            &wrapped,
            vec![
                Attribute::Class(ObjectClass::PrivateKey),
                Attribute::KeyType(KeyType::Ec),
                Attribute::Private(true),
            ],
        )
        .unwrap();

    assert_eq!(
        hsm.object_attribute(session, unwrapped.clone(), AttributeType::Sign)
            .unwrap(),
        Some(Attribute::Sign(true))
    );
    hsm.sign_init(session, &Mechanism::Ecdsa, unwrapped).unwrap();
    let signature = hsm.sign(session, &[0x5A; 32]).unwrap();
    assert_eq!(signature.len(), 64);
}

#[test]
fn unwrap_drops_untracked_template_attributes() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let wrapping_key = generate_secret_key(&hsm, session, 32, "kek");
    let key = generate_secret_key(&hsm, session, 32, "payload");
    let wrapped = hsm
        .wrap_key(session, &Mechanism::AesKeyWrapPad, wrapping_key.clone(), key)
        .unwrap();

    // Unwrap with a template carrying an untracked (Unknown) attribute: it must
    // be dropped, not persisted, like every other object-creating path.
    let unwrapped = hsm
        .unwrap_key(
            session,
            &Mechanism::AesKeyWrapPad,
            wrapping_key,
            &wrapped,
            vec![Attribute::Label(String::from("unwrapped")), Attribute::Unknown],
        )
        .unwrap();

    // A search whose template carries an Unknown attribute must not match it
    // (it would if the Unknown had been stored, since `Unknown == Unknown`).
    hsm.find_objects_init(session, vec![Attribute::Unknown]).unwrap();
    let found = hsm.find_objects_next(session, 10).unwrap();
    hsm.find_objects_final(session).unwrap();
    assert!(!found.contains(&unwrapped));

    // It remains findable by its real label.
    hsm.find_objects_init(session, vec![Attribute::Label(String::from("unwrapped"))])
        .unwrap();
    let found = hsm.find_objects_next(session, 10).unwrap();
    hsm.find_objects_final(session).unwrap();
    assert_eq!(found, vec![unwrapped]);
}

// ---- login enforcement (PKCS#11 §4.4) ----------------------------------

#[test]
fn private_objects_are_inaccessible_without_login() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    // A private object and a public one, both session objects.
    let private_key = generate_secret_key(&hsm, session, 32, "secret");
    // Secret keys are private by default, so the public one is explicit.
    let public_key = hsm
        .generate_key(
            session,
            &Mechanism::AesKeyGen,
            vec![
                Attribute::ValueLen(32),
                Attribute::Label(String::from("public")),
                Attribute::Private(false),
            ],
        )
        .unwrap();

    // Drop the user login (the session and its objects remain). Login is
    // per-token, so this makes the whole session un-authenticated.
    hsm.logout(session).unwrap();

    // The private object is excluded from searches...
    hsm.find_objects_init(session, vec![Attribute::Label(String::from("secret"))])
        .unwrap();
    let found = hsm.find_objects_next(session, 10).unwrap();
    hsm.find_objects_final(session).unwrap();
    assert!(found.is_empty());

    // ...and inaccessible by handle (read, use as a key, destroy).
    assert!(matches!(
        hsm.object_attribute(session, private_key.clone(), AttributeType::Label),
        Err(HsmError::UserNotLoggedIn)
    ));
    assert!(matches!(
        hsm.sign_init(session, &Mechanism::Sha256Hmac, private_key.clone()),
        Err(HsmError::UserNotLoggedIn)
    ));
    assert!(matches!(
        hsm.destroy_object(session, private_key),
        Err(HsmError::UserNotLoggedIn)
    ));

    // The public object stays visible and readable.
    hsm.find_objects_init(session, vec![Attribute::Label(String::from("public"))])
        .unwrap();
    let found = hsm.find_objects_next(session, 10).unwrap();
    hsm.find_objects_final(session).unwrap();
    assert_eq!(found, vec![public_key.clone()]);
    assert!(hsm.object_attribute(session, public_key, AttributeType::Label).is_ok());
}

#[test]
fn creating_a_private_object_requires_login() {
    let hsm = hsm_with_token();
    // A session that never logged in.
    let session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();

    // A private key cannot be generated without logging in...
    assert!(matches!(
        hsm.generate_key(
            session,
            &Mechanism::AesKeyGen,
            vec![
                Attribute::ValueLen(32),
                Attribute::Label(String::from("k")),
                Attribute::Private(true),
            ],
        ),
        Err(HsmError::UserNotLoggedIn)
    ));

    // ...nor one that is private only by its class default (no CKA_PRIVATE in
    // the template), matching SoftHSM, which applies the default before the
    // §4.4 check rather than after.
    assert!(matches!(
        hsm.generate_key(
            session,
            &Mechanism::AesKeyGen,
            vec![Attribute::ValueLen(32), Attribute::Label(String::from("def"))],
        ),
        Err(HsmError::UserNotLoggedIn)
    ));

    // ...but an explicitly public key is allowed. (A secret key is private by
    // default, so the public one must set CKA_PRIVATE=false.)
    assert!(hsm
        .generate_key(
            session,
            &Mechanism::AesKeyGen,
            vec![
                Attribute::ValueLen(32),
                Attribute::Label(String::from("pub")),
                Attribute::Private(false),
            ],
        )
        .is_ok());
}

#[test]
fn write_paths_materialize_class_default_booleans() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    // A secret key whose template sets only length/label plus one explicit
    // opt-out flag.
    let secret = hsm
        .generate_key(
            session,
            &Mechanism::AesKeyGen,
            vec![
                Attribute::ValueLen(32),
                Attribute::Label(String::from("k")),
                Attribute::Sign(false),
            ],
        )
        .unwrap();

    let read = |id: &ObjectId, type_| hsm.object_attribute(session, id.clone(), type_).unwrap();

    // The class defaults are materialized for the booleans the template
    // omitted (usage flags true, following SoftHSM)...
    assert_eq!(read(&secret, AttributeType::Token), Some(Attribute::Token(false)));
    assert_eq!(read(&secret, AttributeType::Private), Some(Attribute::Private(true)));
    assert_eq!(
        read(&secret, AttributeType::Sensitive),
        Some(Attribute::Sensitive(true))
    );
    assert_eq!(
        read(&secret, AttributeType::Extractable),
        Some(Attribute::Extractable(false))
    );
    assert_eq!(read(&secret, AttributeType::Encrypt), Some(Attribute::Encrypt(true)));
    assert_eq!(read(&secret, AttributeType::Derive), Some(Attribute::Derive(false)));
    // ...but an explicit template value is never overwritten by its default.
    assert_eq!(read(&secret, AttributeType::Sign), Some(Attribute::Sign(false)));

    // The now-complete stored list lets an equality search on a defaulted
    // attribute match — which the old presence-plus-equality match could not,
    // since the template never stored CKA_ENCRYPT.
    hsm.find_objects_init(
        session,
        vec![Attribute::Label(String::from("k")), Attribute::Encrypt(true)],
    )
    .unwrap();
    let found = hsm.find_objects_next(session, 10).unwrap();
    hsm.find_objects_final(session).unwrap();
    assert_eq!(found, vec![secret]);

    // Public keys default CKA_PRIVATE=false (so they need no login), unlike the
    // private half of the pair.
    let (public, private) = hsm
        .generate_key_pair(
            session,
            &Mechanism::EcKeyPairGen,
            vec![Attribute::Label(String::from("pub"))],
            vec![Attribute::Label(String::from("priv"))],
        )
        .unwrap();
    assert_eq!(read(&public, AttributeType::Private), Some(Attribute::Private(false)));
    assert_eq!(read(&public, AttributeType::Verify), Some(Attribute::Verify(true)));
    assert_eq!(read(&private, AttributeType::Private), Some(Attribute::Private(true)));
    assert_eq!(read(&private, AttributeType::Sign), Some(Attribute::Sign(true)));
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
    let (_, material) = hsm.object_store().unwrap().read_parts(&object).unwrap();
    let stored: Vec<u8> = material.deserialized().unwrap();
    assert_eq!(stored, key_bytes);

    hsm.find_objects_init(session, vec![Attribute::Label(String::from("created"))])
        .unwrap();
    let found = hsm.find_objects_next(session, 10).unwrap();
    hsm.find_objects_final(session).unwrap();
    assert_eq!(found, vec![object]);
}

#[test]
fn imported_key_carries_class_defaults() {
    // import_secret_key delegates to create_object, which runs the template
    // through Template::merge — so the stored object carries class defaults
    // (CKA_SENSITIVE = true, CKA_EXTRACTABLE = false, …) even though the
    // import template never mentioned them. This pins the drift fix: the old
    // import path stored the raw template and skipped merge.
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    let key_bytes = vec![0x7Fu8; 32];
    let object = hsm
        .import_secret_key(session, key_bytes, String::from("imported"), None)
        .unwrap();

    // CKA_SENSITIVE reads back true (the SecretKey class default).
    assert_eq!(
        hsm.object_attribute(session, object.clone(), AttributeType::Sensitive)
            .unwrap(),
        Some(Attribute::Sensitive(true))
    );

    // The key is findable by a Sensitive(true) template — search is a plain
    // presence-and-equality match, and the default was materialized at write
    // time, not synthesized at search time.
    hsm.find_objects_init(
        session,
        vec![Attribute::Sensitive(true), Attribute::Label(String::from("imported"))],
    )
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
fn create_object_rejects_token_managed_attributes() {
    use crate::attribute::ObjectClass;

    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    // A read-only, token-managed attribute (e.g. CKA_UNIQUE_ID) in the
    // template is rejected rather than silently ignored.
    assert!(matches!(
        hsm.create_object(
            session,
            vec![
                Attribute::Class(ObjectClass::SecretKey),
                Attribute::Value(vec![0u8; 32]),
                Attribute::Unsupported,
            ],
        ),
        Err(HsmError::AttributeTypeInvalid)
    ));
}

#[test]
fn generate_key_rejects_token_managed_attributes() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    assert!(matches!(
        hsm.generate_key(
            session,
            &Mechanism::AesKeyGen,
            vec![Attribute::ValueLen(32), Attribute::Unsupported],
        ),
        Err(HsmError::AttributeTypeInvalid)
    ));
}

#[test]
fn create_ec_private_key_is_importable_and_signs() {
    use signature::hazmat::PrehashVerifier;

    use crate::attribute::KeyType;
    use crate::attribute::ObjectClass;

    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    // A known P-256 key: import its scalar (CKA_VALUE) as an EC private key.
    let signing_key = ecdsa::SigningKey::from_slice(&[0x42u8; 32]).unwrap();
    let scalar = signing_key.to_bytes().to_vec();
    let verifying_key = *signing_key.verifying_key();

    let private = hsm
        .create_object(
            session,
            vec![
                Attribute::Class(ObjectClass::PrivateKey),
                Attribute::KeyType(KeyType::Ec),
                Attribute::Value(scalar),
                Attribute::Label(String::from("imported_signing_key")),
                Attribute::Sign(true),
                Attribute::Token(true),
            ],
        )
        .unwrap();

    // Findable by label (as wallet_provider looks keys up).
    hsm.find_objects_init(session, vec![Attribute::Label(String::from("imported_signing_key"))])
        .unwrap();
    let found = hsm.find_objects_next(session, 10).unwrap();
    hsm.find_objects_final(session).unwrap();
    assert_eq!(found, vec![private.clone()]);

    // Usable to sign: the signature verifies under the matching public key.
    let digest = [0x11u8; 32];
    hsm.sign_init(session, &Mechanism::Ecdsa, private).unwrap();
    let signature = hsm.sign(session, &digest).unwrap();
    let signature = ecdsa::Signature::from_slice(&signature).unwrap();
    verifying_key.verify_prehash(&digest, &signature).unwrap();
}

#[test]
fn create_private_key_rejects_non_ec_and_bad_scalars() {
    use crate::attribute::KeyType;
    use crate::attribute::ObjectClass;

    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    // RSA private key import is not supported.
    assert!(matches!(
        hsm.create_object(
            session,
            vec![
                Attribute::Class(ObjectClass::PrivateKey),
                Attribute::KeyType(KeyType::Rsa),
                Attribute::Value(vec![1u8; 32]),
            ],
        ),
        Err(HsmError::TemplateInconsistent)
    ));
    // Missing key type is treated as inconsistent for a private key.
    assert!(matches!(
        hsm.create_object(
            session,
            vec![
                Attribute::Class(ObjectClass::PrivateKey),
                Attribute::Value(vec![1u8; 32])
            ],
        ),
        Err(HsmError::TemplateInconsistent)
    ));
    // EC private key without CKA_VALUE.
    assert!(matches!(
        hsm.create_object(
            session,
            vec![
                Attribute::Class(ObjectClass::PrivateKey),
                Attribute::KeyType(KeyType::Ec)
            ],
        ),
        Err(HsmError::TemplateIncomplete)
    ));
    // An all-zero scalar is not a valid P-256 key.
    assert!(matches!(
        hsm.create_object(
            session,
            vec![
                Attribute::Class(ObjectClass::PrivateKey),
                Attribute::KeyType(KeyType::Ec),
                Attribute::Value(vec![0u8; 32]),
            ],
        ),
        Err(HsmError::AttributeValueInvalid)
    ));
    // An over-long scalar is rejected.
    assert!(matches!(
        hsm.create_object(
            session,
            vec![
                Attribute::Class(ObjectClass::PrivateKey),
                Attribute::KeyType(KeyType::Ec),
                Attribute::Value(vec![1u8; 40]),
            ],
        ),
        Err(HsmError::AttributeValueInvalid)
    ));
}

#[test]
fn create_ec_private_key_rejects_unsupported_curve() {
    use crate::attribute::KeyType;
    use crate::attribute::ObjectClass;

    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    // An EC private key with CKA_EC_PARAMS naming a curve other than secp256r1
    // is rejected with CKR_CURVE_NOT_SUPPORTED. This is the secp384r1 OID.
    let secp384r1 = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
    assert!(matches!(
        hsm.create_object(
            session,
            vec![
                Attribute::Class(ObjectClass::PrivateKey),
                Attribute::KeyType(KeyType::Ec),
                Attribute::EcParams(secp384r1.to_vec()),
                Attribute::Value(vec![0x42u8; 32]),
            ],
        ),
        Err(HsmError::CurveNotSupported)
    ));
}

#[test]
fn create_ec_private_key_accepts_explicit_p256_params() {
    use crate::attribute::KeyType;
    use crate::attribute::ObjectClass;

    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    // nl-wallet passes the P-256 OID explicitly; that must succeed (the
    // validation rejects only *other* curves, not the supported one).
    let p256 = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    assert!(hsm
        .create_object(
            session,
            vec![
                Attribute::Class(ObjectClass::PrivateKey),
                Attribute::KeyType(KeyType::Ec),
                Attribute::EcParams(p256.to_vec()),
                Attribute::Value(vec![0x42u8; 32]),
                Attribute::Label(String::from("explicit-p256")),
            ],
        )
        .is_ok());
}

#[test]
fn generate_key_pair_rejects_unsupported_curve() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    // The public half advertises secp384r1 while the mechanism generates
    // P-256; the mismatch is caught before generation.
    let secp384r1 = vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
    assert!(matches!(
        hsm.generate_key_pair(
            session,
            &Mechanism::EcKeyPairGen,
            vec![Attribute::EcParams(secp384r1)],
            vec![],
        ),
        Err(HsmError::CurveNotSupported)
    ));
}

#[test]
fn generate_key_pair_accepts_explicit_p256_params() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    // Explicit P-256 OID in the public half is accepted.
    let p256 = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    assert!(hsm
        .generate_key_pair(
            session,
            &Mechanism::EcKeyPairGen,
            vec![Attribute::EcParams(p256)],
            vec![],
        )
        .is_ok());
}

#[test]
fn create_token_object_in_read_only_session_is_rejected() {
    use crate::attribute::ObjectClass;

    let hsm = hsm_with_token();
    // Log the token in (secret keys are private by default) so the read-only
    // rejection is what fires, not the §4.4 login check.
    let _authed = user_session(&hsm);
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
        Some(Attribute::Class(ObjectClass::PublicKey))
    );
    assert_eq!(
        hsm.object_attribute(session, private_key, AttributeType::KeyType)
            .unwrap(),
        Some(Attribute::KeyType(KeyType::Ec))
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
fn generated_rsa_key_pair_exposes_derived_attributes() {
    use crate::attribute::KeyType;
    use crate::attribute::ObjectClass;

    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    let (public_key, private_key) = hsm
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

    // The private half carries the pair's public metadata too — spec-defined
    // RSA private-key attributes, read e.g. to size signature buffers.
    assert_eq!(
        hsm.object_attribute(session, private_key.clone(), AttributeType::Modulus)
            .unwrap(),
        Some(Attribute::Modulus(modulus))
    );
    assert_eq!(
        hsm.object_attribute(session, private_key.clone(), AttributeType::PublicExponent)
            .unwrap(),
        Some(Attribute::PublicExponent(vec![0x01, 0x00, 0x01]))
    );
    assert_eq!(
        hsm.object_attribute(session, private_key, AttributeType::ModulusBits)
            .unwrap(),
        Some(Attribute::ModulusBits(2048))
    );
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
fn set_object_attributes_enforces_one_way_guarantees() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    // Secret-key class defaults: CKA_SENSITIVE true, CKA_EXTRACTABLE false —
    // both in their protected state.
    let key = generate_secret_key(&hsm, session, 32, "one-way");

    assert!(matches!(
        hsm.set_object_attributes(session, key.clone(), vec![Attribute::Sensitive(false)]),
        Err(HsmError::AttributeReadOnly)
    ));
    assert!(matches!(
        hsm.set_object_attributes(session, key.clone(), vec![Attribute::Extractable(true)]),
        Err(HsmError::AttributeReadOnly)
    ));

    // Re-asserting the protected state is not a downgrade.
    hsm.set_object_attributes(
        session,
        key.clone(),
        vec![Attribute::Sensitive(true), Attribute::Extractable(false)],
    )
    .unwrap();

    assert_eq!(
        hsm.object_attribute(session, key, AttributeType::Sensitive).unwrap(),
        Some(Attribute::Sensitive(true))
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
fn copy_object_duplicates_material_and_applies_overrides() {
    use crate::attribute::KeyType;
    use crate::attribute::ObjectClass;

    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    let source = hsm
        .generate_key(
            session,
            &Mechanism::AesKeyGen,
            vec![
                Attribute::Class(ObjectClass::SecretKey),
                Attribute::KeyType(KeyType::Aes),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Token(true),
                Attribute::ValueLen(16),
                Attribute::Label(String::from("original")),
            ],
        )
        .unwrap();

    // Copy with a label override: new handle, same key bytes, new label.
    let copy = hsm
        .copy_object(session, source.clone(), vec![Attribute::Label(String::from("copy"))])
        .unwrap();
    assert_ne!(copy, source);

    let (_, source_material) = hsm.object_store().unwrap().read_parts(&source).unwrap();
    let source_material: Vec<u8> = source_material.deserialized().unwrap();
    let (_, copy_material) = hsm.object_store().unwrap().read_parts(&copy).unwrap();
    let copy_material: Vec<u8> = copy_material.deserialized().unwrap();
    assert_eq!(source_material, copy_material);

    assert_eq!(
        hsm.object_attribute(session, copy.clone(), AttributeType::Label)
            .unwrap(),
        Some(Attribute::Label(String::from("copy")))
    );
    // Attributes not overridden are carried over from the source.
    assert_eq!(
        hsm.object_attribute(session, copy, AttributeType::KeyType).unwrap(),
        Some(Attribute::KeyType(KeyType::Aes))
    );

    // Copying with no template succeeds and keeps the original label.
    let plain_copy = hsm.copy_object(session, source.clone(), vec![]).unwrap();
    assert_eq!(
        hsm.object_attribute(session, plain_copy, AttributeType::Label).unwrap(),
        Some(Attribute::Label(String::from("original")))
    );
}

#[test]
fn copy_object_rejects_security_downgrades_and_read_only_overrides() {
    use crate::attribute::ObjectClass;

    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    let source = hsm
        .generate_key(
            session,
            &Mechanism::AesKeyGen,
            vec![
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::ValueLen(16),
            ],
        )
        .unwrap();

    // A non-extractable key may not be copied into an extractable one.
    assert!(matches!(
        hsm.copy_object(session, source.clone(), vec![Attribute::Extractable(true)]),
        Err(HsmError::AttributeReadOnly)
    ));
    // A sensitive key may not be copied into a non-sensitive one.
    assert!(matches!(
        hsm.copy_object(session, source.clone(), vec![Attribute::Sensitive(false)]),
        Err(HsmError::AttributeReadOnly)
    ));
    // Identity/key-material attributes are read-only in a copy template.
    assert!(matches!(
        hsm.copy_object(session, source.clone(), vec![Attribute::Class(ObjectClass::PublicKey)]),
        Err(HsmError::AttributeReadOnly)
    ));
    // Token-managed attributes are invalid.
    assert!(matches!(
        hsm.copy_object(session, source, vec![Attribute::Unsupported]),
        Err(HsmError::AttributeTypeInvalid)
    ));
}

#[test]
fn create_object_rejects_duplicate_attribute_types() {
    use crate::attribute::ObjectClass;

    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    // The same attribute type supplied twice is inconsistent, even when the
    // two values agree: readback and search must stay single-valued.
    assert!(matches!(
        hsm.create_object(
            session,
            vec![
                Attribute::Class(ObjectClass::SecretKey),
                Attribute::Value(vec![0u8; 32]),
                Attribute::Label(String::from("dup")),
                Attribute::Label(String::from("dup")),
            ],
        ),
        Err(HsmError::TemplateInconsistent)
    ));
}

#[test]
fn generate_key_rejects_duplicate_attribute_types() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    assert!(matches!(
        hsm.generate_key(
            session,
            &Mechanism::AesKeyGen,
            vec![Attribute::ValueLen(32), Attribute::ValueLen(32)],
        ),
        Err(HsmError::TemplateInconsistent)
    ));
}

#[test]
fn generate_key_pair_rejects_duplicate_attribute_types() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    // Duplicate CKA_LABEL in the private half.
    let dup = vec![Attribute::Label(String::from("a")), Attribute::Label(String::from("b"))];
    assert!(matches!(
        hsm.generate_key_pair(session, &Mechanism::EcKeyPairGen, vec![], dup,),
        Err(HsmError::TemplateInconsistent)
    ));
}

#[test]
fn unwrap_key_rejects_duplicate_attribute_types() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let wrapping_key = generate_secret_key(&hsm, session, 32, "kek");
    let key = generate_secret_key(&hsm, session, 32, "payload");
    let wrapped = hsm
        .wrap_key(session, &Mechanism::AesKeyWrapPad, wrapping_key.clone(), key)
        .unwrap();

    assert!(matches!(
        hsm.unwrap_key(
            session,
            &Mechanism::AesKeyWrapPad,
            wrapping_key,
            &wrapped,
            vec![
                Attribute::Label(String::from("unwrapped")),
                Attribute::Label(String::from("dup")),
            ],
        ),
        Err(HsmError::TemplateInconsistent)
    ));
}

#[test]
fn copy_object_rejects_duplicate_attribute_types() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    let source = hsm
        .generate_key(session, &Mechanism::AesKeyGen, vec![Attribute::ValueLen(32)])
        .unwrap();

    assert!(matches!(
        hsm.copy_object(
            session,
            source,
            vec![
                Attribute::Label(String::from("copy")),
                Attribute::Label(String::from("dup")),
            ],
        ),
        Err(HsmError::TemplateInconsistent)
    ));
}

#[test]
fn duplicate_attribute_types_check_allows_distinct_types() {
    use crate::attribute::ObjectClass;

    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    // Distinct attribute types are fine; the new guard must not reject a
    // legitimate template.
    assert!(hsm
        .create_object(
            session,
            vec![
                Attribute::Class(ObjectClass::SecretKey),
                Attribute::Value(vec![0u8; 32]),
                Attribute::Label(String::from("ok")),
                Attribute::Token(true),
            ],
        )
        .is_ok());
}

#[test]
fn session_objects_are_destroyed_when_their_session_closes() {
    let hsm = hsm_with_token();
    let creator = user_session(&hsm);
    let other = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();

    // A generated key with no CKA_TOKEN(true) is a session object.
    let key = hsm
        .generate_key(creator, &Mechanism::AesKeyGen, vec![Attribute::ValueLen(32)])
        .unwrap();

    // Visible to another live session while the creator is open.
    assert!(hsm.object_exists(other, key.clone()).unwrap());

    hsm.close_session(creator).unwrap();

    // Gone once the creating session closes.
    assert!(!hsm.object_exists(other, key).unwrap());
}

#[test]
fn token_objects_outlive_their_creating_session() {
    let hsm = hsm_with_token();
    let creator = user_session(&hsm);

    let key = hsm
        .generate_key(
            creator,
            &Mechanism::AesKeyGen,
            vec![Attribute::ValueLen(32), Attribute::Token(true)],
        )
        .unwrap();

    hsm.close_session(creator).unwrap();

    let other = user_session(&hsm);
    assert!(hsm.object_exists(other, key).unwrap());
}

#[test]
fn session_objects_live_in_memory_with_partitioned_handles() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    let session_key = generate_secret_key(&hsm, session, 32, "ephemeral");
    let token_key = generate_token_secret_key(&hsm, session, 32, "persistent");

    // The handle spaces are partitioned by the top bit.
    assert!(session_key.is_session_object());
    assert!(!token_key.is_session_object());

    // The session object never reaches the persistent store...
    assert!(hsm.object_store().unwrap().read_parts(&session_key).is_err());
    // ...but is fully usable through the API: attributes read back and it
    // drives crypto.
    assert_eq!(
        hsm.object_attribute(session, session_key.clone(), AttributeType::Label)
            .unwrap(),
        Some(Attribute::Label(String::from("ephemeral")))
    );
    hsm.sign_init(session, &Mechanism::Sha256Hmac, session_key.clone())
        .unwrap();
    assert!(!hsm.sign(session, b"data").unwrap().is_empty());

    // A search sees both stores merged.
    hsm.find_objects_init(session, vec![Attribute::Private(true)]).unwrap();
    let found = hsm.find_objects_next(session, 10).unwrap();
    hsm.find_objects_final(session).unwrap();
    assert!(found.contains(&session_key));
    assert!(found.contains(&token_key));

    // Session objects are visible to (and usable by) the process's other
    // sessions, per the spec.
    let sibling = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();
    assert!(hsm.object_exists(sibling, session_key.clone()).unwrap());
    hsm.sign_init(sibling, &Mechanism::Sha256Hmac, session_key).unwrap();
    assert!(!hsm.sign(sibling, b"data").unwrap().is_empty());
}

#[test]
fn closing_a_session_destroys_only_its_session_objects() {
    let hsm = hsm_with_token();
    let session_a = user_session(&hsm);
    let session_b = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();

    let key_a = generate_secret_key(&hsm, session_a, 32, "a");
    let key_b = generate_secret_key(&hsm, session_b, 32, "b");
    let token_key = generate_token_secret_key(&hsm, session_a, 32, "tok");

    hsm.close_session(session_a).unwrap();

    // Session A's object is gone; session B's and the token object remain.
    assert!(!hsm.object_exists(session_b, key_a).unwrap());
    assert!(hsm.object_exists(session_b, key_b).unwrap());
    assert!(hsm.object_exists(session_b, token_key).unwrap());
}

#[test]
fn copy_object_moves_across_the_token_boundary() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);

    // Session object → token object: the copy is persisted.
    let session_key = generate_secret_key(&hsm, session, 32, "ephemeral");
    let promoted = hsm
        .copy_object(session, session_key.clone(), vec![Attribute::Token(true)])
        .unwrap();
    assert!(!promoted.is_session_object());
    assert!(hsm.object_store().unwrap().read_parts(&promoted).is_ok());

    // Token object → session object: the copy is in-memory only.
    let demoted = hsm
        .copy_object(session, promoted.clone(), vec![Attribute::Token(false)])
        .unwrap();
    assert!(demoted.is_session_object());
    assert!(hsm.object_store().unwrap().read_parts(&demoted).is_err());

    // All three share the key material: the demoted copy signs identically
    // to the original session key.
    hsm.sign_init(session, &Mechanism::Sha256Hmac, session_key).unwrap();
    let original = hsm.sign(session, b"data").unwrap();
    hsm.sign_init(session, &Mechanism::Sha256Hmac, demoted).unwrap();
    assert_eq!(hsm.sign(session, b"data").unwrap(), original);
}

#[test]
fn set_object_attributes_rejects_token_changes() {
    let hsm = hsm_with_token();
    let session = user_session(&hsm);
    let key = generate_token_secret_key(&hsm, session, 32, "fixed");

    // CKA_TOKEN selects the object's store (and thereby its handle), so it
    // is fixed at creation; C_CopyObject is the way to change token-ness.
    assert!(matches!(
        hsm.set_object_attributes(session, key.clone(), vec![Attribute::Token(false)]),
        Err(HsmError::AttributeReadOnly)
    ));
    assert!(matches!(
        hsm.set_object_attributes(session, key, vec![Attribute::Token(true)]),
        Err(HsmError::AttributeReadOnly)
    ));
}

#[test]
fn session_objects_do_not_survive_a_restart() {
    let path = std::env::temp_dir().join(format!("rustssm-session-obj-{}.db", std::process::id()));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }

    let token_key;
    {
        let hsm = Hsm::with_store(ObjectStore::at_path(&path).unwrap());
        hsm.initialize().unwrap();
        hsm.init_token(&SLOT, Pin::new(SO_PIN), Some(String::from("persisted")))
            .unwrap();
        let session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();
        hsm.login(session, UserType::So, Pin::new(SO_PIN)).unwrap();
        hsm.init_pin(session, Pin::new(USER_PIN)).unwrap();
        hsm.logout(session).unwrap();
        hsm.login(session, UserType::User, Pin::new(USER_PIN)).unwrap();

        // One token object and one session object; the process ends without
        // closing the session (simulating a crash).
        token_key = hsm
            .generate_key(
                session,
                &Mechanism::AesKeyGen,
                vec![
                    Attribute::ValueLen(32),
                    Attribute::Token(true),
                    Attribute::Label(String::from("tok")),
                ],
            )
            .unwrap();
        hsm.generate_key(
            session,
            &Mechanism::AesKeyGen,
            vec![Attribute::ValueLen(32), Attribute::Label(String::from("ephemeral"))],
        )
        .unwrap();
    }

    {
        let hsm = Hsm::with_store(ObjectStore::at_path(&path).unwrap());
        hsm.initialize().unwrap();
        let session = hsm.open_session(SLOT, SessionState::ReadWrite).unwrap();
        hsm.login(session, UserType::User, Pin::new(USER_PIN)).unwrap();

        // The token object survives; the leftover session object is purged.
        assert!(hsm.object_exists(session, token_key).unwrap());

        hsm.find_objects_init(session, vec![Attribute::Label(String::from("ephemeral"))])
            .unwrap();
        let found = hsm.find_objects_next(session, 10).unwrap();
        hsm.find_objects_final(session).unwrap();
        assert!(found.is_empty());
    }

    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
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
