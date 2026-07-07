use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;

use aes_kw::KwpAes256;
use der::asn1::OctetString;
use der::Encode;
use elliptic_curve::Generate;
use hmac::KeyInit;
use p256::ecdsa;
use p256::ecdsa::VerifyingKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use rsa::RsaPublicKey;
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::attribute::Attribute;
use crate::attribute::AttributeType;
use crate::attribute::KeyType;
use crate::attribute::ObjectClass;
use crate::mechanism::Mechanism;
use crate::object_store::ObjectId;
use crate::object_store::ObjectStore;
use crate::object_store::ObjectStoreError;
use crate::object_store::TokenRecord;
use crate::operation::Operation;
use crate::pin::Pin;
use crate::pin::PinHash;
use crate::session::Session;
use crate::session::SessionError;
use crate::session::SessionId;
use crate::session::SessionState;
use crate::signing::Decrypt;
use crate::signing::Encrypt;
use crate::signing::HmacSha256;
use crate::signing::Sign;
use crate::signing::SignatureLength;
use crate::signing::Verify;
use crate::signing::AES_GCM_TAG_LENGTH;
use crate::slot::Slot;
use crate::slot::SlotId;
use crate::slot::UserType;
use crate::util::random_bytes;

/// Bounds on caller-controlled sizes. Anything beyond these is a caller bug
/// and must not drive an allocation or a long-running computation.
pub const MAX_SECRET_KEY_LENGTH: u64 = 8192;
/// The `rsa` crate refuses to generate keys below 1024 bits, so that is our
/// floor too.
pub const MIN_RSA_MODULUS_BITS: u64 = 1024;
pub const MAX_RSA_MODULUS_BITS: u64 = 8192;

/// Domain errors. The FFI layer maps each variant onto a `CK_RV` code; this
/// module never deals in raw PKCS#11 codes.
#[derive(Error, Debug)]
pub enum HsmError {
    #[error("not initialized")]
    NotInitialized,

    #[error("already initialized")]
    AlreadyInitialized,

    #[error("slot not found: {0:?}")]
    SlotNotFound(SlotId),

    #[error("session not found: {0:?}")]
    SessionNotFound(SessionId),

    #[error("open sessions exist on slot: {0:?}")]
    SessionExists(SlotId),

    #[error("session is read-only")]
    SessionReadOnly,

    #[error("a read-only session is open")]
    SessionReadOnlyExists,

    #[error("user already logged in")]
    UserAlreadyLoggedIn,

    #[error("another user already logged in")]
    UserAnotherAlreadyLoggedIn,

    #[error("user not logged in")]
    UserNotLoggedIn,

    #[error("user PIN not initialized")]
    UserPinNotInitialized,

    #[error("PIN incorrect")]
    PinIncorrect,

    #[error("operation active")]
    OperationActive,

    #[error("operation not initialized")]
    OperationNotInitialized,

    #[error("mechanism invalid for this operation")]
    MechanismInvalid,

    #[error("template incomplete")]
    TemplateIncomplete,

    #[error("template inconsistent")]
    TemplateInconsistent,

    #[error("attribute value invalid")]
    AttributeValueInvalid,

    #[error("attribute type invalid")]
    AttributeTypeInvalid,

    #[error("key handle invalid")]
    KeyHandleInvalid,

    #[error("key size out of range")]
    KeySizeRange,

    #[error("wrapping key handle invalid")]
    WrappingKeyHandleInvalid,

    #[error("wrapping key size out of range")]
    WrappingKeySizeRange,

    #[error("unwrapping key handle invalid")]
    UnwrappingKeyHandleInvalid,

    #[error("unwrapping key size out of range")]
    UnwrappingKeySizeRange,

    #[error("wrapped key invalid")]
    WrappedKeyInvalid,

    #[error("object handle invalid")]
    ObjectHandleInvalid,

    #[error("signature invalid")]
    SignatureInvalid,

    #[error("data length out of range")]
    DataLenRange,

    #[error("encrypted data length out of range")]
    EncryptedDataLenRange,

    #[error("encrypted data invalid")]
    EncryptedDataInvalid,

    #[error("object store unavailable: {0}")]
    ObjectStore(#[source] ObjectStoreError),

    #[error("internal error")]
    GeneralError,
}

pub type Result<T> = std::result::Result<T, HsmError>;

/// A session together with the slot it belongs to.
type SessionAndSlot = (Arc<RwLock<Session>>, Arc<RwLock<Slot>>);

pub struct SessionInfo {
    pub slot_id: u64,
    pub read_write: bool,
    pub user: Option<UserType>,
}

pub struct TokenStatus {
    pub label: Option<String>,
    pub initialized: bool,
    pub user_pin_set: bool,
    pub session_count: usize,
}

pub struct Hsm {
    slots: RwLock<HashMap<SlotId, Arc<RwLock<Slot>>>>,
    object_store: OnceLock<Arc<ObjectStore>>,
    next_session_id: AtomicU64,
    initialized: AtomicBool,
}

impl Default for Hsm {
    fn default() -> Self {
        Self {
            slots: RwLock::new(HashMap::from_iter(
                (0..4).map(|i| (SlotId(i), Arc::new(RwLock::new(Slot::default())))),
            )),
            object_store: OnceLock::new(),
            next_session_id: AtomicU64::new(1),
            initialized: AtomicBool::new(false),
        }
    }
}

impl Hsm {
    #[cfg(test)]
    pub fn with_store(store: ObjectStore) -> Self {
        let hsm = Self::default();
        let _ = hsm.object_store.set(Arc::new(store));
        hsm
    }

    // ---- lifecycle -------------------------------------------------------

    pub fn initialize(&self) -> Result<()> {
        if self.initialized.swap(true, Ordering::SeqCst) {
            return Err(HsmError::AlreadyInitialized);
        }
        // Load persisted token state so a restarted process sees the same
        // tokens (and accepts the same PINs). Roll back on failure so the
        // caller can retry once the store is reachable.
        if let Err(error) = self.hydrate_slots() {
            self.initialized.store(false, Ordering::SeqCst);
            return Err(error);
        }
        Ok(())
    }

    /// Replaces each slot's persistent fields (initialized flag, label, PIN
    /// hashes) with what the store holds. Runtime state (login, sessions) is
    /// left untouched.
    fn hydrate_slots(&self) -> Result<()> {
        let store = self.object_store()?;
        let tokens = store.load_tokens().map_err(HsmError::ObjectStore)?;
        let by_slot: HashMap<u64, TokenRecord> = tokens.into_iter().map(|token| (token.slot_id, token)).collect();

        let slots = self.slots.read().unwrap();
        for (slot_id, slot_lock) in slots.iter() {
            let mut slot = slot_lock.write().unwrap();
            match by_slot.get(&slot_id.0) {
                Some(record) => {
                    slot.initialized = true;
                    slot.label = record.label.clone();
                    slot.so_pin = Some(PinHash::from_stored(record.so_pin_hash.clone()));
                    slot.user_pin = record.user_pin_hash.clone().map(PinHash::from_stored);
                }
                None => {
                    slot.initialized = false;
                    slot.label = None;
                    slot.so_pin = None;
                    slot.user_pin = None;
                }
            }
        }
        Ok(())
    }

    /// Closes all sessions on all slots and resets login state.
    pub fn finalize(&self) -> Result<()> {
        if !self.initialized.swap(false, Ordering::SeqCst) {
            return Err(HsmError::NotInitialized);
        }

        let slots = self.slots.read().unwrap();
        for slot_lock in slots.values() {
            let mut slot = slot_lock.write().unwrap();
            slot.sessions.write().unwrap().clear();
            slot.current_user_type = None;
        }
        Ok(())
    }

    pub fn ensure_initialized(&self) -> Result<()> {
        if self.initialized.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(HsmError::NotInitialized)
        }
    }

    fn object_store(&self) -> Result<Arc<ObjectStore>> {
        // `OnceLock` has no stable fallible initializer, so open the store and
        // race to install it. A concurrent caller may win, in which case its
        // value is kept and the loser's connection is simply dropped.
        if let Some(store) = self.object_store.get() {
            return Ok(store.clone());
        }
        let store = Arc::new(ObjectStore::new().map_err(HsmError::ObjectStore)?);
        let _ = self.object_store.set(store);
        Ok(self.object_store.get().expect("object store just initialized").clone())
    }

    // ---- slots and tokens ------------------------------------------------

    pub fn slot_ids(&self) -> Result<Vec<u64>> {
        self.ensure_initialized()?;
        let mut ids: Vec<u64> = self.slots.read().unwrap().keys().map(|id| id.0).collect();
        ids.sort_unstable();
        Ok(ids)
    }

    pub fn slot_exists(&self, slot_id: SlotId) -> Result<()> {
        self.get_slot(&slot_id).map(|_| ())
    }

    pub fn token_status(&self, slot_id: SlotId) -> Result<TokenStatus> {
        let slot_lock = self.get_slot(&slot_id)?;
        let slot = slot_lock.read().unwrap();
        let session_count = slot.sessions.read().unwrap().len();

        Ok(TokenStatus {
            label: slot.label.clone(),
            initialized: slot.initialized,
            user_pin_set: slot.user_pin.is_some(),
            session_count,
        })
    }

    pub fn init_token(&self, slot_id: &SlotId, so_pin: Pin, label: Option<String>) -> Result<()> {
        let store = self.object_store()?;
        let slot_lock = self.get_slot(slot_id)?;
        let mut slot = slot_lock.write().unwrap();

        if !slot.sessions.read().unwrap().is_empty() {
            return Err(HsmError::SessionExists(*slot_id));
        }

        // (Re)initializing a token destroys all its objects and resets its PINs.
        store.clear().map_err(HsmError::ObjectStore)?;

        let so_pin_hash = PinHash::from_pin(&so_pin);
        store
            .save_token(slot_id.0, label.as_deref(), so_pin_hash.as_str())
            .map_err(HsmError::ObjectStore)?;

        slot.initialized = true;
        slot.so_pin = Some(so_pin_hash);
        slot.user_pin = None;
        slot.current_user_type = None;
        slot.label = label;
        Ok(())
    }

    // ---- sessions ----------------------------------------------------------

    pub fn open_session(&self, slot_id: SlotId, state: SessionState) -> Result<SessionId> {
        let store = self.object_store()?;
        let slot_lock = self.get_slot(&slot_id)?;
        let slot = slot_lock.read().unwrap();

        // While the SO is logged in, no read-only session may be opened.
        if matches!(state, SessionState::ReadOnly) && slot.current_user_type == Some(UserType::So) {
            return Err(HsmError::SessionReadOnlyExists);
        }

        let session_id = SessionId(self.next_session_id.fetch_add(1, Ordering::Relaxed));
        let session = Session::new(slot_id, state, store);
        slot.sessions
            .write()
            .unwrap()
            .insert(session_id, Arc::new(RwLock::new(session)));
        Ok(session_id)
    }

    pub fn close_session(&self, session_id: SessionId) -> Result<()> {
        let slot_lock = self
            .find_by_session_id(session_id)
            .ok_or(HsmError::SessionNotFound(session_id))?;

        let mut slot = slot_lock.write().unwrap();
        let no_sessions_left = {
            let mut sessions = slot.sessions.write().unwrap();
            sessions.remove(&session_id);
            sessions.is_empty()
        };

        // When the last session with a token closes, the login state resets.
        if no_sessions_left {
            slot.current_user_type = None;
        }
        Ok(())
    }

    pub fn validate_session(&self, session_id: SessionId) -> Result<()> {
        self.get_session(session_id).map(|_| ())
    }

    pub fn session_info(&self, session_id: SessionId) -> Result<SessionInfo> {
        let (session_lock, slot_lock) = self.get_session_and_slot(session_id)?;
        let session = session_lock.read().unwrap();
        let slot = slot_lock.read().unwrap();

        Ok(SessionInfo {
            slot_id: session.slot_id.0,
            read_write: matches!(session.state, SessionState::ReadWrite),
            user: slot.current_user_type,
        })
    }

    // ---- authentication ----------------------------------------------------

    pub fn login(&self, session_id: SessionId, user_type: UserType, pin: Pin) -> Result<()> {
        let (session_lock, slot_lock) = self.get_session_and_slot(session_id)?;
        let read_only_session = matches!(session_lock.read().unwrap().state, SessionState::ReadOnly);

        let mut slot = slot_lock.write().unwrap();
        match slot.current_user_type {
            Some(current) if current == user_type => return Err(HsmError::UserAlreadyLoggedIn),
            Some(_) => return Err(HsmError::UserAnotherAlreadyLoggedIn),
            None => {}
        }

        match user_type {
            UserType::So => {
                // The SO may not log in while any read-only session is open.
                if read_only_session || slot.has_read_only_session() {
                    return Err(HsmError::SessionReadOnlyExists);
                }

                if !slot.so_pin.as_ref().is_some_and(|hash| hash.verify(&pin)) {
                    return Err(HsmError::PinIncorrect);
                }
            }
            UserType::User => {
                let Some(hash) = slot.user_pin.as_ref() else {
                    return Err(HsmError::UserPinNotInitialized);
                };

                if !hash.verify(&pin) {
                    return Err(HsmError::PinIncorrect);
                }
            }
        }

        slot.current_user_type = Some(user_type);
        Ok(())
    }

    pub fn logout(&self, session_id: SessionId) -> Result<()> {
        let (_session_lock, slot_lock) = self.get_session_and_slot(session_id)?;
        let mut slot = slot_lock.write().unwrap();

        if slot.current_user_type.is_none() {
            return Err(HsmError::UserNotLoggedIn);
        }

        slot.current_user_type = None;
        Ok(())
    }

    /// Sets the user PIN. Requires an SO login in a read/write session.
    pub fn init_pin(&self, session_id: SessionId, pin: Pin) -> Result<()> {
        let store = self.object_store()?;
        let (session_lock, slot_lock) = self.get_session_and_slot(session_id)?;
        let session = session_lock.read().unwrap();
        let mut slot = slot_lock.write().unwrap();

        if slot.current_user_type != Some(UserType::So) || !matches!(session.state, SessionState::ReadWrite) {
            return Err(HsmError::UserNotLoggedIn);
        }

        let user_pin_hash = PinHash::from_pin(&pin);
        store
            .set_user_pin_hash(session.slot_id.0, user_pin_hash.as_str())
            .map_err(HsmError::ObjectStore)?;
        slot.user_pin = Some(user_pin_hash);
        Ok(())
    }

    /// Changes the PIN of the currently logged-in user, or the user PIN when
    /// no one is logged in.
    pub fn set_pin(&self, session_id: SessionId, old_pin: Pin, new_pin: Pin) -> Result<()> {
        let store = self.object_store()?;
        let (session_lock, slot_lock) = self.get_session_and_slot(session_id)?;
        let session = session_lock.read().unwrap();
        let slot_id = session.slot_id;
        let mut slot = slot_lock.write().unwrap();

        if !matches!(session.state, SessionState::ReadWrite) {
            return Err(HsmError::SessionReadOnly);
        }

        if slot.current_user_type == Some(UserType::So) {
            if !slot.so_pin.as_ref().is_some_and(|hash| hash.verify(&old_pin)) {
                return Err(HsmError::PinIncorrect);
            }
            let so_pin_hash = PinHash::from_pin(&new_pin);
            store
                .set_so_pin_hash(slot_id.0, so_pin_hash.as_str())
                .map_err(HsmError::ObjectStore)?;
            slot.so_pin = Some(so_pin_hash);
        } else {
            if !slot.user_pin.as_ref().is_some_and(|hash| hash.verify(&old_pin)) {
                return Err(HsmError::PinIncorrect);
            }
            let user_pin_hash = PinHash::from_pin(&new_pin);
            store
                .set_user_pin_hash(slot_id.0, user_pin_hash.as_str())
                .map_err(HsmError::ObjectStore)?;
            slot.user_pin = Some(user_pin_hash);
        }

        Ok(())
    }

    // ---- key management ----------------------------------------------------

    /// Creates an object from a template. Secret keys (`CKO_SECRET_KEY` with
    /// `CKA_VALUE`) are stored like a generated or imported symmetric key.
    /// Public keys (`CKO_PUBLIC_KEY`) are stored as metadata-only objects so
    /// their attributes can be read back and searched. Other classes are rejected
    /// as inconsistent. In every case the template attributes are persisted verbatim
    /// (minus `CKA_VALUE`, which becomes the key material) for later readback.
    pub fn create_object(&self, session_id: SessionId, attributes: Vec<Attribute>) -> Result<ObjectId> {
        let session_lock = self.get_session(session_id)?;
        let session = session_lock.read().unwrap();

        self.check_writable(&session, &attributes)?;

        let class = attributes.iter().find_map(|attr| match attr {
            Attribute::Class(class) => Some(class),
            _ => None,
        });

        match class {
            Some(ObjectClass::SecretKey) => {
                let value = attributes
                    .iter()
                    .find_map(|attr| match attr {
                        Attribute::Value(bytes) => Some(bytes.clone()),
                        _ => None,
                    })
                    .ok_or(HsmError::TemplateIncomplete)?;

                if value.is_empty() {
                    return Err(HsmError::AttributeValueInvalid);
                }

                let attributes = merge_attributes(attributes, vec![]);
                session.write_object(&value, attributes).map_err(store_error)
            }
            Some(ObjectClass::PublicKey) => {
                let attributes = merge_attributes(attributes, vec![]);
                let material: Vec<u8> = Vec::new();
                session.write_object(&material, attributes).map_err(store_error)
            }
            Some(ObjectClass::PrivateKey) | Some(ObjectClass::Unknown) => Err(HsmError::TemplateInconsistent),
            None => Err(HsmError::TemplateIncomplete),
        }
    }

    /// Imports raw key material as a labelled token secret key, the same way
    /// a generated symmetric key is stored.
    pub fn import_secret_key(&self, session_id: SessionId, key: Vec<u8>, label: String) -> Result<ObjectId> {
        let session_lock = self.get_session(session_id)?;
        let session = session_lock.read().unwrap();

        let attributes = vec![
            Attribute::Class(ObjectClass::SecretKey),
            Attribute::Label(label),
            Attribute::Private(true),
            Attribute::Token(true),
        ];
        self.check_writable(&session, &attributes)?;

        session.write_object(&key, attributes).map_err(store_error)
    }

    pub fn generate_key(
        &self,
        session_id: SessionId,
        mechanism: &Mechanism,
        attributes: Vec<Attribute>,
    ) -> Result<ObjectId> {
        let session_lock = self.get_session(session_id)?;
        let session = session_lock.read().unwrap();

        self.check_writable(&session, &attributes)?;

        let (key_len, key_type) = match mechanism {
            Mechanism::GenericSecretKeyGen => {
                let key_len = value_len(&attributes)?;
                if key_len == 0 || key_len > MAX_SECRET_KEY_LENGTH {
                    return Err(HsmError::AttributeValueInvalid);
                }
                (key_len, KeyType::GenericSecret)
            }
            Mechanism::AesKeyGen => {
                // CKM_AES_KEY_GEN takes the key length from CKA_VALUE_LEN;
                // AES defines exactly three key sizes.
                let key_len = value_len(&attributes)?;
                if !matches!(key_len, 16 | 24 | 32) {
                    return Err(HsmError::AttributeValueInvalid);
                }
                (key_len, KeyType::Aes)
            }
            _ => return Err(HsmError::MechanismInvalid),
        };

        let key = random_bytes(key_len as usize);
        let attributes = merge_attributes(
            attributes,
            vec![Attribute::Class(ObjectClass::SecretKey), Attribute::KeyType(key_type)],
        );
        let object_id = session.write_object(&key, attributes).map_err(store_error)?;
        Ok(object_id)
    }

    /// Generates a key pair, returning `(public, private)` object ids.
    pub fn generate_key_pair(
        &self,
        session_id: SessionId,
        mechanism: &Mechanism,
        public_key_attributes: Vec<Attribute>,
        private_key_attributes: Vec<Attribute>,
    ) -> Result<(ObjectId, ObjectId)> {
        let session_lock = self.get_session(session_id)?;

        {
            let session = session_lock.read().unwrap();
            self.check_writable(&session, &public_key_attributes)?;
            self.check_writable(&session, &private_key_attributes)?;
        }

        match mechanism {
            Mechanism::RsaPkcsKeyPairGen => {
                let bits = public_key_attributes
                    .iter()
                    .find_map(|attr| match attr {
                        Attribute::ModulusBits(bits) => Some(*bits),
                        _ => None,
                    })
                    .ok_or(HsmError::TemplateIncomplete)?;

                if !(MIN_RSA_MODULUS_BITS..=MAX_RSA_MODULUS_BITS).contains(&bits) {
                    return Err(HsmError::AttributeValueInvalid);
                }

                // Key generation is slow; run it without holding any lock.
                let mut rng = rand::rng();
                let private_key =
                    RsaPrivateKey::new(&mut rng, bits as usize).map_err(|_| HsmError::AttributeValueInvalid)?;
                let public_key = private_key.to_public_key();

                let public_key_attributes = merge_attributes(
                    public_key_attributes,
                    vec![
                        Attribute::Class(ObjectClass::PublicKey),
                        Attribute::KeyType(KeyType::Rsa),
                        Attribute::Modulus(public_key.n_bytes().to_vec()),
                        Attribute::PublicExponent(public_key.e_bytes().to_vec()),
                        Attribute::ModulusBits(public_key.n().bits() as u64),
                    ],
                );
                let private_key_attributes = merge_attributes(
                    private_key_attributes,
                    vec![
                        Attribute::Class(ObjectClass::PrivateKey),
                        Attribute::KeyType(KeyType::Rsa),
                    ],
                );

                let session = session_lock.read().unwrap();
                let private_id = session
                    .write_object(&private_key, private_key_attributes)
                    .map_err(store_error)?;
                let public_id = session
                    .write_object(&public_key, public_key_attributes)
                    .map_err(store_error)?;

                Ok((public_id, private_id))
            }
            Mechanism::EcKeyPairGen => {
                let signing_key = ecdsa::SigningKey::generate();
                let private_bytes = signing_key.to_bytes().to_vec();
                let verifying_key = *signing_key.verifying_key();

                let public_key_attributes = merge_attributes(
                    public_key_attributes,
                    vec![
                        Attribute::Class(ObjectClass::PublicKey),
                        Attribute::KeyType(KeyType::Ec),
                        Attribute::EcPoint(ec_point_der(&verifying_key)?),
                        Attribute::EcParams(SECP256R1_EC_PARAMS.to_vec()),
                    ],
                );
                let private_key_attributes = merge_attributes(
                    private_key_attributes,
                    vec![
                        Attribute::Class(ObjectClass::PrivateKey),
                        Attribute::KeyType(KeyType::Ec),
                    ],
                );

                let session = session_lock.read().unwrap();
                let private_id = session
                    .write_object(&private_bytes, private_key_attributes)
                    .map_err(store_error)?;
                let public_id = session
                    .write_object(&verifying_key, public_key_attributes)
                    .map_err(store_error)?;

                Ok((public_id, private_id))
            }
            _ => Err(HsmError::MechanismInvalid),
        }
    }

    pub fn wrap_key(
        &self,
        session_id: SessionId,
        mechanism: &Mechanism,
        wrapping_key: ObjectId,
        key: ObjectId,
    ) -> Result<Vec<u8>> {
        let session_lock = self.get_session(session_id)?;
        let session = session_lock.read().unwrap();

        match mechanism {
            Mechanism::AesKeyWrapPad => {
                let wrapping_key_bytes: Vec<u8> =
                    read_handle(&session, &wrapping_key, HsmError::WrappingKeyHandleInvalid)?;
                let key_bytes: Vec<u8> = read_handle(&session, &key, HsmError::KeyHandleInvalid)?;

                let kek = KwpAes256::new_from_slice(&wrapping_key_bytes).map_err(|_| HsmError::WrappingKeySizeRange)?;

                // AES-KWP output is the plaintext padded up to an 8-byte
                // boundary plus one 8-byte block.
                let mut buffer = vec![0u8; key_bytes.len().div_ceil(8) * 8 + 8];
                let wrapped = kek
                    .wrap_key(&key_bytes, &mut buffer)
                    .map_err(|_| HsmError::GeneralError)?;
                Ok(wrapped.to_vec())
            }
            _ => Err(HsmError::MechanismInvalid),
        }
    }

    pub fn unwrap_key(
        &self,
        session_id: SessionId,
        mechanism: &Mechanism,
        unwrapping_key: ObjectId,
        wrapped_key: &[u8],
        attributes: Vec<Attribute>,
    ) -> Result<ObjectId> {
        let session_lock = self.get_session(session_id)?;
        let session = session_lock.read().unwrap();

        match mechanism {
            Mechanism::AesKeyWrapPad => {
                let unwrapping_key_bytes: Vec<u8> =
                    read_handle(&session, &unwrapping_key, HsmError::UnwrappingKeyHandleInvalid)?;

                let kek =
                    KwpAes256::new_from_slice(&unwrapping_key_bytes).map_err(|_| HsmError::UnwrappingKeySizeRange)?;

                // Unwrapped output is at most the wrapped length less one
                // 8-byte block; `unwrap_key` truncates to the true length.
                let mut buffer = vec![0u8; wrapped_key.len()];
                let key_bytes = kek
                    .unwrap_key(wrapped_key, &mut buffer)
                    .map_err(|_| HsmError::WrappedKeyInvalid)?
                    .to_vec();

                let object_id = session.write_object(&key_bytes, attributes).map_err(store_error)?;
                Ok(object_id)
            }
            _ => Err(HsmError::MechanismInvalid),
        }
    }

    // ---- objects -----------------------------------------------------------

    pub fn destroy_object(&self, session_id: SessionId, object: ObjectId) -> Result<()> {
        let session_lock = self.get_session(session_id)?;
        let session = session_lock.read().unwrap();

        session.delete_object(&object).map_err(|error| match error {
            SessionError::ObjectStore(ObjectStoreError::Database(e)) => {
                HsmError::ObjectStore(ObjectStoreError::Database(e))
            }
            _ => HsmError::ObjectHandleInvalid,
        })
    }

    pub fn object_exists(&self, session_id: SessionId, object: ObjectId) -> Result<bool> {
        let session_lock = self.get_session(session_id)?;
        let session = session_lock.read().unwrap();
        Ok(session.object_exists(&object))
    }

    /// Returns the requested attribute of an object, or `None` if the object
    /// does not carry it. Attributes are served from the object's stored
    /// typed attribute list, which was assembled at creation from the
    /// template plus token-synthesized and derived values.
    pub fn object_attribute(
        &self,
        session_id: SessionId,
        object: ObjectId,
        attribute_type: AttributeType,
    ) -> Result<Option<Attribute>> {
        let session_lock = self.get_session(session_id)?;
        let session = session_lock.read().unwrap();

        let attributes = session.read_object_attributes(&object).map_err(|error| match error {
            SessionError::ObjectStore(ObjectStoreError::Database(e)) => {
                HsmError::ObjectStore(ObjectStoreError::Database(e))
            }
            _ => HsmError::ObjectHandleInvalid,
        })?;

        Ok(attributes
            .into_iter()
            .find(|attr| attr.attribute_type() == Some(attribute_type)))
    }

    pub fn find_objects_init(&self, session_id: SessionId, attributes: Vec<Attribute>) -> Result<()> {
        let session_lock = self.get_session(session_id)?;
        let session = session_lock.read().unwrap();

        session.init_search(attributes).map_err(|_| HsmError::OperationActive)
    }

    pub fn find_objects_next(&self, session_id: SessionId, max_count: usize) -> Result<Vec<ObjectId>> {
        let session_lock = self.get_session(session_id)?;
        let mut session = session_lock.write().unwrap();

        if !session.is_search_active() {
            return Err(HsmError::OperationNotInitialized);
        }

        let mut found = Vec::new();
        while found.len() < max_count {
            match session.search_result().map_err(store_error)? {
                Some(object_id) => found.push(object_id),
                None => break,
            }
        }

        Ok(found)
    }

    pub fn find_objects_final(&self, session_id: SessionId) -> Result<()> {
        let session_lock = self.get_session(session_id)?;
        let mut session = session_lock.write().unwrap();

        session.finish_search().map_err(|_| HsmError::OperationNotInitialized)
    }

    // ---- sign / verify / encrypt --------------------------------------------

    pub fn sign_init(&self, session_id: SessionId, mechanism: &Mechanism, key: ObjectId) -> Result<()> {
        let session_lock = self.get_session(session_id)?;
        let session = session_lock.read().unwrap();

        if session.operation.get().is_some() {
            return Err(HsmError::OperationActive);
        }

        let operation = match mechanism {
            Mechanism::RsaPkcs => {
                let private_key: RsaPrivateKey = read_handle(&session, &key, HsmError::KeyHandleInvalid)?;
                Operation::SignRsa {
                    private_key: Box::new(private_key),
                }
            }
            Mechanism::Ecdsa => {
                let key_bytes: Vec<u8> = read_handle(&session, &key, HsmError::KeyHandleInvalid)?;
                let signing_key = ecdsa::SigningKey::from_slice(&key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
                Operation::SignEcdsa {
                    signing_key: Box::new(signing_key),
                }
            }
            Mechanism::Sha256Hmac => {
                let key_bytes: Vec<u8> = read_handle(&session, &key, HsmError::KeyHandleInvalid)?;
                let signing_key = HmacSha256::new_from_slice(&key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
                Operation::SignSha256Hmac {
                    signing_key: Box::new(signing_key),
                }
            }
            _ => return Err(HsmError::MechanismInvalid),
        };

        session.operation.set(operation).map_err(|_| HsmError::OperationActive)
    }

    /// Length of the signature the active sign operation will produce. Does
    /// not consume the operation.
    pub fn signature_length(&self, session_id: SessionId) -> Result<u64> {
        let session_lock = self.get_session(session_id)?;
        let session = session_lock.read().unwrap();

        let operation = session.operation.get().ok_or(HsmError::OperationNotInitialized)?;
        if !operation.is_sign() {
            return Err(HsmError::OperationNotInitialized);
        }

        Ok(operation.signature_length())
    }

    /// Signs `data`, consuming the active sign operation.
    pub fn sign(&self, session_id: SessionId, data: &[u8]) -> Result<Vec<u8>> {
        let session_lock = self.get_session(session_id)?;
        let mut session = session_lock.write().unwrap();

        if !session.operation.get().is_some_and(Operation::is_sign) {
            return Err(HsmError::OperationNotInitialized);
        }

        let operation = session.operation.take().unwrap();
        Ok(operation.sign(data).0)
    }

    pub fn verify_init(&self, session_id: SessionId, mechanism: &Mechanism, key: ObjectId) -> Result<()> {
        let session_lock = self.get_session(session_id)?;
        let session = session_lock.read().unwrap();

        if session.operation.get().is_some() {
            return Err(HsmError::OperationActive);
        }

        let operation = match mechanism {
            Mechanism::RsaPkcs => {
                let public_key: RsaPublicKey = read_handle(&session, &key, HsmError::KeyHandleInvalid)?;
                Operation::VerifyRsa {
                    public_key: Box::new(public_key),
                }
            }
            Mechanism::Ecdsa => {
                let verifying_key: VerifyingKey = read_handle(&session, &key, HsmError::KeyHandleInvalid)?;
                Operation::VerifyEcdsa {
                    verifying_key: Box::new(verifying_key),
                }
            }
            Mechanism::Sha256Hmac => {
                let key_bytes: Vec<u8> = read_handle(&session, &key, HsmError::KeyHandleInvalid)?;
                let verifying_key = HmacSha256::new_from_slice(&key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
                Operation::VerifySha256Hmac {
                    verifying_key: Box::new(verifying_key),
                }
            }
            _ => return Err(HsmError::MechanismInvalid),
        };

        session.operation.set(operation).map_err(|_| HsmError::OperationActive)
    }

    /// Verifies `signature` over `data`, consuming the active verify operation.
    pub fn verify(&self, session_id: SessionId, data: &[u8], signature: &[u8]) -> Result<()> {
        let session_lock = self.get_session(session_id)?;
        let mut session = session_lock.write().unwrap();

        if !session.operation.get().is_some_and(Operation::is_verify) {
            return Err(HsmError::OperationNotInitialized);
        }

        let operation = session.operation.take().unwrap();
        if operation.verify(data, signature) {
            Ok(())
        } else {
            Err(HsmError::SignatureInvalid)
        }
    }

    pub fn encrypt_init(&self, session_id: SessionId, mechanism: &Mechanism, key: ObjectId) -> Result<()> {
        let session_lock = self.get_session(session_id)?;
        let session = session_lock.read().unwrap();

        if session.operation.get().is_some() {
            return Err(HsmError::OperationActive);
        }

        match mechanism {
            Mechanism::AesGcm {
                initialization_vector,
                additional_authenticated_data,
            } => {
                let key_bytes: Vec<u8> = read_handle(&session, &key, HsmError::KeyHandleInvalid)?;
                if !matches!(key_bytes.len(), 16 | 32) {
                    return Err(HsmError::KeySizeRange);
                }

                session
                    .operation
                    .set(Operation::EncryptAesGcm {
                        key: key_bytes,
                        initialization_vector: initialization_vector.clone(),
                        additional_authenticated_data: additional_authenticated_data.clone(),
                    })
                    .map_err(|_| HsmError::OperationActive)
            }
            _ => Err(HsmError::MechanismInvalid),
        }
    }

    /// Length of the ciphertext the active encrypt operation will produce for
    /// `data_length` bytes of plaintext. Does not consume the operation.
    pub fn encrypted_length(&self, session_id: SessionId, data_length: u64) -> Result<u64> {
        let session_lock = self.get_session(session_id)?;
        let session = session_lock.read().unwrap();

        if !session.operation.get().is_some_and(Operation::is_encrypt) {
            return Err(HsmError::OperationNotInitialized);
        }

        data_length
            .checked_add(AES_GCM_TAG_LENGTH as u64)
            .ok_or(HsmError::DataLenRange)
    }

    /// Encrypts `data`, consuming the active encrypt operation.
    pub fn encrypt(&self, session_id: SessionId, data: &[u8]) -> Result<Vec<u8>> {
        let session_lock = self.get_session(session_id)?;
        let mut session = session_lock.write().unwrap();

        if !session.operation.get().is_some_and(Operation::is_encrypt) {
            return Err(HsmError::OperationNotInitialized);
        }

        let operation = session.operation.take().unwrap();
        operation.encrypt(data).ok_or(HsmError::GeneralError)
    }

    pub fn decrypt_init(&self, session_id: SessionId, mechanism: &Mechanism, key: ObjectId) -> Result<()> {
        let session_lock = self.get_session(session_id)?;
        let session = session_lock.read().unwrap();

        if session.operation.get().is_some() {
            return Err(HsmError::OperationActive);
        }

        match mechanism {
            Mechanism::AesGcm {
                initialization_vector,
                additional_authenticated_data,
            } => {
                let key_bytes: Vec<u8> = read_handle(&session, &key, HsmError::KeyHandleInvalid)?;
                if !matches!(key_bytes.len(), 16 | 32) {
                    return Err(HsmError::KeySizeRange);
                }

                session
                    .operation
                    .set(Operation::DecryptAesGcm {
                        key: key_bytes,
                        initialization_vector: initialization_vector.clone(),
                        additional_authenticated_data: additional_authenticated_data.clone(),
                    })
                    .map_err(|_| HsmError::OperationActive)
            }
            _ => Err(HsmError::MechanismInvalid),
        }
    }

    /// Upper bound on the plaintext length the active decrypt operation will
    /// produce for `data_length` bytes of ciphertext. Does not consume the
    /// operation. AES-GCM ciphertext carries a trailing tag, so anything
    /// shorter than the tag cannot be valid.
    pub fn decrypted_length(&self, session_id: SessionId, data_length: u64) -> Result<u64> {
        let session_lock = self.get_session(session_id)?;
        let session = session_lock.read().unwrap();

        if !session.operation.get().is_some_and(Operation::is_decrypt) {
            return Err(HsmError::OperationNotInitialized);
        }

        data_length
            .checked_sub(AES_GCM_TAG_LENGTH as u64)
            .ok_or(HsmError::EncryptedDataLenRange)
    }

    /// Decrypts `data`, consuming the active decrypt operation.
    pub fn decrypt(&self, session_id: SessionId, data: &[u8]) -> Result<Vec<u8>> {
        let session_lock = self.get_session(session_id)?;
        let mut session = session_lock.write().unwrap();

        if !session.operation.get().is_some_and(Operation::is_decrypt) {
            return Err(HsmError::OperationNotInitialized);
        }

        let operation = session.operation.take().unwrap();
        operation.decrypt(data).ok_or(HsmError::EncryptedDataInvalid)
    }

    // ---- internals -----------------------------------------------------------

    fn check_writable(&self, session: &Session, attributes: &[Attribute]) -> Result<()> {
        let token_object = attributes.iter().any(|attr| matches!(attr, Attribute::Token(true)));
        if token_object && matches!(session.state, SessionState::ReadOnly) {
            return Err(HsmError::SessionReadOnly);
        }
        Ok(())
    }

    fn get_slot(&self, slot_id: &SlotId) -> Result<Arc<RwLock<Slot>>> {
        self.ensure_initialized()?;
        let slots = self.slots.read().unwrap();
        let slot = slots.get(slot_id).ok_or(HsmError::SlotNotFound(*slot_id))?;
        Ok(Arc::clone(slot))
    }

    fn find_by_session_id(&self, session_id: SessionId) -> Option<Arc<RwLock<Slot>>> {
        let slots = self.slots.read().unwrap();
        slots
            .iter()
            .find(|(_slot_id, slot)| slot.read().unwrap().sessions.read().unwrap().contains_key(&session_id))
            .map(|(_id, slot)| Arc::clone(slot))
    }

    fn get_session_and_slot(&self, session_id: SessionId) -> Result<SessionAndSlot> {
        self.ensure_initialized()?;
        let slot_lock = self
            .find_by_session_id(session_id)
            .ok_or(HsmError::SessionNotFound(session_id))?;
        let session = slot_lock
            .read()
            .unwrap()
            .sessions
            .read()
            .unwrap()
            .get(&session_id)
            .cloned()
            .ok_or(HsmError::SessionNotFound(session_id))?;
        Ok((session, slot_lock))
    }

    fn get_session(&self, session_id: SessionId) -> Result<Arc<RwLock<Session>>> {
        self.get_session_and_slot(session_id).map(|(session, _slot)| session)
    }
}

/// Reads an object, mapping "not found" and "wrong type" onto the
/// context-specific invalid-handle error while letting database failures
/// surface as such.
fn read_handle<T>(session: &Session, object_id: &ObjectId, invalid: HsmError) -> Result<T>
where
    T: DeserializeOwned,
{
    session.read_object(object_id).map_err(|error| match error {
        SessionError::ObjectStore(ObjectStoreError::Database(e)) => {
            HsmError::ObjectStore(ObjectStoreError::Database(e))
        }
        _ => invalid,
    })
}

/// Reads `CKA_VALUE_LEN` (the secret-key length in bytes) from a template,
/// which every symmetric key-generation mechanism requires.
fn value_len(attributes: &[Attribute]) -> Result<u64> {
    attributes
        .iter()
        .find_map(|attr| match attr {
            Attribute::ValueLen(len) => Some(*len),
            _ => None,
        })
        .ok_or(HsmError::TemplateIncomplete)
}

fn store_error(error: SessionError) -> HsmError {
    match error {
        SessionError::ObjectStore(e) => HsmError::ObjectStore(e),
        _ => HsmError::GeneralError,
    }
}

/// DER encoding of the `prime256v1` (P-256) named curve OID, the value of
/// `CKA_EC_PARAMS` for every EC key this token produces.
const SECP256R1_EC_PARAMS: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// Merges token-synthesized/derived attributes into an application template,
/// producing the attribute list persisted with the object. `CKA_VALUE` (the
/// key material) and unrecognized attributes are dropped, and each derived
/// attribute is added only when the template does not already carry that type
/// so the application's choice wins.
fn merge_attributes(mut attributes: Vec<Attribute>, derived: Vec<Attribute>) -> Vec<Attribute> {
    attributes.retain(|attr| !matches!(attr, Attribute::Value(_) | Attribute::Unknown));

    for attribute in derived {
        let already_present = attribute.attribute_type().is_some_and(|type_| {
            attributes
                .iter()
                .any(|existing| existing.attribute_type() == Some(type_))
        });
        if !already_present {
            attributes.push(attribute);
        }
    }

    attributes
}

/// The `CKA_EC_POINT` value of a P-256 public key: its uncompressed SEC1
/// encoding wrapped in a DER `OCTET STRING`.
fn ec_point_der(verifying_key: &VerifyingKey) -> Result<Vec<u8>> {
    OctetString::new(verifying_key.to_sec1_bytes().to_vec())
        .ok()
        .and_then(|octets| octets.to_der().ok())
        .ok_or(HsmError::GeneralError)
}

#[cfg(test)]
#[path = "hsm_tests.rs"]
mod tests;
