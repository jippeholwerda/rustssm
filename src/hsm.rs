use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::sync::RwLockReadGuard;
use std::sync::RwLockWriteGuard;

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
use thiserror::Error;

use crate::attribute::default_boolean_attributes;
use crate::attribute::Attribute;
use crate::attribute::AttributeType;
use crate::attribute::CanonicalAttributes;
use crate::attribute::KeyType;
use crate::attribute::ObjectClass;
use crate::attribute::Template;
use crate::attribute::TemplateError;
use crate::encryption::Decrypt;
use crate::encryption::Encrypt;
use crate::mechanism::Mechanism;
use crate::object_store::ObjectId;
use crate::object_store::ObjectStore;
use crate::object_store::ObjectStoreError;
use crate::object_store::TokenRecord;
use crate::operation::Operation;
use crate::pin::Pin;
use crate::pin::PinHash;
use crate::session::ObjectParts;
use crate::session::Session;
use crate::session::SessionError;
use crate::session::SessionId;
use crate::session::SessionState;
use crate::signing::HmacSha256;
use crate::signing::Sign;
use crate::signing::SignatureLength;
use crate::signing::Verify;
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

    #[error("attribute read-only")]
    AttributeReadOnly,

    #[error("key handle invalid")]
    KeyHandleInvalid,

    #[error("key does not permit this operation")]
    KeyFunctionNotPermitted,

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

    #[error("curve not supported")]
    CurveNotSupported,

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
    slots: HashMap<SlotId, Arc<RwLock<Slot>>>,
    object_store: OnceLock<Arc<ObjectStore>>,
    next_session_id: AtomicU64,
    initialized: AtomicBool,
}

impl Default for Hsm {
    fn default() -> Self {
        // rustssm exposes a single token. PKCS#11 is slot-addressed, so the slot
        // is still keyed by `SlotId`, but there is exactly one.
        Self {
            slots: HashMap::from_iter([(SlotId(0), Arc::new(RwLock::new(Slot::default())))]),
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
        // tokens (and accepts the same PINs). Session objects need no crash
        // recovery: they live in process memory only, so they cannot outlive
        // a process. Roll back on failure so the caller can retry once the
        // store is reachable.
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

        for (slot_id, slot_lock) in self.slots.iter() {
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

    /// Closes all sessions on all slots (destroying their session objects)
    /// and resets login state.
    pub fn finalize(&self) -> Result<()> {
        if !self.initialized.swap(false, Ordering::SeqCst) {
            return Err(HsmError::NotInitialized);
        }

        for slot_lock in self.slots.values() {
            let mut slot = slot_lock.write().unwrap();
            slot.sessions.clear();
            slot.session_objects.write().unwrap().clear();
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
        let mut ids: Vec<u64> = self.slots.keys().map(|id| id.0).collect();
        ids.sort_unstable();
        Ok(ids)
    }

    pub fn slot_exists(&self, slot_id: SlotId) -> Result<()> {
        self.get_slot(&slot_id).map(|_| ())
    }

    pub fn token_status(&self, slot_id: SlotId) -> Result<TokenStatus> {
        let slot_lock = self.get_slot(&slot_id)?;
        let slot = slot_lock.read().unwrap();
        let session_count = slot.sessions.len();

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

        if !slot.sessions.is_empty() {
            return Err(HsmError::SessionExists(*slot_id));
        }

        // Re-initializing an already-initialized token requires the supplied SO
        // PIN to match the existing one (PKCS#11 §5.6); a fresh token accepts
        // any PIN as its new SO PIN. Checked before `clear()` so a wrong PIN
        // cannot destroy the token's objects.
        if slot.initialized && !slot.so_pin.as_ref().is_some_and(|hash| hash.verify(&so_pin)) {
            return Err(HsmError::PinIncorrect);
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
        let mut slot = slot_lock.write().unwrap();

        // While the SO is logged in, no read-only session may be opened.
        if matches!(state, SessionState::ReadOnly) && slot.current_user_type == Some(UserType::So) {
            return Err(HsmError::SessionReadOnlyExists);
        }

        let session_id = SessionId(self.next_session_id.fetch_add(1, Ordering::Relaxed));
        let session = Session::new(session_id, slot_id, state, store, slot.session_objects.clone());
        slot.sessions.insert(session_id, Arc::new(RwLock::new(session)));
        Ok(session_id)
    }

    pub fn close_session(&self, session_id: SessionId) -> Result<()> {
        self.ensure_initialized()?;
        let slot_lock = self
            .find_by_session_id(session_id)
            .ok_or(HsmError::SessionNotFound(session_id))?;

        let mut slot = slot_lock.write().unwrap();
        slot.sessions.remove(&session_id);

        // When the last session with a token closes, the login state resets.
        if slot.sessions.is_empty() {
            slot.current_user_type = None;
        }
        let session_objects = slot.session_objects.clone();
        drop(slot);

        // Session objects live only as long as the session that created them.
        session_objects.write().unwrap().remove_owned_by(session_id);
        Ok(())
    }

    pub fn validate_session(&self, session_id: SessionId) -> Result<()> {
        self.session_context(session_id).map(|_| ())
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
    /// EC private keys (`CKO_PRIVATE_KEY` + `CKK_EC` with `CKA_VALUE` = the
    /// scalar) are stored like a generated EC private key, so they can be
    /// found by label and used to sign. Public keys (`CKO_PUBLIC_KEY`) are
    /// stored as metadata-only objects so their attributes can be read back
    /// and searched. Other classes are rejected as inconsistent. In every case
    /// the template attributes are persisted verbatim (minus `CKA_VALUE`, which
    /// becomes the key material) for later readback.
    pub fn create_object(&self, session_id: SessionId, attributes: Vec<Attribute>) -> Result<ObjectId> {
        let ctx = self.session_context(session_id)?;
        let template = Template::new(attributes).map_err(template_error)?;
        let class = template.class();

        ctx.require_login_to_create(&template, class)?;
        ctx.check_writable(template.attributes())?;

        match class {
            Some(ObjectClass::SecretKey) => {
                let value = value_attribute(template.attributes())?;
                if value.is_empty() {
                    return Err(HsmError::AttributeValueInvalid);
                }

                let attributes = template.merge(vec![]);
                let session = ctx.session();
                session.write_object(&value, attributes).map_err(store_error)
            }
            Some(ObjectClass::PrivateKey) => {
                // Only EC private keys are supported; the material is the P-256
                // scalar, stored exactly as a generated EC private key is.
                let key_type = template.attributes().iter().find_map(|attr| match attr {
                    Attribute::KeyType(key_type) => Some(*key_type),
                    _ => None,
                });
                if key_type != Some(KeyType::Ec) {
                    return Err(HsmError::TemplateInconsistent);
                }

                validate_ec_params(template.attributes())?;

                let value = value_attribute(template.attributes())?;
                let material = ec_private_key_material(&value)?;

                let attributes = template.merge(vec![]);
                let session = ctx.session();
                session.write_object(&material, attributes).map_err(store_error)
            }
            Some(ObjectClass::PublicKey) => {
                let attributes = template.merge(vec![]);
                let material: Vec<u8> = Vec::new();
                let session = ctx.session();
                session.write_object(&material, attributes).map_err(store_error)
            }
            Some(ObjectClass::Unknown) => Err(HsmError::TemplateInconsistent),
            None => Err(HsmError::TemplateIncomplete),
        }
    }

    /// Imports raw key material as a labelled token secret key by delegating
    /// to [`Self::create_object`] with the equivalent `C_CreateObject`
    /// template, so imported keys go through the same validation, login
    /// checks, class defaults and storage as any created object.
    pub fn import_secret_key(
        &self,
        session_id: SessionId,
        key: Vec<u8>,
        label: String,
        id: Option<Vec<u8>>,
    ) -> Result<ObjectId> {
        let mut attributes = vec![
            Attribute::Class(ObjectClass::SecretKey),
            Attribute::KeyType(KeyType::Aes),
            Attribute::Label(label),
            Attribute::Private(true),
            Attribute::Token(true),
            Attribute::Value(key),
        ];
        if let Some(id) = id {
            attributes.push(Attribute::Id(id));
        }

        self.create_object(session_id, attributes)
    }

    pub fn generate_key(
        &self,
        session_id: SessionId,
        mechanism: &Mechanism,
        attributes: Vec<Attribute>,
    ) -> Result<ObjectId> {
        let ctx = self.session_context(session_id)?;
        let template = Template::new(attributes).map_err(template_error)?;

        // A generated symmetric key is a secret key, which is private by
        // default, so creating one without login requires it (§4.4).
        ctx.require_login_to_create(&template, Some(ObjectClass::SecretKey))?;
        ctx.check_writable(template.attributes())?;

        let (key_len, key_type) = match mechanism {
            Mechanism::GenericSecretKeyGen => {
                let key_len = value_len(template.attributes())?;
                if key_len == 0 || key_len > MAX_SECRET_KEY_LENGTH {
                    return Err(HsmError::AttributeValueInvalid);
                }
                (key_len, KeyType::GenericSecret)
            }
            Mechanism::AesKeyGen => {
                // CKM_AES_KEY_GEN takes the key length from CKA_VALUE_LEN;
                // AES defines exactly three key sizes.
                let key_len = value_len(template.attributes())?;
                if !matches!(key_len, 16 | 24 | 32) {
                    return Err(HsmError::AttributeValueInvalid);
                }
                (key_len, KeyType::Aes)
            }
            _ => return Err(HsmError::MechanismInvalid),
        };

        let key = random_bytes(key_len as usize);
        let attributes = template.merge(vec![
            Attribute::Class(ObjectClass::SecretKey),
            Attribute::KeyType(key_type),
        ]);
        let session = ctx.session();
        session.write_object(&key, attributes).map_err(store_error)
    }

    /// Generates a key pair, returning `(public, private)` object ids.
    pub fn generate_key_pair(
        &self,
        session_id: SessionId,
        mechanism: &Mechanism,
        public_key_attributes: Vec<Attribute>,
        private_key_attributes: Vec<Attribute>,
    ) -> Result<(ObjectId, ObjectId)> {
        let ctx = self.session_context(session_id)?;
        let public_template = Template::new(public_key_attributes).map_err(template_error)?;
        let private_template = Template::new(private_key_attributes).map_err(template_error)?;

        // The private half is private by default, so generating a pair without
        // login is refused unless it is explicitly made public (§4.4).
        ctx.require_login_to_create(&public_template, Some(ObjectClass::PublicKey))?;
        ctx.require_login_to_create(&private_template, Some(ObjectClass::PrivateKey))?;
        ctx.check_writable(public_template.attributes())?;
        ctx.check_writable(private_template.attributes())?;

        match mechanism {
            Mechanism::RsaPkcsKeyPairGen => {
                let bits = public_template
                    .attributes()
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

                let public_key_attributes = public_template.merge(vec![
                    Attribute::Class(ObjectClass::PublicKey),
                    Attribute::KeyType(KeyType::Rsa),
                    Attribute::Modulus(public_key.n_bytes().to_vec()),
                    Attribute::PublicExponent(public_key.e_bytes().to_vec()),
                    Attribute::ModulusBits(public_key.n().bits() as u64),
                ]);
                // The private key carries the pair's public metadata too
                // (`CKA_MODULUS` and friends are spec-defined RSA private-key
                // attributes, and clients read them to size buffers).
                let private_key_attributes = private_template.merge(vec![
                    Attribute::Class(ObjectClass::PrivateKey),
                    Attribute::KeyType(KeyType::Rsa),
                    Attribute::Modulus(public_key.n_bytes().to_vec()),
                    Attribute::PublicExponent(public_key.e_bytes().to_vec()),
                    Attribute::ModulusBits(public_key.n().bits() as u64),
                ]);

                let session = ctx.session();
                let (private_id, public_id) = session
                    .write_object_pair(
                        (&private_key, private_key_attributes),
                        (&public_key, public_key_attributes),
                    )
                    .map_err(store_error)?;

                Ok((public_id, private_id))
            }
            Mechanism::EcKeyPairGen => {
                validate_ec_params(public_template.attributes())?;
                validate_ec_params(private_template.attributes())?;

                let signing_key = ecdsa::SigningKey::generate();
                let private_bytes = signing_key.to_bytes().to_vec();
                let verifying_key = *signing_key.verifying_key();

                let public_key_attributes = public_template.merge(vec![
                    Attribute::Class(ObjectClass::PublicKey),
                    Attribute::KeyType(KeyType::Ec),
                    Attribute::EcPoint(ec_point_der(&verifying_key)?),
                    Attribute::EcParams(SECP256R1_EC_PARAMS.to_vec()),
                ]);
                let private_key_attributes = private_template.merge(vec![
                    Attribute::Class(ObjectClass::PrivateKey),
                    Attribute::KeyType(KeyType::Ec),
                ]);

                let session = ctx.session();
                let (private_id, public_id) = session
                    .write_object_pair(
                        (&private_bytes, private_key_attributes),
                        (&verifying_key, public_key_attributes),
                    )
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
        let ctx = self.session_context(session_id)?;

        // §4.4 is enforced on both handles before the mechanism match,
        // preserving the current precedence.
        let wrapping_parts = ctx.object(&wrapping_key, HsmError::WrappingKeyHandleInvalid)?;
        let key_parts = ctx.object(&key, HsmError::KeyHandleInvalid)?;
        check_key_usage(&wrapping_parts.attributes, Attribute::Wrap(false))?;

        match mechanism {
            Mechanism::AesKeyWrapPad => {
                let wrapping_key_bytes: Vec<u8> =
                    wrapping_parts.material().ok_or(HsmError::WrappingKeyHandleInvalid)?;
                let key_bytes: Vec<u8> = key_parts.material().ok_or(HsmError::KeyHandleInvalid)?;

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
        let ctx = self.session_context(session_id)?;
        let template = Template::new(attributes).map_err(template_error)?;

        let unwrapping_parts = ctx.object(&unwrapping_key, HsmError::UnwrappingKeyHandleInvalid)?;
        check_key_usage(&unwrapping_parts.attributes, Attribute::Unwrap(false))?;
        ctx.require_login_to_create(&template, template.class())?;

        match mechanism {
            Mechanism::AesKeyWrapPad => {
                let unwrapping_key_bytes: Vec<u8> = unwrapping_parts
                    .material()
                    .ok_or(HsmError::UnwrappingKeyHandleInvalid)?;

                let kek =
                    KwpAes256::new_from_slice(&unwrapping_key_bytes).map_err(|_| HsmError::UnwrappingKeySizeRange)?;

                // Unwrapped output is at most the wrapped length less one
                // 8-byte block; `unwrap_key` truncates to the true length.
                let mut buffer = vec![0u8; wrapped_key.len()];
                let key_bytes = kek
                    .unwrap_key(wrapped_key, &mut buffer)
                    .map_err(|_| HsmError::WrappedKeyInvalid)?
                    .to_vec();

                let attributes = template.merge(vec![]);
                let session = ctx.session();
                session.write_object(&key_bytes, attributes).map_err(store_error)
            }
            _ => Err(HsmError::MechanismInvalid),
        }
    }

    // ---- objects -----------------------------------------------------------

    pub fn destroy_object(&self, session_id: SessionId, object: ObjectId) -> Result<()> {
        let ctx = self.session_context(session_id)?;
        ctx.object(&object, HsmError::ObjectHandleInvalid)?;
        let session = ctx.session();
        session
            .delete_object(&object)
            .map_err(|error| store_read_error(error, HsmError::ObjectHandleInvalid))
    }

    pub fn object_exists(&self, session_id: SessionId, object: ObjectId) -> Result<bool> {
        let ctx = self.session_context(session_id)?;
        let session = ctx.session();
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
        let ctx = self.session_context(session_id)?;
        let parts = ctx.object(&object, HsmError::ObjectHandleInvalid)?;
        Ok(parts
            .attributes
            .into_iter()
            .find(|attr| attr.attribute_type() == Some(attribute_type)))
    }

    /// Applies a `C_SetAttributeValue` update: each attribute replaces (or
    /// adds) the object's value of that type. Untracked attribute types are
    /// rejected as invalid, and identity/key-material attributes as read-only,
    /// as are the one-way downgrades (sensitive → non-sensitive,
    /// non-extractable → extractable). Token objects can only be modified in
    /// a read/write session.
    pub fn set_object_attributes(
        &self,
        session_id: SessionId,
        object: ObjectId,
        updates: Vec<Attribute>,
    ) -> Result<()> {
        let ctx = self.session_context(session_id)?;
        let mut attributes = ctx.object(&object, HsmError::ObjectHandleInvalid)?.attributes;
        ctx.check_writable(&attributes)?;

        // CKA_TOKEN decides which store holds the object — and thereby its
        // handle — so it is fixed at creation; changing token-ness requires
        // C_CopyObject, which mints a new object with a new handle.
        if updates.iter().any(|update| matches!(update, Attribute::Token(_))) {
            return Err(HsmError::AttributeReadOnly);
        }

        apply_attribute_updates(&mut attributes, updates)?;
        let session = ctx.session();
        session
            .set_object_attributes(&object, CanonicalAttributes::from_persisted(attributes))
            .map_err(store_error)
    }

    /// Copies an object, applying a template of attribute overrides to the
    /// copy. Overrides follow the same rules as `C_SetAttributeValue`
    /// (identity/key-material attributes are read-only, untracked/token-managed
    /// types are invalid, one-way guarantees are enforced). The copy shares
    /// the source's key material.
    pub fn copy_object(&self, session_id: SessionId, source: ObjectId, overrides: Vec<Attribute>) -> Result<ObjectId> {
        let ctx = self.session_context(session_id)?;
        let mut attributes = ctx.object(&source, HsmError::ObjectHandleInvalid)?.attributes;
        let overrides = Template::new(overrides).map_err(template_error)?.into_vec();
        apply_attribute_updates(&mut attributes, overrides)?;
        require_login_for_private(&attributes, ctx.logged_in_as_user)?;
        ctx.check_writable(&attributes)?;
        let session = ctx.session();
        session
            .copy_object(&source, CanonicalAttributes::from_persisted(attributes))
            .map_err(store_error)
    }

    pub fn find_objects_init(&self, session_id: SessionId, attributes: Vec<Attribute>) -> Result<()> {
        let ctx = self.session_context(session_id)?;
        let session = ctx.session();
        session
            .init_search(attributes, ctx.logged_in_as_user)
            .map_err(|_| HsmError::OperationActive)
    }

    pub fn find_objects_next(&self, session_id: SessionId, max_count: usize) -> Result<Vec<ObjectId>> {
        let ctx = self.session_context(session_id)?;
        let mut session = ctx.session_mut();

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
        let ctx = self.session_context(session_id)?;
        let mut session = ctx.session_mut();
        session.finish_search().map_err(|_| HsmError::OperationNotInitialized)
    }

    // ---- sign / verify / encrypt --------------------------------------------

    pub fn sign_init(&self, session_id: SessionId, mechanism: &Mechanism, key: ObjectId) -> Result<()> {
        let ctx = self.session_context(session_id)?;

        if ctx.session().operation.get().is_some() {
            return Err(HsmError::OperationActive);
        }

        let key_parts = ctx.object(&key, HsmError::KeyHandleInvalid)?;
        check_key_usage(&key_parts.attributes, Attribute::Sign(false))?;

        let operation = match mechanism {
            Mechanism::RsaPkcs => {
                let private_key: RsaPrivateKey = key_parts.material().ok_or(HsmError::KeyHandleInvalid)?;
                Operation::SignRsa {
                    private_key: Box::new(private_key),
                }
            }
            Mechanism::Ecdsa => {
                let key_bytes: Vec<u8> = key_parts.material().ok_or(HsmError::KeyHandleInvalid)?;
                let signing_key = ecdsa::SigningKey::from_slice(&key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
                Operation::SignEcdsa {
                    signing_key: Box::new(signing_key),
                }
            }
            Mechanism::Sha256Hmac => {
                let key_bytes: Vec<u8> = key_parts.material().ok_or(HsmError::KeyHandleInvalid)?;
                let signing_key = HmacSha256::new_from_slice(&key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
                Operation::SignSha256Hmac {
                    signing_key: Box::new(signing_key),
                }
            }
            _ => return Err(HsmError::MechanismInvalid),
        };

        let session = ctx.session();
        session.operation.set(operation).map_err(|_| HsmError::OperationActive)
    }

    /// Length of the signature the active sign operation will produce. Does
    /// not consume the operation.
    pub fn signature_length(&self, session_id: SessionId) -> Result<u64> {
        let ctx = self.session_context(session_id)?;
        let session = ctx.session();

        let operation = session.operation.get().ok_or(HsmError::OperationNotInitialized)?;
        if !operation.is_sign() {
            return Err(HsmError::OperationNotInitialized);
        }

        Ok(operation.signature_length())
    }

    /// Signs `data`, consuming the active sign operation.
    pub fn sign(&self, session_id: SessionId, data: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.session_context(session_id)?;
        let mut session = ctx.session_mut();

        if !session.operation.get().is_some_and(Operation::is_sign) {
            return Err(HsmError::OperationNotInitialized);
        }

        let operation = session.operation.take().unwrap();
        // `None` means the input is unusable for the mechanism — for raw
        // CKM_RSA_PKCS, data longer than the modulus can pad.
        Ok(operation.sign(data).ok_or(HsmError::DataLenRange)?.0)
    }

    pub fn verify_init(&self, session_id: SessionId, mechanism: &Mechanism, key: ObjectId) -> Result<()> {
        let ctx = self.session_context(session_id)?;

        if ctx.session().operation.get().is_some() {
            return Err(HsmError::OperationActive);
        }

        let key_parts = ctx.object(&key, HsmError::KeyHandleInvalid)?;
        check_key_usage(&key_parts.attributes, Attribute::Verify(false))?;

        let operation = match mechanism {
            Mechanism::RsaPkcs => {
                let public_key: RsaPublicKey = key_parts.material().ok_or(HsmError::KeyHandleInvalid)?;
                Operation::VerifyRsa {
                    public_key: Box::new(public_key),
                }
            }
            Mechanism::Ecdsa => {
                // A public-key handle stores the `VerifyingKey` directly; a
                // private-key handle stores the P-256 scalar, so the public
                // key is derived from it. Both reads come from the single
                // `ctx.object` call above.
                let verifying_key = match key_parts.material::<VerifyingKey>() {
                    Some(vk) => vk,
                    None => {
                        let key_bytes: Vec<u8> = key_parts.material().ok_or(HsmError::KeyHandleInvalid)?;
                        let signing_key =
                            ecdsa::SigningKey::from_slice(&key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
                        *signing_key.verifying_key()
                    }
                };
                Operation::VerifyEcdsa {
                    verifying_key: Box::new(verifying_key),
                }
            }
            Mechanism::Sha256Hmac => {
                let key_bytes: Vec<u8> = key_parts.material().ok_or(HsmError::KeyHandleInvalid)?;
                let verifying_key = HmacSha256::new_from_slice(&key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
                Operation::VerifySha256Hmac {
                    verifying_key: Box::new(verifying_key),
                }
            }
            _ => return Err(HsmError::MechanismInvalid),
        };

        let session = ctx.session();
        session.operation.set(operation).map_err(|_| HsmError::OperationActive)
    }

    /// Verifies `signature` over `data`, consuming the active verify operation.
    pub fn verify(&self, session_id: SessionId, data: &[u8], signature: &[u8]) -> Result<()> {
        let ctx = self.session_context(session_id)?;
        let mut session = ctx.session_mut();

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
        let ctx = self.session_context(session_id)?;

        if ctx.session().operation.get().is_some() {
            return Err(HsmError::OperationActive);
        }

        let key_parts = ctx.object(&key, HsmError::KeyHandleInvalid)?;
        check_key_usage(&key_parts.attributes, Attribute::Encrypt(false))?;

        let operation = match mechanism {
            Mechanism::AesGcm {
                initialization_vector,
                additional_authenticated_data,
            } => {
                let key_bytes: Vec<u8> = key_parts.material().ok_or(HsmError::KeyHandleInvalid)?;
                if !matches!(key_bytes.len(), 16 | 32) {
                    return Err(HsmError::KeySizeRange);
                }

                Operation::EncryptAesGcm {
                    key: key_bytes,
                    initialization_vector: initialization_vector.clone(),
                    additional_authenticated_data: additional_authenticated_data.clone(),
                }
            }
            Mechanism::AesEcb => Operation::EncryptAesEcb {
                key: aes_key_bytes(&key_parts)?,
            },
            Mechanism::AesCbc { initialization_vector } | Mechanism::AesCbcPad { initialization_vector } => {
                Operation::EncryptAesCbc {
                    key: aes_key_bytes(&key_parts)?,
                    initialization_vector: initialization_vector.clone(),
                    pad: matches!(mechanism, Mechanism::AesCbcPad { .. }),
                }
            }
            _ => return Err(HsmError::MechanismInvalid),
        };

        let session = ctx.session();
        session.operation.set(operation).map_err(|_| HsmError::OperationActive)
    }

    /// Length of the ciphertext the active encrypt operation will produce for
    /// `data_length` bytes of plaintext. Does not consume the operation.
    pub fn encrypted_length(&self, session_id: SessionId, data_length: u64) -> Result<u64> {
        let ctx = self.session_context(session_id)?;
        let session = ctx.session();

        let operation = session.operation.get().ok_or(HsmError::OperationNotInitialized)?;
        if !operation.is_encrypt() {
            return Err(HsmError::OperationNotInitialized);
        }

        operation.encrypted_length(data_length).ok_or(HsmError::DataLenRange)
    }

    /// Encrypts `data`, consuming the active encrypt operation.
    pub fn encrypt(&self, session_id: SessionId, data: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.session_context(session_id)?;
        let mut session = ctx.session_mut();

        if !session.operation.get().is_some_and(Operation::is_encrypt) {
            return Err(HsmError::OperationNotInitialized);
        }

        let operation = session.operation.take().unwrap();
        // The only expected failure is input unusable for the mechanism
        // (unaligned data for an unpadded block mode); anything else would be
        // a corrupt stored key.
        operation.encrypt(data).ok_or(HsmError::DataLenRange)
    }

    pub fn decrypt_init(&self, session_id: SessionId, mechanism: &Mechanism, key: ObjectId) -> Result<()> {
        let ctx = self.session_context(session_id)?;

        if ctx.session().operation.get().is_some() {
            return Err(HsmError::OperationActive);
        }

        let key_parts = ctx.object(&key, HsmError::KeyHandleInvalid)?;
        check_key_usage(&key_parts.attributes, Attribute::Decrypt(false))?;

        let operation = match mechanism {
            Mechanism::AesGcm {
                initialization_vector,
                additional_authenticated_data,
            } => {
                let key_bytes: Vec<u8> = key_parts.material().ok_or(HsmError::KeyHandleInvalid)?;
                if !matches!(key_bytes.len(), 16 | 32) {
                    return Err(HsmError::KeySizeRange);
                }

                Operation::DecryptAesGcm {
                    key: key_bytes,
                    initialization_vector: initialization_vector.clone(),
                    additional_authenticated_data: additional_authenticated_data.clone(),
                }
            }
            Mechanism::AesEcb => Operation::DecryptAesEcb {
                key: aes_key_bytes(&key_parts)?,
            },
            Mechanism::AesCbc { initialization_vector } | Mechanism::AesCbcPad { initialization_vector } => {
                Operation::DecryptAesCbc {
                    key: aes_key_bytes(&key_parts)?,
                    initialization_vector: initialization_vector.clone(),
                    pad: matches!(mechanism, Mechanism::AesCbcPad { .. }),
                }
            }
            _ => return Err(HsmError::MechanismInvalid),
        };

        let session = ctx.session();
        session.operation.set(operation).map_err(|_| HsmError::OperationActive)
    }

    /// Upper bound on the plaintext length the active decrypt operation will
    /// produce for `data_length` bytes of ciphertext. Does not consume the
    /// operation.
    pub fn decrypted_length(&self, session_id: SessionId, data_length: u64) -> Result<u64> {
        let ctx = self.session_context(session_id)?;
        let session = ctx.session();

        let operation = session.operation.get().ok_or(HsmError::OperationNotInitialized)?;
        if !operation.is_decrypt() {
            return Err(HsmError::OperationNotInitialized);
        }

        operation
            .decrypted_length(data_length)
            .ok_or(HsmError::EncryptedDataLenRange)
    }

    /// Decrypts `data`, consuming the active decrypt operation.
    pub fn decrypt(&self, session_id: SessionId, data: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.session_context(session_id)?;
        let mut session = ctx.session_mut();

        if !session.operation.get().is_some_and(Operation::is_decrypt) {
            return Err(HsmError::OperationNotInitialized);
        }

        let operation = session.operation.take().unwrap();
        operation.decrypt(data).ok_or(HsmError::EncryptedDataInvalid)
    }

    // ---- internals -----------------------------------------------------------

    fn get_slot(&self, slot_id: &SlotId) -> Result<Arc<RwLock<Slot>>> {
        self.ensure_initialized()?;
        let slot = self.slots.get(slot_id).ok_or(HsmError::SlotNotFound(*slot_id))?;
        Ok(Arc::clone(slot))
    }

    fn find_by_session_id(&self, session_id: SessionId) -> Option<Arc<RwLock<Slot>>> {
        self.slots
            .values()
            .find(|slot| slot.read().unwrap().sessions.contains_key(&session_id))
            .map(Arc::clone)
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
            .get(&session_id)
            .cloned()
            .ok_or(HsmError::SessionNotFound(session_id))?;

        Ok((session, slot_lock))
    }

    /// Resolves a session id to its session plus a snapshot of its slot's login
    /// state. Every session-scoped entry point starts here.
    fn session_context(&self, session_id: SessionId) -> Result<SessionContext> {
        self.ensure_initialized()?;

        let slot_lock = self
            .find_by_session_id(session_id)
            .ok_or(HsmError::SessionNotFound(session_id))?;

        let slot = slot_lock.read().unwrap();

        let session = slot
            .sessions
            .get(&session_id)
            .cloned()
            .ok_or(HsmError::SessionNotFound(session_id))?;

        Ok(SessionContext {
            session,
            logged_in_as_user: slot.current_user_type == Some(UserType::User),
        })
    }
}

/// The single place `TemplateError` meets `HsmError`.
fn template_error(error: TemplateError) -> HsmError {
    match error {
        TemplateError::UnsupportedAttribute => HsmError::AttributeTypeInvalid,
        TemplateError::DuplicateAttributeType => HsmError::TemplateInconsistent,
    }
}

/// Handle database failures if applicable, anything else becomes the
/// context-specific invalid-handle error.
fn store_read_error(error: SessionError, invalid: HsmError) -> HsmError {
    match error {
        SessionError::ObjectStore(ObjectStoreError::Database(e)) => {
            HsmError::ObjectStore(ObjectStoreError::Database(e))
        }
        _ => invalid,
    }
}

/// Reads an AES key's raw bytes for a block-mode operation; any AES length
/// (128/192/256-bit) is usable.
fn aes_key_bytes(key_parts: &ObjectParts) -> Result<Vec<u8>> {
    let key_bytes: Vec<u8> = key_parts.material().ok_or(HsmError::KeyHandleInvalid)?;
    if !matches!(key_bytes.len(), 16 | 24 | 32) {
        return Err(HsmError::KeySizeRange);
    }
    Ok(key_bytes)
}

/// Usage-flag enforcement (`CKA_SIGN`, `CKA_ENCRYPT`, …): refuses the
/// operation iff the key's stored attributes carry `denied` — the required
/// flag with value false. Flags default to true at creation (see
/// `default_boolean_attributes`), so only an explicit opt-out blocks; a flag
/// the key's class does not define is absent and never blocks, which keeps
/// the ECDSA verify-via-private-key-handle extension working (private keys
/// carry no `CKA_VERIFY`).
fn check_key_usage(attributes: &[Attribute], denied: Attribute) -> Result<()> {
    if attributes.contains(&denied) {
        return Err(HsmError::KeyFunctionNotPermitted);
    }
    Ok(())
}

/// Shared `C_SetAttributeValue`/`C_CopyObject` update loop, including the
/// one-way guarantees: a sensitive key may not be made non-sensitive and a
/// non-extractable key may not be made extractable.
fn apply_attribute_updates(attributes: &mut Vec<Attribute>, updates: Vec<Attribute>) -> Result<()> {
    for update in updates {
        let attribute_type = update.attribute_type().ok_or(HsmError::AttributeTypeInvalid)?;

        if !attribute_type.is_modifiable() {
            return Err(HsmError::AttributeReadOnly);
        }

        if forbidden_downgrade(attributes, &update) {
            return Err(HsmError::AttributeReadOnly);
        }

        attributes.retain(|existing| existing.attribute_type() != Some(attribute_type));
        attributes.push(update);
    }

    Ok(())
}

/// A session together with a snapshot of its slot's login state, captured
/// before any session lock (lock order is slot→session).
///
/// Methods that take the session lock themselves (`object`, `check_writable`)
/// must NOT be called while a guard from `session()`/`session_mut()` is
/// alive — a second read of the same `RwLock` can deadlock behind a queued
/// writer.
struct SessionContext {
    session: Arc<RwLock<Session>>,
    /// Login state when the call entered the domain; §4.4 gates private
    /// objects on it.
    logged_in_as_user: bool,
}

impl SessionContext {
    fn session(&self) -> RwLockReadGuard<'_, Session> {
        self.session.read().unwrap()
    }

    fn session_mut(&self) -> RwLockWriteGuard<'_, Session> {
        self.session.write().unwrap()
    }

    /// One store read: attributes + material, with §4.4 enforced. "Not
    /// found"/"wrong shape" map onto the context-specific `invalid` error.
    fn object(&self, object_id: &ObjectId, invalid: HsmError) -> Result<ObjectParts> {
        let parts = self
            .session()
            .read_object_parts(object_id)
            .map_err(|error| store_read_error(error, invalid))?;

        require_login_for_private(&parts.attributes, self.logged_in_as_user)?;

        Ok(parts)
    }

    fn require_login_to_create(&self, template: &Template, class: Option<ObjectClass>) -> Result<()> {
        if !self.logged_in_as_user && effective_private(template.attributes(), class) {
            return Err(HsmError::UserNotLoggedIn);
        }

        Ok(())
    }

    /// A token object (`CKA_TOKEN` true) needs a read/write session.
    fn check_writable(&self, attributes: &[Attribute]) -> Result<()> {
        let token_object = attributes.iter().any(|attr| matches!(attr, Attribute::Token(true)));

        if token_object && matches!(self.session().state, SessionState::ReadOnly) {
            return Err(HsmError::SessionReadOnly);
        }

        Ok(())
    }
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

/// Validates a supplied `CKA_EC_PARAMS`: it must name the one curve rustssm
/// supports (secp256r1). Other curves are rejected with
/// `CKR_CURVE_NOT_SUPPORTED`. An omitted `CKA_EC_PARAMS` is fine — the
/// P-256 OID is injected as a derived attribute at write time.
fn validate_ec_params(attributes: &[Attribute]) -> Result<()> {
    for attr in attributes {
        if let Attribute::EcParams(params) = attr {
            if params.as_slice() != SECP256R1_EC_PARAMS {
                return Err(HsmError::CurveNotSupported);
            }
        }
    }
    Ok(())
}

/// Whether `attributes` describe a private object (`CKA_PRIVATE` true).
fn is_private(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attr| matches!(attr, Attribute::Private(true)))
}

/// Enforces PKCS#11 §4.4 for creating or accessing an object whose attributes
/// (a creation template or an object's stored list) are already in hand: a
/// private object requires a session logged in as the normal user.
/// `logged_in_as_user` must be captured from the slot before the session lock.
fn require_login_for_private(attributes: &[Attribute], logged_in_as_user: bool) -> Result<()> {
    if !logged_in_as_user && is_private(attributes) {
        return Err(HsmError::UserNotLoggedIn);
    }
    Ok(())
}

/// Whether an object created from `template` for `class` ends up private,
/// accounting for the `CKA_PRIVATE` class default materialized when the
/// template omits it. An explicit template value wins; otherwise the class
/// default decides.
fn effective_private(template: &[Attribute], class: Option<ObjectClass>) -> bool {
    if let Some(explicit) = template.iter().find_map(|attr| match attr {
        Attribute::Private(value) => Some(*value),
        _ => None,
    }) {
        return explicit;
    }
    class.is_some_and(|class| is_private(&default_boolean_attributes(class)))
}

/// Whether applying `update` to an object carrying `current` attributes would
/// violate PKCS#11's one-way security guarantees: `CKA_SENSITIVE` may not go
/// from true to false, and `CKA_EXTRACTABLE` may not go from false to true.
fn forbidden_downgrade(current: &[Attribute], update: &Attribute) -> bool {
    match update {
        Attribute::Sensitive(false) => current.iter().any(|attr| matches!(attr, Attribute::Sensitive(true))),
        Attribute::Extractable(true) => current.iter().any(|attr| matches!(attr, Attribute::Extractable(false))),
        _ => false,
    }
}

/// Reads the `CKA_VALUE` bytes from a template, which key-object creation
/// requires.
fn value_attribute(attributes: &[Attribute]) -> Result<Vec<u8>> {
    attributes
        .iter()
        .find_map(|attr| match attr {
            Attribute::Value(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .ok_or(HsmError::TemplateIncomplete)
}

/// Normalizes a `CKA_VALUE` P-256 private scalar to the fixed 32-byte material
/// a generated EC private key is stored as, validating it is a usable key.
/// Some encoders strip leading zeros, so a shorter value is left-padded.
fn ec_private_key_material(value: &[u8]) -> Result<Vec<u8>> {
    const P256_SCALAR_LEN: usize = 32;
    if value.is_empty() || value.len() > P256_SCALAR_LEN {
        return Err(HsmError::AttributeValueInvalid);
    }

    let mut scalar = vec![0u8; P256_SCALAR_LEN];
    scalar[P256_SCALAR_LEN - value.len()..].copy_from_slice(value);
    ecdsa::SigningKey::from_slice(&scalar).map_err(|_| HsmError::AttributeValueInvalid)?;
    Ok(scalar)
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
