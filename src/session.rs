use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;

use ciborium::Value;
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

use crate::attribute::matches_template;
use crate::attribute::Attribute;
use crate::attribute::CanonicalAttributes;
use crate::object_store::ObjectId;
use crate::object_store::ObjectStore;
use crate::object_store::ObjectStoreError;
use crate::object_store::SESSION_OBJECT_HANDLE_BIT;
use crate::operation::Operation;
use crate::session::SessionError::SearchActive;
use crate::slot::SlotId;

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("error storing object: {0}")]
    ObjectStore(#[source] ObjectStoreError),

    #[error("object not found: {0:?}")]
    ObjectNotFound(ObjectId),

    #[error("error encoding object material: {0}")]
    MaterialEncoding(#[source] ciborium::value::Error),

    #[error("search already active")]
    SearchActive,

    #[error("search not active")]
    SearchNotActive,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SessionId(pub u64);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionState {
    ReadOnly,
    ReadWrite,
}

/// The in-memory store for session objects (`CKA_TOKEN` false), shared by
/// every session of the slot: PKCS#11 makes session objects visible to all
/// sessions of the application, and their lifetime is bounded by the process,
/// so they never touch the persistent store. That is also what makes sharing
/// one database between processes safe — a session object cannot collide with
/// or be purged by another process, because it never leaves this one — and it
/// keeps short-lived key material off disk. Handles carry
/// [`SESSION_OBJECT_HANDLE_BIT`], so they can never collide with store
/// rowids; the `BTreeMap` keeps search results in stable handle order.
#[derive(Default)]
pub struct SessionObjects {
    next_id: u64,
    objects: BTreeMap<ObjectId, SessionObject>,
}

struct SessionObject {
    owner: SessionId,
    attributes: Vec<Attribute>,
    material: Value,
}

impl SessionObjects {
    fn insert(&mut self, owner: SessionId, attributes: Vec<Attribute>, material: Value) -> ObjectId {
        self.next_id += 1;
        let id = ObjectId::new(SESSION_OBJECT_HANDLE_BIT | self.next_id);
        let object = SessionObject {
            owner,
            attributes,
            material,
        };
        self.objects.insert(id.clone(), object);
        id
    }

    fn parts(&self, object_id: &ObjectId) -> Option<ObjectParts> {
        self.objects.get(object_id).map(|object| ObjectParts {
            attributes: object.attributes.clone(),
            material: object.material.clone(),
        })
    }

    fn contains(&self, object_id: &ObjectId) -> bool {
        self.objects.contains_key(object_id)
    }

    fn set_attributes(&mut self, object_id: &ObjectId, attributes: Vec<Attribute>) -> Option<()> {
        self.objects
            .get_mut(object_id)
            .map(|object| object.attributes = attributes)
    }

    fn remove(&mut self, object_id: &ObjectId) -> Option<()> {
        self.objects.remove(object_id).map(|_| ())
    }

    /// Destroys every object owned by `session_id`; called when it closes.
    pub fn remove_owned_by(&mut self, session_id: SessionId) {
        self.objects.retain(|_, object| object.owner != session_id);
    }

    /// Drops all session objects; called on `C_Finalize`.
    pub fn clear(&mut self) {
        self.objects.clear();
    }

    /// Ids of the session objects matching `template`, in handle order. Same
    /// semantics as `ObjectStore::search`: a template carrying `Unknown`
    /// matches nothing, and private objects require `include_private`.
    fn search(&self, template: &[Attribute], include_private: bool) -> Vec<ObjectId> {
        if template.iter().any(|attr| matches!(attr, Attribute::Unknown)) {
            return Vec::new();
        }

        self.objects
            .iter()
            .filter(|(_, object)| {
                let private = object
                    .attributes
                    .iter()
                    .any(|attr| matches!(attr, Attribute::Private(true)));
                (include_private || !private) && matches_template(template, &object.attributes)
            })
            .map(|(id, _)| id.clone())
            .collect()
    }
}

pub struct Session {
    pub session_id: SessionId,
    pub slot_id: SlotId,
    pub state: SessionState,
    objects: Arc<ObjectStore>,
    /// The slot-wide in-memory session-object store, shared by all sessions.
    session_objects: Arc<RwLock<SessionObjects>>,
    pub operation: OnceLock<Operation>,
    pub search_operation: OnceLock<SearchOperation>,
}

/// An object's stored attribute list together with its key material (an
/// undecoded CBOR value), read from the store in one access. The material is
/// decoded into its concrete key type on demand.
pub struct ObjectParts {
    pub attributes: Vec<Attribute>,
    material: Value,
}

impl ObjectParts {
    /// Decodes the key material as `T`. `None` means the material is not a
    /// `T` — for a handle-typed operation, a wrong-type key handle.
    pub fn material<T>(&self) -> Option<T>
    where
        T: DeserializeOwned,
    {
        self.material.deserialized().ok()
    }
}

#[derive(Default)]
pub struct SearchOperation {
    attributes: Vec<Attribute>,
    include_private: bool,
    object_ids: Vec<ObjectId>,
    search_performed: bool,
}

impl SearchOperation {
    pub fn init(attributes: Vec<Attribute>, include_private: bool) -> Self {
        Self {
            attributes,
            include_private,
            ..Default::default()
        }
    }
}

impl Session {
    pub fn new(
        session_id: SessionId,
        slot_id: SlotId,
        state: SessionState,
        objects: Arc<ObjectStore>,
        session_objects: Arc<RwLock<SessionObjects>>,
    ) -> Self {
        Self {
            session_id,
            slot_id,
            state,
            objects,
            session_objects,
            operation: OnceLock::new(),
            search_operation: OnceLock::new(),
        }
    }

    pub fn write_object<T>(&self, object: &T, attributes: CanonicalAttributes) -> Result<ObjectId, SessionError>
    where
        T: Serialize + ?Sized,
    {
        let material = Value::serialized(object).map_err(SessionError::MaterialEncoding)?;
        self.write_material(material, attributes)
    }

    /// Routes a new object to its store: token objects (`CKA_TOKEN` true) are
    /// persisted, session objects go to the slot's in-memory store and are
    /// destroyed when this session closes.
    fn write_material(&self, material: Value, attributes: CanonicalAttributes) -> Result<ObjectId, SessionError> {
        let attributes = attributes.into_vec();
        if is_token_object(&attributes) {
            self.objects
                .write(attributes, &material)
                .map_err(SessionError::ObjectStore)
        } else {
            let id = self
                .session_objects
                .write()
                .unwrap()
                .insert(self.session_id, attributes, material);
            Ok(id)
        }
    }

    /// Reads an object's attributes and key material in one access, from
    /// whichever store its handle denotes.
    pub fn read_object_parts(&self, object_id: &ObjectId) -> Result<ObjectParts, SessionError> {
        if object_id.is_session_object() {
            self.session_objects
                .read()
                .unwrap()
                .parts(object_id)
                .ok_or_else(|| SessionError::ObjectNotFound(object_id.clone()))
        } else {
            let (attributes, material) = self.objects.read_parts(object_id).map_err(SessionError::ObjectStore)?;
            Ok(ObjectParts { attributes, material })
        }
    }

    pub fn set_object_attributes(
        &self,
        object_id: &ObjectId,
        attributes: CanonicalAttributes,
    ) -> Result<(), SessionError> {
        let attributes = attributes.into_vec();
        if object_id.is_session_object() {
            self.session_objects
                .write()
                .unwrap()
                .set_attributes(object_id, attributes)
                .ok_or_else(|| SessionError::ObjectNotFound(object_id.clone()))
        } else {
            self.objects
                .set_attributes(object_id, attributes)
                .map_err(SessionError::ObjectStore)
        }
    }

    /// Copies an object — from either store — into the store selected by the
    /// copy's own `CKA_TOKEN`, so `C_CopyObject` is the one way an object's
    /// token-ness can change (a copy is a new object with a new handle;
    /// `C_SetAttributeValue` rejects `CKA_TOKEN` because a handle cannot
    /// switch stores in place).
    pub fn copy_object(&self, source: &ObjectId, attributes: CanonicalAttributes) -> Result<ObjectId, SessionError> {
        let parts = self.read_object_parts(source)?;
        self.write_material(parts.material, attributes)
    }

    pub fn object_exists(&self, object_id: &ObjectId) -> bool {
        if object_id.is_session_object() {
            self.session_objects.read().unwrap().contains(object_id)
        } else {
            self.objects.read_raw(object_id).is_ok()
        }
    }

    pub fn delete_object(&self, object_id: &ObjectId) -> Result<(), SessionError> {
        if object_id.is_session_object() {
            self.session_objects
                .write()
                .unwrap()
                .remove(object_id)
                .ok_or_else(|| SessionError::ObjectNotFound(object_id.clone()))
        } else {
            self.objects.delete(object_id).map_err(SessionError::ObjectStore)
        }
    }

    pub fn init_search(&self, attributes: Vec<Attribute>, include_private: bool) -> Result<(), SessionError> {
        self.search_operation
            .set(SearchOperation::init(attributes, include_private))
            .map_err(|_| SearchActive)
    }

    pub fn is_search_active(&self) -> bool {
        self.search_operation.get().is_some()
    }

    pub fn search_result(&mut self) -> Result<Option<ObjectId>, SessionError> {
        if let Some(SearchOperation {
            attributes,
            include_private,
            object_ids,
            search_performed,
        }) = self.search_operation.get_mut()
        {
            if !*search_performed {
                // Token objects (store scan, rowid order) followed by session
                // objects (in-memory, handle order).
                let mut ids = self
                    .objects
                    .search(attributes, *include_private)
                    .map_err(SessionError::ObjectStore)?;
                ids.extend(
                    self.session_objects
                        .read()
                        .unwrap()
                        .search(attributes, *include_private),
                );
                *object_ids = ids;
                *search_performed = true;
            }

            if object_ids.is_empty() {
                return Ok(None);
            }

            let object_id: ObjectId = object_ids.remove(0);
            Ok(Some(object_id))
        } else {
            Err(SessionError::SearchNotActive)
        }
    }

    pub fn finish_search(&mut self) -> Result<(), SessionError> {
        if self.search_operation.take().is_some() {
            Ok(())
        } else {
            Err(SessionError::SearchNotActive)
        }
    }
}

/// Whether these attributes make a token object (persisted) rather than a
/// session object (in-memory).
fn is_token_object(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attr| matches!(attr, Attribute::Token(true)))
}
