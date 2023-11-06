use std::sync::Arc;
use std::sync::OnceLock;

use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

use crate::attribute::Attribute;
use crate::object_store::ObjectId;
use crate::object_store::ObjectStore;
use crate::object_store::ObjectStoreError;
use crate::operation::Operation;
use crate::session::SessionError::SearchActive;
use crate::slot::SlotId;

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("error storing object: {0}")]
    ObjectStore(#[from] ObjectStoreError),
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

pub struct Session {
    pub slot_id: SlotId,
    pub state: SessionState,
    objects: Arc<ObjectStore>,
    pub operation: OnceLock<Operation>,
    pub search_operation: OnceLock<SearchOperation>,
}

#[derive(Default)]
pub struct SearchOperation {
    attributes: Vec<Attribute>,
    object_ids: Vec<ObjectId>,
    search_performed: bool,
}

impl SearchOperation {
    pub fn init(attributes: Vec<Attribute>) -> Self {
        Self {
            attributes,
            ..Default::default()
        }
    }
}

impl Session {
    pub fn new(slot_id: SlotId, state: SessionState, objects: Arc<ObjectStore>) -> Self {
        Self {
            slot_id,
            state,
            objects,
            operation: OnceLock::new(),
            search_operation: OnceLock::new(),
        }
    }

    pub fn write_object<T>(&self, object: &T, attributes: Vec<Attribute>) -> Result<ObjectId, SessionError>
    where
        T: Serialize + ?Sized,
    {
        let mut private = None;
        let mut label = None;

        attributes.into_iter().for_each(|attr| match attr {
            Attribute::Private(v) => {
                private = Some(v);
            }
            Attribute::Label(v) => {
                label = Some(v);
            }
            _ => {}
        });

        let object_id = self.objects.write(object, private, label)?;
        Ok(object_id)
    }

    pub fn read_object<T>(&self, object_id: &ObjectId) -> Result<T, SessionError>
    where
        T: DeserializeOwned,
    {
        Ok(self.objects.read(object_id)?)
    }

    pub fn object_exists(&self, object_id: &ObjectId) -> bool {
        self.objects.read_raw(object_id).is_ok()
    }

    pub fn delete_object(&self, object_id: &ObjectId) -> Result<(), SessionError> {
        Ok(self.objects.delete(object_id)?)
    }

    pub fn init_search(&self, attributes: Vec<Attribute>) -> Result<(), SessionError> {
        self.search_operation
            .set(SearchOperation::init(attributes))
            .map_err(|_| SearchActive)
    }

    pub fn is_search_active(&self) -> bool {
        self.search_operation.get().is_some()
    }

    pub fn search_result(&mut self) -> Result<Option<ObjectId>, SessionError> {
        if let Some(SearchOperation {
            attributes,
            object_ids,
            search_performed,
        }) = self.search_operation.get_mut()
        {
            if !*search_performed {
                let mut private = None;
                let mut label = None;

                attributes.iter().for_each(|attr| match attr {
                    Attribute::Private(v) => {
                        private = Some(*v);
                    }
                    Attribute::Label(v) => {
                        label = Some(v.clone());
                    }
                    _ => {}
                });

                *object_ids = self.objects.search(private, label)?;
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
