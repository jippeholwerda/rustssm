use std::sync::{OnceLock, RwLock};

use crate::operation::Operation;
use slab::Slab;

use crate::slot::SlotId;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);

// todo: have different kinds of sessions (R/W SO, R/W Public, R/W User, R/O SO, R/O User as enum values)
pub struct Session {
    pub slot_id: SlotId,
    pub so_authenticated: bool,
    pub user_authenticated: bool,
    pub objects: RwLock<Slab<Vec<u8>>>,
    pub operation: OnceLock<Operation>,
}

impl Session {
    pub fn new(slot_id: SlotId) -> Self {
        Self {
            slot_id,
            so_authenticated: false,
            user_authenticated: false,
            objects: RwLock::new(Slab::default()),
            operation: OnceLock::new(),
        }
    }
}
