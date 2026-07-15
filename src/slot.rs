use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

use crate::pin::PinHash;
use crate::session::Session;
use crate::session::SessionId;
use crate::session::SessionObjects;
use crate::session::SessionState;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SlotId(pub u64);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UserType {
    So,
    User,
}

pub struct Slot {
    pub label: Option<String>,
    pub initialized: bool,
    pub so_pin: Option<PinHash>,
    pub user_pin: Option<PinHash>,
    pub current_user_type: Option<UserType>,
    pub sessions: RwLock<HashMap<SessionId, Arc<RwLock<Session>>>>,
    /// The slot's in-memory session objects, shared with every session opened
    /// on it (each `Session` holds a clone of the `Arc`).
    pub session_objects: Arc<RwLock<SessionObjects>>,
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            label: None,
            initialized: false,
            so_pin: None,
            user_pin: None,
            current_user_type: None,
            sessions: RwLock::new(HashMap::default()),
            session_objects: Arc::new(RwLock::new(SessionObjects::default())),
        }
    }
}

impl Slot {
    pub fn has_read_only_session(&self) -> bool {
        self.sessions
            .read()
            .unwrap()
            .iter()
            .any(|(_, session)| matches!(session.read().unwrap().state, SessionState::ReadOnly))
    }
}
