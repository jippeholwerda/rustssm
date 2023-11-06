use crate::{
    hsm::Hsm,
    pin::Pin,
    session::{Session, SessionId},
};

#[derive(Clone, PartialEq, Eq)]
pub struct SlotId(pub u8);

pub struct Slot {
    pub id: SlotId,
    pub initialized: bool,
    pub so_pin: Option<Pin>,
    pub user_pin: Option<Pin>,
    pub label: Option<String>,
}

impl Slot {
    pub fn new(id: u8) -> Self {
        Self {
            id: SlotId(id),
            initialized: false,
            so_pin: None,
            user_pin: None,
            label: None,
        }
    }

    pub fn create_session(&self, token: &Hsm, slot: SlotId) -> SessionId {
        let index = token.sessions.write().unwrap().insert(Session::new(slot));
        SessionId(index as u64)
    }
}
