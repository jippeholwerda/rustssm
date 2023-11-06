use std::sync::{
    atomic::{AtomicBool, Ordering},
    RwLock,
};

use slab::Slab;

use crate::{session::Session, slot::Slot};

pub struct Hsm {
    is_so_write_session_open: AtomicBool,
    pub slots: RwLock<Slab<Slot>>,
    pub sessions: RwLock<Slab<Session>>,
}

impl Default for Hsm {
    fn default() -> Self {
        Self {
            is_so_write_session_open: AtomicBool::new(false),
            slots: RwLock::new(Slab::from_iter((0..4).map(|i| (i.into(), Slot::new(i))))),
            sessions: RwLock::new(Slab::default()),
        }
    }
}

impl Hsm {
    pub fn is_so_write_session_open(&self) -> bool {
        self.is_so_write_session_open.load(Ordering::Acquire)
    }

    pub fn open_so_write_session(&self) {
        self.is_so_write_session_open.store(true, Ordering::Release)
    }

    pub fn close_so_write_session(&self) {
        self.is_so_write_session_open.store(false, Ordering::Release)
    }
}
