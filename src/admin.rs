//! Operator tooling: provision tokens (labels, PINs) and import keys outside
//! the PKCS#11 API. State is written to the same SQLite store the module reads
//! at `C_Initialize`, so a subsequent process sees it immediately. Backs the
//! `rustssm-util` binary; a roughly similar to `softhsm2-util`.

use thiserror::Error;

use crate::hsm::Hsm;
use crate::hsm::HsmError;
use crate::pin::Pin;
use crate::session::SessionState;
use crate::slot::SlotId;
use crate::slot::UserType;

#[derive(Debug, Error)]
pub enum AdminError {
    #[error("{0}")]
    Hsm(#[source] HsmError),

    #[error("no free (uninitialized) slot available")]
    NoFreeSlot,

    #[error("no initialized token with label {0:?}")]
    TokenNotFound(String),

    #[error("an AES key must be 16, 24, or 32 bytes, got {0}")]
    KeyLength(usize),
}

/// Selects which slot an operation targets.
pub enum SlotSelector {
    /// A specific slot by id.
    Slot(u64),
    /// The first uninitialized slot.
    Free,
    /// The (initialized) slot whose token carries this label.
    Token(String),
}

pub struct SlotSummary {
    pub slot_id: u64,
    pub initialized: bool,
    pub label: Option<String>,
    pub user_pin_set: bool,
}

/// Reports every slot and its token state.
pub fn show_slots() -> Result<Vec<SlotSummary>, AdminError> {
    let hsm = booted_hsm()?;

    hsm.slot_ids()
        .map_err(AdminError::Hsm)?
        .into_iter()
        .map(|slot_id| {
            let status = hsm.token_status(SlotId(slot_id)).map_err(AdminError::Hsm)?;
            Ok(SlotSummary {
                slot_id,
                initialized: status.initialized,
                label: status.label,
                user_pin_set: status.user_pin_set,
            })
        })
        .collect()
}

/// Initializes the token on the selected slot, setting the SO PIN, label and
/// optionally the user PIN. Like `C_InitToken`/`softhsm2-util --init-token`,
/// this destroys any objects already in the store. Returns the resolved slot.
pub fn init_token(
    selector: SlotSelector,
    label: String,
    so_pin: String,
    user_pin: Option<String>,
) -> Result<u64, AdminError> {
    let hsm = booted_hsm()?;
    let slot = resolve_slot(&hsm, &selector)?;

    hsm.init_token(&slot, Pin::new(so_pin.clone()), Some(label))
        .map_err(AdminError::Hsm)?;

    if let Some(user_pin) = user_pin {
        // Setting the user PIN requires an SO login in a read/write session,
        // exactly as an operator would do it through the PKCS#11 API.
        let session = hsm
            .open_session(slot, SessionState::ReadWrite)
            .map_err(AdminError::Hsm)?;
        hsm.login(session, UserType::So, Pin::new(so_pin))
            .map_err(AdminError::Hsm)?;
        hsm.init_pin(session, Pin::new(user_pin)).map_err(AdminError::Hsm)?;
    }

    Ok(slot.0)
}

/// Imports raw AES key material as a labelled secret key on the selected
/// token. Requires the user PIN.
pub fn import_aes_key(selector: SlotSelector, user_pin: String, key: Vec<u8>, label: String) -> Result<(), AdminError> {
    if !matches!(key.len(), 16 | 24 | 32) {
        return Err(AdminError::KeyLength(key.len()));
    }

    let hsm = booted_hsm()?;
    let slot = resolve_slot(&hsm, &selector)?;

    let session = hsm
        .open_session(slot, SessionState::ReadWrite)
        .map_err(AdminError::Hsm)?;
    hsm.login(session, UserType::User, Pin::new(user_pin))
        .map_err(AdminError::Hsm)?;
    hsm.import_secret_key(session, key, label).map_err(AdminError::Hsm)?;

    Ok(())
}

/// Builds and initializes an `Hsm`, which hydrates it from the store.
fn booted_hsm() -> Result<Hsm, AdminError> {
    crate::logging::init();
    let hsm = Hsm::default();
    hsm.initialize().map_err(AdminError::Hsm)?;
    Ok(hsm)
}

fn resolve_slot(hsm: &Hsm, selector: &SlotSelector) -> Result<SlotId, AdminError> {
    match selector {
        SlotSelector::Slot(id) => {
            hsm.slot_exists(SlotId(*id)).map_err(AdminError::Hsm)?;
            Ok(SlotId(*id))
        }
        SlotSelector::Free => {
            for id in hsm.slot_ids().map_err(AdminError::Hsm)? {
                if !hsm.token_status(SlotId(id)).map_err(AdminError::Hsm)?.initialized {
                    return Ok(SlotId(id));
                }
            }
            Err(AdminError::NoFreeSlot)
        }
        SlotSelector::Token(label) => {
            for id in hsm.slot_ids().map_err(AdminError::Hsm)? {
                let status = hsm.token_status(SlotId(id)).map_err(AdminError::Hsm)?;
                if status.initialized && status.label.as_deref() == Some(label.as_str()) {
                    return Ok(SlotId(id));
                }
            }
            Err(AdminError::TokenNotFound(label.clone()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::import_aes_key;
    use super::init_token;
    use super::show_slots;
    use super::SlotSelector;
    use crate::hsm::Hsm;
    use crate::mechanism::Mechanism;
    use crate::pin::Pin;
    use crate::session::SessionState;
    use crate::slot::SlotId;
    use crate::slot::UserType;

    const SO_PIN: &str = "so-pin-123456";
    const USER_PIN: &str = "user-pin-123456";

    /// Serializes the admin tests: they all steer the process-global
    /// `DATABASE_URL`, so only one may run at a time.
    static DB_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Points `DATABASE_URL` at a unique throwaway file for the duration of a
    /// test, holding [`DB_LOCK`] so concurrent admin tests don't collide.
    struct TempDb {
        path: std::path::PathBuf,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl TempDb {
        fn new(tag: &str) -> Self {
            let guard = DB_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            let path = std::env::temp_dir().join(format!("rustssm-admin-{tag}-{}.db", std::process::id()));
            let db = TempDb { path, _guard: guard };
            db.remove();
            std::env::set_var("DATABASE_URL", &db.path);
            db
        }

        fn remove(&self) {
            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{suffix}", self.path.display()));
            }
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            self.remove();
        }
    }

    #[test]
    fn init_token_provisions_a_token_a_later_process_can_use() {
        let _db = TempDb::new("init");

        let slot = init_token(
            SlotSelector::Slot(0),
            String::from("cli token"),
            String::from(SO_PIN),
            Some(String::from(USER_PIN)),
        )
        .unwrap();
        assert_eq!(slot, 0);

        // A fresh HSM — as a restarted process would build — must see the
        // provisioned token and accept the user PIN.
        let hsm = Hsm::default();
        hsm.initialize().unwrap();

        let status = hsm.token_status(SlotId(0)).unwrap();
        assert!(status.initialized);
        assert!(status.user_pin_set);
        assert_eq!(status.label.as_deref(), Some("cli token"));

        let session = hsm.open_session(SlotId(0), SessionState::ReadWrite).unwrap();
        hsm.login(session, UserType::User, Pin::new(USER_PIN)).unwrap();
    }

    #[test]
    fn init_token_free_picks_an_uninitialized_slot_and_token_finds_it() {
        let _db = TempDb::new("free");

        // Slot 0 is taken first...
        let first = init_token(SlotSelector::Free, String::from("a"), String::from(SO_PIN), None).unwrap();
        // ...so the next --free lands on a different slot.
        let second = init_token(SlotSelector::Free, String::from("b"), String::from(SO_PIN), None).unwrap();
        assert_ne!(first, second);

        // A token can then be located by its label.
        let found = init_token(
            SlotSelector::Token(String::from("a")),
            String::from("a"),
            String::from(SO_PIN),
            None,
        )
        .unwrap();
        assert_eq!(found, first);
    }

    #[test]
    fn show_slots_reflects_initialized_tokens() {
        let _db = TempDb::new("show");

        init_token(
            SlotSelector::Slot(1),
            String::from("only one"),
            String::from(SO_PIN),
            Some(String::from(USER_PIN)),
        )
        .unwrap();

        let slots = show_slots().unwrap();
        assert_eq!(slots.len(), 4);
        let one = slots.iter().find(|s| s.slot_id == 1).unwrap();
        assert!(one.initialized && one.user_pin_set);
        assert_eq!(one.label.as_deref(), Some("only one"));
        assert_eq!(slots.iter().filter(|s| !s.initialized).count(), 3);
    }

    #[test]
    fn import_aes_key_stores_a_usable_key() {
        let _db = TempDb::new("import");

        init_token(
            SlotSelector::Slot(0),
            String::from("t"),
            String::from(SO_PIN),
            Some(String::from(USER_PIN)),
        )
        .unwrap();

        let key = vec![0x11u8; 32];
        import_aes_key(
            SlotSelector::Token(String::from("t")),
            String::from(USER_PIN),
            key.clone(),
            String::from("imported"),
        )
        .unwrap();

        // The imported key is found by label and can drive an AES-GCM encrypt.
        let hsm = Hsm::default();
        hsm.initialize().unwrap();
        let session = hsm.open_session(SlotId(0), SessionState::ReadWrite).unwrap();
        hsm.login(session, UserType::User, Pin::new(USER_PIN)).unwrap();

        hsm.find_objects_init(
            session,
            vec![crate::attribute::Attribute::Label(String::from("imported"))],
        )
        .unwrap();
        let found = hsm.find_objects_next(session, 10).unwrap();
        hsm.find_objects_final(session).unwrap();
        assert_eq!(found.len(), 1);

        let mechanism = Mechanism::AesGcm {
            initialization_vector: vec![0x22; 12],
            additional_authenticated_data: vec![],
        };
        hsm.encrypt_init(session, &mechanism, found[0].clone()).unwrap();
        assert!(hsm.encrypt(session, b"payload").is_ok());
    }

    #[test]
    fn import_rejects_wrong_key_length() {
        let _db = TempDb::new("badlen");

        init_token(
            SlotSelector::Slot(0),
            String::from("t"),
            String::from(SO_PIN),
            Some(String::from(USER_PIN)),
        )
        .unwrap();

        assert!(matches!(
            import_aes_key(
                SlotSelector::Slot(0),
                String::from(USER_PIN),
                vec![0u8; 20],
                String::from("bad"),
            ),
            Err(super::AdminError::KeyLength(20))
        ));
    }
}
