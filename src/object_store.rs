use std::sync::Mutex;
use std::time::Duration;

use log::info;
use rusqlite::params;
use rusqlite::params_from_iter;
use rusqlite::types::Value;
use rusqlite::Connection;
use rusqlite::OptionalExtension;
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

use crate::raw::CK_OBJECT_HANDLE;
use crate::util::random_string;

#[derive(Error, Debug)]
pub enum ObjectStoreError {
    #[error("serialization/deserialization error {0:?}")]
    Serialize(#[source] postcard::Error),

    #[error("database error {0:?}")]
    Database(#[source] rusqlite::Error),

    #[error("object not found: {0:?}")]
    NotFound(ObjectId),
}

#[derive(Debug, Hash, Clone, Eq, PartialEq)]
pub struct ObjectId(u64);

impl ObjectId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

impl From<ObjectId> for u64 {
    fn from(value: ObjectId) -> Self {
        value.0
    }
}

impl From<CK_OBJECT_HANDLE> for ObjectId {
    fn from(value: CK_OBJECT_HANDLE) -> Self {
        ObjectId::new(value)
    }
}

const OBJECT_SCHEMA: &str = include_str!("../db/migrations/20240107000001_object.sql");
const TOKEN_SCHEMA: &str = include_str!("../db/migrations/20260706000001_token.sql");

fn apply_schema(connection: &Connection) -> Result<(), ObjectStoreError> {
    connection
        .execute_batch(OBJECT_SCHEMA)
        .map_err(ObjectStoreError::Database)?;
    connection
        .execute_batch(TOKEN_SCHEMA)
        .map_err(ObjectStoreError::Database)?;
    Ok(())
}

/// Persisted per-slot token state. A row exists exactly when the token is
/// initialized; PINs are stored as salted hashes (see [`crate::pin::PinHash`]).
#[derive(Debug, Clone)]
pub struct TokenRecord {
    pub slot_id: u64,
    pub label: Option<String>,
    pub so_pin_hash: String,
    pub user_pin_hash: Option<String>,
}

pub struct ObjectStore {
    connection: Mutex<Connection>,
}

impl ObjectStore {
    pub fn new() -> Result<Self, ObjectStoreError> {
        // DATABASE_URL is accepted both as a plain path and as a
        // sqlite://path?params URL (the format the previous sqlx-based store
        // used).
        let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| String::from("rustssm.db"));
        let path = url.strip_prefix("sqlite://").unwrap_or(&url);
        let path = path.split('?').next().unwrap_or(path);

        info!(
            "object store: {} (cwd: {})",
            path,
            std::env::current_dir()
                .map(|d| d.display().to_string())
                .unwrap_or_default()
        );

        let connection = Connection::open(path).map_err(ObjectStoreError::Database)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(ObjectStoreError::Database)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(ObjectStoreError::Database)?;
        apply_schema(&connection)?;

        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    #[cfg(test)]
    pub fn in_memory() -> Result<Self, ObjectStoreError> {
        let connection = Connection::open_in_memory().map_err(ObjectStoreError::Database)?;
        apply_schema(&connection)?;

        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Opens (creating if needed) a file-backed store at `path`. Used by tests
    /// that need state to survive across `ObjectStore` instances.
    #[cfg(test)]
    pub fn at_path(path: &std::path::Path) -> Result<Self, ObjectStoreError> {
        let connection = Connection::open(path).map_err(ObjectStoreError::Database)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(ObjectStoreError::Database)?;
        apply_schema(&connection)?;

        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn write<T>(
        &self,
        object: &T,
        private: Option<bool>,
        label: Option<String>,
    ) -> Result<ObjectId, ObjectStoreError>
    where
        T: Serialize + ?Sized,
    {
        let content = postcard::to_allocvec(&object).map_err(ObjectStoreError::Serialize)?;

        let private = i64::from(private.unwrap_or(false));
        let label = label.unwrap_or_else(|| random_string(16));

        let connection = self.connection.lock().unwrap();
        connection
            .execute(
                "insert into object (content, private, label) values (?1, ?2, ?3)",
                params![content, private, label],
            )
            .map_err(ObjectStoreError::Database)?;

        Ok(ObjectId(connection.last_insert_rowid() as u64))
    }

    pub fn read<T>(&self, object_id: &ObjectId) -> Result<T, ObjectStoreError>
    where
        T: DeserializeOwned,
    {
        let content = self.read_raw(object_id)?;
        let object = postcard::from_bytes(&content).map_err(ObjectStoreError::Serialize)?;
        Ok(object)
    }

    pub fn read_raw(&self, object_id: &ObjectId) -> Result<Vec<u8>, ObjectStoreError> {
        let id = object_id.0 as i64;

        let connection = self.connection.lock().unwrap();
        connection
            .query_row("select content from object where id = ?1", params![id], |row| {
                row.get(0)
            })
            .optional()
            .map_err(ObjectStoreError::Database)?
            .ok_or_else(|| ObjectStoreError::NotFound(object_id.clone()))
    }

    pub fn delete(&self, object_id: &ObjectId) -> Result<(), ObjectStoreError> {
        let id = object_id.0 as i64;

        let connection = self.connection.lock().unwrap();
        let deleted = connection
            .execute("delete from object where id = ?1", params![id])
            .map_err(ObjectStoreError::Database)?;

        if deleted == 0 {
            return Err(ObjectStoreError::NotFound(object_id.clone()));
        }

        Ok(())
    }

    /// Removes all stored objects. Used when a token is (re)initialized.
    pub fn clear(&self) -> Result<(), ObjectStoreError> {
        let connection = self.connection.lock().unwrap();
        connection
            .execute("delete from object", [])
            .map_err(ObjectStoreError::Database)?;
        Ok(())
    }

    pub fn search(&self, private: Option<bool>, label: Option<String>) -> Result<Vec<ObjectId>, ObjectStoreError> {
        let mut sql = String::from("select id from object where 1 = 1");
        let mut values: Vec<Value> = Vec::new();

        if let Some(private) = private {
            sql.push_str(" and private = ?");
            values.push(i64::from(private).into());
        }
        if let Some(label) = label {
            sql.push_str(" and label = ?");
            values.push(label.into());
        }

        let connection = self.connection.lock().unwrap();
        let mut statement = connection.prepare(&sql).map_err(ObjectStoreError::Database)?;
        let ids = statement
            .query_map(params_from_iter(values), |row| row.get::<_, i64>(0))
            .map_err(ObjectStoreError::Database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(ObjectStoreError::Database)?;

        Ok(ids.into_iter().map(|id| ObjectId(id as u64)).collect())
    }

    // ---- token state -------------------------------------------------------

    /// Reads the persisted token state for every initialized slot.
    pub fn load_tokens(&self) -> Result<Vec<TokenRecord>, ObjectStoreError> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection
            .prepare("select slot_id, label, so_pin_hash, user_pin_hash from token")
            .map_err(ObjectStoreError::Database)?;
        let records = statement
            .query_map([], |row| {
                Ok(TokenRecord {
                    slot_id: row.get::<_, i64>(0)? as u64,
                    label: row.get(1)?,
                    so_pin_hash: row.get(2)?,
                    user_pin_hash: row.get(3)?,
                })
            })
            .map_err(ObjectStoreError::Database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(ObjectStoreError::Database)?;

        Ok(records)
    }

    /// (Re)initializes a token's persisted state, replacing any existing row
    /// and clearing the user PIN.
    pub fn save_token(&self, slot_id: u64, label: Option<&str>, so_pin_hash: &str) -> Result<(), ObjectStoreError> {
        let connection = self.connection.lock().unwrap();
        connection
            .execute(
                "insert into token (slot_id, label, so_pin_hash, user_pin_hash) values (?1, ?2, ?3, null) on \
                 conflict(slot_id) do update set label = ?2, so_pin_hash = ?3, user_pin_hash = null",
                params![slot_id as i64, label, so_pin_hash],
            )
            .map_err(ObjectStoreError::Database)?;
        Ok(())
    }

    pub fn set_so_pin_hash(&self, slot_id: u64, so_pin_hash: &str) -> Result<(), ObjectStoreError> {
        let connection = self.connection.lock().unwrap();
        connection
            .execute(
                "update token set so_pin_hash = ?2 where slot_id = ?1",
                params![slot_id as i64, so_pin_hash],
            )
            .map_err(ObjectStoreError::Database)?;
        Ok(())
    }

    pub fn set_user_pin_hash(&self, slot_id: u64, user_pin_hash: &str) -> Result<(), ObjectStoreError> {
        let connection = self.connection.lock().unwrap();
        connection
            .execute(
                "update token set user_pin_hash = ?2 where slot_id = ?1",
                params![slot_id as i64, user_pin_hash],
            )
            .map_err(ObjectStoreError::Database)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use elliptic_curve::Generate;
    use p256::ecdsa;

    use crate::object_store::ObjectStore;

    #[test]
    fn store_read_delete_roundtrip() {
        let store = ObjectStore::in_memory().unwrap();

        let key = ecdsa::SigningKey::generate();
        let bytes = key.to_bytes().to_vec();

        let id = store.write(&bytes, Some(true), Some(String::from("test1"))).unwrap();

        let stored_bytes: Vec<u8> = store.read(&id).unwrap();
        let stored_key = ecdsa::SigningKey::from_slice(&stored_bytes).unwrap();

        assert_eq!(key, stored_key);

        store.delete(&id).unwrap();
        assert!(store.read_raw(&id).is_err());
    }
}
