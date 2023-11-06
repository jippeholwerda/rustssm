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

use crate::raw;
use crate::raw::CK_OBJECT_HANDLE;
use crate::util::random_string;

#[derive(Error, Debug)]
pub enum ObjectStoreError {
    #[error("serialization/deserialization error {0:?}")]
    Serialize(#[from] postcard::Error),
    #[error("database error {0:?}")]
    Database(#[from] rusqlite::Error),
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

impl From<raw::CK_OBJECT_HANDLE> for ObjectId {
    fn from(value: CK_OBJECT_HANDLE) -> Self {
        ObjectId::new(value)
    }
}

const SCHEMA: &str = include_str!("../db/migrations/20240107000001_object.sql");

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

        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.execute_batch(SCHEMA)?;

        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    #[cfg(test)]
    pub fn in_memory() -> Result<Self, ObjectStoreError> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(SCHEMA)?;

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
        let content = postcard::to_allocvec(&object)?;

        let private = i64::from(private.unwrap_or(false));
        let label = label.unwrap_or_else(|| random_string(16));

        let connection = self.connection.lock().unwrap();
        connection.execute(
            "insert into object (content, private, label) values (?1, ?2, ?3)",
            params![content, private, label],
        )?;

        Ok(ObjectId(connection.last_insert_rowid() as u64))
    }

    pub fn read<T>(&self, object_id: &ObjectId) -> Result<T, ObjectStoreError>
    where
        T: DeserializeOwned,
    {
        let content = self.read_raw(object_id)?;
        let object = postcard::from_bytes(&content)?;
        Ok(object)
    }

    pub fn read_raw(&self, object_id: &ObjectId) -> Result<Vec<u8>, ObjectStoreError> {
        let id = object_id.0 as i64;

        let connection = self.connection.lock().unwrap();
        connection
            .query_row("select content from object where id = ?1", params![id], |row| {
                row.get(0)
            })
            .optional()?
            .ok_or_else(|| ObjectStoreError::NotFound(object_id.clone()))
    }

    pub fn delete(&self, object_id: &ObjectId) -> Result<(), ObjectStoreError> {
        let id = object_id.0 as i64;

        let connection = self.connection.lock().unwrap();
        let deleted = connection.execute("delete from object where id = ?1", params![id])?;

        if deleted == 0 {
            return Err(ObjectStoreError::NotFound(object_id.clone()));
        }

        Ok(())
    }

    /// Removes all stored objects. Used when a token is (re)initialized.
    pub fn clear(&self) -> Result<(), ObjectStoreError> {
        let connection = self.connection.lock().unwrap();
        connection.execute("delete from object", [])?;
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
        let mut statement = connection.prepare(&sql)?;
        let ids = statement
            .query_map(params_from_iter(values), |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ids.into_iter().map(|id| ObjectId(id as u64)).collect())
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa;
    use p256::elliptic_curve::rand_core::OsRng;

    use crate::object_store::ObjectStore;

    #[test]
    fn store_read_delete_roundtrip() {
        let store = ObjectStore::in_memory().unwrap();

        let key = ecdsa::SigningKey::random(&mut OsRng);
        let bytes = key.to_bytes().to_vec();

        let id = store.write(&bytes, Some(true), Some(String::from("test1"))).unwrap();

        let stored_bytes: Vec<u8> = store.read(&id).unwrap();
        let stored_key = ecdsa::SigningKey::from_slice(&stored_bytes).unwrap();

        assert_eq!(key, stored_key);

        store.delete(&id).unwrap();
        assert!(store.read_raw(&id).is_err());
    }
}
