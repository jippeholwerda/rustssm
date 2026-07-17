use std::sync::Mutex;
use std::time::Duration;

use ciborium::Value;
use log::info;
use rusqlite::params;
use rusqlite::Connection;
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::attribute::matches_template;
use crate::attribute::Attribute;
use crate::raw::CK_OBJECT_HANDLE;
use crate::util::random_string;

#[derive(Error, Debug)]
pub enum ObjectStoreError {
    #[error("serialization error {0:?}")]
    Serialize(#[source] ciborium::ser::Error<std::io::Error>),

    #[error("deserialization error {0:?}")]
    Deserialize(#[source] ciborium::de::Error<std::io::Error>),

    /// The object blob's version byte is not one this build understands
    /// (`0` doubles for an empty blob, which no version of rustssm writes).
    #[error("unsupported object record format: version byte {0}")]
    UnsupportedFormat(u8),

    #[error("database error {0:?}")]
    Database(#[source] rusqlite::Error),

    #[error("object not found: {0:?}")]
    NotFound(ObjectId),
}

/// The object-handle space is partitioned between the two object stores by
/// the top bit: SQLite rowids are positive `i64` (bit 63 always clear), so
/// handles with this bit set denote in-memory session objects (allocated by
/// [`crate::session::SessionObjects`]). The partition requires a 64-bit
/// `CK_OBJECT_HANDLE` to survive the FFI boundary, which the assert pins.
pub const SESSION_OBJECT_HANDLE_BIT: u64 = 1 << 63;
const _: () = assert!(std::mem::size_of::<CK_OBJECT_HANDLE>() == 8);

#[derive(Debug, Hash, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct ObjectId(u64);

impl ObjectId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Whether this handle denotes an in-memory session object rather than a
    /// persisted token object.
    pub fn is_session_object(&self) -> bool {
        self.0 & SESSION_OBJECT_HANDLE_BIT != 0
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

/// Derives the legacy `private` and `label` index columns from an object's
/// attributes. Matching is done against the full stored attribute list; these
/// columns exist only so rows remain human-inspectable.
fn indexed_columns(attributes: &[Attribute]) -> (i64, String) {
    let private = i64::from(attributes.iter().any(|attr| matches!(attr, Attribute::Private(true))));
    let label = attributes
        .iter()
        .find_map(|attr| match attr {
            Attribute::Label(label) => Some(label.clone()),
            _ => None,
        })
        .unwrap_or_else(|| random_string(16));
    (private, label)
}

fn apply_schema(connection: &Connection) -> Result<(), ObjectStoreError> {
    connection
        .execute_batch(OBJECT_SCHEMA)
        .map_err(ObjectStoreError::Database)?;
    connection
        .execute_batch(TOKEN_SCHEMA)
        .map_err(ObjectStoreError::Database)?;
    Ok(())
}

/// Version byte prefixed to every object blob, so a future format break is
/// detected loudly (`ObjectStoreError::UnsupportedFormat`) instead of being
/// misread. Version 1 is self-describing CBOR: struct fields and enum
/// variants are encoded by *name*, so reordering or appending
/// `Attribute`/`ObjectClass`/`KeyType` variants (or adding a record field)
/// leaves previously-stored objects readable.
const OBJECT_RECORD_FORMAT_V1: u8 = 1;

/// The persisted form of an object: its full typed attribute list (the
/// creation template merged with token-synthesized and derived attributes)
/// together with the key material used by crypto operations. The material is
/// embedded as a CBOR value in the same document — one encoding, decoded into
/// its concrete key type on demand — rather than a serialized byte blob
/// inside the record.
#[derive(Debug, Serialize, Deserialize)]
struct ObjectRecord {
    attributes: Vec<Attribute>,
    material: Value,
}

/// View of [`ObjectRecord`] used for writing: the typed key material is serialized
/// in place, in one pass. Field names must match `ObjectRecord`.
#[derive(Serialize)]
struct NewObjectRecord<'a, T>
where
    T: Serialize + ?Sized,
{
    attributes: &'a [Attribute],
    material: &'a T,
}

/// Encodes a record as a version-prefixed object blob.
fn encode_content<T>(record: &T) -> Result<Vec<u8>, ObjectStoreError>
where
    T: Serialize,
{
    let mut content = vec![OBJECT_RECORD_FORMAT_V1];
    ciborium::into_writer(record, &mut content).map_err(ObjectStoreError::Serialize)?;
    Ok(content)
}

/// Encodes attributes plus material as an object blob ready to insert.
fn encode_record<T>(attributes: &[Attribute], material: &T) -> Result<Vec<u8>, ObjectStoreError>
where
    T: Serialize + ?Sized,
{
    encode_content(&NewObjectRecord { attributes, material })
}

/// Inserts an encoded object blob; `connection` may be a plain connection or
/// an open transaction.
fn insert_object(
    connection: &Connection,
    attributes: &[Attribute],
    content: &[u8],
) -> Result<ObjectId, ObjectStoreError> {
    let (private, label) = indexed_columns(attributes);
    connection
        .execute(
            "insert into object (content, private, label) values (?1, ?2, ?3)",
            params![content, private, label],
        )
        .map_err(ObjectStoreError::Database)?;

    Ok(ObjectId(connection.last_insert_rowid() as u64))
}

/// Decodes a version-prefixed object blob.
fn decode_content(content: &[u8]) -> Result<ObjectRecord, ObjectStoreError> {
    match content.split_first() {
        Some((&OBJECT_RECORD_FORMAT_V1, cbor)) => ciborium::from_reader(cbor).map_err(ObjectStoreError::Deserialize),
        Some((&version, _)) => Err(ObjectStoreError::UnsupportedFormat(version)),
        None => Err(ObjectStoreError::UnsupportedFormat(0)),
    }
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
        // The store path comes from RUSTSSM_DATABASE_URL — deliberately
        // namespaced so it can't clash with a host process's own
        // `DATABASE_URL` (e.g. its application database). It is accepted both
        // as a plain path and as a sqlite://path?params URL (the format the
        // previous sqlx-based store used).
        let url = std::env::var("RUSTSSM_DATABASE_URL").unwrap_or_else(|_| String::from("rustssm.db"));
        let path = url.strip_prefix("sqlite://").unwrap_or(&url);
        let path = path.split('?').next().unwrap_or(path);

        // `:memory:` selects a private in-memory store: no file is created and
        // all state is lost when the process exits. The single connection is
        // held for the process lifetime, so token state still survives
        // C_Finalize/C_Initialize cycles — but nothing is shared with other
        // processes, so a token must be provisioned in-process (via the PKCS#11
        // API), not with the rustssm-util CLI.
        if path == ":memory:" {
            info!("object store: in-memory (state is not persisted)");
            return Self::in_memory();
        }

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

    /// Opens a private in-memory store. Selected in production by
    /// `RUSTSSM_DATABASE_URL=:memory:` (see [`ObjectStore::new`]) and used
    /// directly by tests. WAL and a busy timeout do not apply to an in-memory
    /// database, so neither is set.
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

    /// Persists key `material` under its full typed attribute list. Only
    /// token objects (`CKA_TOKEN` true) reach the store — session objects
    /// live in process memory (see [`crate::session::SessionObjects`]). The
    /// `private` and `label` columns are derived from the attributes purely
    /// for legacy indexing; matching is done against the stored attribute
    /// list (see [`ObjectStore::search`]).
    pub fn write<T>(&self, attributes: Vec<Attribute>, material: &T) -> Result<ObjectId, ObjectStoreError>
    where
        T: Serialize + ?Sized,
    {
        let content = encode_record(&attributes, material)?;

        let connection = self.connection.lock().unwrap();
        insert_object(&connection, &attributes, &content)
    }

    /// Persists two objects inside a single transaction — used for token key
    /// pairs, so a crash between the halves (the process aborts on panic)
    /// cannot leave an orphaned single key in the store.
    pub fn write_pair<A, B>(
        &self,
        first: (Vec<Attribute>, &A),
        second: (Vec<Attribute>, &B),
    ) -> Result<(ObjectId, ObjectId), ObjectStoreError>
    where
        A: Serialize + ?Sized,
        B: Serialize + ?Sized,
    {
        let (first_attributes, first_material) = first;
        let (second_attributes, second_material) = second;
        let first_content = encode_record(&first_attributes, first_material)?;
        let second_content = encode_record(&second_attributes, second_material)?;

        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction().map_err(ObjectStoreError::Database)?;
        let first_id = insert_object(&transaction, &first_attributes, &first_content)?;
        let second_id = insert_object(&transaction, &second_attributes, &second_content)?;
        transaction.commit().map_err(ObjectStoreError::Database)?;

        Ok((first_id, second_id))
    }

    /// Returns an object's stored attribute list together with its key
    /// material (as an undecoded CBOR value), in a single read.
    pub fn read_parts(&self, object_id: &ObjectId) -> Result<(Vec<Attribute>, Value), ObjectStoreError> {
        let record = self.read_record(object_id)?;
        Ok((record.attributes, record.material))
    }

    /// Replaces an object's stored attribute list, preserving its key
    /// material.
    pub fn set_attributes(&self, object_id: &ObjectId, attributes: Vec<Attribute>) -> Result<(), ObjectStoreError> {
        let mut record = self.read_record(object_id)?;

        let (private, label) = indexed_columns(&attributes);
        record.attributes = attributes;
        let content = encode_content(&record)?;

        let id = object_id.0 as i64;
        let connection = self.connection.lock().unwrap();
        let updated = connection
            .execute(
                "update object set content = ?2, private = ?3, label = ?4 where id = ?1",
                params![id, content, private, label],
            )
            .map_err(ObjectStoreError::Database)?;

        if updated == 0 {
            return Err(ObjectStoreError::NotFound(object_id.clone()));
        }

        Ok(())
    }

    fn read_record(&self, object_id: &ObjectId) -> Result<ObjectRecord, ObjectStoreError> {
        let content = self.read_raw(object_id)?;
        decode_content(&content)
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

    /// Returns the ids of all objects whose stored attributes are a superset
    /// of `template`: every requested attribute must be present with an equal
    /// value. An empty template matches every object. When `include_private`
    /// is false, private objects (`CKA_PRIVATE` true) are excluded — the caller
    /// is a session not logged in as the normal user (PKCS#11 §4.4).
    pub fn search(&self, template: &[Attribute], include_private: bool) -> Result<Vec<ObjectId>, ObjectStoreError> {
        // A template carrying an `Unknown` attribute (a recognized-but-unmodelled
        // type) matches nothing explicitly. By construction no object stores an
        // `Unknown` (every write path runs `merge_attributes`, which drops them),
        // so without this guard `Unknown == Unknown` would make any two
        // unrecognized attributes match each other — a wildcard the spec does
        // not intend. Making the semantics explicit here keeps the invariant
        // from silently depending on every future write path remembering to
        // merge.
        if template.iter().any(|attr| matches!(attr, Attribute::Unknown)) {
            return Ok(Vec::new());
        }

        let connection = self.connection.lock().unwrap();
        let mut statement = connection
            .prepare("select id, content from object")
            .map_err(ObjectStoreError::Database)?;
        let rows = statement
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)))
            .map_err(ObjectStoreError::Database)?;

        let mut ids = Vec::new();
        for row in rows {
            let (id, content) = row.map_err(ObjectStoreError::Database)?;
            let record = decode_content(&content)?;

            if !include_private
                && record
                    .attributes
                    .iter()
                    .any(|attr| matches!(attr, Attribute::Private(true)))
            {
                continue;
            }

            if matches_template(template, &record.attributes) {
                ids.push(ObjectId(id as u64));
            }
        }

        Ok(ids)
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

    use crate::attribute::Attribute;
    use crate::object_store::ObjectId;
    use crate::object_store::ObjectStore;
    use crate::object_store::ObjectStoreError;
    use crate::object_store::OBJECT_RECORD_FORMAT_V1;
    use crate::object_store::SESSION_OBJECT_HANDLE_BIT;

    #[test]
    fn store_read_delete_roundtrip() {
        let store = ObjectStore::in_memory().unwrap();

        let key = ecdsa::SigningKey::generate();
        let bytes = key.to_bytes().to_vec();

        let id = store
            .write(
                vec![Attribute::Private(true), Attribute::Label(String::from("test1"))],
                &bytes,
            )
            .unwrap();

        let (_attributes, material) = store.read_parts(&id).unwrap();
        let stored_bytes: Vec<u8> = material.deserialized().unwrap();
        let stored_key = ecdsa::SigningKey::from_slice(&stored_bytes).unwrap();

        assert_eq!(key, stored_key);

        store.delete(&id).unwrap();
        assert!(store.read_raw(&id).is_err());
    }

    #[test]
    fn write_pair_persists_both_halves() {
        let store = ObjectStore::in_memory().unwrap();

        let (first, second) = store
            .write_pair(
                (vec![Attribute::Label(String::from("private"))], &vec![1u8, 2, 3]),
                (vec![Attribute::Label(String::from("public"))], &vec![4u8, 5, 6]),
            )
            .unwrap();

        assert_ne!(first, second);

        let (attributes, material) = store.read_parts(&first).unwrap();
        assert_eq!(attributes, vec![Attribute::Label(String::from("private"))]);
        assert_eq!(material.deserialized::<Vec<u8>>().unwrap(), vec![1, 2, 3]);

        let (attributes, material) = store.read_parts(&second).unwrap();
        assert_eq!(attributes, vec![Attribute::Label(String::from("public"))]);
        assert_eq!(material.deserialized::<Vec<u8>>().unwrap(), vec![4, 5, 6]);
    }

    /// Inserts a raw content blob, bypassing the store's encoding. Simulates
    /// blobs written by a different (older or newer) rustssm build.
    fn insert_raw_content(store: &ObjectStore, content: &[u8]) -> ObjectId {
        let connection = store.connection.lock().unwrap();
        connection
            .execute(
                "insert into object (content, private, label) values (?1, 0, 'raw')",
                rusqlite::params![content],
            )
            .unwrap();
        ObjectId(connection.last_insert_rowid() as u64)
    }

    #[test]
    fn unknown_record_format_is_rejected_loudly() {
        let store = ObjectStore::in_memory().unwrap();

        // A blob with a version byte this build does not know (e.g. a future
        // format, or a pre-CBOR postcard record that happens to start with
        // 0xff) must fail with UnsupportedFormat — never be misread.
        let id = insert_raw_content(&store, &[0xff, 0x01, 0x02]);
        assert!(matches!(
            store.read_parts(&id).unwrap_err(),
            ObjectStoreError::UnsupportedFormat(0xff)
        ));

        // An empty blob reports version 0 (which nothing ever writes).
        let empty = insert_raw_content(&store, &[]);
        assert!(matches!(
            store.read_parts(&empty).unwrap_err(),
            ObjectStoreError::UnsupportedFormat(0)
        ));
    }

    #[test]
    fn record_decoding_tolerates_unknown_fields() {
        use ciborium::Value;

        // Simulate a record written by a future rustssm whose ObjectRecord
        // gained a field: self-describing CBOR with named fields must still
        // decode into today's struct, ignoring what it does not know. This is
        // the schema-evolution property the postcard→CBOR migration buys.
        let value = Value::Map(vec![
            (
                Value::Text(String::from("attributes")),
                Value::serialized(&vec![Attribute::Label(String::from("from-the-future"))]).unwrap(),
            ),
            (
                Value::Text(String::from("material")),
                Value::serialized(&vec![0u8; 4]).unwrap(),
            ),
            (Value::Text(String::from("added_in_v2")), Value::Bool(true)),
        ]);
        let mut content = vec![OBJECT_RECORD_FORMAT_V1];
        ciborium::into_writer(&value, &mut content).unwrap();

        let store = ObjectStore::in_memory().unwrap();
        let id = insert_raw_content(&store, &content);

        let (attributes, material) = store.read_parts(&id).unwrap();
        assert_eq!(attributes, vec![Attribute::Label(String::from("from-the-future"))]);
        assert_eq!(material.deserialized::<Vec<u8>>().unwrap(), vec![0u8; 4]);
    }

    #[test]
    fn records_encode_attribute_variants_by_name() {
        let store = ObjectStore::in_memory().unwrap();
        let id = store
            .write(vec![Attribute::Label(String::from("named"))], &[0u8; 4][..])
            .unwrap();

        // The blob must carry the variant *name*, not a positional
        // discriminant — that is what makes reordering/appending Attribute
        // variants safe for already-stored objects.
        let content = store.read_raw(&id).unwrap();
        assert_eq!(content[0], OBJECT_RECORD_FORMAT_V1);
        assert!(content.windows(5).any(|window| window == b"Label"));
    }

    #[test]
    fn search_matches_attribute_superset() {
        let store = ObjectStore::in_memory().unwrap();

        let bytes = vec![0u8; 32];
        let a = store
            .write(
                vec![Attribute::Label(String::from("a")), Attribute::Id(b"shared".to_vec())],
                &bytes,
            )
            .unwrap();
        let b = store
            .write(
                vec![Attribute::Label(String::from("b")), Attribute::Id(b"shared".to_vec())],
                &bytes,
            )
            .unwrap();

        // Both share the id; only one has label "a".
        assert_eq!(
            store.search(&[Attribute::Id(b"shared".to_vec())], true).unwrap().len(),
            2
        );
        assert_eq!(
            store.search(&[Attribute::Label(String::from("a"))], true).unwrap(),
            vec![a]
        );
        // An unmatched attribute value excludes everything.
        assert!(store
            .search(&[Attribute::Id(b"other".to_vec())], true)
            .unwrap()
            .is_empty());
        // An empty template matches all.
        assert_eq!(store.search(&[], true).unwrap().len(), 2);

        let _ = b;
    }

    #[test]
    fn search_excludes_private_objects_when_not_permitted() {
        let store = ObjectStore::in_memory().unwrap();
        let bytes = vec![0u8; 8];

        let public = store
            .write(vec![Attribute::Label(String::from("pub"))], &bytes)
            .unwrap();
        let private = store
            .write(
                vec![Attribute::Label(String::from("priv")), Attribute::Private(true)],
                &bytes,
            )
            .unwrap();

        // Permitted: both are visible.
        assert_eq!(store.search(&[], true).unwrap().len(), 2);
        // Not permitted: the private object is filtered out.
        assert_eq!(store.search(&[], false).unwrap(), vec![public]);
        assert!(store
            .search(&[Attribute::Label(String::from("priv"))], false)
            .unwrap()
            .is_empty());
        let _ = private;
    }

    #[test]
    fn search_template_with_unknown_matches_nothing() {
        let store = ObjectStore::in_memory().unwrap();
        let bytes = vec![0u8; 8];

        // Store an object that genuinely carries an `Unknown` attribute. By
        // construction no domain write path does this (every entry point runs
        // `merge_attributes`, which drops them), but the store itself is
        // agnostic — so this guards against a future write path that forgets
        // to merge. Without the explicit check in `search`, the template's
        // `Unknown` would match the stored `Unknown` (`Unknown == Unknown`),
        // turning two unrecognized attributes into a wildcard match.
        store
            .write(
                vec![Attribute::Label(String::from("has-unknown")), Attribute::Unknown],
                &bytes,
            )
            .unwrap();
        store
            .write(vec![Attribute::Label(String::from("clean"))], &bytes)
            .unwrap();

        // A template with `Unknown` matches nothing, even when an object
        // stores an `Unknown`.
        assert!(store.search(&[Attribute::Unknown], true).unwrap().is_empty());

        // A combined template is also empty: `Unknown` short-circuits to no
        // matches regardless of the other (otherwise-matching) attribute.
        assert!(store
            .search(
                &[Attribute::Unknown, Attribute::Label(String::from("has-unknown"))],
                true
            )
            .unwrap()
            .is_empty());

        // The objects are still findable by a real attribute.
        assert_eq!(
            store
                .search(&[Attribute::Label(String::from("clean"))], true)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn store_rowids_never_collide_with_session_object_handles() {
        let store = ObjectStore::in_memory().unwrap();
        let bytes = vec![0u8; 8];

        // The handle-space partition: store rowids are positive i64, so a
        // store handle can never carry the session-object bit.
        let id = store
            .write(vec![Attribute::Label(String::from("tok"))], &bytes)
            .unwrap();
        assert!(!id.is_session_object());
        assert!(ObjectId::new(SESSION_OBJECT_HANDLE_BIT | 1).is_session_object());
    }
}
