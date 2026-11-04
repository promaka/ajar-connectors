// SPDX-License-Identifier: Apache-2.0
//! Append-only SQLite store of verified events, hash-chained so a deleted,
//! inserted, reordered or edited record breaks every link after it:
//!
//! ```text
//! record_hash[n] = SHA-256( record_hash[n-1] ++ sealed[n] )
//! record_hash[0] = SHA-256( 0x00 * 32       ++ sealed[0] )
//! ```

use std::collections::HashMap;
use std::path::Path;

use ajar_connector::event::Event;
use ajar_connector::{SealError, VerifyingKey, SEAL_SIGNATURE_LEN};
use anyhow::Context;
use prost::Message;
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

/// The hash a chain starts from, before any record exists.
pub const GENESIS: [u8; 32] = [0u8; 32];

pub struct Store {
    db: Connection,
}

pub struct Appended {
    /// 1-based position in the chain.
    pub seq: i64,
    pub record_hash: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
pub enum Audit {
    Intact {
        records: i64,
        head: [u8; 32],
    },
    /// `seq` is the first record that failed.
    Broken {
        seq: i64,
        reason: String,
    },
}

/// Why an incoming event was not recorded.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    #[error("not a decodable event: {0}")]
    Undecodable(prost::DecodeError),
    #[error("unregistered source {0}")]
    UnregisteredSource(String),
    #[error(transparent)]
    Signature(#[from] SealError),
}

impl Store {
    /// Open the store at `path`, creating it and its directory if needed.
    pub fn open(path: &Path) -> anyhow::Result<Store> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        Self::init(Connection::open(path)?)
    }

    /// Open an existing database without creating one. SQLite creates a file on
    /// open, and an empty chain audits intact, so a mistyped path must fail.
    pub fn open_existing(path: &Path) -> anyhow::Result<Store> {
        if !path.is_file() {
            anyhow::bail!("no database at {}, check the path", path.display());
        }
        Self::init(Connection::open(path)?)
    }

    fn init(db: Connection) -> anyhow::Result<Store> {
        // WAL keeps readers (an audit, a query) from blocking the ingest path.
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS record (
                seq          INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at  TEXT NOT NULL,
                source_id    TEXT NOT NULL,
                event_id     TEXT NOT NULL,
                entity_type  TEXT NOT NULL,
                timestamp    TEXT NOT NULL,
                latitude     REAL,
                longitude    REAL,
                altitude_m   REAL,
                sealed       BLOB NOT NULL,
                prev_hash    BLOB NOT NULL,
                record_hash  BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS record_source ON record(source_id, seq);
            CREATE INDEX IF NOT EXISTS record_entity ON record(entity_type, seq);
            CREATE UNIQUE INDEX IF NOT EXISTS record_hash_unique ON record(record_hash);
            "#,
        )?;
        Ok(Store { db })
    }

    /// The most recent link, or [`GENESIS`] when the store is empty.
    pub fn head(&self) -> anyhow::Result<[u8; 32]> {
        let hash: Option<Vec<u8>> = self
            .db
            .prepare_cached("SELECT record_hash FROM record ORDER BY seq DESC LIMIT 1")?
            .query_row([], |r| r.get(0))
            .optional()?;
        let Some(bytes) = hash else {
            return Ok(GENESIS);
        };
        <[u8; 32]>::try_from(bytes.as_slice())
            .with_context(|| format!("stored hash is {} bytes, expected 32", bytes.len()))
    }

    pub fn count(&self) -> anyhow::Result<i64> {
        Ok(self
            .db
            .query_row("SELECT COUNT(*) FROM record", [], |r| r.get(0))?)
    }

    pub fn by_source(&self) -> anyhow::Result<Vec<(String, i64)>> {
        let mut stmt = self
            .db
            .prepare("SELECT source_id, COUNT(*) FROM record GROUP BY source_id ORDER BY 2 DESC")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Append an already-verified event, extending the chain. `sealed` is
    /// stored as received: it is what the signature covers and the chain hashes.
    pub fn append(
        &mut self,
        sealed: &[u8],
        event: &Event,
        received_at: &str,
    ) -> anyhow::Result<Appended> {
        let prev = self.head()?;
        let record_hash = link(&prev, sealed);
        let loc = event.location.as_ref();
        let tx = self.db.transaction()?;
        tx.prepare_cached(
            r#"INSERT INTO record
               (received_at, source_id, event_id, entity_type, timestamp,
                latitude, longitude, altitude_m, sealed, prev_hash, record_hash)
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"#,
        )?
        .execute(rusqlite::params![
            received_at,
            event.source_id,
            event.id,
            event.entity_type,
            event.timestamp,
            loc.map(|l| l.latitude),
            loc.map(|l| l.longitude),
            loc.map(|l| l.altitude_m),
            sealed,
            prev.as_slice(),
            record_hash.as_slice(),
        ])?;
        let seq = tx.last_insert_rowid();
        tx.commit()?;
        Ok(Appended { seq, record_hash })
    }

    /// Re-verify the store from the beginning: every signature, every link. A
    /// source with no key in `keys` breaks the audit rather than being skipped.
    pub fn audit(&self, keys: &HashMap<String, VerifyingKey>) -> anyhow::Result<Audit> {
        let mut stmt = self.db.prepare(
            "SELECT seq, source_id, sealed, prev_hash, record_hash FROM record ORDER BY seq",
        )?;
        let mut rows = stmt.query([])?;

        let mut expected_prev = GENESIS;
        let mut expected_seq = 1i64;
        let mut records = 0i64;

        while let Some(row) = rows.next()? {
            let seq: i64 = row.get(0)?;
            let source_id: String = row.get(1)?;
            let sealed: Vec<u8> = row.get(2)?;
            let stored_prev: Vec<u8> = row.get(3)?;
            let stored_hash: Vec<u8> = row.get(4)?;

            // A gap means a row was deleted; SQLite does not reuse the rowid.
            if seq != expected_seq {
                return Ok(Audit::Broken {
                    seq: expected_seq,
                    reason: format!("record {expected_seq} is missing (next stored is {seq})"),
                });
            }
            if stored_prev != expected_prev {
                return Ok(Audit::Broken {
                    seq,
                    reason: "previous-hash does not match the record before it".into(),
                });
            }
            let recomputed = link(&expected_prev, &sealed);
            if stored_hash != recomputed {
                return Ok(Audit::Broken {
                    seq,
                    reason: "record hash does not match its stored bytes".into(),
                });
            }
            let Some(key) = keys.get(&source_id) else {
                return Ok(Audit::Broken {
                    seq,
                    reason: format!("no verifying key configured for source {source_id}"),
                });
            };
            if ajar_connector::verify(&sealed, key).is_err() {
                return Ok(Audit::Broken {
                    seq,
                    reason: format!("signature does not verify for source {source_id}"),
                });
            }

            expected_prev = recomputed;
            expected_seq += 1;
            records += 1;
        }

        Ok(Audit::Intact {
            records,
            head: expected_prev,
        })
    }
}

fn link(prev: &[u8; 32], sealed: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher.update(sealed);
    hasher.finalize().into()
}

/// Verify a sealed event against its registered source and decode it. The
/// source is read from the signed bytes, not the NATS subject, so a publisher
/// cannot claim one identity on the wire and another inside the signature. The
/// decoded bytes are exactly the ones the seal covers, so the event is returned
/// only once the seal verifies.
pub fn accept(sealed: &[u8], keys: &HashMap<String, VerifyingKey>) -> Result<Event, Refusal> {
    let event = Event::decode(&sealed[SEAL_SIGNATURE_LEN.min(sealed.len())..])
        .map_err(Refusal::Undecodable)?;
    let key = keys
        .get(&event.source_id)
        .ok_or_else(|| Refusal::UnregisteredSource(event.source_id.clone()))?;
    ajar_connector::verify(sealed, key)?;
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ajar_connector::{EventBuilder, SigningKey};

    const SOURCE: &str = "acme-radar-1";

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[0x47; 32])
    }

    fn sealed_event() -> (Vec<u8>, Event) {
        let event = EventBuilder::new(SOURCE, "mim:aircraft")
            .new_id()
            .timestamp("2026-06-10T08:00:00Z")
            .location(26.4, 50.9, 1200.0)
            .build()
            .unwrap();
        (
            ajar_connector::seal(&ajar_connector::canonical_bytes(&event), &key()),
            event,
        )
    }

    fn keys() -> HashMap<String, VerifyingKey> {
        HashMap::from([(SOURCE.to_string(), key().verifying_key())])
    }

    fn store_with(records: usize) -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("sink.db")).unwrap();
        for _ in 0..records {
            let (sealed, event) = sealed_event();
            store
                .append(&sealed, &event, "2026-06-10T08:00:01Z")
                .unwrap();
        }
        (store, dir)
    }

    #[test]
    fn intact_chain_audits_clean() {
        let (store, _dir) = store_with(5);
        assert_eq!(store.count().unwrap(), 5);
        match store.audit(&keys()).unwrap() {
            Audit::Intact { records, head } => {
                assert_eq!(records, 5);
                assert_ne!(head, GENESIS);
                assert_eq!(head, store.head().unwrap());
            }
            other => panic!("expected an intact chain, got {other:?}"),
        }
    }

    #[test]
    fn each_link_covers_the_previous() {
        let (mut store, _dir) = store_with(0);
        let (a, ea) = sealed_event();
        let first = store.append(&a, &ea, "t").unwrap();
        assert_eq!(first.record_hash, link(&GENESIS, &a));

        let (b, eb) = sealed_event();
        let second = store.append(&b, &eb, "t").unwrap();
        assert_eq!(second.record_hash, link(&first.record_hash, &b));
    }

    #[test]
    fn edited_record_breaks_the_audit() {
        let (store, _dir) = store_with(3);
        store
            .db
            .execute("UPDATE record SET sealed = X'00' WHERE seq = 2", [])
            .unwrap();
        match store.audit(&keys()).unwrap() {
            Audit::Broken { seq, reason } => {
                assert_eq!(seq, 2);
                assert!(reason.contains("record hash"), "{reason}");
            }
            other => panic!("tampering must break the audit, got {other:?}"),
        }
    }

    #[test]
    fn deleted_record_breaks_the_audit() {
        let (store, _dir) = store_with(3);
        store
            .db
            .execute("DELETE FROM record WHERE seq = 2", [])
            .unwrap();
        match store.audit(&keys()).unwrap() {
            Audit::Broken { seq, reason } => {
                assert_eq!(seq, 2);
                assert!(reason.contains("missing"), "{reason}");
            }
            other => panic!("a deletion must break the audit, got {other:?}"),
        }
    }

    #[test]
    fn unregistered_source_breaks_the_audit() {
        let (store, _dir) = store_with(1);
        match store.audit(&HashMap::new()).unwrap() {
            Audit::Broken { reason, .. } => {
                assert!(reason.contains("no verifying key"), "{reason}")
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn accept_takes_a_registered_source() {
        let (sealed, event) = sealed_event();
        assert_eq!(accept(&sealed, &keys()).unwrap(), event);
    }

    #[test]
    fn accept_refuses_an_unregistered_source() {
        let (sealed, _) = sealed_event();
        let err = accept(&sealed, &HashMap::new()).unwrap_err();
        assert!(err.to_string().contains("unregistered source"), "{err}");
    }

    #[test]
    fn accept_refuses_a_bad_signature() {
        let (mut sealed, _) = sealed_event();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(accept(&sealed, &keys()).is_err());
    }

    #[test]
    fn empty_store_has_the_genesis_head() {
        let (store, _dir) = store_with(0);
        assert_eq!(store.head().unwrap(), GENESIS);
        assert_eq!(store.count().unwrap(), 0);
        assert!(matches!(
            store.audit(&HashMap::new()).unwrap(),
            Audit::Intact { records: 0, .. }
        ));
    }

    #[test]
    fn open_existing_refuses_a_missing_database() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.db");
        assert!(Store::open_existing(&missing).is_err());
        assert!(!missing.exists(), "the refusal must not create the file");
    }
}
