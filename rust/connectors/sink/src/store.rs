// SPDX-License-Identifier: Apache-2.0
//! Persistence and the audit chain.
//!
//! Every accepted event is appended to a SQLite table as the exact bytes that
//! arrived, plus the fields worth querying on. Each row also carries a link in a
//! hash chain:
//!
//! ```text
//! record_hash[n] = SHA-256( record_hash[n-1] ++ sealed[n] )
//! record_hash[0] = SHA-256( 0x00 * 32       ++ sealed[0] )
//! ```
//!
//! That gives two independent guarantees, and it is worth being precise about
//! which is which. The **signature** on each event proves who produced it and
//! that its contents are unaltered. The **chain** proves the record *set* is
//! unaltered: deleting a row, inserting one, reordering two, or editing any
//! stored byte all break every link from that point on. A signature alone cannot
//! detect a deletion, because a removed event leaves nothing behind to check.
//!
//! Neither guarantee depends on trusting this process after the fact. [`audit`]
//! recomputes both from the stored bytes, so a third party with the database file
//! and the publishers' verifying keys can reach the same verdict independently.

use std::collections::HashMap;
use std::path::Path;

use ajar_connector::{event::Event, verify, VerifyingKey};
use prost::Message;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

/// The hash a chain starts from, before any record exists.
pub const GENESIS: [u8; 32] = [0u8; 32];

/// An append-only, hash-chained store of verified events.
pub struct Store {
    db: Connection,
}

/// What one appended record ended up as.
pub struct Appended {
    /// 1-based position in the chain.
    pub seq: i64,
    /// This record's link hash.
    pub record_hash: [u8; 32],
}

/// The result of re-verifying a stored chain.
#[derive(Debug, PartialEq, Eq)]
pub enum Audit {
    /// Every record verified and every link matched.
    Intact {
        /// Number of records checked.
        records: i64,
        /// The final link, which summarises the whole chain.
        head: [u8; 32],
    },
    /// The chain is broken, or a record no longer verifies.
    Broken {
        /// Sequence number of the first record that failed.
        seq: i64,
        /// What was wrong with it.
        reason: String,
    },
}

impl Store {
    /// Open (creating if needed) the store at `path`.
    pub fn open(path: &Path) -> anyhow::Result<Store> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let db = Connection::open(path)?;
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
            .query_row(
                "SELECT record_hash FROM record ORDER BY seq DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match hash {
            Some(bytes) => to_hash(&bytes)?,
            None => GENESIS,
        })
    }

    /// Number of records held.
    pub fn count(&self) -> anyhow::Result<i64> {
        Ok(self
            .db
            .query_row("SELECT COUNT(*) FROM record", [], |r| r.get(0))?)
    }

    /// Per-source counts, for a quick view of what a deployment is receiving.
    pub fn by_source(&self) -> anyhow::Result<Vec<(String, i64)>> {
        let mut stmt = self
            .db
            .prepare("SELECT source_id, COUNT(*) FROM record GROUP BY source_id ORDER BY 2 DESC")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Append an already-verified event, extending the chain.
    ///
    /// `sealed` must be the exact bytes received: they are what the signature
    /// covers and what the chain hashes, so re-encoding here would make the store
    /// unverifiable later.
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
        tx.execute(
            r#"INSERT INTO record
               (received_at, source_id, event_id, entity_type, timestamp,
                latitude, longitude, altitude_m, sealed, prev_hash, record_hash)
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"#,
            params![
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
            ],
        )?;
        let seq = tx.last_insert_rowid();
        tx.commit()?;
        Ok(Appended { seq, record_hash })
    }

    /// Re-verify the store from the beginning: every signature, every link.
    ///
    /// `keys` maps `source_id` to the verifying key it registered. A source with
    /// no key is a failure rather than a skip, because an unverifiable record is
    /// exactly what an audit exists to surface.
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

            // A gap means a row was deleted; SQLite will not reuse the rowid.
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
            match keys.get(&source_id) {
                Some(key) => {
                    if verify(&sealed, key).is_err() {
                        return Ok(Audit::Broken {
                            seq,
                            reason: format!("signature does not verify for source {source_id}"),
                        });
                    }
                }
                None => {
                    return Ok(Audit::Broken {
                        seq,
                        reason: format!("no verifying key configured for source {source_id}"),
                    })
                }
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

/// One link in the chain.
fn link(prev: &[u8; 32], sealed: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher.update(sealed);
    hasher.finalize().into()
}

fn to_hash(bytes: &[u8]) -> anyhow::Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("stored hash is {} bytes, expected 32", bytes.len()))
}

/// Verify a sealed event against a known source and decode it.
///
/// The `source_id` is taken from the decoded event rather than the NATS subject,
/// so a publisher cannot claim one identity on the wire and another inside the
/// signature. The event is decoded only after its signature verifies.
pub fn accept(sealed: &[u8], keys: &HashMap<String, VerifyingKey>) -> Result<Event, String> {
    // The source is inside the signed bytes, so read it from a provisional decode
    // and then confirm the signature under that source's key.
    let provisional =
        Event::decode(&sealed[ajar_connector::SEAL_SIGNATURE_LEN.min(sealed.len())..])
            .map_err(|e| format!("not a decodable event: {e}"))?;
    let key = keys
        .get(&provisional.source_id)
        .ok_or_else(|| format!("unregistered source {}", provisional.source_id))?;
    let canonical = verify(sealed, key).map_err(|e| e.to_string())?;
    Event::decode(canonical).map_err(|e| format!("verified bytes are not an event: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ajar_connector::{canonical_bytes, seal, EventBuilder, SigningKey};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[0x47; 32])
    }

    fn sealed_event(source: &str) -> (Vec<u8>, Event) {
        let event = EventBuilder::new(source, "mim:aircraft")
            .new_id()
            .timestamp("2026-06-10T08:00:00Z")
            .location(26.4, 50.9, 1200.0)
            .build()
            .unwrap();
        (seal(&canonical_bytes(&event), &key()), event)
    }

    fn keys(source: &str) -> HashMap<String, VerifyingKey> {
        HashMap::from([(source.to_string(), key().verifying_key())])
    }

    fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("sink.db")).unwrap();
        (store, dir)
    }

    #[test]
    fn appends_and_audits_an_intact_chain() {
        let (mut store, _dir) = store();
        for _ in 0..5 {
            let (sealed, event) = sealed_event("acme-radar-1");
            store
                .append(&sealed, &event, "2026-06-10T08:00:01Z")
                .unwrap();
        }
        assert_eq!(store.count().unwrap(), 5);
        match store.audit(&keys("acme-radar-1")).unwrap() {
            Audit::Intact { records, head } => {
                assert_eq!(records, 5);
                assert_ne!(head, GENESIS);
                assert_eq!(head, store.head().unwrap());
            }
            other => panic!("expected an intact chain, got {other:?}"),
        }
    }

    #[test]
    fn each_link_covers_the_one_before_it() {
        let (mut store, _dir) = store();
        let (a, ea) = sealed_event("acme-radar-1");
        let first = store.append(&a, &ea, "t").unwrap();
        assert_eq!(first.record_hash, link(&GENESIS, &a));

        let (b, eb) = sealed_event("acme-radar-1");
        let second = store.append(&b, &eb, "t").unwrap();
        assert_eq!(second.record_hash, link(&first.record_hash, &b));
    }

    #[test]
    fn editing_a_stored_event_breaks_the_audit() {
        let (mut store, _dir) = store();
        for _ in 0..3 {
            let (sealed, event) = sealed_event("acme-radar-1");
            store.append(&sealed, &event, "t").unwrap();
        }
        // Tamper with the middle record's bytes, as an attacker with database
        // access would.
        store
            .db
            .execute("UPDATE record SET sealed = X'00' WHERE seq = 2", [])
            .unwrap();
        match store.audit(&keys("acme-radar-1")).unwrap() {
            Audit::Broken { seq, reason } => {
                assert_eq!(seq, 2);
                assert!(reason.contains("record hash"), "{reason}");
            }
            other => panic!("tampering must break the audit, got {other:?}"),
        }
    }

    #[test]
    fn deleting_a_record_breaks_the_audit() {
        let (mut store, _dir) = store();
        for _ in 0..3 {
            let (sealed, event) = sealed_event("acme-radar-1");
            store.append(&sealed, &event, "t").unwrap();
        }
        store
            .db
            .execute("DELETE FROM record WHERE seq = 2", [])
            .unwrap();
        match store.audit(&keys("acme-radar-1")).unwrap() {
            Audit::Broken { seq, reason } => {
                assert_eq!(seq, 2);
                assert!(reason.contains("missing"), "{reason}");
            }
            other => panic!("a deletion must break the audit, got {other:?}"),
        }
    }

    #[test]
    fn an_unregistered_source_fails_the_audit_rather_than_being_skipped() {
        let (mut store, _dir) = store();
        let (sealed, event) = sealed_event("acme-radar-1");
        store.append(&sealed, &event, "t").unwrap();
        match store.audit(&HashMap::new()).unwrap() {
            Audit::Broken { reason, .. } => {
                assert!(reason.contains("no verifying key"), "{reason}")
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn accept_rejects_an_unregistered_source_and_a_bad_signature() {
        let (sealed, _) = sealed_event("acme-radar-1");
        assert!(accept(&sealed, &keys("acme-radar-1")).is_ok());
        assert!(accept(&sealed, &HashMap::new())
            .unwrap_err()
            .contains("unregistered source"));

        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(accept(&tampered, &keys("acme-radar-1")).is_err());
    }

    #[test]
    fn an_empty_store_has_the_genesis_head() {
        let (store, _dir) = store();
        assert_eq!(store.head().unwrap(), GENESIS);
        assert_eq!(store.count().unwrap(), 0);
        assert!(matches!(
            store.audit(&HashMap::new()).unwrap(),
            Audit::Intact { records: 0, .. }
        ));
    }
}
