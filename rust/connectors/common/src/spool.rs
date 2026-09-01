// SPDX-License-Identifier: Apache-2.0
//! Store-and-forward disk spool for intermittent links (#76).
//!
//! When the publish path stalls, the runtime appends the SEALED envelope to a
//! bounded segment log on local disk instead of shedding it; a paced drain
//! replays it when the link returns. The spooled bytes are byte-identical to
//! what the bus would have carried, sealed before publish, so provenance
//! survives the outage with no re-signing.
//!
//! Durability posture, stated honestly: the spool protects against LINK loss,
//! which is what it exists for. Against power loss it is best-effort: segments
//! are fsynced on rotation and shutdown, not per append, and a torn tail
//! record is detected and truncated on reopen. The drain verifies each
//! record's signature with the connector's own key before publishing, so disk
//! corruption is caught here, counted, and skipped, never sent.
//!
//! Bounding policy is drop-oldest: for a tactical picture the newest
//! observations are worth the most (they also render pre-stale downstream
//! when hours old), so when the spool is full the oldest segment is deleted
//! and counted, matching the live path's freshest-wins posture.

use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use serde::Deserialize;

/// Spool configuration, under `[spool]` in the connector config.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpoolConfig {
    /// Directory for the segment log. Created if missing; must be writable
    /// and should survive restarts (a real disk, not tmpfs, if the events
    /// are to outlive a reboot).
    pub dir: String,
    /// Upper bound on spooled bytes. When exceeded, the oldest segment is
    /// dropped and counted. Default 256 MiB.
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
    /// Drain pace in events per second. Core's per-source token bucket sheds
    /// (not queues) over-rate events, and live traffic shares the same
    /// bucket, so set this from the rate on your Connector Brief with
    /// headroom to spare; ~70-80% of the registered refill rate is the
    /// guidance. The conservative default assumes nothing.
    #[serde(default = "default_drain_rate")]
    pub drain_rate: f64,
}

impl SpoolConfig {
    /// The one-line form: a directory with safe defaults for everything else.
    pub fn with_dir(dir: &str) -> Self {
        Self {
            dir: dir.to_string(),
            max_bytes: default_max_bytes(),
            drain_rate: default_drain_rate(),
        }
    }
}

fn default_max_bytes() -> u64 {
    256 * 1024 * 1024
}

fn default_drain_rate() -> f64 {
    50.0
}

/// Segment rotation threshold. Small enough that drop-oldest is fine-grained,
/// large enough that a directory listing stays short.
const SEGMENT_BYTES: u64 = 4 * 1024 * 1024;

/// One spooled record: the event id (for the Nats-Msg-Id header on replay)
/// and the sealed envelope, exactly as the bus would have carried it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub event_id: String,
    pub sealed: Vec<u8>,
}

/// A drain position: segment sequence number + byte offset within it.
/// Advanced only after the replay publish is confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cursor {
    seg: u64,
    offset: u64,
}

/// The bounded segment log. All operations are synchronous and small; the
/// runtime calls them from its async context without ceremony.
pub struct Spool {
    dir: PathBuf,
    max_bytes: u64,
    /// Open segment being appended to.
    head_seq: u64,
    head: std::fs::File,
    head_len: u64,
    /// Where the next drain read happens.
    cursor: Cursor,
    /// Oldest segments dropped to stay under max_bytes (event count unknown
    /// once dropped, so this counts segments).
    pub dropped_segments: u64,
}

fn seg_path(dir: &Path, seq: u64) -> PathBuf {
    dir.join(format!("spool-{seq:016x}.seg"))
}

fn cursor_path(dir: &Path) -> PathBuf {
    dir.join("cursor")
}

impl Spool {
    /// Open (or create) the spool in `dir`, recovering the cursor and
    /// truncating any torn tail record left by a crash.
    pub fn open(cfg: &SpoolConfig) -> anyhow::Result<Self> {
        let dir = PathBuf::from(&cfg.dir);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating spool dir {}", cfg.dir))?;

        let mut segs = existing_segments(&dir)?;
        // Recover the cursor; a missing or unparsable cursor drains from the
        // oldest byte (safe: replay duplicates are deduped by Nats-Msg-Id
        // inside the broker window and visible in the audit plane beyond it).
        let cursor = read_cursor(&dir).unwrap_or(Cursor {
            seg: segs.first().copied().unwrap_or(0),
            offset: 0,
        });

        // Truncate a torn tail on the newest segment.
        if let Some(&last) = segs.last() {
            truncate_torn_tail(&seg_path(&dir, last))?;
        }

        let head_seq = segs.last().copied().unwrap_or(0);
        if segs.is_empty() {
            segs.push(head_seq);
        }
        let head_path = seg_path(&dir, head_seq);
        let mut head = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&head_path)
            .with_context(|| format!("opening spool segment {}", head_path.display()))?;
        let head_len = head.seek(SeekFrom::End(0))?;

        Ok(Self {
            dir,
            max_bytes: cfg.max_bytes,
            head_seq,
            head,
            head_len,
            cursor,
            dropped_segments: 0,
        })
    }

    /// Append one sealed event. Rotates segments and drops the oldest when
    /// over budget. Returns whether an old segment was dropped to make room.
    pub fn append(&mut self, event_id: &str, sealed: &[u8]) -> anyhow::Result<bool> {
        if self.head_len >= SEGMENT_BYTES {
            self.rotate()?;
        }
        let id = event_id.as_bytes();
        let mut buf = Vec::with_capacity(8 + id.len() + sealed.len());
        buf.extend_from_slice(&(id.len() as u32).to_be_bytes());
        buf.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
        buf.extend_from_slice(id);
        buf.extend_from_slice(sealed);
        self.head.write_all(&buf)?;
        self.head_len += buf.len() as u64;
        self.enforce_bound()
    }

    fn rotate(&mut self) -> anyhow::Result<()> {
        self.head.sync_data().ok();
        self.head_seq += 1;
        let path = seg_path(&self.dir, self.head_seq);
        self.head = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .with_context(|| format!("rotating to spool segment {}", path.display()))?;
        self.head_len = 0;
        Ok(())
    }

    fn enforce_bound(&mut self) -> anyhow::Result<bool> {
        let mut dropped = false;
        loop {
            let segs = existing_segments(&self.dir)?;
            let total: u64 = segs
                .iter()
                .map(|s| {
                    std::fs::metadata(seg_path(&self.dir, *s))
                        .map(|m| m.len())
                        .unwrap_or(0)
                })
                .sum();
            if total <= self.max_bytes || segs.len() <= 1 {
                return Ok(dropped);
            }
            let oldest = segs[0];
            std::fs::remove_file(seg_path(&self.dir, oldest)).ok();
            self.dropped_segments += 1;
            dropped = true;
            if self.cursor.seg <= oldest {
                self.cursor = Cursor {
                    seg: oldest + 1,
                    offset: 0,
                };
            }
        }
    }

    /// The next record to drain, if any, with the cursor that [`advance`]
    /// takes once the replay publish is confirmed. Reading does not move the
    /// cursor; a crash between read and advance replays the record, which
    /// the broker's duplicate window absorbs.
    ///
    /// [`advance`]: Self::advance
    pub fn peek(&mut self) -> anyhow::Result<Option<(Cursor, Record)>> {
        loop {
            let path = seg_path(&self.dir, self.cursor.seg);
            let data = match std::fs::read(&path) {
                Ok(d) => d,
                Err(_) if self.cursor.seg < self.head_seq => {
                    // Segment was dropped or never existed; move on.
                    self.cursor = Cursor {
                        seg: self.cursor.seg + 1,
                        offset: 0,
                    };
                    continue;
                }
                Err(_) => return Ok(None),
            };
            match read_record(&data, self.cursor.offset as usize) {
                Some((rec, _next)) => {
                    return Ok(Some((self.cursor, rec)));
                }
                None if self.cursor.seg < self.head_seq => {
                    self.cursor = Cursor {
                        seg: self.cursor.seg + 1,
                        offset: 0,
                    };
                    continue;
                }
                None => return Ok(None),
            }
        }
    }

    /// Confirm the record at `at` was delivered: move the cursor past it and
    /// persist the position (atomic rename), then reclaim fully-drained
    /// segments behind it.
    pub fn advance(&mut self, at: Cursor) -> anyhow::Result<()> {
        let path = seg_path(&self.dir, at.seg);
        let data =
            std::fs::read(&path).with_context(|| format!("re-reading {}", path.display()))?;
        let (_, next) = read_record(&data, at.offset as usize)
            .ok_or_else(|| anyhow!("advance past a record that is not there"))?;
        self.cursor = Cursor {
            seg: at.seg,
            offset: next as u64,
        };
        write_cursor(&self.dir, self.cursor)?;
        // Reclaim any segment fully behind the cursor.
        for seg in existing_segments(&self.dir)? {
            if seg < self.cursor.seg {
                std::fs::remove_file(seg_path(&self.dir, seg)).ok();
            }
        }
        Ok(())
    }

    /// Total bytes currently on disk (for the metrics endpoint).
    pub fn depth_bytes(&self) -> u64 {
        existing_segments(&self.dir)
            .unwrap_or_default()
            .iter()
            .map(|s| {
                std::fs::metadata(seg_path(&self.dir, *s))
                    .map(|m| m.len())
                    .unwrap_or(0)
            })
            .sum()
    }

    /// Flush the open segment to disk (shutdown path).
    pub fn sync(&mut self) {
        let _ = self.head.sync_data();
    }
}

fn existing_segments(dir: &Path) -> anyhow::Result<Vec<u64>> {
    let mut segs: Vec<u64> = std::fs::read_dir(dir)
        .with_context(|| format!("listing spool dir {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name();
            let name = name.to_str()?;
            let hex = name.strip_prefix("spool-")?.strip_suffix(".seg")?;
            u64::from_str_radix(hex, 16).ok()
        })
        .collect();
    segs.sort_unstable();
    Ok(segs)
}

/// Parse the record at `offset`; `None` on a clean end or a torn tail.
fn read_record(data: &[u8], offset: usize) -> Option<(Record, usize)> {
    let rest = data.get(offset..)?;
    if rest.len() < 8 {
        return None;
    }
    let id_len = u32::from_be_bytes(rest[0..4].try_into().ok()?) as usize;
    let payload_len = u32::from_be_bytes(rest[4..8].try_into().ok()?) as usize;
    let total = 8usize.checked_add(id_len)?.checked_add(payload_len)?;
    if rest.len() < total {
        return None; // torn tail
    }
    let event_id = String::from_utf8(rest[8..8 + id_len].to_vec()).ok()?;
    let sealed = rest[8 + id_len..total].to_vec();
    Some((Record { event_id, sealed }, offset + total))
}

/// Drop a torn tail record left by a crash mid-append.
fn truncate_torn_tail(path: &Path) -> anyhow::Result<()> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return Ok(()),
    };
    let mut offset = 0usize;
    while let Some((_, next)) = read_record(&data, offset) {
        offset = next;
    }
    if offset < data.len() {
        let f = std::fs::OpenOptions::new().write(true).open(path)?;
        f.set_len(offset as u64)?;
    }
    Ok(())
}

fn read_cursor(dir: &Path) -> Option<Cursor> {
    let text = std::fs::read_to_string(cursor_path(dir)).ok()?;
    let mut parts = text.split_whitespace();
    Some(Cursor {
        seg: parts.next()?.parse().ok()?,
        offset: parts.next()?.parse().ok()?,
    })
}

fn write_cursor(dir: &Path, cursor: Cursor) -> anyhow::Result<()> {
    let tmp = dir.join("cursor.tmp");
    let mut f = std::fs::File::create(&tmp)?;
    write!(f, "{} {}", cursor.seg, cursor.offset)?;
    f.sync_data().ok();
    std::fs::rename(&tmp, cursor_path(dir)).context("persisting spool cursor")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(dir: &Path, max_bytes: u64) -> SpoolConfig {
        SpoolConfig {
            dir: dir.to_str().unwrap().to_string(),
            max_bytes,
            drain_rate: 50.0,
        }
    }

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ajar-spool-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_spooled_event_replays_byte_identical_across_a_reopen() {
        let dir = tmp("roundtrip");
        let sealed = vec![7u8; 220];
        {
            let mut spool = Spool::open(&cfg(&dir, u64::MAX)).unwrap();
            spool.append("id-1", &sealed).unwrap();
            spool.append("id-2", &sealed).unwrap();
            spool.sync();
        }
        // Reopen: both records still there, in order, byte-identical.
        let mut spool = Spool::open(&cfg(&dir, u64::MAX)).unwrap();
        let (c1, r1) = spool.peek().unwrap().unwrap();
        assert_eq!(r1.event_id, "id-1");
        assert_eq!(r1.sealed, sealed);
        spool.advance(c1).unwrap();
        let (c2, r2) = spool.peek().unwrap().unwrap();
        assert_eq!(r2.event_id, "id-2");
        spool.advance(c2).unwrap();
        assert!(spool.peek().unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_cursor_survives_a_restart_so_nothing_replays_twice() {
        let dir = tmp("cursor");
        {
            let mut spool = Spool::open(&cfg(&dir, u64::MAX)).unwrap();
            spool.append("a", b"one").unwrap();
            spool.append("b", b"two").unwrap();
            let (c, r) = spool.peek().unwrap().unwrap();
            assert_eq!(r.event_id, "a");
            spool.advance(c).unwrap();
            spool.sync();
        }
        let mut spool = Spool::open(&cfg(&dir, u64::MAX)).unwrap();
        let (_, r) = spool.peek().unwrap().unwrap();
        assert_eq!(r.event_id, "b", "the drained record must not replay");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_torn_tail_from_a_crash_is_truncated_not_propagated() {
        let dir = tmp("torn");
        {
            let mut spool = Spool::open(&cfg(&dir, u64::MAX)).unwrap();
            spool.append("whole", b"intact-bytes").unwrap();
            spool.sync();
        }
        // Simulate a crash mid-append: garbage half-record at the tail.
        let seg = seg_path(&dir, 0);
        let mut f = std::fs::OpenOptions::new().append(true).open(&seg).unwrap();
        f.write_all(&[0, 0, 0, 5, 0, 0]).unwrap(); // truncated header+id
        drop(f);

        let mut spool = Spool::open(&cfg(&dir, u64::MAX)).unwrap();
        let (c, r) = spool.peek().unwrap().unwrap();
        assert_eq!(r.event_id, "whole");
        assert_eq!(r.sealed, b"intact-bytes");
        spool.advance(c).unwrap();
        assert!(spool.peek().unwrap().is_none(), "the torn record is gone");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn over_budget_drops_the_oldest_segment_and_counts_it() {
        let dir = tmp("bound");
        // Segments rotate at SEGMENT_BYTES; a tiny budget forces the bound
        // logic as soon as a second segment exists.
        let payload = vec![9u8; 1024 * 1024];
        let mut spool = Spool::open(&cfg(&dir, SEGMENT_BYTES + 1024)).unwrap();
        let mut appended = 0u32;
        while spool.head_seq < 2 {
            spool.append(&format!("id-{appended}"), &payload).unwrap();
            appended += 1;
        }
        assert!(spool.dropped_segments > 0, "the oldest segment was dropped");
        // The survivor drains from the oldest remaining record, not seg 0.
        let (_, r) = spool.peek().unwrap().unwrap();
        assert_ne!(r.event_id, "id-0", "id-0 lived in the dropped segment");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn draining_reclaims_fully_consumed_segments() {
        let dir = tmp("reclaim");
        let payload = vec![1u8; 1024 * 1024];
        let mut spool = Spool::open(&cfg(&dir, u64::MAX)).unwrap();
        for i in 0..6 {
            spool.append(&format!("id-{i}"), &payload).unwrap();
        }
        assert!(spool.head_seq >= 1, "several segments exist");
        while let Some((c, _)) = spool.peek().unwrap() {
            spool.advance(c).unwrap();
        }
        let left = existing_segments(&dir).unwrap();
        assert_eq!(left.len(), 1, "only the head segment remains: {left:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
