// SPDX-License-Identifier: Apache-2.0
//! Directory-watch transport — consume files that a source *drops* into a folder
//! (SFTP batch exports, scheduled dumps), the other ubiquitous legacy pattern
//! next to `file` tailing. Each settled file is read line-by-line, one line per
//! frame, then remembered so it is never re-read.
//!
//! Partial uploads are the classic trap: a file that has *appeared* may still be
//! being written. A file is only read once its size is stable across two
//! consecutive polls — by which point a stalled transfer is indistinguishable
//! from a finished one, which is exactly the operator's intent.
//!
//! Zero dependencies: plain polling (default 1 s), portable everywhere. The
//! seen-files set is bounded (FIFO) so a drop directory that is never cleaned
//! cannot grow the connector's memory without limit.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use tokio::fs::File;
use tokio::io::BufReader;

use crate::runtime::FrameSource;
use crate::stream;

/// Upper bound on remembered file names. At capacity the oldest is forgotten —
/// if that file still exists it would be re-read, so size the bound generously
/// and clean the drop directory operationally (as batch drops always are).
const MAX_SEEN: usize = 100_000;

/// Reads newly-dropped files from a directory, one line per frame.
pub struct DirSource {
    path: PathBuf,
    poll: std::time::Duration,
    seen: HashSet<String>,
    seen_order: VecDeque<String>,
    /// Candidate files awaiting a stable size: name → size at last poll.
    settling: HashMap<String, u64>,
    /// Settled files not yet read.
    ready: VecDeque<PathBuf>,
    /// The file currently being streamed.
    current: Option<BufReader<File>>,
}

/// Open a directory watch. With `process_existing`, files already present are
/// read first; otherwise only files appearing after startup are consumed.
///
/// The baseline (which files count as "already present") is taken **here, at
/// startup** — synchronously — not on the first poll, so a file dropped in the
/// window between opening the watch and the first scan is correctly treated as
/// new rather than swept into the baseline.
pub fn open(path: &str, process_existing: bool) -> anyhow::Result<DirSource> {
    let p = PathBuf::from(path);
    if !p.is_dir() {
        anyhow::bail!("dir transport: {path} is not a directory");
    }
    let mut seen = HashSet::new();
    let mut seen_order = VecDeque::new();
    if !process_existing {
        if let Ok(rd) = std::fs::read_dir(&p) {
            for entry in rd.flatten() {
                if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    seen.insert(name.clone());
                    seen_order.push_back(name);
                }
            }
        }
    }
    Ok(DirSource {
        path: p,
        poll: std::time::Duration::from_secs(1),
        seen,
        seen_order,
        settling: HashMap::new(),
        ready: VecDeque::new(),
        current: None,
    })
}

impl DirSource {
    fn remember(&mut self, name: String) {
        if self.seen.insert(name.clone()) {
            self.seen_order.push_back(name);
            while self.seen.len() > MAX_SEEN {
                if let Some(oldest) = self.seen_order.pop_front() {
                    self.seen.remove(&oldest);
                } else {
                    break;
                }
            }
        }
    }

    /// One poll of the directory: move any not-yet-seen file whose size is
    /// unchanged since the previous poll into the ready queue.
    async fn scan(&mut self) -> std::io::Result<()> {
        let mut entries = tokio::fs::read_dir(&self.path).await?;
        while let Some(entry) = entries.next_entry().await? {
            let meta = match entry.metadata().await {
                Ok(m) if m.is_file() => m,
                _ => continue,
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if self.seen.contains(&name) {
                continue;
            }
            let size = meta.len();
            match self.settling.get(&name) {
                Some(&prev) if prev == size => {
                    self.settling.remove(&name);
                    self.remember(name.clone());
                    self.ready.push_back(entry.path());
                    tracing::info!(file = %name, bytes = size, "new file settled");
                }
                _ => {
                    self.settling.insert(name, size);
                }
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl FrameSource for DirSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            // Stream the current file to its end.
            if let Some(reader) = self.current.as_mut() {
                match stream::read_line(reader, buf).await {
                    Ok(n) => return Ok(n),
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        self.current = None; // file finished; move on
                    }
                    Err(e) => return Err(e), // oversized line: surface, keep file
                }
                continue;
            }
            // Open the next settled file, or poll for one.
            if let Some(path) = self.ready.pop_front() {
                match File::open(&path).await {
                    Ok(f) => self.current = Some(BufReader::new(f)),
                    Err(e) => {
                        tracing::warn!(file = %path.display(), error = %e, "cannot open dropped file, skipping")
                    }
                }
                continue;
            }
            self.scan().await?;
            if self.ready.is_empty() {
                tokio::time::sleep(self.poll).await;
            }
        }
    }

    fn describe(&self) -> String {
        format!("dir {}", self.path.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("ajar-dir-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[tokio::test]
    async fn reads_only_files_dropped_after_start_and_never_rereads() {
        let dir = test_dir("new");
        std::fs::write(dir.join("old.txt"), "stale\n").unwrap();

        let mut src = open(dir.to_str().unwrap(), false).unwrap();
        src.poll = std::time::Duration::from_millis(20);

        // Drop a new file after the source exists.
        std::fs::write(dir.join("drop1.txt"), "alpha\nbravo\n").unwrap();

        let mut buf = vec![0u8; 256];
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"alpha");
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"bravo");

        // A second drop is picked up; the old baseline file never appears.
        std::fs::write(dir.join("drop2.txt"), "charlie\n").unwrap();
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"charlie");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn process_existing_reads_the_baseline_files() {
        let dir = test_dir("existing");
        std::fs::write(dir.join("batch.txt"), "one\n").unwrap();

        let mut src = open(dir.to_str().unwrap(), true).unwrap();
        src.poll = std::time::Duration::from_millis(20);

        let mut buf = vec![0u8; 256];
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"one");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
