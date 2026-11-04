// SPDX-License-Identifier: Apache-2.0
//! Directory transport: read each file dropped into a folder, one line per
//! frame, once its size is stable across two polls, then remember its name. A
//! transfer that stalls for a poll looks finished: the file is read as it
//! stands, and what arrives later is not read.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use tokio::fs::File;
use tokio::io::BufReader;

use crate::runtime::FrameSource;
use crate::stream;

/// Upper bound on remembered file names. At capacity the oldest is forgotten,
/// and re-read if it is still there.
const MAX_SEEN: usize = 100_000;

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

/// Open a directory watch. Without `process_existing`, the files present now
/// are the baseline and are skipped. The baseline is taken here rather than on
/// the first poll, so a file dropped in between counts as new.
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
            if let Some(reader) = self.current.as_mut() {
                match stream::read_line(reader, buf).await {
                    Ok(n) => return Ok(n),
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        self.current = None;
                    }
                    // An oversized line: the file stays open.
                    Err(e) => return Err(e),
                }
                continue;
            }
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

    fn watch(dir: &tempfile::TempDir, process_existing: bool) -> DirSource {
        let mut src = open(dir.path().to_str().unwrap(), process_existing).unwrap();
        src.poll = std::time::Duration::from_millis(20);
        src
    }

    #[tokio::test]
    async fn reads_only_new_drops_and_never_rereads() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::fs::write(dir.join("old.txt"), "stale\n").unwrap();
        let mut src = watch(&tmp, false);

        std::fs::write(dir.join("drop1.txt"), "alpha\nbravo\n").unwrap();

        let mut buf = vec![0u8; 256];
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"alpha");
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"bravo");

        std::fs::write(dir.join("drop2.txt"), "charlie\n").unwrap();
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"charlie", "the baseline file never appears");
    }

    #[tokio::test]
    async fn process_existing_reads_the_baseline() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("batch.txt"), "one\n").unwrap();
        let mut src = watch(&tmp, true);

        let mut buf = vec![0u8; 256];
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"one");
    }
}
