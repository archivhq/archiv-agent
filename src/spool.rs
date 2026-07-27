//! Bounded, durable destination spool (`docs/architecture/core/07-disk-spool.md`).
//!
//! When the destination is down, governed payloads that fail to forward are
//! persisted here and retried, so the sender can be told "accepted" only once
//! the payload is durable (`core/05` §4). When the spool is full the agent
//! applies backpressure (a non-2xx) rather than discarding — data is delayed,
//! never lost (`core/05` §3.2).
//!
//! Durability: each payload is written to `<seq>.otlp.tmp`, `fsync`ed, then
//! atomically `rename`d to `<seq>.otlp` (FIFO by name). A crash leaves at worst
//! a stray `.tmp`, swept on recovery. On startup the spool re-counts bytes and
//! resumes draining the backlog oldest-first.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::forward::{HttpClient, forward};
use archiv_export::AssembledPayload;

/// Idle poll when the spool is empty.
const IDLE_POLL: Duration = Duration::from_secs(1);
/// Retry backoff bounds when the destination is down.
const BACKOFF_BASE: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    #[error("spool full ({current}/{max} bytes)")]
    Full { current: u64, max: u64 },
    #[error("spool io: {0}")]
    Io(String),
}

fn io_err(e: std::io::Error) -> SpoolError {
    SpoolError::Io(e.to_string())
}

/// Parse a published spool filename `<20 digits>.otlp` into its sequence.
fn parse_seq(name: &str) -> Option<u64> {
    let stem = name.strip_suffix(".otlp")?;
    if stem.len() == 20 && stem.bytes().all(|b| b.is_ascii_digit()) {
        stem.parse().ok()
    } else {
        None
    }
}

struct State {
    next_seq: u64,
    total_bytes: u64,
    /// Published (durable) files: `seq → byte length`. Ordered ⇒ FIFO drain.
    pending: BTreeMap<u64, u64>,
}

/// Result of one drain attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum DrainOutcome {
    /// A payload was delivered and removed from the spool.
    Delivered,
    /// Nothing to drain.
    Idle,
    /// The destination is still down; the payload was left on disk.
    Retry,
}

/// A bounded on-disk spool of governed OTLP payloads awaiting delivery.
pub struct Spool {
    dir: PathBuf,
    max_bytes: u64,
    state: Mutex<State>,
}

impl Spool {
    /// Open (creating if needed) the spool at `dir`, recovering any backlog.
    /// Sweeps stray `*.tmp`, re-counts `*.otlp` bytes, and resumes the sequence.
    pub async fn open(dir: impl AsRef<Path>, max_bytes: u64) -> std::io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).await?;

        let mut pending = BTreeMap::new();
        let mut total_bytes = 0u64;
        let mut max_seq: Option<u64> = None;

        let mut rd = fs::read_dir(&dir).await?;
        while let Some(entry) = rd.next_entry().await? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".tmp") {
                let _ = fs::remove_file(entry.path()).await; // stray partial write
                continue;
            }
            if let Some(seq) = parse_seq(&name) {
                let len = entry.metadata().await?.len();
                pending.insert(seq, len);
                total_bytes += len;
                max_seq = Some(max_seq.map_or(seq, |m| m.max(seq)));
            }
        }

        let next_seq = max_seq.map_or(0, |m| m + 1);
        if !pending.is_empty() {
            tracing::info!(
                files = pending.len(),
                bytes = total_bytes,
                "recovered spooled payloads — will drain to destination"
            );
        }

        Ok(Self {
            dir,
            max_bytes,
            state: Mutex::new(State {
                next_seq,
                total_bytes,
                pending,
            }),
        })
    }

    /// Files and bytes currently spooled.
    pub async fn stats(&self) -> (usize, u64) {
        let s = self.state.lock().await;
        (s.pending.len(), s.total_bytes)
    }

    fn otlp_path(&self, seq: u64) -> PathBuf {
        self.dir.join(format!("{seq:020}.otlp"))
    }
    fn tmp_path(&self, seq: u64) -> PathBuf {
        self.dir.join(format!("{seq:020}.otlp.tmp"))
    }

    /// Durably append one payload. Reserves the bytes under the cap first
    /// (returning [`SpoolError::Full`] as backpressure), then writes crash-atomically.
    pub async fn push(&self, payload: &Bytes) -> Result<u64, SpoolError> {
        let len = payload.len() as u64;

        // Reserve under the cap. Never evict to make room (that would lose data).
        let seq = {
            let mut s = self.state.lock().await;
            if s.total_bytes + len > self.max_bytes {
                return Err(SpoolError::Full {
                    current: s.total_bytes,
                    max: self.max_bytes,
                });
            }
            let seq = s.next_seq;
            s.next_seq += 1;
            s.total_bytes += len; // reserved; published below
            seq
        };

        // Write tmp → fsync → rename (atomic publish). Roll back on failure.
        let result = async {
            let tmp = self.tmp_path(seq);
            let mut f = fs::File::create(&tmp).await.map_err(io_err)?;
            f.write_all(payload).await.map_err(io_err)?;
            f.sync_all().await.map_err(io_err)?;
            drop(f);
            fs::rename(&tmp, self.otlp_path(seq)).await.map_err(io_err)
        }
        .await;

        match result {
            Ok(()) => {
                let mut s = self.state.lock().await;
                s.pending.insert(seq, len);
                Ok(seq)
            }
            Err(err) => {
                let mut s = self.state.lock().await;
                s.total_bytes = s.total_bytes.saturating_sub(len); // release reservation
                Err(err)
            }
        }
    }

    /// Attempt to deliver the oldest spooled payload.
    pub async fn drain_once(&self, client: &HttpClient, endpoint: &str) -> DrainOutcome {
        let Some((seq, len)) = ({
            let s = self.state.lock().await;
            s.pending.iter().next().map(|(&seq, &len)| (seq, len))
        }) else {
            return DrainOutcome::Idle;
        };

        let path = self.otlp_path(seq);
        let bytes = match fs::read(&path).await {
            Ok(b) => Bytes::from(b),
            Err(err) => {
                // A local storage fault is not successful delivery. Preserve
                // the entry and accounting so an operator can repair/restore
                // the file without later payloads silently overtaking it.
                tracing::warn!(seq, error = %err, "spooled payload unreadable — retaining for retry");
                return DrainOutcome::Retry;
            }
        };

        match forward(client, endpoint, &AssembledPayload::passthrough(bytes)).await {
            Ok(()) => {
                let _ = fs::remove_file(&path).await;
                let mut s = self.state.lock().await;
                if s.pending.remove(&seq).is_some() {
                    s.total_bytes = s.total_bytes.saturating_sub(len);
                }
                DrainOutcome::Delivered
            }
            Err(err) => {
                tracing::debug!(seq, error = %err, "spool drain: destination still down");
                DrainOutcome::Retry
            }
        }
    }
}

/// Small deterministic jitter (0..250 ms) so a fleet doesn't retry in lockstep.
fn jitter() -> Duration {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    Duration::from_millis(u64::from(n % 250))
}

/// Drain the spool to `endpoint` until `shutdown` resolves: greedy while the
/// destination is up, jittered exponential backoff while it is down, slow poll
/// when empty.
pub async fn run_drain_loop(
    spool: Arc<Spool>,
    client: HttpClient,
    endpoint: String,
    shutdown: impl Future<Output = ()>,
) {
    let mut backoff = BACKOFF_BASE;
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let wait = match spool.drain_once(&client, &endpoint).await {
            DrainOutcome::Delivered => {
                backoff = BACKOFF_BASE;
                Duration::ZERO // catch up greedily
            }
            DrainOutcome::Idle => IDLE_POLL,
            DrainOutcome::Retry => {
                let w = backoff + jitter();
                backoff = (backoff * 2).min(BACKOFF_MAX);
                w
            }
        };
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tokio::time::sleep(wait) => {}
        }
    }
}
