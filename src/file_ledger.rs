//! Append-only audit ledger backed by a JSON-L file with POSIX file locking.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::{
    hex_lower, sign_event_hash, validate_canonical_payload, validate_identifiers, AuditEvent,
    AuditLedgerReader, AuditLedgerWriter, AuditVerifier, ChainVerificationReport, LedgerError,
    VerificationPolicy, GENESIS_PREV_HASH, HASH_VERSION, MAX_PAYLOAD_BYTES,
};

#[cfg(unix)]
unsafe extern "C" {
    fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
}

#[cfg(unix)]
const LOCK_SH: std::os::raw::c_int = 1;
#[cfg(unix)]
const LOCK_EX: std::os::raw::c_int = 2;
#[cfg(unix)]
const LOCK_UN: std::os::raw::c_int = 8;

const TAIL_BLOCK_SIZE: u64 = 65536;

/// Append-only audit ledger backed by a JSON-L file on disk with POSIX permissions and sync_data durability.
#[derive(Clone)]
pub struct FileLedger {
    path: PathBuf,
    signing_key: Option<Arc<ed25519_dalek::SigningKey>>,
    ledger_id: Arc<str>,
    lock: Arc<Mutex<()>>,
}

impl FileLedger {
    /// Open or create an audit ledger at `path`.
    ///
    /// The file is created with owner-only (0600) permissions on Unix systems.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, LedgerError> {
        Self::open(path, None)
    }

    /// Open or create an audit ledger at `path` that signs every event with an Ed25519 signing key.
    pub fn with_signing_key<P: AsRef<Path>>(
        path: P,
        signing_key: ed25519_dalek::SigningKey,
    ) -> Result<Self, LedgerError> {
        Self::open(path, Some(signing_key))
    }

    fn open<P: AsRef<Path>>(
        path: P,
        signing_key: Option<ed25519_dalek::SigningKey>,
    ) -> Result<Self, LedgerError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                LedgerError::InvalidInput(format!("cannot create parent directory: {e}"))
            })?;
        }

        // Ensure file exists with 0600 permissions
        let mut opts = OpenOptions::new();
        opts.create(true).read(true).append(true);
        #[cfg(unix)]
        opts.mode(0o600);

        let file = opts.open(&path).map_err(|e| {
            LedgerError::InvalidInput(format!("cannot open ledger file at {:?}: {e}", path))
        })?;

        #[cfg(unix)]
        {
            if let Ok(metadata) = file.metadata() {
                let current_mode = metadata.permissions().mode() & 0o777;
                if current_mode != 0o600 {
                    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                }
            }
        }

        let mut id = [0u8; 16];
        getrandom::fill(&mut id).expect("OS RNG unavailable; cannot derive ledger identity");
        let ledger_id = hex_lower(&id);

        Ok(Self {
            path,
            signing_key: signing_key.map(Arc::new),
            ledger_id: ledger_id.into(),
            lock: Arc::new(Mutex::new(())),
        })
    }

    /// Path to the underlying ledger file on disk.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Random 128-bit identity bound into event IDs for this ledger instance.
    pub fn ledger_id(&self) -> &str {
        &self.ledger_id
    }

    /// Read the last non-empty line of the file backwards: O(record), not O(file).
    fn tail_record(file: &mut File) -> Result<Option<String>, LedgerError> {
        let len = file
            .seek(SeekFrom::End(0))
            .map_err(|e| LedgerError::LockError(format!("seek end failed: {e}")))?;
        if len == 0 {
            return Ok(None);
        }

        let mut pos = len;
        let mut tail_buf = Vec::new();

        while pos > 0 {
            let chunk_size = pos.min(TAIL_BLOCK_SIZE);
            pos -= chunk_size;
            file.seek(SeekFrom::Start(pos))
                .map_err(|e| LedgerError::LockError(format!("seek chunk failed: {e}")))?;

            let mut chunk = vec![0u8; chunk_size as usize];
            file.read_exact(&mut chunk)
                .map_err(|e| LedgerError::LockError(format!("read chunk failed: {e}")))?;

            chunk.extend_from_slice(&tail_buf);
            tail_buf = chunk;

            // Search backwards for a newline
            let trimmed = match tail_buf.iter().rposition(|&b| !b.is_ascii_whitespace()) {
                Some(idx) => &tail_buf[..=idx],
                None => continue,
            };

            let line_start = match trimmed.iter().rposition(|&b| b == b'\n') {
                Some(idx) => idx + 1,
                None if pos == 0 => 0,
                None => continue,
            };

            let line_bytes = &trimmed[line_start..];
            let s = std::str::from_utf8(line_bytes).map_err(|e| {
                LedgerError::HashMismatch(format!("tail record is not valid UTF-8: {e}"))
            })?;
            return Ok(Some(s.trim().to_string()));
        }

        Ok(None)
    }

    #[cfg(unix)]
    fn flock_ex(file: &File) -> Result<(), LedgerError> {
        use std::os::unix::io::AsRawFd;
        let ret = unsafe { flock(file.as_raw_fd(), LOCK_EX) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            return Err(LedgerError::LockError(format!(
                "flock LOCK_EX failed: {err}"
            )));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn flock_sh(file: &File) -> Result<(), LedgerError> {
        use std::os::unix::io::AsRawFd;
        let ret = unsafe { flock(file.as_raw_fd(), LOCK_SH) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            return Err(LedgerError::LockError(format!(
                "flock LOCK_SH failed: {err}"
            )));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn flock_un(file: &File) {
        use std::os::unix::io::AsRawFd;
        unsafe {
            flock(file.as_raw_fd(), LOCK_UN);
        }
    }

    #[cfg(not(unix))]
    fn flock_ex(_file: &File) -> Result<(), LedgerError> {
        Ok(())
    }

    #[cfg(not(unix))]
    fn flock_sh(_file: &File) -> Result<(), LedgerError> {
        Ok(())
    }

    #[cfg(not(unix))]
    fn flock_un(_file: &File) {}
}

impl AuditLedgerWriter for FileLedger {
    fn append(
        &self,
        event_type: &str,
        actor: &str,
        payload: &str,
    ) -> Result<AuditEvent, LedgerError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            let detail = format!("payload exceeds {MAX_PAYLOAD_BYTES} bytes");
            return Err(LedgerError::InvalidInput(detail));
        }
        validate_identifiers(event_type, actor)?;
        validate_canonical_payload(payload)?;

        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok())
            .ok_or_else(|| LedgerError::InvalidTimestamp("clock outside 1970-2554".into()))?;

        // Precompute payload digest outside lock: O(payload) work before locking
        let digest_hex_str = crate::compute_payload_digest(payload);

        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());

        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true);
        #[cfg(unix)]
        opts.mode(0o600);

        let mut file = opts.open(&self.path).map_err(|e| {
            LedgerError::LockError(format!("cannot open ledger file for writing: {e}"))
        })?;

        Self::flock_ex(&file)?;

        let append_res = (|| -> Result<AuditEvent, LedgerError> {
            let (sequence, prev_hash, last_ts) = match Self::tail_record(&mut file)? {
                None => (1u64, GENESIS_PREV_HASH.to_string(), None),
                Some(last_line) => {
                    let last_ev = AuditEvent::from_json_line(&last_line)?;
                    (
                        last_ev.sequence + 1,
                        last_ev.event_hash,
                        crate::parse_timestamp_nanos(&last_ev.timestamp),
                    )
                }
            };

            // Strictly increasing within the ledger, even if the host clock steps backwards or
            // the previous record was written by the Python package in RFC 3339 form.
            let timestamp = last_ts
                .map_or(now_ns, |lts| now_ns.max(lts.saturating_add(1)))
                .to_string();

            let event_id = format!("ev_{}_{}", self.ledger_id, sequence);
            let event_hash = crate::compute_event_hash_from_digest(
                sequence,
                &event_id,
                &timestamp,
                event_type,
                actor,
                &prev_hash,
                &digest_hex_str,
            );

            let signature = self
                .signing_key
                .as_deref()
                .map(|key| sign_event_hash(key, &event_hash));

            let event = AuditEvent {
                sequence,
                event_id,
                timestamp,
                event_type: event_type.to_string(),
                actor: actor.to_string(),
                payload: payload.to_string(),
                prev_hash,
                event_hash,
                signature,
                hash_version: HASH_VERSION,
            };

            let line = event.to_json_line();

            let end_pos = file
                .seek(SeekFrom::End(0))
                .map_err(|e| LedgerError::LockError(format!("seek end failed: {e}")))?;

            let mut bytes_to_write = Vec::new();
            if end_pos > 0 {
                file.seek(SeekFrom::Start(end_pos - 1))
                    .map_err(|e| LedgerError::LockError(format!("seek last byte failed: {e}")))?;
                let mut last_byte = [0u8; 1];
                file.read_exact(&mut last_byte)
                    .map_err(|e| LedgerError::LockError(format!("read last byte failed: {e}")))?;
                if last_byte[0] != b'\n' {
                    bytes_to_write.push(b'\n');
                }
                file.seek(SeekFrom::End(0))
                    .map_err(|e| LedgerError::LockError(format!("seek end failed: {e}")))?;
            }

            bytes_to_write.extend_from_slice(line.as_bytes());
            bytes_to_write.push(b'\n');

            file.write_all(&bytes_to_write)
                .map_err(|e| LedgerError::LockError(format!("write_all failed: {e}")))?;

            file.sync_data()
                .map_err(|e| LedgerError::LockError(format!("sync_data failed: {e}")))?;

            Ok(event)
        })();

        Self::flock_un(&file);
        append_res
    }
}

impl AuditLedgerReader for FileLedger {
    fn get_event(&self, sequence: u64) -> Result<Option<AuditEvent>, LedgerError> {
        let events = self.all_events()?;
        Ok(events.into_iter().find(|e| e.sequence == sequence))
    }

    fn head(&self) -> Result<Option<AuditEvent>, LedgerError> {
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());

        if !self.path.exists() {
            return Ok(None);
        }

        let mut file = File::open(&self.path)
            .map_err(|e| LedgerError::LockError(format!("cannot open ledger for head: {e}")))?;

        Self::flock_sh(&file)?;
        let tail = Self::tail_record(&mut file);
        Self::flock_un(&file);

        match tail? {
            None => Ok(None),
            Some(line) => Ok(Some(AuditEvent::from_json_line(&line)?)),
        }
    }

    fn all_events(&self) -> Result<Vec<AuditEvent>, LedgerError> {
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());

        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&self.path)
            .map_err(|e| LedgerError::LockError(format!("cannot open ledger for reading: {e}")))?;

        Self::flock_sh(&file)?;

        let reader = BufReader::new(file);
        let mut events = Vec::new();

        for (idx, line_res) in reader.lines().enumerate() {
            let line =
                line_res.map_err(|e| LedgerError::LockError(format!("read line failed: {e}")))?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let event = AuditEvent::from_json_line(trimmed).map_err(|e| {
                LedgerError::HashMismatch(format!("malformed line {}: {e}", idx + 1))
            })?;
            events.push(event);
        }

        // The shared lock belongs to `file`, which the `lines()` iterator owns; it is released
        // when that iterator drops at the end of the loop. Unlocking a freshly opened descriptor
        // would not touch it.
        Ok(events)
    }
}

impl AuditVerifier for FileLedger {
    /// One pass over the file, parsing and checking each line as it is read: a 50k-record
    /// ledger does not become 50k resident `AuditEvent`s (F3). A line that does not parse
    /// fails the chain at that position (F2).
    fn verify_chain_with(
        &self,
        policy: &VerificationPolicy,
    ) -> Result<ChainVerificationReport, LedgerError> {
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());

        if !self.path.exists() {
            return policy.verify_stream(std::iter::empty());
        }

        let file = File::open(&self.path)
            .map_err(|e| LedgerError::LockError(format!("cannot open ledger for verify: {e}")))?;
        Self::flock_sh(&file)?;

        let mut io_error = None;
        let records = BufReader::new(&file)
            .lines()
            .enumerate()
            .map_while(|(idx, line_res)| match line_res {
                Ok(line) => Some(line),
                Err(e) => {
                    io_error = Some(LedgerError::LockError(format!(
                        "read line {} failed: {e}",
                        idx + 1
                    )));
                    None
                }
            })
            .enumerate()
            .filter(|(_, line)| !line.trim().is_empty())
            .map(|(idx, line)| {
                AuditEvent::from_json_line(line.trim()).map_err(|e| {
                    LedgerError::InvalidInput(format!("malformed line {}: {e}", idx + 1))
                })
            });
        let report = policy.verify_stream(records);
        Self::flock_un(&file);
        match io_error {
            Some(e) => Err(e),
            None => report,
        }
    }
}
