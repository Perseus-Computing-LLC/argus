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

/// `bytes` without the padding every reader drops from both ends of a line
/// ([`crate::RECORD_PADDING`]: space, tab, CR, LF).
fn trim_padding(bytes: &[u8]) -> &[u8] {
    let padding = |b: &u8| matches!(*b, b' ' | b'\t' | b'\r' | b'\n');
    let start = bytes
        .iter()
        .position(|b| !padding(b))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !padding(b))
        .map_or(start, |i| i + 1);
    &bytes[start..end]
}

/// Parse one stored line. Bytes that are not UTF-8 are a malformed record like any other line
/// that does not parse, so a verifier reports them at their position instead of failing to read.
fn parse_record_bytes(line: &[u8]) -> Result<AuditEvent, LedgerError> {
    let text = std::str::from_utf8(line).map_err(|e| {
        LedgerError::InvalidInput(format!("malformed JSON: record is not valid UTF-8: {e}"))
    })?;
    AuditEvent::from_json_line(text)
}

/// The records of a JSON Lines ledger, framed the way every reader of this crate and of the
/// Python package frames them: a record ends at LF and nowhere else; spaces, tabs and CRs at
/// both ends of a line are dropped; a line that is empty afterwards is skipped. Every other
/// line is yielded with its 1-based line number and the result of parsing it. `Err` items are
/// read failures; nothing follows one.
pub struct RecordLines<R> {
    reader: R,
    line_no: usize,
    buf: Vec<u8>,
    done: bool,
}

impl<R: BufRead> RecordLines<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            line_no: 0,
            buf: Vec::new(),
            done: false,
        }
    }
}

impl<R: BufRead> Iterator for RecordLines<R> {
    type Item = std::io::Result<(usize, Result<AuditEvent, LedgerError>)>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            self.buf.clear();
            match self.reader.read_until(b'\n', &mut self.buf) {
                Ok(0) => self.done = true,
                Ok(_) => {
                    self.line_no += 1;
                    let line = trim_padding(&self.buf);
                    if !line.is_empty() {
                        return Some(Ok((self.line_no, parse_record_bytes(line))));
                    }
                }
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            }
        }
        None
    }
}

/// Flush the directory at `dir` so that an entry just created in it survives a crash.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// The directory holding `path`; `.` for a bare file name.
fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// `YYYYMMDDTHHMMSSffffffZ` for a time given as microseconds since the Unix epoch.
fn utc_stamp(micros: u128) -> String {
    let secs = (micros / 1_000_000) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Day number to civil date in the proleptic Gregorian calendar (Hinnant, `civil_from_days`).
    let z = days + 719_468;
    let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}{:06}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        micros % 1_000_000
    )
}

/// End of the file as an append finds it under the exclusive lock.
struct Tail {
    /// The last record, or `None` for an empty ledger.
    last: Option<AuditEvent>,
    /// Length of the file; the append writes from here and a failed one cuts back to here.
    end_pos: u64,
    /// The last record lost its newline, so one is written before the next record.
    needs_newline: bool,
}

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
    index: Arc<Mutex<Vec<(u64, u64)>>>,
}

impl FileLedger {
    /// Open the audit ledger at `path`. Nothing is created here: the first append creates the
    /// file, with owner-only (0600) permissions on Unix systems, and its missing directories.
    /// Reading or verifying a path that does not exist therefore leaves it that way.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, LedgerError> {
        Self::open(path, None)
    }

    /// Open the audit ledger at `path`, signing every appended event with an Ed25519 signing key.
    /// Like [`FileLedger::new`], this creates nothing until the first append.
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

        // An existing file is kept owner-only (best effort; a verifier may not own it).
        #[cfg(unix)]
        {
            if let Ok(metadata) = std::fs::metadata(&path) {
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
            index: Arc::new(Mutex::new(Vec::new())),
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

    /// Read the last non-blank line of the first `len` bytes of the file backwards: O(record),
    /// not O(file).
    fn tail_record(file: &mut File, len: u64) -> Result<Option<String>, LedgerError> {
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

            // Search backwards for a newline. Only line padding is skipped: any other byte,
            // such as 0x0C or 0x1C, is record content for every reader.
            let end = tail_buf
                .iter()
                .rposition(|b| !matches!(*b, b' ' | b'\t' | b'\r' | b'\n'))
                .map_or(0, |idx| idx + 1);
            let trimmed = &tail_buf[..end];
            if trimmed.is_empty() {
                continue;
            }

            let line_start = match trimmed.iter().rposition(|&b| b == b'\n') {
                Some(idx) => idx + 1,
                None if pos == 0 => 0,
                None => continue,
            };

            let line_bytes = trim_padding(&trimmed[line_start..]);
            let s = std::str::from_utf8(line_bytes).map_err(|e| {
                LedgerError::HashMismatch(format!("tail record is not valid UTF-8: {e}"))
            })?;
            return Ok(Some(s.to_string()));
        }

        Ok(None)
    }

    /// The bytes after the last newline of the first `len` bytes of the file, and the offset
    /// at which they start. Empty when the file ends with a newline.
    fn unterminated_tail(file: &mut File, len: u64) -> Result<(u64, Vec<u8>), LedgerError> {
        let mut pos = len;
        let mut tail = Vec::new();
        while pos > 0 {
            let chunk_size = pos.min(TAIL_BLOCK_SIZE);
            pos -= chunk_size;
            file.seek(SeekFrom::Start(pos))
                .map_err(|e| LedgerError::LockError(format!("seek chunk failed: {e}")))?;
            let mut chunk = vec![0u8; chunk_size as usize];
            file.read_exact(&mut chunk)
                .map_err(|e| LedgerError::LockError(format!("read chunk failed: {e}")))?;
            if let Some(idx) = chunk.iter().rposition(|&b| b == b'\n') {
                let mut fragment = chunk.split_off(idx + 1);
                fragment.extend_from_slice(&tail);
                return Ok((pos + idx as u64 + 1, fragment));
            }
            chunk.extend_from_slice(&tail);
            tail = chunk;
        }
        Ok((0, tail))
    }

    /// Open the ledger file for an append. A missing file is created owner-only (0600) along
    /// with its missing directories, and the directories are flushed: without that a crash
    /// can lose the new file's name although its records were synced.
    fn open_for_append(&self) -> Result<File, LedgerError> {
        let open_err = |e: std::io::Error| {
            LedgerError::LockError(format!("cannot open ledger file for writing: {e}"))
        };
        let mut existing = OpenOptions::new();
        existing.read(true).write(true);
        match existing.open(&self.path) {
            Ok(file) => return Ok(file),
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(open_err(e)),
            Err(_) => {}
        }

        let parent = parent_dir(&self.path);
        let mut created_dirs = Vec::new();
        let mut probe = parent;
        while !probe.is_dir() {
            created_dirs.push(probe);
            match probe.parent() {
                Some(up) if !up.as_os_str().is_empty() => probe = up,
                _ => break,
            }
        }
        std::fs::create_dir_all(parent).map_err(|e| {
            LedgerError::InvalidInput(format!("cannot create parent directory: {e}"))
        })?;
        for made in created_dirs {
            sync_dir(parent_dir(made)).map_err(|e| {
                LedgerError::LockError(format!("cannot sync directory of {made:?}: {e}"))
            })?;
        }

        let mut fresh = OpenOptions::new();
        fresh.read(true).write(true).create_new(true);
        #[cfg(unix)]
        fresh.mode(0o600);
        match fresh.open(&self.path) {
            Ok(file) => {
                sync_dir(parent).map_err(|e| {
                    LedgerError::LockError(format!("cannot sync ledger directory: {e}"))
                })?;
                Ok(file)
            }
            // Another writer created it in between; append to that file.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                existing.open(&self.path).map_err(open_err)
            }
            Err(e) => Err(open_err(e)),
        }
    }

    /// Read the end of the file for an append; the caller holds the exclusive lock.
    ///
    /// Bytes after the last newline that are not a record are what a writer killed in the
    /// middle of an append leaves behind. Once the record before them has parsed, they are set
    /// aside (see [`FileLedger::set_aside_torn_tail`]). A complete record that lost only its
    /// newline is kept. Readers and verifiers never do this; they keep reporting the fragment
    /// as a malformed record until a writer runs.
    fn prepare_tail(&self, file: &mut File) -> Result<Tail, LedgerError> {
        let len = file
            .seek(SeekFrom::End(0))
            .map_err(|e| LedgerError::LockError(format!("seek end failed: {e}")))?;
        let (torn_at, fragment) = Self::unterminated_tail(file, len)?;
        let unterminated = trim_padding(&fragment);
        let torn = !unterminated.is_empty() && parse_record_bytes(unterminated).is_err();
        let end_pos = if torn { torn_at } else { len };

        let last = match Self::tail_record(file, end_pos)? {
            None => None,
            Some(line) => Some(AuditEvent::from_json_line(&line)?),
        };
        if torn {
            self.set_aside_torn_tail(file, torn_at, &fragment)?;
        }
        Ok(Tail {
            last,
            end_pos,
            needs_newline: !torn && !fragment.is_empty(),
        })
    }

    /// Remove an incomplete record from the end of the file. `fragment` is everything after
    /// the last newline, starting at `offset`. It is first copied to
    /// `<ledger>.torn-<offset>-<UTC time>` (0600, synced) in the ledger's directory; if that
    /// copy cannot be written nothing is removed.
    fn set_aside_torn_tail(
        &self,
        file: &mut File,
        offset: u64,
        fragment: &[u8],
    ) -> Result<(), LedgerError> {
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_micros());
        let mut sidecar = self.path.clone().into_os_string();
        sidecar.push(format!(".torn-{offset}-{}", utc_stamp(micros)));
        let sidecar = PathBuf::from(sidecar);

        let save = || -> std::io::Result<()> {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            opts.mode(0o600);
            let mut copy = opts.open(&sidecar)?;
            copy.write_all(fragment)?;
            copy.sync_all()?;
            sync_dir(parent_dir(&sidecar))
        };
        save().map_err(|e| {
            LedgerError::LockError(format!(
                "cannot append to ledger with an incomplete record at byte {offset}: saving it \
                 to {sidecar:?} failed ({e}); nothing was removed"
            ))
        })?;
        file.set_len(offset)
            .and_then(|()| file.sync_data())
            .map_err(|e| {
                LedgerError::LockError(format!(
                    "cannot append to ledger with an incomplete record at byte {offset}: it was \
                     saved to {sidecar:?} but could not be removed ({e}); the tail needs recovery"
                ))
            })
    }

    /// Write `bytes` at `end_pos`, the end of the file, and flush them. If either step fails
    /// the file is cut back to `end_pos` before the error is returned: the caller is told the
    /// append failed, so no part of it may stay. If the cut fails too, the error says that the
    /// tail needs recovery.
    fn commit(file: &mut File, end_pos: u64, bytes: &[u8]) -> Result<(), LedgerError> {
        let written = file
            .seek(SeekFrom::Start(end_pos))
            .map_err(|e| format!("seek end failed: {e}"))
            .and_then(|_| {
                file.write_all(bytes)
                    .map_err(|e| format!("write_all failed: {e}"))
            })
            .and_then(|()| {
                file.sync_data()
                    .map_err(|e| format!("sync_data failed: {e}"))
            });
        let Err(cause) = written else {
            return Ok(());
        };
        if let Err(e) = file.set_len(end_pos) {
            return Err(LedgerError::LockError(format!(
                "{cause}, and what the append wrote could not be removed ({e}): the ledger tail \
                 needs recovery; bytes from offset {end_pos} on are not an acknowledged record"
            )));
        }
        // Best effort: the append has already failed and is reported as such.
        let _ = file.sync_data();
        Err(LedgerError::LockError(cause))
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

    /// Append multiple events in a single group commit: O(payloads) digests computed outside lock,
    /// single fsync/sync_data call for the entire batch.
    pub fn append_batch(
        &self,
        events: &[(&str, &str, &str)],
    ) -> Result<Vec<AuditEvent>, LedgerError> {
        if events.is_empty() {
            return Ok(Vec::new());
        }
        for &(event_type, actor, payload) in events {
            if payload.len() > MAX_PAYLOAD_BYTES {
                let detail = format!("payload exceeds {MAX_PAYLOAD_BYTES} bytes");
                return Err(LedgerError::InvalidInput(detail));
            }
            validate_identifiers(event_type, actor)?;
            validate_canonical_payload(payload)?;
        }

        // Precompute all payload digests outside lock: O(payload) work before locking
        let digests: Vec<String> = events
            .iter()
            .map(|&(_, _, payload)| crate::compute_payload_digest(payload))
            .collect();

        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok())
            .ok_or_else(|| LedgerError::InvalidTimestamp("clock outside 1970-2554".into()))?;

        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());

        let mut file = self.open_for_append()?;

        Self::flock_ex(&file)?;

        let append_res = (|| -> Result<Vec<AuditEvent>, LedgerError> {
            let tail = self.prepare_tail(&mut file)?;
            let (mut cur_seq, mut cur_prev_hash, mut last_ts) = match tail.last {
                None => (1u64, GENESIS_PREV_HASH.to_string(), None),
                Some(last_ev) => (
                    last_ev.sequence + 1,
                    last_ev.event_hash,
                    crate::parse_timestamp_nanos(&last_ev.timestamp),
                ),
            };

            let mut bytes_to_write = Vec::new();
            if tail.needs_newline {
                bytes_to_write.push(b'\n');
            }

            let mut committed = Vec::with_capacity(events.len());
            let mut index_entries = Vec::with_capacity(events.len());
            let mut running_offset = tail.end_pos + u64::from(tail.needs_newline);

            for (i, &(event_type, actor, payload)) in events.iter().enumerate() {
                let sequence = cur_seq;
                let timestamp = last_ts
                    .map_or(now_ns, |lts| now_ns.max(lts.saturating_add(1)))
                    .to_string();
                last_ts = crate::parse_timestamp_nanos(&timestamp);

                let event_id = format!("ev_{}_{}", self.ledger_id, sequence);
                let event_hash = crate::compute_event_hash_from_digest(
                    sequence,
                    &event_id,
                    &timestamp,
                    event_type,
                    actor,
                    &cur_prev_hash,
                    &digests[i],
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
                    prev_hash: cur_prev_hash.clone(),
                    event_hash: event_hash.clone(),
                    signature,
                    hash_version: HASH_VERSION,
                };

                let line = event.to_json_line();
                index_entries.push((sequence, running_offset));
                running_offset += line.len() as u64 + 1; // +1 for newline

                bytes_to_write.extend_from_slice(line.as_bytes());
                bytes_to_write.push(b'\n');

                cur_prev_hash = event_hash;
                cur_seq += 1;
                committed.push(event);
            }

            Self::commit(&mut file, tail.end_pos, &bytes_to_write)?;

            let mut idx = self.index.lock().unwrap_or_else(|p| p.into_inner());
            idx.extend(index_entries);

            Ok(committed)
        })();

        Self::flock_un(&file);
        append_res
    }
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

        let mut file = self.open_for_append()?;

        Self::flock_ex(&file)?;

        let append_res = (|| -> Result<AuditEvent, LedgerError> {
            let tail = self.prepare_tail(&mut file)?;
            let end_pos = tail.end_pos;
            let (sequence, prev_hash, last_ts) = match tail.last {
                None => (1u64, GENESIS_PREV_HASH.to_string(), None),
                Some(last_ev) => (
                    last_ev.sequence + 1,
                    last_ev.event_hash,
                    crate::parse_timestamp_nanos(&last_ev.timestamp),
                ),
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

            let mut bytes_to_write = Vec::new();
            if tail.needs_newline {
                bytes_to_write.push(b'\n');
            }

            bytes_to_write.extend_from_slice(line.as_bytes());
            bytes_to_write.push(b'\n');

            Self::commit(&mut file, end_pos, &bytes_to_write)?;

            let mut idx = self.index.lock().unwrap_or_else(|p| p.into_inner());
            idx.push((sequence, end_pos));

            Ok(event)
        })();

        Self::flock_un(&file);
        append_res
    }
}

impl AuditLedgerReader for FileLedger {
    fn get_event(&self, sequence: u64) -> Result<Option<AuditEvent>, LedgerError> {
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());

        if !self.path.exists() {
            return Ok(None);
        }

        let mut file = File::open(&self.path).map_err(|e| {
            LedgerError::LockError(format!("cannot open ledger for get_event: {e}"))
        })?;

        Self::flock_sh(&file)?;

        let res = (|| -> Result<Option<AuditEvent>, LedgerError> {
            let idx = self.index.lock().unwrap_or_else(|p| p.into_inner());
            let seek_offset = match idx.binary_search_by_key(&sequence, |&(s, _)| s) {
                Ok(pos) => idx[pos].1,
                Err(pos) if pos > 0 => idx[pos - 1].1,
                _ => 0,
            };
            drop(idx);

            file.seek(SeekFrom::Start(seek_offset))
                .map_err(|e| LedgerError::LockError(format!("seek failed: {e}")))?;

            for record in RecordLines::new(BufReader::new(file)) {
                let (_, parsed) =
                    record.map_err(|e| LedgerError::LockError(format!("read line failed: {e}")))?;
                let event = parsed?;
                if event.sequence == sequence {
                    return Ok(Some(event));
                }
                if event.sequence > sequence {
                    return Ok(None);
                }
            }
            Ok(None)
        })();

        // unlock advisory flock
        // file is consumed by BufReader so flock is released when descriptor drops
        res
    }

    fn head(&self) -> Result<Option<AuditEvent>, LedgerError> {
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());

        if !self.path.exists() {
            return Ok(None);
        }

        let mut file = File::open(&self.path)
            .map_err(|e| LedgerError::LockError(format!("cannot open ledger for head: {e}")))?;

        Self::flock_sh(&file)?;
        let tail = file
            .seek(SeekFrom::End(0))
            .map_err(|e| LedgerError::LockError(format!("seek end failed: {e}")))
            .and_then(|len| Self::tail_record(&mut file, len));
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

        let mut events = Vec::new();

        for record in RecordLines::new(BufReader::new(file)) {
            let (line_no, parsed) =
                record.map_err(|e| LedgerError::LockError(format!("read line failed: {e}")))?;
            let event = parsed
                .map_err(|e| LedgerError::HashMismatch(format!("malformed line {line_no}: {e}")))?;
            events.push(event);
        }

        // The shared lock belongs to `file`, which the record iterator owns; it is released
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

        // A file that is not there is not an intact empty ledger (it may have been deleted, or
        // its volume may not be mounted), so this is an error and never a valid report.
        let file = File::open(&self.path)
            .map_err(|e| LedgerError::LockError(format!("cannot open ledger for verify: {e}")))?;
        Self::flock_sh(&file)?;

        let mut io_error = None;
        let mut last_line = 0;
        let records = RecordLines::new(BufReader::new(&file))
            .map_while(|record| match record {
                Ok((line_no, parsed)) => {
                    last_line = line_no;
                    Some((line_no, parsed))
                }
                Err(e) => {
                    io_error = Some(LedgerError::LockError(format!(
                        "read line {} failed: {e}",
                        last_line + 1
                    )));
                    None
                }
            })
            .map(|(line_no, parsed)| {
                parsed.map_err(|e| {
                    LedgerError::InvalidInput(format!("malformed line {line_no}: {e}"))
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
