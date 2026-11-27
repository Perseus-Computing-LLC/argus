# Input and path validation

Inputs at the public entry points are now checked by type, grammar and size. Hostile paths are
refused, and the library no longer misbehaves on them.

## Ledger paths and files

- `AppendOnlyLedger(ledger_path)` accepts `str`, `bytes` and `os.PathLike` paths.
  - `bytes` paths are decoded with `os.fsdecode`, so names derived from the path (the torn-tail
    sidecar) are real paths.
  - An empty path, a path containing NUL, or a path of any other type is refused with
    `ValueError`/`TypeError`.
- Opening a ledger no longer follows a symlink at the ledger path. If the path is a regular file,
  its group/other bits are still cleared. If it is a link, the file it points to keeps its mode.
- `append()` writes only to a regular file at the path itself. A symlink, directory, FIFO or device
  there is refused with `LedgerCorruptionError`.
- Ledger directories that `append()` creates are now 0700 at every level. Directories that already
  exist are left as they are.
- `append()` now refuses (`LedgerCorruptionError`) when the bytes after the last newline are not a
  record and not the start of one, for example a config value or token. The file is left unchanged.
  Previously such a file was cut to its last newline, which could mean cutting it to zero bytes.
- The torn-tail sidecar name is shortened when `<ledger>.torn-<offset>-<time>` would exceed 255
  bytes. The shortened name keeps a prefix of the ledger name plus a short digest of it. Ledgers
  with long names can now recover from a torn append.
- `verify_chain()` returns `valid=False` ("not a regular file") for a directory, FIFO or device at
  the ledger path, on both the native and pure-Python paths.
  - Previously an empty directory verified as valid, a populated one raised, and a FIFO hung.
  - `head()` and `iter_events()` raise `LedgerCorruptionError` for such paths instead of hanging or
    raising `IsADirectoryError`.

## Identifiers, payloads and keys

- `event_type` and `actor` must now match their grammar exactly. A trailing newline is no longer
  accepted.
- A caller-supplied `append(event_id=...)` must be 1-256 bytes of printable ASCII, with no
  whitespace, `"` or `\`. Otherwise it is refused with `IdentifierError` before anything is written.
  UUIDs and ULIDs are accepted.
- A payload with integer keys that `validate_payload()` accepts is now stored with those keys as
  strings, and it verifies. Previously `append()` raised a pydantic `ValidationError` for it.
  `append()` also stores a private copy of the payload.
- `signing_key` and `verify_key` must be bytes-like; a `str` key raises `TypeError`.
  `verify_signature()` and `verify_signature_ed25519()` return `False` for a non-bytes key instead
  of raising.
- **Behaviour change:** `AppendOnlyLedger.load_key()` now returns the key file's bytes exactly as
  stored. Before, leading and trailing whitespace was stripped, which corrupted raw random keys.
  - If your key file was written with a trailing newline (for example `echo secret > key`),
    rewrite it without the newline (`printf %s secret > key`). Otherwise records signed with the
    old, stripped key will no longer verify under the key that `load_key` now returns.
  - `load_key` also refuses a FIFO or device at the path, and checks the mode of the file it
    actually opened.
- `get_event()` and `iter_events()` refuse a non-int (or bool) sequence with `TypeError`.

## ProofWeave and Praxa

- `PraxaGovernanceGovernor.evaluate_proposal()` now REJECTS an intent that is not a dict, or whose
  `action` is missing, not a string, or empty. A deny-list cannot vet an action that is not named.
- `PolicyActionBinding`, `AgentTraceBinding`, `ProofWeaveTransaction` and
  `MerkleMountainRange.create_blinded_commitment` refuse object keys, at any depth, that would hash
  differently once stored as JSON (`ValueError`). Their `verify()` methods return `False` for such
  inputs.
- `step_index` and `timestamp_epoch_ms` must be ints of 0 or more. A float or bool is refused,
  because it would be sealed as written but stored coerced.
- **Seal format change:** `RAGTriadBinding.evaluation_seal` now covers `triad_harmonic_mean`, and
  every score is sealed at full precision. The seal is domain-tagged, so seals made by earlier
  versions do not match.
  - Scores must be numbers in [0, 1].
  - `passes_threshold` must be a bool.
- `create_blinded_commitment()` requires a dict payload and a bytes salt of at least 16 bytes.
  The commitment format for valid inputs is unchanged.
