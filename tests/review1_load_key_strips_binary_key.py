"""severity: medium
finding: AppendOnlyLedger.load_key() strips leading/trailing whitespace bytes from a binary key file, so a raw random key that begins or ends with 0x09-0x0d or 0x20 (about 1 in 21 random 32-byte seeds) loads shorter and different: an Ed25519 seed then fails to load and an HMAC key differs from the file.

Convention: test_attack_* asserts the secure behaviour (load_key returns the key bytes stored in the
file), so a failure proves the defect. ledger.py:390 returns fh.read().strip().
"""

import os

from argus_ledger import AppendOnlyLedger


def _write_key(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def test_control_key_without_edge_whitespace_roundtrips(tmp_path):
    seed = bytes(range(0x30, 0x50))  # 32 bytes, no whitespace at either end
    path = os.path.join(str(tmp_path), "seed.key")
    _write_key(path, seed)
    assert AppendOnlyLedger.load_key(path) == seed
    AppendOnlyLedger(os.path.join(str(tmp_path), "a.jsonl"), signing_key=seed, use_ed25519=True)


def test_attack_binary_seed_roundtrips(tmp_path):
    # A 32-byte Ed25519 seed as os.urandom(32) can produce: last byte 0x0a, first byte 0x20.
    seed = b"\x20" + bytes(range(0x30, 0x4e)) + b"\x0a"
    assert len(seed) == 32
    path = os.path.join(str(tmp_path), "seed.key")
    _write_key(path, seed)
    loaded = AppendOnlyLedger.load_key(path)
    assert loaded == seed, f"load_key returned {len(loaded)} bytes, not the 32 stored"
