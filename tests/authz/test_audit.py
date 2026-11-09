from __future__ import annotations

import json

import pytest

from sentinel_arena.authz import AuditLog, ChainBroken


def test_append_and_iterate(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    log.append(actor="u", action="authorized", host="h.example.com", outcome="allow")
    log.append(actor="u", action="check", host="h.example.com", outcome="allow")
    entries = list(log)
    assert [e.seq for e in entries] == [0, 1]
    assert entries[0].prev_hash == "0" * 64
    assert entries[1].prev_hash == entries[0].entry_hash


def test_chain_verifies_clean(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(5):
        log.append(actor="u", action="check", host=f"h{i}.example.com")
    assert log.verify_chain() is True


def test_tamper_is_detected(tmp_path):
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    log.append(actor="u", action="authorized", host="h.example.com", outcome="allow")
    log.append(actor="u", action="check", host="h.example.com", outcome="allow")

    # Tamper: flip the outcome of the first entry on disk.
    lines = path.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[0])
    obj["outcome"] = "deny"
    lines[0] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ChainBroken):
        AuditLog(path).verify_chain()


def test_deleting_an_entry_is_detected(tmp_path):
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    for i in range(3):
        log.append(actor="u", action="check", host=f"h{i}.example.com")
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]  # drop the middle entry
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ChainBroken):
        AuditLog(path).verify_chain()


def test_reopen_continues_chain(tmp_path):
    path = tmp_path / "a.jsonl"
    AuditLog(path).append(actor="u", action="authorized", host="h.example.com")
    log2 = AuditLog(path)  # reopened; must pick up the tip
    e = log2.append(actor="u", action="check", host="h.example.com")
    assert e.seq == 1
    assert log2.verify_chain() is True
