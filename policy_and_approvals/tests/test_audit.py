import json

from policy_and_approvals.audit import AuditLog


def test_append_creates_records_and_chain_is_valid(tmp_path):
    log = AuditLog(path=tmp_path / "audit.jsonl", mirror_to_cloud=False)
    log.append("policy_decision", tool_name="x", actor="a", args={}, entities={})
    log.append("tool_executed", tool_name="x", actor="a", args={}, entities={}, outcome="success")
    ok, bad = log.verify_chain()
    assert ok
    assert bad is None


def test_tampering_breaks_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path=path, mirror_to_cloud=False)
    log.append("policy_decision", tool_name="x", actor="a", args={}, entities={})
    log.append("tool_executed", tool_name="x", actor="a", args={}, entities={}, outcome="success")

    # Tamper with the first record's outcome — chain must break.
    lines = path.read_text().splitlines()
    first = json.loads(lines[0])
    first["outcome"] = "success-but-actually-forged"
    lines[0] = json.dumps(first)
    path.write_text("\n".join(lines) + "\n")

    fresh = AuditLog(path=path, mirror_to_cloud=False)
    ok, bad = fresh.verify_chain()
    assert not ok
    assert bad == 1


def test_seq_recovers_after_restart(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path=path, mirror_to_cloud=False)
    log.append("a", tool_name="x", actor="a", args={}, entities={})
    log.append("b", tool_name="x", actor="a", args={}, entities={})
    reopened = AuditLog(path=path, mirror_to_cloud=False)
    rec = reopened.append("c", tool_name="x", actor="a", args={}, entities={})
    assert rec.seq == 3
    ok, _ = reopened.verify_chain()
    assert ok
