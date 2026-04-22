"""Hash-chained append-only audit log.

- Every record has `prev_hash` = SHA-256 of the previous record's canonical JSON,
  and `hash` = SHA-256 of its own canonical JSON (excluding the `hash` field).
- Tampering with any past record breaks the chain and is detected by verify_chain().
- Records are also mirrored to Google Cloud Logging (when available) under the
  log name `mcp-boss-audit`, so they land in SIEMs that pull from Cloud Logging.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional, Tuple

from .models import AuditRecord


def _get_cloud_logger():
    """Lazily initialise Cloud Logging. Returns None if unavailable."""
    global _CLOUD_LOGGER
    try:
        return _CLOUD_LOGGER
    except NameError:
        pass
    try:
        from google.cloud import logging as cloud_logging  # type: ignore
        client = cloud_logging.Client()
        logger = client.logger("mcp-boss-audit")
    except Exception:
        logger = None
    globals()["_CLOUD_LOGGER"] = logger
    return logger


def _compute_hash(rec: AuditRecord) -> str:
    d = asdict(rec)
    d.pop("hash", None)
    canonical = json.dumps(d, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class AuditLog:
    def __init__(
        self,
        path: str | Path = "/var/log/mcp-boss/audit.jsonl",
        mirror_to_cloud: bool = True,
    ):
        self._path = Path(path)
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            fallback = Path.home() / ".mcp-boss" / "audit.jsonl"
            fallback.parent.mkdir(parents=True, exist_ok=True)
            self._path = fallback
        self._lock = threading.Lock()
        self._mirror = mirror_to_cloud
        self._seq, self._last_hash = self._recover_state()

    def _recover_state(self) -> Tuple[int, str]:
        if not self._path.exists():
            return 0, ""
        seq = 0
        last_hash = ""
        with self._path.open() as f:
            for line in f:
                if not line.strip():
                    continue
                seq += 1
                try:
                    last_hash = json.loads(line).get("hash", "")
                except json.JSONDecodeError:
                    continue
        return seq, last_hash

    def append(self, event_type: str, **kwargs) -> AuditRecord:
        with self._lock:
            self._seq += 1
            rec = AuditRecord(
                seq=self._seq,
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type=event_type,
                invocation_id=kwargs.get("invocation_id", ""),
                actor=kwargs.get("actor", ""),
                tool_name=kwargs.get("tool_name", ""),
                args=kwargs.get("args", {}),
                entities=kwargs.get("entities", {}),
                policy_decision=kwargs.get("policy_decision"),
                approval_id=kwargs.get("approval_id"),
                approval_state=kwargs.get("approval_state"),
                decided_by=kwargs.get("decided_by"),
                reasoning=kwargs.get("reasoning", ""),
                outcome=kwargs.get("outcome"),
                prev_hash=self._last_hash,
            )
            rec.hash = _compute_hash(rec)
            self._last_hash = rec.hash
            line = json.dumps(asdict(rec), default=str)
            with self._path.open("a") as f:
                f.write(line + "\n")
        if self._mirror:
            logger = _get_cloud_logger()
            if logger is not None:
                try:
                    logger.log_struct(asdict(rec), severity="NOTICE")
                except Exception:
                    pass
        return rec

    def verify_chain(self) -> Tuple[bool, Optional[int]]:
        """Verify the full chain. Returns (ok, bad_seq_or_None)."""
        if not self._path.exists():
            return True, None
        prev_hash = ""
        with self._path.open() as f:
            for line in f:
                if not line.strip():
                    continue
                rec_d = json.loads(line)
                if rec_d.get("prev_hash") != prev_hash:
                    return False, rec_d.get("seq")
                stored_hash = rec_d.pop("hash", "")
                temp = AuditRecord(**rec_d)
                if _compute_hash(temp) != stored_hash:
                    return False, rec_d.get("seq")
                prev_hash = stored_hash
        return True, None

    def iter_records(self) -> Iterator[AuditRecord]:
        if not self._path.exists():
            return
        with self._path.open() as f:
            for line in f:
                if not line.strip():
                    continue
                yield AuditRecord(**json.loads(line))

    @property
    def path(self) -> Path:
        return self._path
