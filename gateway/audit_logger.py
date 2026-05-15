
import json
import logging
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)

LOGS_DIR = Path("logs")


@dataclass
class AuditEntry:
    """
    Represents a single audit record for one complete request lifecycle.
    Every request that passes through the gateway generates one entry.
    """
    request_id:   str
    timestamp:    str
    user_id:      str
    department:   Optional[str]
    prompt:       str
    model_used:   Optional[str]
    risk_score:   float
    threat_type:  str
    action:       str
    policy_allowed: bool
    response_flagged: bool
    flag_reason:  Optional[str]
    duration_ms:  Optional[float] = None
    metadata:     dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "request_id":       self.request_id,
            "timestamp":        self.timestamp,
            "user_id":          self.user_id,
            "department":       self.department,
            "prompt_preview":   self.prompt[:120] + "..." if len(self.prompt) > 120 else self.prompt,
            "model_used":       self.model_used,
            "risk_score":       self.risk_score,
            "threat_type":      self.threat_type,
            "action":           self.action,
            "policy_allowed":   self.policy_allowed,
            "response_flagged": self.response_flagged,
            "flag_reason":      self.flag_reason,
            "duration_ms":      self.duration_ms,
            "metadata":         self.metadata,
        }


class AuditLogger:
    """
    Records all gateway activity to both an in-memory log and a JSONL file.
    Each line in the file is a valid JSON object (JSONL format).
    """

    def __init__(self, log_to_file: bool = True, logs_dir: Path = LOGS_DIR):
        self.log_to_file = log_to_file
        self.logs_dir = logs_dir
        self._entries: list[AuditEntry] = []  # in-memory store

        if self.log_to_file:
            self.logs_dir.mkdir(exist_ok=True)
            self._log_file = self.logs_dir / "audit.jsonl"

    # ---------------------------------------------------------------------------
    # Main logging method
    # ---------------------------------------------------------------------------

    def log(
        self,
        request_id:      str,
        user_id:         str,
        department:      Optional[str],
        prompt:          str,
        model_used:      Optional[str],
        risk_score:      float,
        threat_type:     str,
        action:          str,
        policy_allowed:  bool,
        response_flagged: bool,
        flag_reason:     Optional[str] = None,
        duration_ms:     Optional[float] = None,
        metadata:        Optional[dict] = None,
    ) -> AuditEntry:
        """
        Creates and stores an audit entry for a completed request.
        """
        entry = AuditEntry(
            request_id=request_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=user_id,
            department=department,
            prompt=prompt,
            model_used=model_used,
            risk_score=risk_score,
            threat_type=threat_type,
            action=action,
            policy_allowed=policy_allowed,
            response_flagged=response_flagged,
            flag_reason=flag_reason,
            duration_ms=duration_ms,
            metadata=metadata or {},
        )

        self._entries.append(entry)
        logger.info(f"[AUDIT] {request_id} | user={user_id} | risk={risk_score} | action={action}")

        if self.log_to_file:
            self._write_to_file(entry)

        return entry

    # ---------------------------------------------------------------------------
    # File I/O
    # ---------------------------------------------------------------------------

    def _write_to_file(self, entry: AuditEntry) -> None:
        """Appends the entry as a JSON line to the audit file."""
        try:
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry.to_dict()) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit entry to file: {e}")

    # ---------------------------------------------------------------------------
    # Query methods for the dashboard
    # ---------------------------------------------------------------------------

    def get_all(self) -> list[dict]:
        """Returns all in-memory audit entries as dicts."""
        return [e.to_dict() for e in self._entries]

    def get_by_request_id(self, request_id: str) -> Optional[dict]:
        """Find a specific entry by request ID."""
        for entry in self._entries:
            if entry.request_id == request_id:
                return entry.to_dict()
        return None

    def get_blocked(self) -> list[dict]:
        """Returns all entries where the request was blocked."""
        return [e.to_dict() for e in self._entries if e.action == "block"]

    def get_flagged(self) -> list[dict]:
        """Returns all entries where the response was flagged."""
        return [e.to_dict() for e in self._entries if e.response_flagged]

    def summary(self) -> dict:
        """Returns a summary of gateway activity for the dashboard."""
        total = len(self._entries)
        if total == 0:
            return {"total": 0}

        blocked  = sum(1 for e in self._entries if e.action == "block")
        warned   = sum(1 for e in self._entries if e.action == "warn")
        flagged  = sum(1 for e in self._entries if e.response_flagged)
        avg_risk = sum(e.risk_score for e in self._entries) / total

        models_used: dict[str, int] = {}
        for e in self._entries:
            if e.model_used:
                models_used[e.model_used] = models_used.get(e.model_used, 0) + 1

        return {
            "total_requests":    total,
            "blocked":           blocked,
            "warned":            warned,
            "allowed":           total - blocked - warned,
            "response_flagged":  flagged,
            "avg_risk_score":    round(avg_risk, 3),
            "models_used":       models_used,
        }