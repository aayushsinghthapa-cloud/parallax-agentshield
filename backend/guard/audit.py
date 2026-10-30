"""Append-only audit log, one JSON line per guard decision, SHA-256 hash-chained.

Each entry stores the previous entry's hash, and its own hash covers everything else,
so editing or deleting any past line breaks verification from that point on.
Vault values are masked before anything is written.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from backend.guard.context import SessionContext
from backend.guard.policy import Decision, ToolCall
from backend.tools.registry import DATA_DIR

AUDIT_PATH = Path(__file__).resolve().parent.parent / "audit" / "audit.jsonl"
GENESIS = "0" * 64


def _hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def _all_secrets() -> dict:
    """Every vault value (redact even ones this session never read: shield-off runs can leak them)."""
    try:
        return {k: v["value"] for k, v in json.loads((DATA_DIR / "vault.json").read_text()).items()}
    except Exception:
        return {}


def redact(value, secrets: dict):
    if isinstance(value, str):
        for k, s in secrets.items():
            if s:
                value = value.replace(s, f"[REDACTED:{k}]")
        return value
    if isinstance(value, dict):
        return {k: redact(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secrets) for v in value]
    return value


class AuditLog:
    def __init__(self, path: Path | str = AUDIT_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._secrets = _all_secrets()
        entries = self.read()
        self._prev = entries[-1]["hash"] if entries else GENESIS

    def append(self, *, decision: Decision, call: ToolCall, ctx: SessionContext, session_id: str,
               shield_mode: str = "on", approver: str | None = None) -> dict:
        secrets = {**self._secrets, **ctx.vault_values}
        entry = {
            "ts": round(time.time(), 3),
            "session_id": session_id,
            "contract_id": ctx.contract.contract_id,
            "shield_mode": shield_mode,
            "decision_id": decision.decision_id,
            "tool": decision.tool,
            "args_redacted": redact(call.args if isinstance(call.args, dict) else str(call.args), secrets),
            "arg_provenance": decision.arg_provenance,
            "rule_id": decision.rule_id,
            # Shield OFF runs the guard in shadow mode: the call executes, the verdict is "would_have".
            "verdict": decision.verdict if shield_mode == "on" else "EXECUTED",
            "would_have": decision.verdict if shield_mode != "on" else None,
            "reason_plain": redact(decision.reason_plain, secrets),
            "source_ref": decision.source_ref,
            "approver": approver,
            "latency_ms": decision.latency_ms,
            "policy_version": decision.policy_version,
            "prev_hash": self._prev,
        }
        entry["hash"] = _hash(entry)
        with open(self.path, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._prev = entry["hash"]
        return entry

    def record_approval(self, decision_id: str, choice: str, approver: str = "user") -> dict:
        """Approvals are their own chained entries, so who said yes is tamper-evident too."""
        entry = {"ts": round(time.time(), 3), "event": "approval", "decision_id": decision_id,
                 "choice": choice, "approver": approver, "prev_hash": self._prev}
        entry["hash"] = _hash(entry)
        with open(self.path, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._prev = entry["hash"]
        return entry

    def read(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]

    def recent(self, n: int = 50) -> list[dict]:
        return self.read()[-n:]

    def verify(self) -> dict:
        prev = GENESIS
        try:
            entries = self.read()
        except json.JSONDecodeError as e:
            return {"ok": False, "entries": None, "broken_at": None, "error": f"unparseable line: {e}"}
        for i, e in enumerate(entries):
            if e.get("prev_hash") != prev or _hash(e) != e.get("hash"):
                return {"ok": False, "entries": len(entries), "broken_at": i}
            prev = e["hash"]
        return {"ok": True, "entries": len(entries), "broken_at": None}
