"""Per-session security state the guard decides from.

Taint is coarse on purpose: the first untrusted tool result taints the whole session and
it never untaints. Tracking taint per value fails because LLMs rewrite attacker values
into "fresh" arguments; after taint, only values that literally match the contract are clean.
Tool outputs are stored only so the guard can say WHERE a value came from (exact matching);
the guard never interprets them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from backend.guard.contract import TaskContract, Workspace, resolve_doc


@dataclass
class TaintSource:
    ref: str  # e.g. "email #5 from billing@nimbus-payments.example"
    kind: str  # email | inbox | doc | web
    tool: str
    text: str


@dataclass
class SessionContext:
    contract: TaskContract
    workspace: Workspace
    tainted: bool = False
    taint_sources: list[TaintSource] = field(default_factory=list)
    vault_touched: bool = False
    vault_values: dict = field(default_factory=dict)  # key -> secret string read this session
    confidential_read: list[str] = field(default_factory=list)  # doc names labelled confidential

    def observe(self, tool: str, args: dict, output: str) -> TaintSource | None:
        """Update state after a tool actually ran. Returns the new taint source, if any."""
        from backend.guard.policy import load_policy  # local import: policy imports this module

        try:
            meta = load_policy().tools.get(tool)
        except Exception:
            meta = None
        args = args if isinstance(args, dict) else {}

        if tool == "read_vault":
            self.vault_touched = True
            # Our own output format: one KEY=value per line.
            for line in str(output).splitlines():
                k, sep, v = line.partition("=")
                if sep and k.strip() in self.workspace.vault_labels:
                    self.vault_values[k.strip()] = v.strip()

        if tool == "read_doc":
            name = resolve_doc(args.get("name", ""), self.workspace)
            if name and self.workspace.docs[name]["label"] == "confidential" and name not in self.confidential_read:
                self.confidential_read.append(name)

        # Unknown tools are treated as untrusted (fail closed).
        if meta is None or meta.get("trust") != "trusted":
            src = TaintSource(ref=_ref(tool, args, output), kind=_kind(tool), tool=tool, text=str(output))
            self.tainted = True
            self.taint_sources.append(src)
            return src
        return None

    def find_source(self, value: str) -> TaintSource | None:
        """The most recent untrusted result that literally contains `value` (case-insensitive)."""
        v = str(value).strip().lower()
        if len(v) < 4:
            return None
        return next((s for s in reversed(self.taint_sources) if v in s.text.lower()), None)


def _kind(tool: str) -> str:
    return {"read_email": "email", "list_inbox": "inbox", "read_doc": "doc", "search_docs": "doc", "fetch_url": "web"}.get(tool, "tool")


def _ref(tool: str, args: dict, output: str) -> str:
    if tool == "read_email":
        # Line 2 of World's own formatting is "From: ..."; the attacker's body only starts after the header.
        m = re.search(r"^From:.*?([\w.+-]+@[\w.-]+)", str(output), re.M)
        return f"email #{args.get('id')}" + (f" from {m.group(1)}" if m else "")
    if tool == "read_doc":
        return f"document '{args.get('name')}'"
    if tool == "search_docs":
        return f"document search for '{args.get('query')}'"
    if tool == "list_inbox":
        return "your inbox list"
    if tool == "fetch_url":
        return f"web page {args.get('url')}"
    return f"output of {tool}"
