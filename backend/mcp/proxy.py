"""leash-mcp: a stdio MCP proxy that puts the LEASH guard in front of any MCP server's tools/call.

    leash-mcp --task "Reply to Priya confirming the meeting time" --upstream "python -m backend.mcp.fake_server"

MCP clients (desktop assistants, IDEs, ...) talk to this process exactly as they would to the upstream
server. Every message is forwarded unchanged, except:

- tools/call: guard(call, ctx) decides first. DENY and REQUIRE_APPROVAL (there's no approval UI here,
  so it fails closed) go back to the client as a tool error; the upstream never sees the call.
- tool results: passed through, and fed to ctx.observe() so untrusted output taints the session.

MCP has no "user turn", so the task contract comes from --task (the user's request). Upstream tool
names must exist in LEASH's registry and policies; anything else is denied (FAILSAFE).
Every decision is written to the same hash-chained audit log as the web app.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import threading
import uuid
from pathlib import Path

from backend.guard.audit import AUDIT_PATH, AuditLog
from backend.guard.context import SessionContext
from backend.guard.contract import compile_contract, load_workspace
from backend.guard.policy import ToolCall, guard

PENDING_TIMEOUT_S = 30


class Proxy:
    def __init__(self, upstream: list[str], task: str, audit_path: Path, out=sys.stdout):
        ws = load_workspace()
        self.ctx = SessionContext(compile_contract(task, ws), ws)
        self.audit = AuditLog(audit_path)
        self.session_id = "mcp-" + uuid.uuid4().hex[:8]
        self.out = out
        self.lock = threading.Lock()
        self.pending: dict = {}  # request id -> (tool, args) for calls forwarded upstream
        self.drained = threading.Condition()
        self.proc = subprocess.Popen(upstream, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        threading.Thread(target=self._pump_upstream, daemon=True).start()

    def _send_client(self, msg: dict) -> None:
        with self.lock:
            self.out.write(json.dumps(msg) + "\n")
            self.out.flush()

    def _send_upstream(self, line: str) -> None:
        self.proc.stdin.write(line if line.endswith("\n") else line + "\n")
        self.proc.stdin.flush()

    def _pump_upstream(self) -> None:
        for line in self.proc.stdout:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue  # never forward garbage
            with self.drained:
                pending = self.pending.pop(msg.get("id"), None)
                if pending:
                    tool, args = pending
                    result = msg.get("result") or {}
                    text = "\n".join(c.get("text", "") for c in result.get("content", []) if isinstance(c, dict))
                    self.ctx.observe(tool, args, text)  # errors still count: the output was untrusted
                self.drained.notify_all()
            self._send_client(msg)

    def handle_client_line(self, line: str) -> None:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            return
        if msg.get("method") != "tools/call":
            self._send_upstream(line)
            return
        # A client may pipeline calls. Never decide while an earlier result (which may taint the
        # session) is still in flight; if it never arrives, assume taint (fail closed).
        with self.drained:
            if not self.drained.wait_for(lambda: not self.pending, timeout=PENDING_TIMEOUT_S):
                self.ctx.tainted = True
        params = msg.get("params") or {}
        call = ToolCall(params.get("name"), params.get("arguments", {}), str(msg.get("id")))
        d = guard(call, self.ctx)
        self.audit.append(decision=d, call=call, ctx=self.ctx, session_id=self.session_id, shield_mode="on")
        if d.verdict == "ALLOW":
            with self.drained:
                self.pending[msg.get("id")] = (call.tool, call.args)
            self._send_upstream(line)
            return
        why = d.reason_plain if d.verdict == "DENY" else d.reason_plain + " (No approval UI over MCP, so it was refused.)"
        self._send_client({"jsonrpc": "2.0", "id": msg.get("id"), "result": {
            "content": [{"type": "text", "text": f"[LEASH] Action denied: {why} Nothing was sent."}],
            "isError": True,
            "_meta": {"leash": {"verdict": d.verdict, "rule_id": d.rule_id, "decision_id": d.decision_id}},
        }})

    def run(self, inp=sys.stdin) -> None:
        for line in inp:
            if line.strip():
                self.handle_client_line(line)
        with self.drained:  # let in-flight results reach the client before shutting down
            self.drained.wait_for(lambda: not self.pending, timeout=PENDING_TIMEOUT_S)
        self.proc.stdin.close()
        self.proc.wait(timeout=5)


def main() -> None:
    ap = argparse.ArgumentParser(prog="leash-mcp")
    ap.add_argument("--upstream", required=True, help='upstream MCP server command, e.g. "python -m backend.mcp.fake_server"')
    ap.add_argument("--task", default=os.getenv("LEASH_TASK", ""), help="the user's request; the task contract is compiled from it")
    ap.add_argument("--audit", default=os.getenv("LEASH_AUDIT", str(AUDIT_PATH)))
    args = ap.parse_args()
    Proxy(shlex.split(args.upstream), args.task, Path(args.audit)).run()


if __name__ == "__main__":
    main()
