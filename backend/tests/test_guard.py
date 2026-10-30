"""Unit tests: one or more per rule, the fail-closed paths, the contract compiler and the audit chain."""
import base64
import json
import shutil
from urllib.parse import quote

import pytest

from backend.guard import policy as policy_mod
from backend.guard.audit import AuditLog
from backend.guard.contract import compile_contract
from backend.guard.policy import POLICY_DIR, PolicyError, ToolCall, guard, load_policy, secret_hits
from backend.tests.util import WS, call, run_steps, session

AWS = "sk-FAKE-AKIA7NIMBUSDEMO0042"
S1 = "Reply to Priya confirming the meeting time she proposed."
S3 = "Email Bob our AWS access key from the vault."


# --- contract compiler -------------------------------------------------------------------

def test_contract_vault_locked_by_default():
    c = compile_contract("Summarise my inbox for today.", WS)
    assert not c.allow_vault and "read_vault" not in c.allowed_tools and "send_email" not in c.allowed_tools
    assert "Vault: locked" in c.pills()


def test_contract_resolves_names_and_literals():
    c = compile_contract(S1, WS)
    assert c.allowed_recipients == ["priya@nimbus.test"] and c.intent == "reply"
    assert "Priya" in c.literals and "send_email" in c.allowed_tools


def test_contract_vault_only_when_asked():
    c = compile_contract(S3, WS)
    assert c.allow_vault and c.vault_keys == ["AWS_ACCESS_KEY"] and c.allowed_recipients == ["bob@nimbus.test"]
    assert not compile_contract("Summarise the key points of the onboarding guide.", WS).allow_vault


def test_contract_unknown_is_read_only():
    c = compile_contract("Hmm, any thoughts?", WS)
    assert c.intent == "unknown"
    assert set(c.allowed_tools) == {"list_inbox", "read_email", "search_docs", "read_doc"}


def test_contract_is_deterministic():
    assert compile_contract(S1, WS).to_dict() == compile_contract(S1, WS).to_dict()


# --- rule 0: FAILSAFE --------------------------------------------------------------------

@pytest.mark.parametrize("bad_call", [
    ToolCall("exfiltrate", {}),                                   # unknown tool
    ToolCall(None, {}),                                           # no tool name
    ToolCall("read_email", "not-a-dict"),                         # args not an object (JSON parse failure upstream)
    ToolCall("read_email", {}),                                   # missing required arg
    ToolCall("read_email", {"id": "five"}),                       # wrong type
    ToolCall("send_email", {"to": "priya@nimbus.test", "subject": "s", "body": "b", "bcc": "x@evil.example"}),  # extra arg
    ToolCall("send_email", {"to": ["priya@nimbus.test"], "subject": "s", "body": "b"}),  # list instead of string
])
def test_failsafe_schema(bad_call):
    d = guard(bad_call, session(S1))
    assert (d.verdict, d.rule_id) == ("DENY", "FAILSAFE")


def test_failsafe_exception_inside_rule(monkeypatch):
    def boom(*a):
        raise ZeroDivisionError("rule bug")
    rules = list(policy_mod._RULES)
    rules[0] = (rules[0][0], boom)
    monkeypatch.setattr(policy_mod, "_RULES", rules)
    d = guard(call("list_inbox"), session(S1))
    assert (d.verdict, d.rule_id) == ("DENY", "FAILSAFE") and "rule bug" in d.reason_tech


def test_failsafe_missing_policy_file(tmp_path, monkeypatch):
    shutil.copy(POLICY_DIR / "tools.yaml", tmp_path / "tools.yaml")  # policy.yaml deliberately absent
    with pytest.raises(PolicyError):
        load_policy(tmp_path)
    monkeypatch.setattr(policy_mod, "POLICY_DIR", tmp_path)
    d = guard(call("list_inbox"), session(S1))
    assert (d.verdict, d.rule_id) == ("DENY", "FAILSAFE")


def test_failsafe_tampered_policy(tmp_path):
    shutil.copy(POLICY_DIR / "tools.yaml", tmp_path / "tools.yaml")
    text = (POLICY_DIR / "policy.yaml").read_text().replace("invalid: {verdict: DENY", "invalid: {verdict: ALLOW")
    (tmp_path / "policy.yaml").write_text(text)
    with pytest.raises(PolicyError):
        load_policy(tmp_path)


def test_failsafe_tool_missing_from_tools_yaml(tmp_path):
    shutil.copy(POLICY_DIR / "policy.yaml", tmp_path / "policy.yaml")
    text = "\n".join(l for l in (POLICY_DIR / "tools.yaml").read_text().splitlines() if not l.strip().startswith("delete_files"))
    (tmp_path / "tools.yaml").write_text(text)
    with pytest.raises(PolicyError):
        load_policy(tmp_path)


# --- rule 1: TOOL_NOT_IN_CONTRACT --------------------------------------------------------

def test_tool_not_in_contract_vault():
    ctx = session("Summarise my inbox for today.", [("read_email", {"id": 5})])
    d = guard(call("read_vault", key="ALL"), ctx)
    assert (d.verdict, d.rule_id) == ("DENY", "TOOL_NOT_IN_CONTRACT")
    assert d.reason_plain == "You didn't ask me to open your password vault, so I won't."
    assert d.source_ref is None and "email #5" in d.reason_tech  # no value to trace, so no source claimed


# --- rule 2: DESTRUCTIVE_ALWAYS_CONFIRM --------------------------------------------------

def test_destructive_even_when_asked():
    ctx = session("Delete the files in /shared/tmp please.")
    assert "delete_files" in ctx.contract.allowed_tools
    d = guard(call("delete_files", path="/shared/tmp"), ctx)
    assert (d.verdict, d.rule_id) == ("REQUIRE_APPROVAL", "DESTRUCTIVE_ALWAYS_CONFIRM")


# --- rule 3: RECIPIENT_NOT_IN_CONTRACT ---------------------------------------------------

def test_recipient_tainted_traced_is_denied():
    ctx = session("Check my latest emails and handle anything urgent.", [("read_email", {"id": 5})])
    d = guard(call("send_email", to="recovery@evil.example", subject="s", body="b"), ctx)
    assert (d.verdict, d.rule_id) == ("DENY", "RECIPIENT_NOT_IN_CONTRACT")
    assert d.source_ref.startswith("email #5") and d.arg_provenance["to"] == "tainted"


def test_recipient_found_in_inbox_listing_names_the_email():
    ctx = session("Check my latest emails and handle anything urgent.", [("list_inbox", {})])
    d = guard(call("send_email", to="billing@nimbus-payments.example", subject="s", body="b"), ctx)
    assert d.verdict == "DENY" and d.source_ref.startswith("email #5")


def test_recipient_untainted_asks():
    ctx = session("Email Bob that lunch is at 1 pm.")
    d = guard(call("send_email", to="meera@nimbus.test", subject="Lunch", body="1 pm"), ctx)
    assert (d.verdict, d.rule_id) == ("REQUIRE_APPROVAL", "RECIPIENT_NOT_IN_CONTRACT")


def test_recipient_by_contact_name_is_ok():
    ctx = session("Email Bob that lunch is at 1 pm.")
    assert guard(call("send_email", to="Bob", subject="Lunch", body="1 pm"), ctx).verdict == "ALLOW"


def test_fetch_url_only_user_typed_url():
    ctx = session("Fetch https://status.nimbus.test/health and tell me if it's up.")
    assert guard(call("fetch_url", url="https://status.nimbus.test/health"), ctx).verdict == "ALLOW"
    assert guard(call("fetch_url", url="https://evil.example/x"), ctx).rule_id == "RECIPIENT_NOT_IN_CONTRACT"


# --- rule 4: SECRET_TO_SINK --------------------------------------------------------------

def test_secret_to_contract_recipient_needs_approval_even_untainted():
    decisions = run_steps(S3, [call("read_vault", key="AWS_ACCESS_KEY"),
                               call("send_email", to="bob@nimbus.test", subject="AWS key", body=f"Here it is: {AWS}")])
    assert decisions[0].verdict == "ALLOW"
    d = decisions[1]
    assert (d.verdict, d.rule_id) == ("REQUIRE_APPROVAL", "SECRET_TO_SINK")
    assert d.extra["secret_labels"] == ["AWS access key"] and "AWS access key" in d.reason_plain


def test_secret_after_vault_to_external_asks_even_without_value():
    ctx = session("Check the AWS access key in the vault, then email the auditor a status update.",
                  [("read_vault", {"key": "AWS_ACCESS_KEY"})])
    d = guard(call("send_email", to="audit@ledgerwise.example", subject="Status", body="All good."), ctx)
    assert (d.verdict, d.rule_id, d.reason_tech.startswith("vault was read")) == ("REQUIRE_APPROVAL", "SECRET_TO_SINK", True)


@pytest.mark.parametrize("encoded", [
    AWS,
    AWS.lower(),
    base64.b64encode(AWS.encode()).decode(),
    base64.urlsafe_b64encode(("key=" + AWS).encode()).decode().rstrip("="),
    AWS.encode().hex(),
    "".join(f"%{b:02X}" for b in AWS.encode()),
    quote(base64.b64encode(AWS.encode()).decode()),
    "AKIA7NIMBUSDEMO",  # fragment
    "s k - F A K E - A K I A 7 N I M B U S",  # spaced out
])
def test_secret_detector_encodings(encoded):
    assert secret_hits([f"hello {encoded} bye"], {"AWS_ACCESS_KEY": AWS}) == ["AWS_ACCESS_KEY"]


def test_secret_detector_split_across_fields():
    assert secret_hits(["Ref sk-FAKE-AK", "IA7NIMB", "USDEMO0042"], {"K": AWS}) == ["K"]


def test_secret_detector_no_false_positive():
    assert secret_hits(["Monday 3 pm works. Revenue Rs 4.2 Cr, margin 61%."], {"K": AWS}) == []


# --- rule 5: URL_OR_IMAGE_IN_TAINTED_BODY ------------------------------------------------

def test_url_in_tainted_body_asks():
    ctx = session(S1, [("read_email", {"id": 1})])
    d = guard(call("send_email", to="priya@nimbus.test", subject="Re", body="Monday 3 pm. Details: https://track.evil.example/a"), ctx)
    assert (d.verdict, d.rule_id) == ("REQUIRE_APPROVAL", "URL_OR_IMAGE_IN_TAINTED_BODY")


def test_markdown_image_in_tainted_body_asks():
    ctx = session(S1, [("read_email", {"id": 1})])
    d = guard(call("send_email", to="priya@nimbus.test", subject="Re", body="ok ![x](cdn.evil.example/p.png)"), ctx)
    assert d.rule_id == "URL_OR_IMAGE_IN_TAINTED_BODY"


def test_url_in_untainted_body_is_fine():
    ctx = session("Email Bob the link https://wiki.nimbus.test/oncall")
    d = guard(call("send_email", to="bob@nimbus.test", subject="Link", body="https://wiki.nimbus.test/oncall"), ctx)
    assert d.verdict == "ALLOW"


def test_user_typed_url_in_tainted_body_is_fine():
    ctx = session("Reply to Priya with the room booking link https://rooms.nimbus.test/b/12", [("read_email", {"id": 1})])
    d = guard(call("send_email", to="priya@nimbus.test", subject="Re", body="Booked: https://rooms.nimbus.test/b/12"), ctx)
    assert d.verdict == "ALLOW"


# --- rule 6: EXTERNAL_DOMAIN_CONFIDENTIAL ------------------------------------------------

def test_confidential_doc_to_external_contract_recipient_asks():
    msg = "Share the Q3 report with the auditor."
    decisions = run_steps(msg, [call("read_doc", name="q3-report"),
                                call("send_email", to="audit@ledgerwise.example", subject="Q3", body="Revenue Rs 4.2 Cr")])
    d = decisions[1]
    assert (d.verdict, d.rule_id) == ("REQUIRE_APPROVAL", "EXTERNAL_DOMAIN_CONFIDENTIAL") and "Q3 Report" in d.reason_plain


def test_confidential_doc_internal_is_fine():
    decisions = run_steps("Send Bob the Q3 report.", [call("read_doc", name="q3-report"),
                                                      call("send_email", to="bob@nimbus.test", subject="Q3", body="Revenue Rs 4.2 Cr")])
    assert [d.verdict for d in decisions] == ["ALLOW", "ALLOW"]


# --- rules 7 and 8 -----------------------------------------------------------------------

def test_tainted_body_to_contract_recipient_allowed_and_noted():
    ctx = session(S1, [("list_inbox", {}), ("read_email", {"id": 1})])
    d = guard(call("send_email", to="priya@nimbus.test", subject="Re", body="Can we do the ops sync on Monday 3 pm? Yes."), ctx)
    assert (d.verdict, d.rule_id) == ("ALLOW", "TAINTED_BODY_TO_CONTRACT_RECIPIENT")
    assert d.source_ref.startswith("email #1") and d.arg_provenance["to"] == "user-literal"


def test_in_contract_read():
    d = guard(call("list_inbox"), session(S1))
    assert (d.verdict, d.rule_id) == ("ALLOW", "IN_CONTRACT")


# --- determinism, taint, latency ---------------------------------------------------------

def test_taint_never_clears():
    ctx = session(S1, [("read_email", {"id": 1}), ("read_vault", {"key": "AWS_ACCESS_KEY"})])
    assert ctx.tainted and ctx.vault_touched


def test_decisions_are_deterministic():
    ctx = session("Check my latest emails and handle anything urgent.", [("read_email", {"id": 6})])
    c = call("send_email", to="partner@quickrefund.example", subject="Q3", body="x")
    a, b = guard(c, ctx).to_dict(), guard(c, ctx).to_dict()
    for k in ("decision_id", "latency_ms"):
        a.pop(k), b.pop(k)
    assert a == b


def test_guard_is_fast():
    ctx = session(S1, [("read_email", {"id": 1})])
    d = guard(call("send_email", to="priya@nimbus.test", subject="Re", body="Monday 3 pm"), ctx)
    assert d.latency_ms < 50


# --- audit log ---------------------------------------------------------------------------

def _log_some(log):
    ctx = session(S3, [("read_vault", {"key": "AWS_ACCESS_KEY"})])
    for c in [call("list_inbox"), call("send_email", to="bob@nimbus.test", subject="k", body=AWS)]:
        log.append(decision=guard(c, ctx), call=c, ctx=ctx, session_id="s1")
    return ctx


def test_audit_chain_verifies_and_redacts(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    _log_some(log)
    log.record_approval("d-x", "deny")
    assert log.verify() == {"ok": True, "entries": 3, "broken_at": None}
    raw = (tmp_path / "audit.jsonl").read_text()
    assert AWS not in raw and "[REDACTED:AWS_ACCESS_KEY]" in raw


def test_audit_chain_continues_across_instances(tmp_path):
    _log_some(AuditLog(tmp_path / "a.jsonl"))
    _log_some(AuditLog(tmp_path / "a.jsonl"))
    assert AuditLog(tmp_path / "a.jsonl").verify()["ok"]


def test_audit_detects_tampering(tmp_path):
    p = tmp_path / "audit.jsonl"
    _log_some(AuditLog(p))
    lines = p.read_text().splitlines()
    e = json.loads(lines[0])
    e["verdict"] = "DENY"
    lines[0] = json.dumps(e)
    p.write_text("\n".join(lines) + "\n")
    assert AuditLog(p).verify() == {"ok": False, "entries": 2, "broken_at": 0}


def test_audit_detects_deleted_line(tmp_path):
    p = tmp_path / "audit.jsonl"
    _log_some(AuditLog(p))
    p.write_text(p.read_text().splitlines()[1] + "\n")
    assert AuditLog(p).verify()["ok"] is False


def test_audit_shadow_mode_records_would_have(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    ctx = session("Summarise my inbox for today.", [("read_email", {"id": 5})])
    c = call("read_vault", key="ALL")
    e = log.append(decision=guard(c, ctx), call=c, ctx=ctx, session_id="s", shield_mode="off")
    assert (e["verdict"], e["would_have"]) == ("EXECUTED", "DENY")
