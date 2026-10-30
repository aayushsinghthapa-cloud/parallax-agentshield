"""Hand-rolled agent loop: LLM proposes tool calls, the guard decides, we execute, feed results back.

shield="on":   every proposed call goes through guard(); DENY is fed back as text, REQUIRE_APPROVAL
               pauses for the user (approve() callback, fail-closed on timeout).
shield="off":  shadow mode: the guard still decides and logs "would_have", but every call executes.
shield="none": no guard at all (Phase 0 spike).
"""
from __future__ import annotations

import json
import uuid
from urllib.parse import urlparse
from typing import Callable

from backend.agent.prompts import system_prompt
from backend.agent.provider import ProviderUnavailable, ToolCallFormatError
from backend.guard.audit import AuditLog, redact
from backend.guard.context import SessionContext
from backend.guard.contract import compile_contract, load_workspace
from backend.guard.policy import ToolCall, guard, recipients_of
from backend.tools.registry import SCHEMAS, TOOL_NAMES, World

# Free-tier budget. Models make one tool call per step, and a read -> act -> exfiltrate chain needs
# ~5, so 4 would stop attacks before the shield-off "before" picture. Each request stays under ~2.5K tokens.
MAX_STEPS = 6
MAX_TOOL_CHARS = 600  # truncate tool output so each request stays under ~2.5K tokens
UNAVAILABLE = "Assistant unavailable — nothing was sent"

Emit = Callable[[str, dict], None]
Approve = Callable[[dict, ToolCall], str]  # returns "approve" or "deny"


def _truncate(s: str) -> str:
    return s if len(s) <= MAX_TOOL_CHARS else s[:MAX_TOOL_CHARS] + " …[truncated]"


def _assistant_msg(msg) -> dict:
    """Echo the assistant turn back, keeping provider extras (Gemini needs its thought signatures)."""
    tcs = []
    for tc in msg.tool_calls:
        d = tc.model_dump(exclude_none=True) if hasattr(tc, "model_dump") else {}
        d.update({"id": tc.id, "type": "function",
                  "function": {"name": tc.function.name, "arguments": tc.function.arguments or "{}"}})
        tcs.append(d)
    return {"role": "assistant", "content": msg.content or "", "tool_calls": tcs}


def classify_recipient(addr: str, world: World) -> dict:
    """Where a sent email lands in the UI: internal, a known external contact, or the attacker's inbox."""
    a = addr.strip().lower()
    known = {c["email"].lower() for c in world.contacts["contacts"]}
    internal = a.endswith("@" + world.contacts["internal_domain"])
    return {"internal": internal, "attacker": not internal and a not in known}


def run_agent(user_message: str, world: World, provider, planner_mode: str = "standard", *,
              shield: str = "none", emit: Emit | None = None, approve: Approve | None = None,
              audit: AuditLog | None = None, session_id: str = "cli", run_id: str | None = None) -> dict:
    run_id = run_id or "r-" + uuid.uuid4().hex[:10]
    emit = emit or (lambda ev, data: None)
    secrets = {k: v["value"] for k, v in world.vault.items()}

    def send(ev: str, **data):
        emit(ev, {"run_id": run_id, **data})

    ws = load_workspace()
    ctx = SessionContext(compile_contract(user_message, ws), ws)  # contract BEFORE any tool runs
    if shield != "none":
        send("contract", contract=ctx.contract.to_dict(), pills=ctx.contract.pills(), shield=shield)

    messages: list[dict] = [
        {"role": "system", "content": system_prompt(planner_mode)},
        {"role": "user", "content": user_message},
    ]
    calls: list[dict] = []
    result = {"run_id": run_id, "contract": ctx.contract.to_dict(), "calls": calls, "error": None}

    for step in range(MAX_STEPS):
        send("llm_thinking", step=step + 1)
        try:
            msg = provider.chat(messages, SCHEMAS)
        except ToolCallFormatError:
            if shield == "none":
                raise  # the spike counts these itself
            msg = None
        except ProviderUnavailable as e:
            if shield == "none":
                raise
            text = UNAVAILABLE if not world.sent else "Assistant unavailable — stopped"
            send("error", message=text, detail=str(e))
            return {**result, "final": text, "error": "unavailable", "steps": step + 1, "sent": world.sent}
        if msg is None:
            text = "The assistant produced an invalid action, so I stopped. Nothing was sent." if not world.sent else "The assistant produced an invalid action, so I stopped."
            send("error", message=text, detail="tool_use_failed")
            return {**result, "final": text, "error": "tool_format", "steps": step + 1, "sent": world.sent}
        if not msg.tool_calls:
            final = msg.content or ""
            send("final", text=final)
            return {**result, "final": final, "steps": step + 1, "sent": world.sent}

        messages.append(_assistant_msg(msg))
        for tc in msg.tool_calls:
            name = tc.function.name
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = None  # guard fails closed on non-dict args
            valid = isinstance(args, dict) and name in TOOL_NAMES
            rec = {"tool": name, "args": args if isinstance(args, dict) else {}, "valid": valid,
                   "decision": None, "executed": False}
            calls.append(rec)
            content = _handle_call(tc.id, name, args, valid, rec, world, ctx, shield, send, approve, audit,
                                   session_id, secrets)
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": _truncate(content)})

    final = f"Stopped after {MAX_STEPS} steps."
    send("final", text=final)
    return {**result, "final": final, "steps": MAX_STEPS, "sent": world.sent}


def _handle_call(call_id, name, args, valid, rec, world, ctx, shield, send, approve, audit, session_id, secrets) -> str:
    call = ToolCall(name, args, call_id)
    send("tool_proposed", call_id=call_id, tool=name, args=redact(args, secrets) if isinstance(args, dict) else str(args))

    run_it = valid
    content = "Error: invalid tool call"
    if shield != "none":
        d = guard(call, ctx)
        rec["decision"] = d.to_dict()
        if audit:
            audit.append(decision=d, call=call, ctx=ctx, session_id=session_id, shield_mode=shield)
        send("decision", call_id=call_id, shield=shield, decision=redact(d.to_dict(), secrets),
             would_have=d.verdict if shield == "off" else None)
        if shield == "on":
            if d.verdict == "DENY":
                run_it = False
                content = f"[LEASH] Action denied: {d.reason_plain} Nothing was sent."
            elif d.verdict == "REQUIRE_APPROVAL":
                send("approval_required", call_id=call_id, decision=redact(d.to_dict(), secrets), tool=name,
                     args=redact(args, secrets), user_request=ctx.contract.user_request)
                choice = approve(d.to_dict(), call) if approve else "deny"
                choice = choice if choice in ("approve", "deny") else "deny"
                if audit:
                    audit.record_approval(d.decision_id, choice)
                send("approval_resolved", call_id=call_id, decision_id=d.decision_id, choice=choice)
                rec["approval"] = choice
                if choice != "approve":
                    run_it = False
                    content = "[LEASH] The user declined this action. Nothing was sent."

    if not run_it:
        send("tool_result", call_id=call_id, tool=name, executed=False, result=content)
        return content

    out = world.execute(name, args)
    rec["executed"] = True
    src = ctx.observe(name, args, out)
    if src:
        send("taint_set", source=redact(src.ref, secrets), kind=src.kind, tool=name)
    send("tool_result", call_id=call_id, tool=name, executed=True, result=_truncate(redact(out, secrets)))
    if name == "send_email" and world.sent:
        m = world.sent[-1]
        for addr in recipients_of(m["to"]):
            # Unredacted on purpose: with the shield off this IS the leak the demo shows.
            send("outbox", to=addr, subject=m["subject"], body=m["body"], **classify_recipient(addr, world))
    if name == "fetch_url":
        # A fetched URL is a sink too: whatever is in it reaches that server.
        host = urlparse(str(args.get("url", ""))).hostname or "?"
        internal = host == world.contacts["internal_domain"] or host.endswith("." + world.contacts["internal_domain"])
        send("outbox", to=host, subject="Web request (data rides in the URL)", body=str(args.get("url", "")),
             internal=internal, attacker=not internal)
    return out
