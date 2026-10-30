"""FastAPI app. Each run streams its events over Server-Sent Events.

  uvicorn backend.server:app --port 8000      (from the repo root)

The agent runs in a worker thread and pushes events onto a queue that the SSE response
drains. An approval pauses that thread until POST /api/approve answers it, or until
APPROVAL_TIMEOUT_S passes, which counts as "deny" (fail closed).
"""
from __future__ import annotations

import json
import os
import queue
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from backend.agent import runner
from backend.agent.provider import configured_providers, key_status
from backend.agent.replay import is_scripted
from backend.guard.audit import AuditLog
from backend.guard.contract import compile_contract, load_workspace
from backend.scenarios import SCENARIOS

APPROVAL_TIMEOUT_S = 120
REPLAY_DELAY_S = float(os.getenv("REPLAY_DELAY_S", "0.8"))  # pace replayed steps so the UI can be followed

app = FastAPI(title="LEASH")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_methods=["*"], allow_headers=["*"])

audit = AuditLog()
_approvals: dict[str, dict] = {}  # decision_id -> {"event": Event, "choice": str | None}
_mailbox: list[dict] = []  # every outbox event this server has seen (UI: outbox + attacker's inbox)
_lock = threading.Lock()


class ApproveBody(BaseModel):
    decision_id: str
    choice: str  # "approve" | "deny"


@app.get("/api/config")
def config():
    return {
        "planner_mode": runner.planner_mode(),
        "llm_mode": runner.llm_mode(),
        "providers": [p.label for p in configured_providers()],
        "keys": key_status(),
        "scenarios": [{"id": k, **v} for k, v in SCENARIOS.items()],
        "approval_timeout_s": APPROVAL_TIMEOUT_S,
    }


@app.get("/api/contract")
def contract(message: str):
    """Preview the contract a message would compile to (no LLM, no tools)."""
    c = compile_contract(message, load_workspace())
    return {"contract": c.to_dict(), "pills": c.pills()}


@app.get("/api/run/stream")
def run_stream(scenario: str | None = None, message: str | None = None, payload: str | None = None,
               shield: str = Query("on", pattern="^(on|off)$"), llm: str | None = Query(None, pattern="^(live|replay)$")):
    sid, msg, extra = runner.resolve(scenario, message, payload)
    if not msg:
        raise HTTPException(400, "give a scenario, a message or a payload")
    run_id = "r-" + uuid.uuid4().hex[:10]
    q: queue.Queue = queue.Queue()

    def emit(ev: str, data: dict) -> None:
        if ev == "outbox":
            with _lock:
                _mailbox.append({**data, "shield": shield, "scenario": sid})
        q.put((ev, data))

    def approve(decision: dict, call) -> str:
        slot = {"event": threading.Event(), "choice": None}
        with _lock:
            _approvals[decision["decision_id"]] = slot
        answered = slot["event"].wait(APPROVAL_TIMEOUT_S)
        with _lock:
            _approvals.pop(decision["decision_id"], None)
        return slot["choice"] if answered and slot["choice"] == "approve" else "deny"

    def work() -> None:
        try:
            result, _, _ = runner.run(sid, msg, extra, shield, emit=emit, approve=approve, audit=audit,
                                      session_id="ui", run_id=run_id, llm=llm, replay_delay_s=REPLAY_DELAY_S)
            q.put(("done", {"run_id": run_id, "scenario": sid, "shield": shield, "llm_source": result["llm_source"],
                            "calls": result["calls"], "error": result["error"]}))
        except Exception as e:  # never leave the browser hanging
            q.put(("error", {"run_id": run_id, "message": runner_error_text(), "detail": f"{type(e).__name__}: {e}"}))
            q.put(("done", {"run_id": run_id, "scenario": sid, "shield": shield, "error": "exception"}))

    threading.Thread(target=work, daemon=True).start()

    def stream():
        yield _sse("start", {"run_id": run_id, "scenario": sid, "message": msg, "shield": shield,
                             "planner_mode": runner.planner_mode(), "llm_mode": llm or runner.llm_mode(),
                             "scripted": (llm or runner.llm_mode()) == "replay" and is_scripted(sid, shield)})
        while True:
            try:
                ev, data = q.get(timeout=15)
            except queue.Empty:
                yield ": keep-alive\n\n"
                continue
            yield _sse(ev, data)
            if ev == "done":
                return

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def runner_error_text() -> str:
    return "Something went wrong in the assistant. Nothing was sent."


def _sse(ev: str, data: dict) -> str:
    return f"event: {ev}\ndata: {json.dumps(data, ensure_ascii=False, default=str)}\n\n"


@app.post("/api/approve")
def approve(body: ApproveBody):
    with _lock:
        slot = _approvals.get(body.decision_id)
    if not slot:
        raise HTTPException(404, "no pending approval with that id (it may have timed out)")
    slot["choice"] = "approve" if body.choice == "approve" else "deny"
    slot["event"].set()
    return {"ok": True, "choice": slot["choice"]}


@app.get("/api/results")
def results():
    """Evidence from backend/scripts/eval.py (docs/results.json)."""
    p = Path(__file__).resolve().parent.parent / "docs" / "results.json"
    if not p.exists():
        raise HTTPException(404, "run backend/scripts/eval.py first")
    return json.loads(p.read_text())


@app.get("/api/audit")
def audit_recent(n: int = 100):
    return {"entries": audit.recent(n)}


@app.get("/api/audit/verify")
def audit_verify():
    return audit.verify()


@app.get("/api/outbox")
def outbox():
    with _lock:
        return {"mail": list(_mailbox)}


@app.post("/api/reset")
def reset():
    with _lock:
        _mailbox.clear()
    return {"ok": True}
