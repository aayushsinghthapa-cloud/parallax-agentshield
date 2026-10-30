"""One run = one scenario (or free text / live payload) through the agent. Shared by the CLI and the API."""
from __future__ import annotations

import os
from pathlib import Path

from backend.agent.loop import run_agent
from backend.agent.provider import configured_providers
from backend.agent.replay import Planner
from backend.guard.audit import AuditLog
from backend.scenarios import LIVE_MESSAGE, LIVE_SENDER, SCENARIOS
from backend.tools.registry import World

OUTBOX_PATH = Path(__file__).resolve().parent.parent / "outbox.jsonl"


def planner_mode() -> str:
    return os.getenv("PLANNER_MODE", "standard")


def llm_mode() -> str:
    return os.getenv("LLM_MODE", "live")


def resolve(scenario: str | None, message: str | None = None, payload: str | None = None) -> tuple[str, str, list[dict]]:
    """-> (scenario_id, user message, extra inbox emails)."""
    if payload is not None:
        email = {"id": 8, "from": LIVE_SENDER, "date": "2026-10-31 11:00", "subject": "New message", "body": payload[:2000]}
        return "LIVE", LIVE_MESSAGE, [email]
    if scenario in SCENARIOS:
        return scenario, SCENARIOS[scenario]["message"], []
    return "custom", (message or "").strip(), []


def run(scenario_id: str, message: str, extra_emails: list[dict], shield: str, *, emit=None, approve=None,
        audit: AuditLog | None = None, session_id: str = "cli", run_id: str | None = None,
        mode: str | None = None, llm: str | None = None, replay_delay_s: float = 0.0) -> tuple[dict, Planner, World]:
    llm = llm or llm_mode()
    # Free text and live payloads can't be replayed (nothing was recorded for them), so they go live.
    planner = Planner(configured_providers(), llm, scenario_id, shield, replay_delay_s)
    world = World(extra_emails=extra_emails, outbox_path=OUTBOX_PATH)
    result = run_agent(message, world, planner, mode or planner_mode(), shield=shield, emit=emit,
                       approve=approve, audit=audit, session_id=session_id, run_id=run_id)
    result["llm_mode"] = llm
    result["llm_source"] = planner.last_source
    return result, planner, world
