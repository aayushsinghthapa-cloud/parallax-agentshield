"""Record/replay of LLM responses, so the demo runs with no network and no rate limits.

LLM_MODE=live    call the providers (Groq, then Gemini on failure)
LLM_MODE=record  call live and keep every response; save() writes replays/<scenario>_<shield>.json
LLM_MODE=replay  answer from the recording; providers are only used for runs nothing was recorded for

Only the LLM is replayed. The guard always runs live on replayed tool calls, so the
defence is never scripted.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from types import SimpleNamespace

from backend.agent.provider import Provider, ProviderUnavailable

REPLAY_DIR = Path(__file__).resolve().parent.parent / "replays"


def _normalize(messages: list[dict]) -> list:
    """Drop the parts that change between runs (tool-call ids, provider extras)."""
    out = []
    for m in messages:
        calls = [(c["function"]["name"], c["function"]["arguments"]) for c in m.get("tool_calls", [])]
        out.append([m["role"], m.get("content") or "", calls])
    return out


def replay_key(scenario_id: str, step: int, messages: list[dict]) -> str:
    blob = json.dumps([scenario_id, step, _normalize(messages)], sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _to_record(msg) -> dict:
    return {"content": msg.content or "",
            "tool_calls": [{"name": tc.function.name, "arguments": tc.function.arguments or "{}"} for tc in msg.tool_calls or []]}


def _to_message(rec: dict, step: int) -> SimpleNamespace:
    calls = [SimpleNamespace(id=f"call_{step}_{i}", function=SimpleNamespace(name=c["name"], arguments=c["arguments"]))
             for i, c in enumerate(rec["tool_calls"])]
    return SimpleNamespace(content=rec["content"], tool_calls=calls or None)


def replay_path(scenario_id: str, shield: str) -> Path:
    return REPLAY_DIR / f"{scenario_id}_{shield}.json"


def is_scripted(scenario_id: str, shield: str) -> bool:
    """True if this recording came from a hand-scripted LLM, not a real model (the UI labels it)."""
    p = replay_path(scenario_id, shield)
    try:
        return bool(json.loads(p.read_text()).get("scripted"))
    except (OSError, ValueError):
        return False


class Planner:
    """Same .chat(messages, tools) interface as Provider, with fallback and record/replay."""

    def __init__(self, providers: list[Provider], llm_mode: str = "live", scenario_id: str = "custom", shield: str = "on",
                 replay_delay_s: float = 0.0):
        self.providers = providers
        self.llm_mode = llm_mode
        self.scenario_id = scenario_id
        self.shield = shield
        self.step = 0
        self.records: list[dict] = []
        self.last_source = "live"  # "replay" or the provider label that answered
        self.replay_delay_s = replay_delay_s  # UI pacing only: a replayed "thinking" pause so the path animates
        self._recording = self._load() if llm_mode == "replay" else []

    @property
    def label(self) -> str:
        return "replay" if self.llm_mode == "replay" else ",".join(p.label for p in self.providers)

    def _load(self) -> list[dict]:
        p = replay_path(self.scenario_id, self.shield)
        return json.loads(p.read_text())["steps"] if p.exists() else []

    def chat(self, messages: list[dict], tools: list[dict] | None = None, max_tokens: int = 600):
        step, self.step = self.step, self.step + 1
        key = replay_key(self.scenario_id, step, messages)
        if self._recording:
            exact = next((r for r in self._recording if r["key"] == key), None)
            # Fallback: closest match by scenario and step (e.g. a policy wording change altered a denial text).
            rec = exact or next((r for r in self._recording if r["step"] == step), None)
            if rec:
                time.sleep(self.replay_delay_s)
                self.last_source = "replay" if exact else "replay~"
                return _to_message(rec["response"], step)
            if not self.providers:
                raise ProviderUnavailable(f"no recording for {self.scenario_id}/{self.shield} step {step}")
        errors = []
        for p in self.providers:
            try:
                msg = p.chat(messages, tools, max_tokens)
            except ProviderUnavailable as e:
                errors.append(str(e))
                continue
            self.last_source = p.label
            if self.llm_mode == "record":
                self.records.append({"key": key, "step": step, "provider": p.label, "response": _to_record(msg)})
            return msg
        raise ProviderUnavailable("; ".join(errors) or "no providers configured")

    def save(self, meta: dict | None = None) -> Path:
        REPLAY_DIR.mkdir(exist_ok=True)
        p = replay_path(self.scenario_id, self.shield)
        p.write_text(json.dumps({"scenario": self.scenario_id, "shield": self.shield, **(meta or {}),
                                 "steps": self.records}, indent=1, ensure_ascii=False))
        return p
