"""Hand-rolled agent loop: LLM proposes tool calls, we execute, feed results back.

Phase 0 runs this with NO guard to measure how often models follow injections.
Phase 2 adds the guard between "proposed" and "executed".
"""
from __future__ import annotations

import json

from backend.agent.prompts import system_prompt
from backend.agent.provider import Provider
from backend.tools.registry import SCHEMAS, TOOL_NAMES, World

MAX_STEPS = 4  # free-tier budget: at most 4 LLM requests per run
MAX_TOOL_CHARS = 600  # truncate tool output so each request stays under ~2.5K tokens


def _truncate(s: str) -> str:
    return s if len(s) <= MAX_TOOL_CHARS else s[:MAX_TOOL_CHARS] + " …[truncated]"


def run_agent(user_message: str, world: World, provider: Provider, planner_mode: str = "standard") -> dict:
    messages: list[dict] = [
        {"role": "system", "content": system_prompt(planner_mode)},
        {"role": "user", "content": user_message},
    ]
    calls: list[dict] = []  # every proposed call, with whether its JSON was valid
    for _step in range(MAX_STEPS):
        msg = provider.chat(messages, SCHEMAS)
        if not msg.tool_calls:
            return {"final": msg.content or "", "calls": calls, "steps": _step + 1}
        messages.append({
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": [
                {"id": tc.id, "type": "function", "function": {"name": tc.function.name, "arguments": tc.function.arguments or "{}"}}
                for tc in msg.tool_calls
            ],
        })
        for tc in msg.tool_calls:
            name = tc.function.name
            try:
                args = json.loads(tc.function.arguments or "{}")
                valid = isinstance(args, dict) and name in TOOL_NAMES
            except json.JSONDecodeError:
                args, valid = {}, False
            result = world.execute(name, args) if valid else "Error: invalid tool call"
            calls.append({"tool": name, "args": args, "valid": valid})
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": _truncate(result)})
    return {"final": "Stopped after 4 steps.", "calls": calls, "steps": MAX_STEPS}
