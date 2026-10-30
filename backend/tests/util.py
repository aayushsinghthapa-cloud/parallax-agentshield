"""Shared helpers: build a real session (real data, real World) and drive the guard like the loop does."""
from __future__ import annotations

from backend.guard.context import SessionContext
from backend.guard.contract import compile_contract, load_workspace
from backend.guard.policy import Decision, ToolCall, guard
from backend.tools.registry import World

WS = load_workspace()


def session(message: str, reads: list[tuple[str, dict]] = (), world: World | None = None) -> SessionContext:
    """Compile the contract from `message`, then run `reads` for real (bypassing the guard) to set
    up taint / vault / confidential state, exactly as if those calls had already been allowed."""
    world = world or World()
    ctx = SessionContext(compile_contract(message, WS), WS)
    for tool, args in reads:
        ctx.observe(tool, args, world.execute(tool, args))
    return ctx


def call(tool: str, **args) -> ToolCall:
    return ToolCall(tool, args)


def run_steps(message: str, steps: list[ToolCall]) -> list[Decision]:
    """Mimic the agent loop: guard each call, execute only if ALLOW, feed the result back."""
    world = World()
    ctx = SessionContext(compile_contract(message, WS), WS)
    out = []
    for c in steps:
        d = guard(c, ctx)
        out.append(d)
        if d.verdict == "ALLOW":
            ctx.observe(c.tool, c.args, world.execute(c.tool, c.args))
    return out
