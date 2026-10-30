"""LEASH guard: a pure, deterministic policy enforcement point for every proposed tool call.

    guard(call, ctx) -> Decision   # ALLOW | DENY | REQUIRE_APPROVAL

It decides from three trusted inputs only: the task contract (compiled from the user's own
words), the session's taint state, and the sink/sensitivity rules below. Untrusted text is
never interpreted: tool outputs are used only for exact value matching, to say where a value
came from. There is NO LLM in this file, and there must never be one.

Fails closed: unknown tool, schema-invalid args, missing/corrupt policy, or any exception
inside a rule all produce DENY (rule FAILSAFE).

Rules are tried in a fixed order and the first match wins. Logic lives here; verdicts,
wording and thresholds live in policies/policy.yaml.
"""
from __future__ import annotations

import base64
import binascii
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote_plus

import yaml

from backend.guard.context import SessionContext, TaintSource
from backend.tools.registry import SCHEMAS

POLICY_DIR = Path(__file__).resolve().parent.parent / "policies"
VERDICTS = {"ALLOW", "DENY", "REQUIRE_APPROVAL"}
RULE_ORDER = [
    "FAILSAFE",
    "TOOL_NOT_IN_CONTRACT",
    "DESTRUCTIVE_ALWAYS_CONFIRM",
    "RECIPIENT_NOT_IN_CONTRACT",
    "SECRET_TO_SINK",
    "URL_OR_IMAGE_IN_TAINTED_BODY",
    "EXTERNAL_DOMAIN_CONFIDENTIAL",
    "TAINTED_BODY_TO_CONTRACT_RECIPIENT",
    "IN_CONTRACT",
]
_FAILSAFE_PLAIN = "I couldn't check this action safely, so I stopped it."
_SCHEMA = {s["function"]["name"]: s["function"]["parameters"] for s in SCHEMAS}


# --- data types --------------------------------------------------------------------------

@dataclass
class ToolCall:
    tool: str
    args: Any  # should be a dict; anything else fails closed
    call_id: str = ""


@dataclass
class Decision:
    verdict: str
    rule_id: str
    reason_plain: str
    reason_tech: str
    tool: str
    arg_provenance: dict = field(default_factory=dict)  # arg -> user-literal | tainted | trusted
    source_ref: str | None = None
    latency_ms: float = 0.0
    policy_version: str = "unknown"
    decision_id: str = field(default_factory=lambda: "d-" + uuid.uuid4().hex[:12])
    extra: dict = field(default_factory=dict)  # plain-language hints for the UI (labels, recipients)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Policy:
    version: str
    internal_domains: tuple[str, ...]
    tools: dict
    rules: dict  # rule_id -> {variant: {"verdict", "plain"}}
    min_fragment: int
    min_encoded_token: int


class PolicyError(Exception):
    pass


@dataclass
class _Hit:
    variant: str = "default"
    tech: str = ""
    fields: dict = field(default_factory=dict)
    source_ref: str | None = None
    extra: dict = field(default_factory=dict)


# --- policy loading ----------------------------------------------------------------------

@lru_cache(maxsize=8)
def _load(policy_dir: str) -> Policy:
    d = Path(policy_dir)
    try:
        tools = yaml.safe_load((d / "tools.yaml").read_text())["tools"]
        pol = yaml.safe_load((d / "policy.yaml").read_text())
    except Exception as e:
        raise PolicyError(f"cannot load policy from {d}: {e}") from e
    ids = [r.get("id") for r in pol.get("rules", [])]
    if ids != RULE_ORDER:
        raise PolicyError(f"policy rules must be exactly {RULE_ORDER}, got {ids}")
    rules = {r["id"]: r["variants"] for r in pol["rules"]}
    for rid, variants in rules.items():
        for v in variants.values():
            if v.get("verdict") not in VERDICTS or not v.get("plain"):
                raise PolicyError(f"bad verdict/wording in {rid}")
    if any(v["verdict"] != "DENY" for v in rules["FAILSAFE"].values()):
        raise PolicyError("FAILSAFE must always DENY")
    for name in _SCHEMA:
        if name not in tools:
            raise PolicyError(f"tool {name} has no entry in tools.yaml")
    sm = pol.get("secret_match", {})
    return Policy(
        version=str(pol["version"]),
        internal_domains=tuple(x.lower() for x in pol["internal_domains"]),
        tools=tools,
        rules=rules,
        min_fragment=int(sm.get("min_fragment", 10)),
        min_encoded_token=int(sm.get("min_encoded_token", 12)),
    )


def load_policy(policy_dir: Path | str | None = None) -> Policy:
    return _load(str(policy_dir or POLICY_DIR))


# --- the guard ---------------------------------------------------------------------------

def guard(call: ToolCall, ctx: SessionContext, policy: Policy | None = None) -> Decision:
    t0 = time.perf_counter()
    version = "unknown"
    try:
        pol = policy or load_policy()
        version = pol.version
        d = _evaluate(call, ctx, pol)
    except Exception as e:  # anything unexpected inside the guard: fail closed
        d = Decision(
            verdict="DENY", rule_id="FAILSAFE", reason_plain=_FAILSAFE_PLAIN,
            reason_tech=f"guard error: {type(e).__name__}: {e}", tool=str(getattr(call, "tool", "?")),
        )
    d.policy_version = version
    d.latency_ms = round((time.perf_counter() - t0) * 1000, 3)
    return d


def _evaluate(call: ToolCall, ctx: SessionContext, pol: Policy) -> Decision:
    err = _schema_error(call, pol)
    if err:
        return _decide(pol, "FAILSAFE", call, ctx, _Hit("invalid", err))
    for rule_id, rule in _RULES:
        hit = rule(call, ctx, pol)
        if hit is not None:
            return _decide(pol, rule_id, call, ctx, hit)
    raise RuntimeError("no rule matched")  # unreachable: IN_CONTRACT always matches


def _decide(pol: Policy, rule_id: str, call: ToolCall, ctx: SessionContext, hit: _Hit) -> Decision:
    spec = pol.rules[rule_id][hit.variant]
    return Decision(
        verdict=spec["verdict"],
        rule_id=rule_id,
        reason_plain=spec["plain"].format(**hit.fields),
        reason_tech=hit.tech or rule_id,
        tool=str(call.tool),
        arg_provenance=_provenance(call, ctx) if isinstance(call.args, dict) else {},
        source_ref=hit.source_ref,
        extra=hit.extra,
    )


# --- rule 0: FAILSAFE (schema) -----------------------------------------------------------

def _schema_error(call: ToolCall, pol: Policy) -> str | None:
    if not isinstance(call.tool, str) or call.tool not in _SCHEMA:
        return f"unknown tool {call.tool!r}"
    if call.tool not in pol.tools:
        return f"no policy entry for {call.tool}"
    if not isinstance(call.args, dict):
        return f"arguments are not an object: {type(call.args).__name__}"
    schema = _SCHEMA[call.tool]
    props = schema.get("properties", {})
    extra = set(call.args) - set(props)
    if extra:
        return f"unexpected arguments {sorted(extra)}"
    missing = [k for k in schema.get("required", []) if k not in call.args]
    if missing:
        return f"missing arguments {missing}"
    for k, v in call.args.items():
        t = props[k].get("type")
        if t == "string" and not isinstance(v, str):
            return f"argument {k} must be a string"
        if t == "integer" and not (isinstance(v, int) and not isinstance(v, bool)) and not (isinstance(v, str) and v.strip().lstrip("#").isdigit()):
            return f"argument {k} must be an integer"
    return None


# --- rules 1-8 ---------------------------------------------------------------------------

def _r_tool_not_in_contract(call, ctx, pol):
    if call.tool in ctx.contract.allowed_tools:
        return None
    return _Hit(
        tech=f"{call.tool} not in contract tools {ctx.contract.allowed_tools}" + _taint_note(ctx),
        fields={"action": pol.tools[call.tool].get("plain", call.tool)},
    )


def _r_destructive(call, ctx, pol):
    if pol.tools[call.tool].get("risk") != "destructive":
        return None
    return _Hit(tech=f"{call.tool} is destructive; always needs confirmation", extra={"targets": list(call.args.values())})


def _r_recipient(call, ctx, pol):
    c = ctx.contract
    if call.tool == "send_email":
        bad = [r for r in recipients_of(call.args["to"]) if not _recipient_ok(r, ctx)]
        what = "address"
    elif call.tool == "fetch_url":
        url = call.args["url"].strip()
        bad = [] if _norm_url(url) in {_norm_url(u) for u in c.urls} else [url]
        what = "web address"
    else:
        return None
    if not bad:
        return None
    tech = f"destination(s) {bad} not in contract (allowed: {c.allowed_recipients or c.urls or 'none'})"
    if not ctx.tainted:
        return _Hit("clean", tech, {"target": ", ".join(bad)}, extra={"targets": bad})
    for b in bad:
        src = ctx.find_source(b)
        if src:
            origin = {"email": "an email you received", "inbox": "an email you received",
                      "doc": "a document you opened", "web": "a web page"}.get(src.kind, "content I read")
            return _Hit("traced", tech + f"; found in {_ref_for(src, b)}", {"what": what, "origin": origin},
                        source_ref=_ref_for(src, b), extra={"targets": bad})
    return _Hit("tainted", tech + "; session tainted" + _taint_note(ctx), {"what": what}, extra={"targets": bad})


def _r_secret_to_sink(call, ctx, pol):
    if not pol.tools[call.tool].get("sink"):
        return None
    texts = [str(v) for v in call.args.values()]
    keys = secret_hits(texts, ctx.vault_values, pol.min_fragment, pol.min_encoded_token)
    if keys:
        labels = [ctx.workspace.vault_labels.get(k, k) for k in keys]
        return _Hit("contains", f"sink args contain vault value(s) {keys} (raw, encoded or fragment)",
                    {"labels": " and ".join(labels)}, extra={"secret_labels": labels})
    if ctx.vault_touched and _is_external(call, ctx, pol):
        return _Hit("after_vault", "vault was read this session and this sink leaves the workspace")
    return None


_LINK = re.compile(r"!\[[^\]]*\]\([^)]*\)|<img\b|https?://[^\s)>\"']+|\bwww\.[^\s)>\"']+", re.I)


def _r_url_in_tainted_body(call, ctx, pol):
    if call.tool != "send_email" or not ctx.tainted:
        return None
    user_urls = {_norm_url(u) for u in ctx.contract.urls}
    links = [m for m in _LINK.findall(call.args["body"]) if _norm_url(m) not in user_urls]
    if not links:
        return None
    return _Hit(tech=f"tainted session; body contains link/image {links[:3]}" + _taint_note(ctx))


def _r_external_confidential(call, ctx, pol):
    # Coarse by design: once a confidential doc was read this session, any external send asks.
    # Matching the doc's text in the body would miss paraphrases (LLMs rewrite).
    if call.tool != "send_email" or not ctx.confidential_read or not _is_external(call, ctx, pol):
        return None
    titles = [ctx.workspace.docs[n]["title"] for n in ctx.confidential_read]
    return _Hit(tech=f"confidential doc(s) {ctx.confidential_read} read this session; recipient is external",
                fields={"docs": ", ".join(titles)}, extra={"docs": titles})


def _r_tainted_body_ok(call, ctx, pol):
    if call.tool != "send_email" or not ctx.tainted:
        return None
    src = _body_source(call.args.get("body", ""), ctx)
    return _Hit(tech="tainted session, but every recipient is in the contract",
                fields={"target": call.args["to"], "origin": src or "content I read"}, source_ref=src)


def _r_in_contract(call, ctx, pol):
    return _Hit(tech=f"{call.tool} is in the contract")


_RULES: list[tuple[str, Callable[[ToolCall, SessionContext, Policy], _Hit | None]]] = [
    ("TOOL_NOT_IN_CONTRACT", _r_tool_not_in_contract),
    ("DESTRUCTIVE_ALWAYS_CONFIRM", _r_destructive),
    ("RECIPIENT_NOT_IN_CONTRACT", _r_recipient),
    ("SECRET_TO_SINK", _r_secret_to_sink),
    ("URL_OR_IMAGE_IN_TAINTED_BODY", _r_url_in_tainted_body),
    ("EXTERNAL_DOMAIN_CONFIDENTIAL", _r_external_confidential),
    ("TAINTED_BODY_TO_CONTRACT_RECIPIENT", _r_tainted_body_ok),
    ("IN_CONTRACT", _r_in_contract),
]
assert [r for r, _ in _RULES] == RULE_ORDER[1:]


# --- helpers -----------------------------------------------------------------------------

_ADDR = re.compile(r"[^\s,;<>\"'()\[\]]+@[^\s,;<>\"'()\[\]]+")


def recipients_of(to: str) -> list[str]:
    """Every address in a `to` field. If there is no address at all, each comma-part is a 'name'."""
    found = [a.lower().rstrip(".") for a in _ADDR.findall(str(to))]
    if found:
        return found
    return [p.strip().lower() for p in re.split(r"[,;]|\band\b", str(to)) if p.strip()]


def _recipient_ok(r: str, ctx: SessionContext) -> bool:
    # Exact string match only: "nímbus.test" is not "nimbus.test".
    return r in ctx.contract.allowed_recipients or r in ctx.contract.recipient_names


def _resolve_email(r: str, ctx: SessionContext) -> str | None:
    if "@" in r:
        return r
    if r in ctx.contract.recipient_names:
        return ctx.contract.recipient_names[r]
    return next((c["email"].lower() for c in ctx.workspace.contacts
                 if r in [n.lower() for n in [c["name"], *c.get("aliases", [])]]), None)


def _is_external(call: ToolCall, ctx: SessionContext, pol: Policy) -> bool:
    if call.tool == "fetch_url":
        return True
    if call.tool != "send_email":
        return False
    for r in recipients_of(call.args.get("to", "")):
        email = _resolve_email(r, ctx)
        if not email or email.rsplit("@", 1)[-1] not in pol.internal_domains:
            return True
    return False


def _norm_url(u: str) -> str:
    return u.strip().rstrip("/.,").lower()


def _alnum(s: str) -> str:
    return re.sub(r"[^0-9a-z]", "", s.lower())


def _decoded_views(text: str, min_token: int) -> list[str]:
    """The text plus every base64/hex/URL decoding of it we can find."""
    views = [text, unquote_plus(text)]
    for t in list(views):
        for tok in re.findall(r"[A-Za-z0-9+/_-]{%d,}={0,2}" % min_token, t):
            for off in range(4):  # token may be glued to a word, so try a few alignments
                chunk = tok[off:]
                for dec in (base64.b64decode, base64.urlsafe_b64decode):
                    try:
                        views.append(dec(chunk + "=" * (-len(chunk) % 4)).decode("utf-8", "ignore"))
                    except (binascii.Error, ValueError):
                        pass
        for tok in re.findall(r"(?:[0-9a-fA-F]{2}){%d,}" % (min_token // 2), t):
            try:
                views.append(bytes.fromhex(tok).decode("utf-8", "ignore"))
            except ValueError:
                pass
    return views


def secret_hits(texts: list[str], vault_values: dict, min_fragment: int = 10, min_token: int = 12) -> list[str]:
    """Vault keys whose value appears in `texts`: raw, base64, hex, URL-encoded, split across
    fields, or as any run of `min_fragment` letters/digits."""
    if not vault_values:
        return []
    joined = "\n".join(texts)
    views = _decoded_views(joined, min_token)
    flat = [_alnum(v) for v in views] + [_alnum("".join(texts)), _alnum("".join(reversed(texts)))]
    low = [v.lower() for v in views]
    hits = []
    for key, value in vault_values.items():
        v, va = value.lower(), _alnum(value)
        if not va:
            continue
        frags = {va[i:i + min_fragment] for i in range(max(1, len(va) - min_fragment + 1))}
        if any(v in x for x in low) or any(va in x or any(f in x for f in frags) for x in flat):
            hits.append(key)
    return hits


def _provenance(call: ToolCall, ctx: SessionContext) -> dict:
    lits = {str(x).strip().lower() for x in ctx.contract.literals}
    out = {}
    for k, v in call.args.items():
        s = str(v).strip().lower()
        if k == "to" and call.tool == "send_email":
            is_lit = all(_recipient_ok(r, ctx) for r in recipients_of(v))
        elif k == "url":
            is_lit = _norm_url(s) in {_norm_url(u) for u in ctx.contract.urls}
        else:
            is_lit = s in lits
        out[k] = "user-literal" if is_lit else ("tainted" if ctx.tainted else "trusted")
    return out


def _ref_for(src: TaintSource, value: str) -> str:
    # For the inbox listing, point at the specific email line ("#5 | sender | subject").
    if src.kind == "inbox":
        for line in src.text.splitlines():
            if value.lower() in line.lower():
                m = re.match(r"#(\d+)", line.strip())
                if m:
                    return f"email #{m.group(1)} (from your inbox list)"
    return src.ref


def _taint_note(ctx: SessionContext) -> str:
    return f"; tainted by {[s.ref for s in ctx.taint_sources]}" if ctx.tainted else ""


def _body_source(body: str, ctx: SessionContext) -> str | None:
    """Which untrusted result shares a 3-word phrase with the body (for the audit note)."""
    words = re.findall(r"\S+", body)
    for i in range(len(words) - 2):
        src = ctx.find_source(" ".join(words[i:i + 3]))
        if src:
            return src.ref
    return None
