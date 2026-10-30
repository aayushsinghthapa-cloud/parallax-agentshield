"""Optional LLM contract compiler (LLM_CONTRACT=1). Stretch feature.

The template compiler misses phrasings like "let Priya know I'm in for Monday". An LLM can read
intent better, so here it proposes a contract. Safety rests on three facts:

1. It sees ONLY the user's message plus trusted metadata (contact names, doc titles, vault labels).
   It runs before any tool, so no untrusted text can reach it.
2. Its output is validated, never trusted. It can only narrow what the user's own words allow:
   recipients must be named in the user's text, the vault only opens on explicit vault words,
   delete_files and fetch_url need the deterministic compiler to agree.
3. Any failure (no provider, bad JSON, timeout) falls back to the deterministic compiler.

The guard itself still never calls an LLM.
"""
from __future__ import annotations

import json
import re

from backend.guard.contract import (READ_DOCS, READ_INBOX, TaskContract, Workspace, _EMAIL, _VAULT_WORDS, _word_in,
                                    compile_contract, resolve_doc)
from backend.tools.registry import TOOL_NAMES

_SYSTEM = (
    "You turn ONE user request for an email/file assistant into a JSON task contract. Output only JSON with keys: "
    '"intent" (summarise|reply|send|search|unknown), "allowed_tools" (subset of: list_inbox, read_email, search_docs, '
    'read_doc, read_vault, send_email, fetch_url, delete_files), "recipients" (contact names or email addresses the user '
    'wants to send to), "docs" (document titles), "allow_vault" (true only if the user explicitly asks for a secret). '
    "Grant the fewest tools that complete the request. Never add recipients the user did not name."
)

INTENTS = {"summarise", "reply", "send", "search", "unknown"}


def _metadata(ws: Workspace) -> str:
    contacts = "; ".join(f"{c['name']} ({', '.join(c.get('aliases', []))})" for c in ws.contacts)
    docs = ", ".join(d["title"] for d in ws.docs.values())
    return f"Contacts: {contacts}\nDocuments: {docs}\nVault keys: {', '.join(ws.vault_labels.values())}"


def _parse(text: str) -> dict:
    m = re.search(r"\{.*\}", text or "", re.S)
    if not m:
        raise ValueError("no JSON object in reply")
    data = json.loads(m.group(0))
    if not isinstance(data, dict):
        raise ValueError("contract is not an object")
    return data


def compile_contract_llm(user_message: str, ws: Workspace, provider) -> TaskContract:
    """Ask the LLM, validate hard, fall back to the deterministic contract on any problem."""
    base = compile_contract(user_message, ws)
    if provider is None:
        return base
    try:
        msg = provider.chat([{"role": "system", "content": _SYSTEM + "\n\n" + _metadata(ws)},
                             {"role": "user", "content": user_message}], None, 300)
        proposal = _parse(msg.content)
    except Exception as e:  # unavailable, rate-limited, unparseable: the rules contract still protects
        base.compiled_by = f"rules (LLM contract failed: {type(e).__name__})"
        return base
    return validate(proposal, user_message, ws, base)


def validate(proposal: dict, user_message: str, ws: Workspace, base: TaskContract) -> TaskContract:
    msg = user_message.strip()
    typed_emails = {e.lower() for e in _EMAIL.findall(msg)}

    # Recipients: only addresses the user typed, or contacts the user named in their own words.
    recipients: list[str] = []
    names: dict[str, str] = {}
    for r in proposal.get("recipients") or []:
        r = str(r).strip().lower()
        if r in typed_emails:
            recipients.append(r)
            continue
        for c in ws.contacts:
            labels = [c["name"], *c.get("aliases", [])]
            if (r == c["email"].lower() or r in [l.lower() for l in labels]) and any(_word_in(l, msg) for l in labels):
                recipients.append(c["email"].lower())
                names.update({l.lower(): c["email"].lower() for l in labels})
    recipients = list(dict.fromkeys(recipients))

    tools = [t for t in proposal.get("allowed_tools") or [] if t in TOOL_NAMES]
    allow_vault = bool(proposal.get("allow_vault")) and bool(_VAULT_WORDS.search(msg) or base.vault_keys)
    if not allow_vault:
        tools = [t for t in tools if t != "read_vault"]
    for risky in ("delete_files", "fetch_url"):  # never wider than the deterministic compiler
        if risky in tools and risky not in base.allowed_tools:
            tools.remove(risky)
    if "send_email" in tools:
        tools += READ_INBOX  # replies need the inbox; reads are never a sink
    if not tools:
        tools = READ_INBOX + READ_DOCS

    docs = [d for d in (resolve_doc(str(x), ws) for x in proposal.get("docs") or []) if d]
    intent = proposal.get("intent") if proposal.get("intent") in INTENTS else "unknown"
    return TaskContract(
        contract_id=base.contract_id.replace("c-", "cl-"),
        user_request=msg,
        intent=intent,
        allowed_tools=list(dict.fromkeys(tools)),
        allowed_recipients=recipients,
        recipient_names=names,
        allowed_docs=list(dict.fromkeys(docs)),
        allow_vault=allow_vault,
        vault_keys=base.vault_keys,
        urls=base.urls,
        paths=base.paths,
        literals=list(dict.fromkeys(base.literals + recipients)),  # literals stay the user's own words
        compiled_by="llm (validated)",
    )
