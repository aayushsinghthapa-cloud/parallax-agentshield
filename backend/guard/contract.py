"""Task contract compiler: what the user asked for, decided before any tool output exists.

Input is ONLY the user's chat message plus trusted workspace metadata (contact book,
document titles/labels, vault key labels; never vault values, never email or doc bodies).
It is deliberately simple keyword templates, no LLM: a contract the attacker cannot
influence is worth more than a clever one. Unknown requests get a read-only contract.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field

from backend.tools.registry import DATA_DIR, load_contacts, load_docs

READ_INBOX = ["list_inbox", "read_email"]
READ_DOCS = ["search_docs", "read_doc"]

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URL = re.compile(r"https?://[^\s<>\"']+")
_PATH = re.compile(r"(?<![\w.])/[\w./-]+")
_TIME = re.compile(
    r"\b(?:(?:mon|tues|wednes|thurs|fri|satur|sun)day|today|tomorrow|tonight)\b"
    r"(?:\s+(?:at\s+)?\d{1,2}(?::\d{2})?\s?(?:am|pm))?"
    r"|\b\d{1,2}(?::\d{2})?\s?(?:am|pm)\b"
    r"|\b\d{1,2}\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\b",
    re.I,
)

_INBOX_WORDS = re.compile(r"\b(inbox|e-?mails?|mails?|messages?|newsletters?|reply|replies|sender|invoice)\b", re.I)
_DOC_WORDS = re.compile(r"\b(docs?|documents?|reports?|guides?|notes|plans?|search|find|files?)\b", re.I)
# "email" only counts as a send verb when a recipient was resolved ("email Bob ..."), so
# "check my emails" stays read-only. "handle"/"deal with" can send, but only to people named.
_SEND_VERBS = re.compile(r"\b(reply|respond|send|forward|share|handle|deal with|take care of)\b", re.I)
_EMAIL_VERB = re.compile(r"\bemail\b", re.I)
_SEARCH_VERBS = re.compile(r"\b(search|find|look for|look up)\b", re.I)
_SUMMARY_VERBS = re.compile(r"\b(summari[sz]e|summary|check|what|tell me|read|list|show)\b", re.I)
_VAULT_WORDS = re.compile(r"\b(vault|passwords?|secrets?|credentials?)\b|\b(api|access|aws|stripe|secret|vault)\s+keys?\b", re.I)
_DELETE_VERBS = re.compile(r"\b(delete|remove|clean up|wipe)\b", re.I)
_FETCH_VERBS = re.compile(r"\b(fetch|open|visit|load|check|ping|get)\b", re.I)


@dataclass(frozen=True)
class Workspace:
    """Trusted metadata the compiler and guard may consult. Holds no secret values."""

    contacts: tuple[dict, ...]
    internal_domain: str
    docs: dict  # name -> {"title", "label"}
    vault_labels: dict  # key -> human label, e.g. AWS_ACCESS_KEY -> "AWS access key"


def load_workspace() -> Workspace:
    c = load_contacts()
    vault = json.loads((DATA_DIR / "vault.json").read_text())
    return Workspace(
        contacts=tuple(c["contacts"]),
        internal_domain=c["internal_domain"],
        docs={n: {"title": d["title"], "label": d["label"]} for n, d in load_docs().items()},
        vault_labels={k: v["label"] for k, v in vault.items()},
    )


def resolve_doc(name: str, ws: Workspace) -> str | None:
    """Map 'q3-report', 'Q3 Report', 'q3-report.md' to the canonical doc name (same as World.find_doc)."""
    n = str(name).lower().strip().removesuffix(".md").replace(" ", "-")
    if n in ws.docs:
        return n
    return next((k for k, d in ws.docs.items() if d["title"].lower() == str(name).lower().strip()), None)


@dataclass
class TaskContract:
    contract_id: str
    user_request: str
    intent: str
    allowed_tools: list[str]
    allowed_recipients: list[str]  # lower-cased email addresses
    recipient_names: dict  # lower-cased name/alias -> email, for allowed contacts only
    allowed_docs: list[str]
    allow_vault: bool
    vault_keys: list[str]  # keys the user named (informational; any key is allowed if allow_vault)
    urls: list[str]
    paths: list[str]
    literals: list[str] = field(default_factory=list)
    compiled_by: str = "rules"  # "rules" | "llm (validated)" (LLM_CONTRACT=1 stretch)

    def to_dict(self) -> dict:
        return asdict(self)

    def pills(self) -> list[str]:
        """Plain-language summary for the UI, e.g. 'Can email: Priya'."""
        out = []
        if "send_email" in self.allowed_tools:
            names = sorted({self._display(e) for e in self.allowed_recipients})
            out.append("Can email: " + (", ".join(names) if names else "no one you haven't named"))
        reads = [w for w, tools in (("inbox", READ_INBOX), ("docs", READ_DOCS)) if set(tools) & set(self.allowed_tools)]
        if reads:
            out.append("Can read: " + ", ".join(reads))
        if "fetch_url" in self.allowed_tools:
            out.append("Can open: " + ", ".join(self.urls))
        if "delete_files" in self.allowed_tools:
            out.append("Can delete: " + ", ".join(self.paths) + " (asks first)")
        out.append("Vault: open" if self.allow_vault else "Vault: locked")
        if self.compiled_by.startswith("llm"):
            out.append("Contract: LLM-compiled, validated")
        return out

    def _display(self, email: str) -> str:
        first = next((n for n, e in self.recipient_names.items() if e == email), None)
        return first.title() if first else email


def _word_in(needle: str, text: str) -> bool:
    return re.search(r"(?<!\w)" + re.escape(needle) + r"(?!\w)", text, re.I) is not None


def compile_contract(user_message: str, ws: Workspace) -> TaskContract:
    msg = user_message.strip()
    literals: list[str] = []

    # Recipients: emails typed verbatim, plus contacts named by full name or alias.
    emails = [e.lower() for e in _EMAIL.findall(msg)]
    recipient_names: dict[str, str] = {}
    for c in ws.contacts:
        named = [n for n in [c["name"], *c.get("aliases", [])] if _word_in(n, msg)]
        if named or c["email"].lower() in emails:
            literals += named
            for n in [c["name"], *c.get("aliases", [])]:
                recipient_names[n.lower()] = c["email"].lower()
            emails.append(c["email"].lower())
    allowed_recipients = list(dict.fromkeys(emails))
    literals += allowed_recipients

    docs = []
    for name, d in ws.docs.items():
        for label in (d["title"], name, name.replace("-", " ")):
            if _word_in(label, msg):
                docs.append(name)
                literals.append(label)
                break

    vault_keys = [k for k, label in ws.vault_labels.items() if _word_in(k, msg) or _word_in(label, msg)]
    allow_vault = bool(vault_keys) or bool(_VAULT_WORDS.search(msg))
    urls = [u.rstrip(".,)") for u in _URL.findall(msg)]
    paths = [p for p in _PATH.findall(_URL.sub(" ", msg))]
    literals += vault_keys + urls + paths + [t.strip() for t in _TIME.findall(msg)]

    tools: list[str] = []
    if _INBOX_WORDS.search(msg):
        tools += READ_INBOX
    if _DOC_WORDS.search(msg) or docs:
        tools += READ_DOCS
    sends = bool(_SEND_VERBS.search(msg)) or (bool(_EMAIL_VERB.search(msg)) and bool(allowed_recipients))
    if sends:
        tools += ["send_email", *READ_INBOX]  # replying usually needs the inbox
    if re.search(r"\b(handle|deal with|take care of)\b", msg, re.I):
        tools += READ_DOCS  # open-ended chores may need docs; reads are never a sink
    if allow_vault:
        tools.append("read_vault")
    if urls and _FETCH_VERBS.search(msg):
        tools.append("fetch_url")
    if paths and _DELETE_VERBS.search(msg):
        tools.append("delete_files")
    if not tools:  # unknown request: minimal read-only contract, never a sink
        tools = READ_INBOX + READ_DOCS

    if sends:
        intent = "reply" if re.search(r"\b(reply|respond)\b", msg, re.I) else "send"
    elif _SEARCH_VERBS.search(msg):
        intent = "search"
    elif _SUMMARY_VERBS.search(msg):
        intent = "summarise"
    else:
        intent = "unknown"

    tools = list(dict.fromkeys(tools))
    cid = "c-" + hashlib.sha256(json.dumps([msg, tools, allowed_recipients]).encode()).hexdigest()[:10]
    return TaskContract(
        contract_id=cid,
        user_request=msg,
        intent=intent,
        allowed_tools=tools,
        allowed_recipients=allowed_recipients,
        recipient_names=recipient_names,
        allowed_docs=docs,
        allow_vault=allow_vault,
        vault_keys=vault_keys,
        urls=urls,
        paths=paths,
        literals=list(dict.fromkeys(literals)),
    )
