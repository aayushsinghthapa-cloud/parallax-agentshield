"""Tool schemas (OpenAI function-calling format) and their simulated implementations.

Everything here is fake on purpose: send_email appends to a JSONL outbox,
fetch_url never touches the network, delete_files deletes nothing. The point of
the project is the decision about *whether* a call runs, not the call itself.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _fn(name: str, description: str, props: dict | None = None, required: list[str] | None = None) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {"type": "object", "properties": props or {}, "required": required or []},
        },
    }


_S = {"type": "string"}

# Descriptions are kept short: every byte here is re-sent on every LLM request (8K TPM budget).
SCHEMAS: list[dict] = [
    _fn("list_inbox", "List emails in the inbox (id, sender, subject)."),
    _fn("read_email", "Read one email by id.", {"id": {"type": "integer"}}, ["id"]),
    _fn("search_docs", "Search workspace documents by keyword.", {"query": _S}, ["query"]),
    _fn("read_doc", "Read a document by name, e.g. q3-report.", {"name": _S}, ["name"]),
    _fn("read_vault", "Read a secret from the vault by key (e.g. AWS_ACCESS_KEY), or ALL.", {"key": _S}, ["key"]),
    _fn("send_email", "Send an email.", {"to": _S, "subject": _S, "body": _S}, ["to", "subject", "body"]),
    _fn("fetch_url", "Fetch a web URL.", {"url": _S}, ["url"]),
    _fn("delete_files", "Delete files at a path.", {"path": _S}, ["path"]),
]
TOOL_NAMES = {s["function"]["name"] for s in SCHEMAS}


def _load_doc(path: Path) -> dict:
    """Parse the tiny front-matter header (title/label) used by data/docs/*.md."""
    text = path.read_text()
    meta: dict[str, str] = {}
    body = text
    if text.startswith("---"):
        _, header, body = text.split("---", 2)
        for line in header.strip().splitlines():
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip()
    return {
        "name": path.stem,
        "title": meta.get("title", path.stem),
        "label": meta.get("label", "internal"),
        "body": body.strip(),
    }


def load_contacts() -> dict:
    return json.loads((DATA_DIR / "contacts.json").read_text())


def load_docs() -> dict[str, dict]:
    return {p.stem: _load_doc(p) for p in sorted((DATA_DIR / "docs").glob("*.md"))}


class World:
    """One session's synthetic workspace. Fresh copy per run so runs never contaminate each other."""

    def __init__(self, extra_emails: list[dict] | None = None, outbox_path: Path | None = None):
        self.contacts = load_contacts()
        self.inbox: list[dict] = json.loads((DATA_DIR / "inbox.json").read_text()) + list(extra_emails or [])
        self.vault: dict = json.loads((DATA_DIR / "vault.json").read_text())
        self.docs = load_docs()
        self.outbox_path = outbox_path
        self.sent: list[dict] = []
        self.fetched: list[str] = []
        self.deleted: list[str] = []

    # --- dispatcher -------------------------------------------------------
    def execute(self, name: str, args: dict) -> str:
        fn = getattr(self, f"_t_{name}", None)
        if fn is None or name not in TOOL_NAMES:
            return f"Error: unknown tool {name}"
        try:
            return fn(**args)
        except TypeError as e:
            return f"Error: bad arguments for {name}: {e}"

    # --- tools ------------------------------------------------------------
    def _t_list_inbox(self) -> str:
        return "\n".join(f"#{m['id']} | {m['from']} | {m['subject']}" for m in self.inbox)

    def _t_read_email(self, id) -> str:
        m = self.find_email(id)
        if not m:
            return f"Error: no email with id {id}"
        return f"Email #{m['id']}\nFrom: {m['from']}\nDate: {m['date']}\nSubject: {m['subject']}\n\n{m['body']}"

    def _t_search_docs(self, query: str) -> str:
        q = str(query).lower()
        hits = [d for d in self.docs.values() if q in d["body"].lower() or q in d["title"].lower() or q in d["name"]]
        if not hits:
            return f"No documents match '{query}'. Available: " + ", ".join(self.docs)
        return "\n".join(f"{d['name']} ({d['title']}, {d['label']})" for d in hits)

    def _t_read_doc(self, name: str) -> str:
        d = self.find_doc(name)
        if not d:
            return f"Error: no document '{name}'. Available: " + ", ".join(self.docs)
        return f"[{d['title']} | label: {d['label']}]\n{d['body']}"

    def _t_read_vault(self, key: str) -> str:
        k = str(key).strip().upper()
        if k in ("ALL", "*", ""):
            return "\n".join(f"{name}={v['value']}" for name, v in self.vault.items())
        if k not in self.vault:
            return f"Error: no vault key {key}. Keys: " + ", ".join(self.vault)
        return f"{k}={self.vault[k]['value']}"

    def _t_send_email(self, to: str, subject: str, body: str) -> str:
        rec = {"ts": time.time(), "to": to, "subject": subject, "body": body}
        self.sent.append(rec)
        if self.outbox_path:
            with open(self.outbox_path, "a") as f:
                f.write(json.dumps(rec) + "\n")
        return f"Email sent to {to}."

    def _t_fetch_url(self, url: str) -> str:
        self.fetched.append(url)
        return "<html><body>OK (simulated page, no real network)</body></html>"

    def _t_delete_files(self, path: str) -> str:
        self.deleted.append(path)
        return f"Deleted {path} (simulated)."

    # --- lookups ----------------------------------------------------------
    def find_email(self, id) -> dict | None:
        try:
            i = int(str(id).lstrip("#"))
        except ValueError:
            return None
        return next((m for m in self.inbox if m["id"] == i), None)

    def find_doc(self, name: str) -> dict | None:
        n = str(name).lower().strip().removesuffix(".md").replace(" ", "-")
        if n in self.docs:
            return self.docs[n]
        return next((d for d in self.docs.values() if d["title"].lower() == str(name).lower().strip()), None)
