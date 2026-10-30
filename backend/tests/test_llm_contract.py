"""LLM contract compiler (stretch): the LLM can only narrow what the user's own words allow."""
import json
from types import SimpleNamespace

from backend.agent.provider import ProviderUnavailable
from backend.guard.contract import compile_contract
from backend.guard.llm_contract import compile_contract_llm
from backend.tests.util import WS


class Says:
    def __init__(self, reply):
        self.reply = reply
        self.seen = None

    def chat(self, messages, tools=None, max_tokens=600):
        self.seen = messages
        if isinstance(self.reply, Exception):
            raise self.reply
        return SimpleNamespace(content=self.reply if isinstance(self.reply, str) else json.dumps(self.reply), tool_calls=None)


def test_llm_understands_phrasing_the_templates_miss():
    msg = "Let Priya know I'm in for Monday 3 pm."
    assert "send_email" not in compile_contract(msg, WS).allowed_tools  # templates: no send verb
    c = compile_contract_llm(msg, WS, Says({"intent": "send", "allowed_tools": ["send_email"], "recipients": ["Priya"]}))
    assert "send_email" in c.allowed_tools and c.allowed_recipients == ["priya@nimbus.test"]
    assert c.compiled_by == "llm (validated)" and "Contract: LLM-compiled, validated" in c.pills()


def test_llm_only_sees_the_user_turn():
    llm = Says({"allowed_tools": ["list_inbox"]})
    compile_contract_llm("Summarise my inbox.", WS, llm)
    assert [m["role"] for m in llm.seen] == ["system", "user"] and llm.seen[1]["content"] == "Summarise my inbox."


def test_unnamed_recipients_are_dropped():
    c = compile_contract_llm("Reply to Priya.", WS, Says({"allowed_tools": ["send_email"],
                                                          "recipients": ["Priya", "Bob", "recovery@evil.example"]}))
    assert c.allowed_recipients == ["priya@nimbus.test"]


def test_vault_needs_explicit_words():
    c = compile_contract_llm("Reply to Bob.", WS, Says({"allowed_tools": ["read_vault", "send_email"], "allow_vault": True,
                                                        "recipients": ["Bob"]}))
    assert not c.allow_vault and "read_vault" not in c.allowed_tools


def test_never_wider_than_rules_for_delete_and_fetch():
    c = compile_contract_llm("Summarise the onboarding guide.", WS,
                             Says({"allowed_tools": ["read_doc", "delete_files", "fetch_url", "made_up_tool"]}))
    assert set(c.allowed_tools) == {"read_doc"}


def test_failures_fall_back_to_rules():
    for bad in ["not json at all", ProviderUnavailable("rate-limited"), "[1, 2]"]:
        c = compile_contract_llm("Reply to Priya.", WS, Says(bad))
        assert c.compiled_by.startswith("rules") and c.allowed_recipients == ["priya@nimbus.test"]
