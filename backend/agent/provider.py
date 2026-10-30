"""Provider adapter for any OpenAI-compatible endpoint (Groq primary, Gemini fallback).

Why hand-rolled: free tiers have tight token-per-minute limits, so we pace
requests ourselves and treat rate limits as "assistant unavailable", never as a
security block.
"""
from __future__ import annotations

import collections
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv
from openai import APIConnectionError, APIStatusError, APITimeoutError, OpenAI, RateLimitError

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

DEFAULTS = {
    "groq": {"base_url": "https://api.groq.com/openai/v1", "model": "openai/gpt-oss-120b", "tpm": 7500},
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "model": "gemini-3.5-flash",
        "tpm": 30000,
        "rpm": 5,  # free tier is requests-per-minute bound well before it is token bound
    },
}
MAX_RETRIES = 3


class ProviderUnavailable(Exception):
    """Every provider failed (rate limit / network). Shown as 'Assistant unavailable — nothing was sent'."""


class ToolCallFormatError(Exception):
    """The model produced a malformed tool call that the endpoint rejected (Groq: tool_use_failed)."""


@dataclass
class Provider:
    name: str
    base_url: str
    model: str
    api_key: str = field(repr=False)
    tpm: int = 0
    rpm: int = 0
    stats: dict = field(default_factory=lambda: {"requests": 0, "tokens": 0, "rate_limited": 0})
    _window: collections.deque = field(default_factory=collections.deque, repr=False)
    _client: OpenAI | None = field(default=None, repr=False)

    @property
    def label(self) -> str:
        return f"{self.name}:{self.model}"

    def client(self) -> OpenAI:
        if self._client is None:
            # max_retries=0: we do our own backoff so 429s are counted and visible.
            self._client = OpenAI(base_url=self.base_url, api_key=self.api_key, max_retries=0, timeout=60)
        return self._client

    def _pace(self, est_tokens: int) -> None:
        """Sleep until the last-60s token total (and request count) leaves room for this request."""
        if self.rpm and self._window:
            wait = 60 / self.rpm - (time.time() - self._window[-1][0])
            if wait > 0:
                time.sleep(wait)
        if not self.tpm:
            return
        while True:
            now = time.time()
            while self._window and now - self._window[0][0] > 60:
                self._window.popleft()
            used = sum(t for _, t in self._window)
            if used + est_tokens <= self.tpm or not self._window:
                return
            time.sleep(max(0.5, 60 - (now - self._window[0][0]) + 0.2))

    def chat(self, messages: list[dict], tools: list[dict] | None = None, max_tokens: int = 600):
        est = len(json.dumps(messages)) // 4 + len(json.dumps(tools or [])) // 4 + max_tokens
        kwargs: dict = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": float(os.getenv("LLM_TEMPERATURE", "0.3")),
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        if "gpt-oss" in self.model:
            kwargs["reasoning_effort"] = "low"  # reasoning tokens count against TPM
        if os.getenv("SIMULATE_RATE_LIMIT") == "1":  # demo/hardening check: behave like an exhausted free tier
            self.stats["rate_limited"] += 1
            raise ProviderUnavailable(f"{self.label} rate-limited (simulated)")
        for attempt in range(MAX_RETRIES + 1):
            self._pace(est)
            try:
                resp = self.client().chat.completions.create(**kwargs)
            except RateLimitError as e:
                self.stats["rate_limited"] += 1
                self._window.append((time.time(), est))
                if attempt == MAX_RETRIES:
                    raise ProviderUnavailable(f"{self.label} rate-limited") from e
                retry_after = e.response.headers.get("retry-after") if e.response is not None else None
                time.sleep(min(30.0, float(retry_after) if retry_after else 4.0 * (2**attempt)))
                continue
            except (APIConnectionError, APITimeoutError) as e:
                if attempt == MAX_RETRIES:
                    raise ProviderUnavailable(f"{self.label} unreachable") from e
                time.sleep(2.0 * (attempt + 1))
                continue
            except APIStatusError as e:
                body = str(getattr(e, "body", "") or e)
                if e.status_code in (401, 403, 404):  # bad key / model gone: try the next provider
                    raise ProviderUnavailable(f"{self.label} refused ({e.status_code})") from e
                if e.status_code == 400 and ("tool_use_failed" in body or "tool call" in body.lower()):
                    raise ToolCallFormatError(body[:300]) from e
                if e.status_code >= 500 and attempt < MAX_RETRIES:
                    time.sleep(2.0 * (attempt + 1))
                    continue
                raise
            used = resp.usage.total_tokens if resp.usage else est
            self._window.append((time.time(), used))
            self.stats["requests"] += 1
            self.stats["tokens"] += used
            return resp.choices[0].message
        raise ProviderUnavailable(self.label)


def _provider_from_env(name: str, model: str | None = None) -> Provider | None:
    p = name.strip().upper()
    key = os.getenv(f"{p}_API_KEY", "").strip()
    if not key:
        return None
    d = DEFAULTS.get(name.lower(), {})
    return Provider(
        name=name.lower(),
        base_url=os.getenv(f"{p}_BASE_URL", d.get("base_url", "")),
        model=model or os.getenv(f"{p}_MODEL", d.get("model", "")),
        api_key=key,
        tpm=int(os.getenv(f"{p}_TPM", d.get("tpm", 0))),
        rpm=int(os.getenv(f"{p}_RPM", d.get("rpm", 0))),
    )


def configured_providers() -> list[Provider]:
    """Providers with a key set, in PROVIDER_ORDER. Used for fallback at run time."""
    order = os.getenv("PROVIDER_ORDER", "groq,gemini").split(",")
    return [p for p in (_provider_from_env(n) for n in order) if p]


def spike_providers() -> list[Provider]:
    """Every provider/model combo the spike should try (primary model + *_SPIKE_MODELS)."""
    out = []
    for name in os.getenv("PROVIDER_ORDER", "groq,gemini").split(","):
        base = _provider_from_env(name)
        if not base:
            continue
        out.append(base)
        for m in filter(None, os.getenv(f"{name.strip().upper()}_SPIKE_MODELS", "").split(",")):
            out.append(_provider_from_env(name, m.strip()))
    return out


def key_status() -> dict[str, bool]:
    """Which keys are present. Never returns or prints the key itself."""
    return {n: bool(os.getenv(f"{n.upper()}_API_KEY", "").strip()) for n in DEFAULTS}
