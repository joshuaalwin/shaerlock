"""Anthropic Claude provider for shaerlock."""

from __future__ import annotations

import json
import os
import sys
import time

from ..secrets import get_secret
from .base import LLMProvider

DEFAULT_MODEL = "claude-sonnet-4-6"


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, model: str | None = None, max_tokens: int = 600):
        try:
            import anthropic  # type: ignore
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "anthropic SDK not installed. Run: pip install -e '.[anthropic]'"
            ) from e
        # Resolution order: keyring → env var → .env (already merged into env).
        api_key = get_secret("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY not configured. "
                "Run `shaerlock configure` to store it in the OS keyring."
            )
        # 30s per request is plenty for a constrained-JSON response. The SDK
        # default is 10 minutes, which causes the e2e harness to appear hung
        # if a single request stalls.
        self._client = anthropic.Anthropic(api_key=api_key, timeout=30.0)
        self._model = model or os.environ.get("AI_FW_AUDIT_ANTHROPIC_MODEL", DEFAULT_MODEL)
        self._max_tokens = max_tokens

    def _call_with_retry(self, system: str, user: str, max_attempts: int = 4):
        """messages.create() with backoff on rate-limit-style errors.

        Anthropic returns either a 429 (true rate limit) or a 400 with a body
        like "current usage..., please reduce the prompt length or the maximum
        tokens requested" when the per-minute input-token budget is exceeded.
        The SDK retries 429s but does not retry the 400 form, so we wrap it.
        """
        import anthropic  # type: ignore

        last_exc: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                return self._client.messages.create(
                    model=self._model,
                    max_tokens=self._max_tokens,
                    system=system,
                    messages=[{"role": "user", "content": user}],
                )
            except anthropic.BadRequestError as e:
                msg = str(e).lower()
                if "current usage" in msg and attempt < max_attempts:
                    delay = min(2 ** attempt, 30)
                    print(
                        f"  [anthropic] per-minute token budget hit, sleeping {delay}s (attempt {attempt}/{max_attempts})",
                        file=sys.stderr,
                        flush=True,
                    )
                    time.sleep(delay)
                    last_exc = e
                    continue
                raise
            except anthropic.RateLimitError as e:
                if attempt < max_attempts:
                    delay = min(2 ** attempt, 30)
                    print(
                        f"  [anthropic] rate-limited, sleeping {delay}s (attempt {attempt}/{max_attempts})",
                        file=sys.stderr,
                        flush=True,
                    )
                    time.sleep(delay)
                    last_exc = e
                    continue
                raise
        if last_exc:
            raise last_exc
        raise RuntimeError("anthropic call failed without surfacing an exception")

    def chat_json(self, system: str, user: str) -> dict:
        msg = self._call_with_retry(system, user)
        text = "".join(block.text for block in msg.content if getattr(block, "type", "") == "text").strip()
        # The system prompt instructs the model to return ONLY JSON. Be defensive
        # in case the model wraps it in code fences.
        if text.startswith("```"):
            text = text.strip("`")
            # strip leading "json\n" if present
            if text.lower().startswith("json"):
                text = text[4:].lstrip()
            # strip trailing fence
            if text.endswith("```"):
                text = text[:-3].rstrip()
        return json.loads(text)
