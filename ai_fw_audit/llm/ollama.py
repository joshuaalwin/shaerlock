"""Ollama provider for shaerlock (local LLM)."""

from __future__ import annotations

import json
import os
from typing import Any

import requests

from .base import LLMProvider

DEFAULT_HOST = "http://localhost:11434"
DEFAULT_MODEL = "llama3.1:8b"


def ollama_reachable(host: str | None = None, timeout: float = 1.0) -> bool:
    host = host or os.environ.get("AI_FW_AUDIT_OLLAMA_HOST", DEFAULT_HOST)
    try:
        r = requests.get(f"{host}/api/tags", timeout=timeout)
        return r.status_code == 200
    except requests.RequestException:
        return False


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, host: str | None = None, model: str | None = None):
        self._host = host or os.environ.get("AI_FW_AUDIT_OLLAMA_HOST", DEFAULT_HOST)
        self._model = model or os.environ.get("AI_FW_AUDIT_OLLAMA_MODEL", DEFAULT_MODEL)

    def chat_json(self, system: str, user: str) -> dict[str, Any]:
        # Ollama supports a `format: "json"` option that constrains output.
        r = requests.post(
            f"{self._host}/api/chat",
            json={
                "model": self._model,
                "format": "json",
                "stream": False,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "options": {"temperature": 0.2},
            },
            timeout=120,
        )
        r.raise_for_status()
        data = r.json()
        content = data.get("message", {}).get("content", "").strip()
        return json.loads(content)
