"""Secret resolution for shaerlock.

Resolution order (highest priority first):
  1. OS keyring (GNOME Keyring on Linux, macOS Keychain, Windows Credential Locker
     via the cross-platform `keyring` library) — encrypted at rest.
  2. Environment variable.
  3. .env file in CWD (loaded via python-dotenv) — already merged into env by
     the time this is called.

The key is never logged or printed.
"""

from __future__ import annotations

import os
from typing import Optional

# Keyring service name. Kept as the original internal name so an existing
# stored key continues to resolve after the project was renamed to shaerlock.
SERVICE = "ai-fw-audit"


def _from_keyring(name: str) -> Optional[str]:
    try:
        import keyring  # noqa: WPS433

        return keyring.get_password(SERVICE, name)
    except Exception:
        return None


def get_secret(name: str) -> Optional[str]:
    """Look up a secret by symbolic name, e.g. 'ANTHROPIC_API_KEY'."""
    val = _from_keyring(name)
    if val:
        return val
    return os.environ.get(name) or None


def set_secret(name: str, value: str) -> str:
    """Store a secret in the OS keyring. Returns a short status string.

    Caller is expected to obtain `value` via getpass — never log it.
    """
    try:
        import keyring  # noqa: WPS433

        keyring.set_password(SERVICE, name, value)
        return f"stored {name} in OS keyring (service={SERVICE})"
    except Exception as e:
        return f"keyring backend unavailable: {type(e).__name__}: {e}"


def delete_secret(name: str) -> str:
    try:
        import keyring  # noqa: WPS433

        keyring.delete_password(SERVICE, name)
        return f"deleted {name} from OS keyring"
    except Exception as e:
        return f"keyring delete failed: {type(e).__name__}: {e}"
