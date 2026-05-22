"""
Connectors for Argus.

Two families of connectors:

  1. CLI sign-in connectors (preferred — same UX as Continue / VSCode "Sign in
     with X"). These rely on the user authenticating once via the provider's
     own CLI (`claude`, `codex`) whose OAuth flow opens a browser. Argus then
     consumes that local credential, no API key needed.

  2. API-key connectors (advanced). For users who already have raw API keys
     and want to use them via LangChain. Persisted to .env.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

log = logging.getLogger(__name__)

ENV_FILE_PATH = Path(__file__).parent / ".env"


# --------------------------------------------------------------------------- #
# .env read / write
# --------------------------------------------------------------------------- #

def _read_env_file() -> Dict[str, str]:
    if not ENV_FILE_PATH.exists():
        return {}
    out: Dict[str, str] = {}
    try:
        for line in ENV_FILE_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError as e:
        log.warning("Could not read %s: %s", ENV_FILE_PATH, e)
    return out


def _write_env_file(updates: Dict[str, str]) -> None:
    """Merge `updates` into .env, preserving other existing keys & comments."""
    existing_lines: List[str] = []
    if ENV_FILE_PATH.exists():
        existing_lines = ENV_FILE_PATH.read_text(encoding="utf-8").splitlines()

    seen: set = set()
    out: List[str] = []
    for line in existing_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            out.append(line)
            continue
        k, _ = stripped.split("=", 1)
        k = k.strip()
        if k in updates:
            new_val = updates[k]
            out.append(f"{k}={new_val}")
            seen.add(k)
        else:
            out.append(line)

    # Append new keys at the end
    for k, v in updates.items():
        if k not in seen:
            out.append(f"{k}={v}")

    ENV_FILE_PATH.write_text("\n".join(out) + "\n", encoding="utf-8")
    # Reflect into the live process
    for k, v in updates.items():
        os.environ[k] = v


# --------------------------------------------------------------------------- #
# Provider definitions
# --------------------------------------------------------------------------- #

@dataclass
class Provider:
    key_env: str                                   # e.g. "ANTHROPIC_API_KEY"
    display: str                                   # e.g. "Anthropic"
    models_unlocked: List[str] = field(default_factory=list)
    docs_url: str = ""
    test_fn: Optional[Callable[[str], Dict]] = None
    extra_env: Dict[str, str] = field(default_factory=dict)  # e.g. base URL


def _mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "•" * len(value)
    return value[:4] + "…" + value[-4:]


# ---- Per-provider test functions ---- #

def _test_anthropic(key: str) -> Dict:
    try:
        import anthropic
    except ImportError:
        return {"ok": False, "msg": "Install `anthropic` (pip install anthropic)"}
    try:
        client = anthropic.Anthropic(api_key=key)
        # Cheapest call: a 1-token request to the smallest model available
        models = client.models.list(limit=1)
        sample = ", ".join(m.id for m in models.data) if models.data else "?"
        return {"ok": True, "msg": f"Authenticated. Sample model: {sample}"}
    except Exception as e:
        return {"ok": False, "msg": f"{type(e).__name__}: {e}"}


def _test_openai(key: str) -> Dict:
    try:
        import openai
    except ImportError:
        return {"ok": False, "msg": "Install `openai` (pip install openai)"}
    try:
        client = openai.OpenAI(api_key=key)
        models = client.models.list()
        first = next(iter(models), None)
        sample = first.id if first else "?"
        return {"ok": True, "msg": f"Authenticated. Sample model: {sample}"}
    except Exception as e:
        return {"ok": False, "msg": f"{type(e).__name__}: {e}"}


def _test_google(key: str) -> Dict:
    try:
        from google import genai  # google-genai (new) or fall back
    except ImportError:
        try:
            import google.generativeai as genai  # legacy
        except ImportError:
            return {"ok": False, "msg": "Install `google-generativeai`"}
    try:
        # The legacy `google.generativeai` accepts an api_key on configure()
        # while the new google-genai takes it in Client()
        if hasattr(genai, "Client"):
            client = genai.Client(api_key=key)
            models = list(client.models.list())
            sample = models[0].name if models else "?"
        else:
            genai.configure(api_key=key)
            models = list(genai.list_models())
            sample = models[0].name if models else "?"
        return {"ok": True, "msg": f"Authenticated. Sample model: {sample}"}
    except Exception as e:
        return {"ok": False, "msg": f"{type(e).__name__}: {e}"}


def _test_openrouter(key: str, base_url: str = "https://openrouter.ai/api/v1") -> Dict:
    try:
        import openai
    except ImportError:
        return {"ok": False, "msg": "Install `openai`"}
    try:
        client = openai.OpenAI(api_key=key, base_url=base_url)
        models = client.models.list()
        first = next(iter(models), None)
        sample = first.id if first else "?"
        return {"ok": True, "msg": f"Authenticated via {base_url}. Sample: {sample}"}
    except Exception as e:
        return {"ok": False, "msg": f"{type(e).__name__}: {e}"}


# ---- Provider registry ---- #

PROVIDERS: List[Provider] = [
    Provider(
        key_env="ANTHROPIC_API_KEY",
        display="Anthropic (Claude)",
        models_unlocked=["claude-sonnet-4-5", "claude-sonnet-4-0",
                         "claude-opus-4-7", "claude-haiku-4-5"],
        docs_url="https://console.anthropic.com/settings/keys",
        test_fn=_test_anthropic,
    ),
    Provider(
        key_env="OPENAI_API_KEY",
        display="OpenAI (GPT)",
        models_unlocked=["gpt-4.1", "gpt-5.1", "gpt-5-mini", "gpt-5-nano"],
        docs_url="https://platform.openai.com/api-keys",
        test_fn=_test_openai,
    ),
    Provider(
        key_env="GOOGLE_API_KEY",
        display="Google (Gemini)",
        models_unlocked=["gemini-2.5-flash", "gemini-2.5-flash-lite",
                         "gemini-2.5-pro"],
        docs_url="https://aistudio.google.com/app/apikey",
        test_fn=_test_google,
    ),
    Provider(
        key_env="OPENROUTER_API_KEY",
        display="OpenRouter (gateway)",
        models_unlocked=["gpt-5.1-openrouter", "gpt-5-mini-openrouter",
                         "claude-sonnet-4.5-openrouter", "grok-4.1-fast-openrouter"],
        docs_url="https://openrouter.ai/keys",
        test_fn=_test_openrouter,
        extra_env={"OPENROUTER_BASE_URL": "https://openrouter.ai/api/v1"},
    ),
]


# --------------------------------------------------------------------------- #
# Public API for the UI
# --------------------------------------------------------------------------- #

def current_status() -> Dict[str, Dict]:
    """For each provider: is the key set, and what does it look like (masked)."""
    out: Dict[str, Dict] = {}
    for p in PROVIDERS:
        val = os.getenv(p.key_env, "")
        placeholder = f"your_{p.key_env.lower()}"
        configured = bool(val) and val != placeholder and not val.startswith("your_")
        out[p.key_env] = {
            "display": p.display,
            "configured": configured,
            "masked": _mask(val) if configured else "",
            "models_unlocked": p.models_unlocked,
            "docs_url": p.docs_url,
        }
    return out


def test_provider(key_env: str, value: str) -> Dict:
    """Run the provider's cheap authenticated test call with `value` as key."""
    p = next((p for p in PROVIDERS if p.key_env == key_env), None)
    if p is None or p.test_fn is None:
        return {"ok": False, "msg": "Unknown provider"}
    if not value:
        return {"ok": False, "msg": "Empty key"}
    return p.test_fn(value)


def save_keys(updates: Dict[str, str]) -> None:
    """Persist a dict of provider keys to .env and refresh os.environ.

    Empty string values are skipped (use clear_key() to remove).
    """
    clean = {k: v for k, v in updates.items() if v}
    if not clean:
        return
    # Also auto-write any extra_env (base URLs, etc.) for providers being saved
    for p in PROVIDERS:
        if p.key_env in clean:
            for k, v in p.extra_env.items():
                if not os.getenv(k):
                    clean.setdefault(k, v)
    _write_env_file(clean)


def clear_key(key_env: str) -> None:
    """Remove a key from .env and os.environ."""
    if not ENV_FILE_PATH.exists():
        os.environ.pop(key_env, None)
        return
    lines = ENV_FILE_PATH.read_text(encoding="utf-8").splitlines()
    out = [
        l for l in lines
        if not (l.strip().startswith(f"{key_env}=") and "=" in l)
    ]
    ENV_FILE_PATH.write_text("\n".join(out) + "\n", encoding="utf-8")
    os.environ.pop(key_env, None)


# --------------------------------------------------------------------------- #
# CLI sign-in connectors (Claude Code, Codex CLI)
# --------------------------------------------------------------------------- #

@dataclass
class CLIConnector:
    id: str                      # short slug, used as widget key
    display: str                 # "Claude Code"
    description: str             # one-line description
    cli_binary: str              # "claude"
    install_doc_url: str
    install_cmd: str             # what the user runs to install
    login_cmd: str               # what the user runs to authenticate
    logout_cmd: Optional[str] = None
    creds_path: Optional[str] = None   # filesystem hint for "logged in" check
    test_fn: Optional[Callable[[], Dict]] = None


def _test_claude_code() -> Dict:
    """Run a 1-token probe through the Claude Agent SDK."""
    try:
        import asyncio
        from claude_agent_sdk import query, ClaudeAgentOptions
    except ImportError:
        return {"ok": False, "msg": "Need `pip install claude-agent-sdk`"}

    async def _probe():
        opts = ClaudeAgentOptions(max_turns=1, permission_mode="bypassPermissions")
        text_seen = []
        async for m in query(prompt="reply OK and nothing else", options=opts):
            blocks = getattr(m, "content", None) or []
            for blk in blocks:
                if hasattr(blk, "text"):
                    text_seen.append(blk.text)
        return "".join(text_seen)

    try:
        text = asyncio.run(_probe())
        if text:
            return {"ok": True, "msg": f"Subscription active. Replied: {text[:60]}"}
        return {"ok": False, "msg": "No text returned — `claude` may not be logged in"}
    except Exception as e:
        emsg = str(e)
        if "login" in emsg.lower() or "auth" in emsg.lower():
            return {"ok": False, "msg": "Not logged in. Run `claude` to authenticate."}
        return {"ok": False, "msg": f"{type(e).__name__}: {emsg[:200]}"}


def _test_codex_cli() -> Dict:
    """Use `codex doctor` to verify install + auth + runtime health."""
    if not shutil.which("codex"):
        return {"ok": False, "msg": "`codex` binary not in PATH."}
    try:
        r = subprocess.run(
            ["codex", "doctor"],
            capture_output=True, text=True, timeout=15,
        )
        out = (r.stdout + r.stderr).strip()
        # Codex doctor prints sections like "Authentication: OK" / "Plan: ChatGPT Pro"
        if r.returncode == 0:
            # Extract the most informative line
            useful_lines = [
                l for l in out.splitlines()
                if any(kw in l.lower() for kw in
                       ("auth", "plan", "account", "login", "logged", "model"))
            ]
            summary = " | ".join(useful_lines[:3]) if useful_lines else out[:200]
            return {"ok": True, "msg": summary or "doctor reports healthy"}
        if "not logged" in out.lower() or "login" in out.lower():
            return {"ok": False, "msg": "Not logged in. Run `codex login`."}
        return {"ok": False, "msg": (out[:200] or
                                      f"codex doctor returned {r.returncode}")}
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": "Timeout running `codex doctor`."}
    except Exception as e:
        return {"ok": False, "msg": f"{type(e).__name__}: {e}"}


CLI_CONNECTORS: List[CLIConnector] = [
    CLIConnector(
        id="claude-code",
        display="Claude Code",
        description=("Sign in to Claude via your Anthropic subscription. "
                     "No API key needed."),
        cli_binary="claude",
        install_doc_url="https://docs.claude.com/claude-code",
        install_cmd="curl -fsSL https://claude.ai/install.sh | sh",
        login_cmd="claude /login",
        logout_cmd="claude /logout",
        creds_path="~/.claude/.credentials.json",
        test_fn=_test_claude_code,
    ),
    CLIConnector(
        id="codex-cli",
        display="Codex CLI (ChatGPT)",
        description=("Sign in to ChatGPT via the OpenAI Codex CLI. "
                     "No API key needed. Uses your ChatGPT subscription."),
        cli_binary="codex",
        install_doc_url="https://github.com/openai/codex",
        install_cmd="npm install -g @openai/codex",
        login_cmd="codex login",
        logout_cmd="codex logout",
        creds_path="~/.codex/auth.json",
        test_fn=_test_codex_cli,
    ),
]


def cli_connector_status(c: CLIConnector) -> Dict:
    """Returns {installed, logged_in, last_test_msg} for a CLI connector."""
    installed = bool(shutil.which(c.cli_binary))
    if not installed:
        return {"installed": False, "logged_in": False, "msg": "Not installed."}
    if not c.test_fn:
        return {"installed": True, "logged_in": False,
                "msg": "Click 'Test' to verify subscription."}
    # We intentionally DON'T run the test on every page render (it's slow).
    # The UI calls test_fn() only when the user clicks 'Test'.
    creds_exists = False
    if c.creds_path:
        creds_exists = Path(os.path.expanduser(c.creds_path)).exists()
    return {
        "installed": True,
        "logged_in": creds_exists,
        "msg": (f"`{c.creds_path}` present (login likely)." if creds_exists
                else "Not logged in yet. Run the login command."),
    }


def test_cli_connector(connector_id: str) -> Dict:
    c = next((c for c in CLI_CONNECTORS if c.id == connector_id), None)
    if c is None or c.test_fn is None:
        return {"ok": False, "msg": "Unknown connector"}
    return c.test_fn()
