"""
Agentic mode for Robin.

Three backends, picked at runtime:

  - `claude-code`   uses Claude Code's local subscription (NO API key).
                    Requires the `claude` CLI installed and `pip install
                    claude-agent-sdk`. The model is whatever Claude Code is
                    configured to use; tools are exposed via in-process
                    MCP-style integration.
  - `codex-cli`     shells out to the `codex exec` binary (NO API key).
                    Tools are exposed via Robin's MCP server (auto-launched).
  - `langchain`     classic LangChain ChatModel + bind_tools(). Needs an
                    API key for the chosen provider (OPENAI_API_KEY, etc.)

Whichever backend, the agent has access to the same set of Robin OSINT tools.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from langchain_core.tools import tool
from langchain_core.messages import (
    AIMessage, HumanMessage, SystemMessage, ToolMessage, BaseMessage,
)

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Tool result truncation helper
# --------------------------------------------------------------------------- #

_MAX_RESULT_CHARS = 8000


def _trim(value: Any) -> str:
    """Compact JSON string capped at _MAX_RESULT_CHARS."""
    try:
        s = json.dumps(value, default=str, ensure_ascii=False, indent=None)
    except Exception:
        s = str(value)
    if len(s) > _MAX_RESULT_CHARS:
        s = s[:_MAX_RESULT_CHARS] + f"\n... (truncated, total {len(s)} chars)"
    return s


# --------------------------------------------------------------------------- #
# Tool definitions — each wraps a Robin function with an LLM-friendly docstring
# --------------------------------------------------------------------------- #

@tool
def trace_pii(value: str) -> str:
    """All-in-one OSINT trace of a personal info value.

    Auto-detects the input type (email, phone, username, name, ip, domain,
    hash, btc) and probes every relevant source: HudsonRock infostealer logs,
    EmailRep, HaveIBeenPwned, Gravatar, Telegram (tgstat + t.me/s + auto-
    discovered stealer channels), dark-web search engines, ransomware leak
    sites, Dread forum, DuckDuckGo dorks on pastebin / breach forums /
    stealer-log mentions, blockchain.info (for BTC), and more.

    Returns a JSON summary with how many probes ran, how many had hits, and
    the per-source findings with raw matched fragments.

    Use this when the user gives a single PII value and asks "has this been
    leaked?" or "where does this appear?". For investigations that should
    follow multiple hops, use `investigate` instead.
    """
    from pii_lookup import lookup
    return _trim(lookup(value))


@tool
def investigate(seed: str, max_depth: int = 2, max_nodes: int = 20) -> str:
    """Multi-hop OSINT investigation: trace the seed, then auto-pivot.

    Starts from any PII value and traces it via `trace_pii`. Then, from the
    traces returned, automatically extracts new candidates (email -> domain,
    domain -> subdomains, Gravatar -> linked usernames, raw Telegram/dark-web
    matches -> new emails/domains) and re-investigates each, up to `max_depth`
    hops and `max_nodes` total nodes.

    Use this when the user asks "build a picture of X" or "find everything
    you can about X". Far more expensive than `trace_pii` (each node spawns
    a full multi-source probe), so cap depth/nodes sensibly.
    """
    from pivot import investigate as _inv, to_dict
    root = _inv(seed, max_depth=max_depth, max_nodes=max_nodes)
    return _trim(to_dict(root))


@tool
def search_darkweb(query: str) -> str:
    """Search exactly the query string across:

    - 11 dark-web search engines (Ahmia, Tor66, Torch v3, Haystack, OnionLand,
      Excavator, Tornado, Amnesia, Kaizer, The Deep Searches, OnionSearchEngine)
    - All currently-active ransomware leak sites (auto-discovered from
      ransomware.live)
    - The Dread forum

    For each promising hit, fetches the page through Tor (or HTTPS for
    clearnet) and grep ±400 chars around the literal match (raw fragment).

    Use this when the user wants a one-shot dark-web pulse on a keyword or
    PII value, without the full multi-source trace.
    """
    from darkweb_extras import darkweb_pii_search
    hits = darkweb_pii_search(query)
    return _trim({"count": len(hits), "hits": hits[:15]})


@tool
def search_telegram(query: str) -> str:
    """Search Telegram for the literal query.

    Sources:
    - tgstat.com post search (indexer)
    - tgstat.com channel search
    - Live-discovered channels for THIS specific value (channels that have
      already indexed the value)
    - Auto-discovered topic channels (stealer-logs / combolist / leak base /
      breach forums...)
    - User-curated channels from $ROBIN_TELEGRAM_CHANNELS_FILE
    - DuckDuckGo dorks limited to site:t.me OR site:tgstat.com

    Each hit includes the channel handle and raw ±200 chars around the match.
    """
    from telegram_sources import search_telegram as _st
    hits = _st(query)
    return _trim({"count": len(hits), "hits": hits[:15]})


@tool
def check_pwned_password(password: str) -> str:
    """Check if a password appears in HaveIBeenPwned's leak corpus using
    k-anonymity (only the first 5 chars of the SHA-1 hash leave the machine).

    Returns whether it was found and the seen-count (how many times this
    password has shown up in known breaches). Use this when the user gives
    a password and asks "is this safe / has this leaked?".

    NEVER include the plaintext password in any later response — refer to it
    only as "your password".
    """
    from password_check import check_password
    return _trim(check_password(password))


@tool
def email_recon(name: str, domain: str, smtp_probe: bool = False) -> str:
    """Generate likely email addresses for `name` at `domain` and probe each.

    Generates ~20 patterns (`first.last`, `flast`, `last.first`, `firstl`...),
    checks MX records, runs HudsonRock infostealer lookup on every candidate
    (a positive HudsonRock signal is strong evidence the address exists), and
    on confirmed candidates traces them through dark web + Telegram for raw
    evidence. Optional SMTP RCPT TO probe (unreliable on accept-all servers).

    Use this when the user gives a person's name + a company.
    """
    from email_recon import recon
    return _trim(recon(name, domain, smtp_probe_enabled=smtp_probe))


@tool
def wayback_snapshots(target: str, limit: int = 15) -> str:
    """List Wayback Machine snapshots of a URL or domain (newest first).

    Useful for finding older versions of pages (team rosters, contact pages)
    that may expose contact info no longer on the live site.
    """
    from wayback import snapshots
    return _trim({"snapshots": snapshots(target, limit=limit)})


@tool
def wayback_search(domain: str, query: str) -> str:
    """Grep Wayback Machine archives of `domain` for a literal `query` string.

    Fetches up to 10 recent archived pages of common paths (root, /team,
    /about, /contact, /staff, /sitemap.xml) and returns raw ±200 chars
    around each match. Excellent for finding contact emails that used to be
    on a website but were since removed.
    """
    from wayback import search_archived_content
    hits = search_archived_content(domain, query, max_snapshots=10)
    return _trim({"matches": hits, "count": len(hits)})


@tool
def enrich_domain(domain: str) -> str:
    """Resolve a domain to A records, RDAP WHOIS data, and crt.sh subdomains.

    Use after finding a new domain to expand the investigation surface.
    """
    from enrichment import enrich_domain as _ed
    return _trim(_ed(domain))


@tool
def enrich_ip(ip: str) -> str:
    """Reverse-DNS + geo (country/city/org/ASN via ipapi.co) + AbuseIPDB
    abuse score for an IP address."""
    from enrichment import enrich_ip as _ei
    return _trim(_ei(ip))


@tool
def enrich_hash(file_hash: str) -> str:
    """Lookup an MD5/SHA1/SHA256 file hash in MalwareBazaar (malware family,
    tags, first-seen) and CIRCL hashlookup (known-good NSRL database)."""
    from enrichment import enrich_hash as _eh
    return _trim(_eh(file_hash))


@tool
def enrich_cve(cve_id: str) -> str:
    """Pull a CVE description and CVSS score from NVD."""
    from enrichment import enrich_cve as _ec
    return _trim(_ec(cve_id))


@tool
def ransomware_victim_search(name: str) -> str:
    """Search all currently-active ransomware leak sites for victims matching
    `name`. Uses ransomware.live's live group list, then scrapes each leak
    site landing page for the keyword.

    Use this when the user asks "is COMPANY listed by any ransomware group?".
    """
    from darkweb_extras import search_ransomware_groups
    hits = search_ransomware_groups(name)
    return _trim({"victims_found": len(hits), "hits": hits[:15]})


@tool
def extract_iocs_from_text(text: str) -> str:
    """Extract structured IOCs from a blob of text: emails, IPs (validated),
    domains (TLD-validated), BTC/ETH/Monero, MD5/SHA1/SHA256, CVEs, JWTs,
    AWS access keys, GitHub PATs, Telegram handles, .onion addresses,
    phone numbers.

    Use after fetching a forum thread or paste-bin content to structure it.
    """
    from iocs import extract_indicators
    return _trim(extract_indicators({"_": text}))


@tool
def local_db_check(email: str) -> str:
    """Look up an email in the user's local breach database (SQLite).

    The local DB is a self-hosted index of breach dumps the user has ingested
    via `argus db ingest`. Highest trust — it's their own data. Returns
    breach names, years, data classes, and masked credentials per breach.
    """
    from local_breach_db import check_email, get_credentials
    breaches = check_email(email)
    if not breaches:
        return _trim({"found": False, "msg": "Not in local DB"})
    return _trim({
        "found": True,
        "breaches": breaches,
        "credentials_sample": get_credentials(email)[:10],
    })


@tool
def local_db_domain_emails(domain: str, limit: int = 50) -> str:
    """Enumerate every breached email at `domain` in the local breach DB.

    Use this to map an organization's exposed accounts. Returns emails with
    breach counts and which breaches they appeared in.
    """
    from local_breach_db import search_domain
    return _trim({"domain": domain, "rows": search_domain(domain, limit=limit)})


@tool
def local_db_stats() -> str:
    """Get a stats overview of the local breach DB: number of breaches
    ingested, total credentials, unique emails, DB size on disk."""
    from local_breach_db import stats
    return _trim(stats())


@tool
def health_check_all() -> str:
    """Check reachability of every onion search engine, dark-web extra
    (Dread, ransomware.live), and clearweb OSINT API. Use this if a previous
    tool returned suspiciously empty results."""
    from search import healthcheck_engines
    from darkweb_extras import darkweb_health
    from osint_sources import health_check
    return _trim({
        "search_engines": healthcheck_engines(timeout=6),
        "darkweb": darkweb_health(),
        "clearweb_osint": health_check(),
    })


ROBIN_TOOLS = [
    trace_pii,
    investigate,
    search_darkweb,
    search_telegram,
    check_pwned_password,
    email_recon,
    wayback_snapshots,
    wayback_search,
    enrich_domain,
    enrich_ip,
    enrich_hash,
    enrich_cve,
    ransomware_victim_search,
    extract_iocs_from_text,
    local_db_check,
    local_db_domain_emails,
    local_db_stats,
    health_check_all,
]

TOOL_MAP: Dict[str, Any] = {t.name: t for t in ROBIN_TOOLS}


# --------------------------------------------------------------------------- #
# Agent loop
# --------------------------------------------------------------------------- #

SYSTEM_PROMPT = """You are Argus, an OSINT investigation agent.

You have access to tools that query the dark web, Telegram, breach databases,
ransomware leak sites, certificate transparency, infostealer logs, Wayback
Machine archives, and IOC enrichment services.

# Workflow

1. Read the user's question carefully. Identify what they're really asking.
2. Start with the most targeted tool:
   - Single PII value (email / phone / username / hash / domain / btc / ip)
     → `trace_pii` first
   - Person's name + company → `email_recon`
   - Password safety check → `check_pwned_password`
   - "Build a picture of X" or "find everything" → `investigate` directly
3. **CRUCIAL — when `trace_pii` returns 0-2 real hits** (most "hits" being
   DDG dork false-positives, Ahmia infrastructure pages, generic articles
   that don't actually contain the value), you MUST NOT conclude yet.
   Pivot with at least 2 of the following before giving up:
     * `investigate(seed=value, max_depth=2)` — explores related domains,
       subdomains, raw matches in dark/Telegram dumps
     * `search_darkweb(value)` — direct dark-web pulse with raw extraction
     * `search_telegram(value)` — Telegram-specific pulse
     * `wayback_search(domain, value)` — for emails, also try the email's
       domain to find archived pages mentioning it
     * For emails: try the localpart as a username via
       `lookup_username` (or `trace_pii` with the localpart alone)
     * For domains: `enrich_domain` to get subdomains, then `trace_pii` on
       the most promising sub
4. Only conclude "no credible evidence" after you've actually pivoted
   and that pivot also came back empty. State exactly which sources were
   queried and which returned positively vs. dork-noise.
5. Cite specific findings (channel handles, URLs, dates, raw excerpts) so
   the user can verify. NEVER invent data.
6. If a tool returns nothing, say so plainly — don't pretend.
7. If the user asks about passwords, NEVER repeat the plaintext password.

# Quality

A good answer:
- Distinguishes true hits from dork false-positives explicitly
- Shows the raw matched fragment when you have one (≤300 chars)
- Notes which sources weren't queryable (missing API key, rate limit) so
  the user knows what's confirmed clean vs untested

# Verdict policy — STRICT

When the user asks "has X leaked / been breached":

- **Never** call the email "clean" or "no leak evidence" if neither
  `XposedOrNot` nor HIBP confirmed a clean result. Without an
  authoritative breach DB, the right verdict is "untested for
  breaches — install an authoritative source".
- **XposedOrNot is FREE and requires no key**. Argus calls it automatically
  through `trace_pii`. If the trace_pii result shows the XposedOrNot
  probe was skipped or errored, call `trace_pii` again, or fall back
  to `search_darkweb` + `search_telegram` + `wayback_search` before
  concluding.
- When XposedOrNot returns breaches, your answer MUST:
   1. List every breach with its YEAR
   2. List the **data classes leaked** for each (passwords, names, phones,
      addresses, dates of birth, IPs, …) using the raw fragment Argus
      provides
   3. Flag plaintext-password breaches as critical
   4. Suggest action items: rotate passwords reused with the email,
      enable 2FA, monitor for follow-on attacks
- Close with a clear verdict: "leaked in N breaches, see above /
  not found in any authoritative source queried / signal unclear,
  recommend manual review of <specific URL>"
"""


@dataclass
class AgentEvent:
    """One step of the agent's transcript. The UI/CLI renders these in order."""
    kind: str                   # "thought" | "tool_call" | "tool_result" | "answer" | "error"
    content: str
    tool_name: Optional[str] = None
    tool_args: Optional[Dict] = None


@dataclass
class AgentResult:
    answer: str
    events: List[AgentEvent] = field(default_factory=list)
    total_tool_calls: int = 0
    iterations: int = 0


def run_agent(
    user_question: str,
    llm,
    max_iterations: int = 8,
    on_event: Optional[Callable[[AgentEvent], None]] = None,
) -> AgentResult:
    """Run the agent loop. `llm` is any ChatModel supporting `bind_tools()`.

    `on_event` is invoked synchronously for each step so callers can stream
    progress to a CLI spinner or a Streamlit container.
    """
    llm_t = llm.bind_tools(ROBIN_TOOLS)
    messages: List[BaseMessage] = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=user_question),
    ]
    events: List[AgentEvent] = []
    total_calls = 0

    def emit(ev: AgentEvent):
        events.append(ev)
        if on_event:
            try:
                on_event(ev)
            except Exception as e:
                log.debug("on_event error: %s", e)

    for iteration in range(1, max_iterations + 1):
        try:
            response = llm_t.invoke(messages)
        except Exception as e:
            emit(AgentEvent(kind="error", content=f"LLM call failed: {e}"))
            return AgentResult(
                answer=f"[agent error] {e}", events=events,
                total_tool_calls=total_calls, iterations=iteration,
            )

        # If the model emitted both text and tool calls, surface the text as
        # a "thought" for transparency
        text = (response.content or "").strip() if isinstance(response.content, str) else ""
        if isinstance(response.content, list):
            for blk in response.content:
                if isinstance(blk, dict) and blk.get("type") == "text" and blk.get("text"):
                    text += blk["text"]
        if text:
            emit(AgentEvent(kind="thought", content=text))

        tool_calls = getattr(response, "tool_calls", None) or []
        if not tool_calls:
            # No more tool calls → this is the final answer
            emit(AgentEvent(kind="answer", content=text))
            return AgentResult(
                answer=text, events=events,
                total_tool_calls=total_calls, iterations=iteration,
            )

        messages.append(response)
        for call in tool_calls:
            name = call.get("name", "")
            args = call.get("args", {}) or {}
            call_id = call.get("id", "")
            total_calls += 1
            emit(AgentEvent(
                kind="tool_call", content=f"{name}({json.dumps(args, default=str)[:200]})",
                tool_name=name, tool_args=args,
            ))
            t = TOOL_MAP.get(name)
            if t is None:
                result_str = f"[error] Unknown tool: {name}"
            else:
                try:
                    result_str = t.invoke(args)
                except Exception as e:
                    result_str = f"[tool error] {type(e).__name__}: {e}"
            emit(AgentEvent(
                kind="tool_result", content=result_str[:_MAX_RESULT_CHARS],
                tool_name=name,
            ))
            messages.append(ToolMessage(content=result_str, tool_call_id=call_id))

    emit(AgentEvent(kind="error", content="Max iterations reached without final answer"))
    return AgentResult(
        answer="[agent: max iterations reached]", events=events,
        total_tool_calls=total_calls, iterations=max_iterations,
    )


# --------------------------------------------------------------------------- #
# Pretty printer (CLI)
# --------------------------------------------------------------------------- #

def format_event(ev: AgentEvent) -> str:
    if ev.kind == "thought":
        return f"💭 {ev.content[:400]}"
    if ev.kind == "tool_call":
        return f"🛠  {ev.tool_name}({json.dumps(ev.tool_args, default=str)[:200]})"
    if ev.kind == "tool_result":
        preview = ev.content[:200].replace("\n", " ")
        return f"   ↳ {preview}{'...' if len(ev.content) > 200 else ''}"
    if ev.kind == "answer":
        return f"\n=== Final answer ===\n{ev.content}"
    if ev.kind == "error":
        return f"❌ {ev.content}"
    return ev.content


# --------------------------------------------------------------------------- #
# Backend 2 — Claude Code via claude-agent-sdk (no API key)
# --------------------------------------------------------------------------- #

def claude_code_available() -> bool:
    """True when both the `claude` CLI and the Python claude-agent-sdk are
    installed. Claude Code's own auth (subscription) handles credentials.
    """
    if not shutil.which("claude"):
        return False
    try:
        import claude_agent_sdk  # noqa: F401
        return True
    except ImportError:
        return False


def run_agent_claude_code(
    user_question: str,
    max_iterations: int = 12,
    on_event: Optional[Callable[[AgentEvent], None]] = None,
    cwd: Optional[str] = None,
    model: Optional[str] = None,
) -> AgentResult:
    """Run the agent loop via Claude Code's local subscription.

    The Claude Code session sees Robin's tools via an in-process MCP server
    constructed from our @tool definitions. No external process, no key.
    """
    if not claude_code_available():
        raise RuntimeError(
            "Claude Code agent backend unavailable. Need both:\n"
            "  - `claude` CLI in PATH (https://docs.claude.com/claude-code)\n"
            "  - pip install claude-agent-sdk"
        )

    import asyncio
    from claude_agent_sdk import (
        query, ClaudeAgentOptions,
        create_sdk_mcp_server, tool as sdk_tool,
        AssistantMessage, ResultMessage,
    )
    try:
        from claude_agent_sdk import TextBlock, ToolUseBlock, ToolResultBlock
    except ImportError:
        TextBlock = ToolUseBlock = ToolResultBlock = None  # older SDK shape

    events: List[AgentEvent] = []

    def emit(ev: AgentEvent):
        events.append(ev)
        if on_event:
            try:
                on_event(ev)
            except Exception as e:
                log.debug("on_event error: %s", e)

    # Wrap each Robin @tool into an SDK MCP tool.
    sdk_tools = []
    for t in ROBIN_TOOLS:
        sdk_tools.append(_wrap_langchain_tool_for_sdk(t, sdk_tool))

    robin_mcp = create_sdk_mcp_server(
        name="robin", version="1.0.0", tools=sdk_tools,
    )

    # Allow our tools by name; Claude Code will use them autonomously
    allowed = [f"mcp__robin__{t.name}" for t in ROBIN_TOOLS]

    options_kwargs = dict(
        cwd=cwd or os.getcwd(),
        mcp_servers={"robin": robin_mcp},
        allowed_tools=allowed,
        system_prompt={"type": "preset", "preset": "claude_code",
                       "append": SYSTEM_PROMPT},
        max_turns=max_iterations,
        permission_mode="bypassPermissions",  # tools are local read-only OSINT
    )
    # If a model is explicitly requested and looks like a Claude model, pass it
    if model and model.lower().startswith("claude"):
        options_kwargs["model"] = model
    options = ClaudeAgentOptions(**options_kwargs)

    async def _drive():
        total_calls = 0
        final_text = ""
        async for message in query(prompt=user_question, options=options):
            cls_name = type(message).__name__
            if isinstance(message, AssistantMessage):
                blocks = getattr(message, "content", None) or []
                for blk in blocks:
                    btype = type(blk).__name__
                    if btype == "TextBlock":
                        emit(AgentEvent(kind="thought", content=blk.text))
                        final_text = blk.text
                    elif btype == "ToolUseBlock":
                        total_calls += 1
                        emit(AgentEvent(
                            kind="tool_call",
                            content=str(blk.input)[:200],
                            tool_name=getattr(blk, "name", "?")
                                .replace("mcp__robin__", ""),
                            tool_args=getattr(blk, "input", {}) or {},
                        ))
                    elif btype == "ToolResultBlock":
                        result_text = ""
                        content_attr = getattr(blk, "content", "")
                        if isinstance(content_attr, list):
                            for c in content_attr:
                                if isinstance(c, dict):
                                    result_text += c.get("text", "")
                                else:
                                    result_text += str(c)
                        else:
                            result_text = str(content_attr or "")
                        emit(AgentEvent(
                            kind="tool_result",
                            content=result_text[:_MAX_RESULT_CHARS],
                        ))
            elif isinstance(message, ResultMessage):
                # End-of-turn marker
                pass
        return AgentResult(answer=final_text, events=events,
                           total_tool_calls=total_calls, iterations=0)

    try:
        return asyncio.run(_drive())
    except RuntimeError as e:
        # Streamlit / Jupyter already have a running loop
        if "already running" in str(e).lower():
            import nest_asyncio
            nest_asyncio.apply()
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(_drive())
        raise


def _wrap_langchain_tool_for_sdk(lc_tool, sdk_tool_decorator):
    """Convert a LangChain @tool into a claude-agent-sdk tool.

    The SDK expects `@tool("name", "desc", schema)` returning an async
    function whose return is `{"content": [{"type": "text", "text": str}]}`.
    """
    name = lc_tool.name
    description = (lc_tool.description or name).strip()
    schema = _lc_tool_input_schema(lc_tool)

    @sdk_tool_decorator(name, description, schema)
    async def _handler(args: dict):
        try:
            result = lc_tool.invoke(args)
        except Exception as e:
            result = f"[tool error] {type(e).__name__}: {e}"
        return {"content": [{"type": "text", "text": str(result)}]}

    return _handler


def _lc_tool_input_schema(lc_tool) -> dict:
    """Translate a LangChain tool's args_schema into a flat name->type dict
    that claude-agent-sdk understands.
    """
    schema = getattr(lc_tool, "args_schema", None)
    if schema is None:
        return {}
    try:
        # Pydantic v2: model_fields
        fields = getattr(schema, "model_fields", None)
        if fields:
            out = {}
            for fname, f in fields.items():
                # f.annotation is the python type
                py_type = getattr(f, "annotation", str) or str
                out[fname] = py_type
            return out
        # Pydantic v1: __fields__
        legacy = getattr(schema, "__fields__", None)
        if legacy:
            return {fname: f.type_ for fname, f in legacy.items()}
    except Exception as e:
        log.debug("schema extract failed for %s: %s", lc_tool.name, e)
    return {}


# --------------------------------------------------------------------------- #
# Backend 3 — Codex CLI (no API key; auth via ChatGPT subscription)
# --------------------------------------------------------------------------- #

def codex_cli_available() -> bool:
    return bool(shutil.which("codex"))


def run_agent_codex_cli(
    user_question: str,
    max_iterations: int = 8,
    on_event: Optional[Callable[[AgentEvent], None]] = None,
    cwd: Optional[str] = None,
    model: Optional[str] = None,
) -> AgentResult:
    """Run the agent loop via Codex CLI's headless exec mode.

    Codex itself can call MCP tools when configured. We rely on the user
    having registered Robin's MCP server in ~/.codex/config.toml (see
    `robin mcp-install` helper). This function just shells out to `codex
    exec` with the prompt and parses the streamed JSON.
    """
    if not codex_cli_available():
        raise RuntimeError(
            "Codex CLI not in PATH. Install from "
            "https://github.com/openai/codex and run `codex login` once."
        )
    events: List[AgentEvent] = []
    total_calls = 0

    def emit(ev: AgentEvent):
        events.append(ev)
        if on_event:
            try:
                on_event(ev)
            except Exception:
                pass

    # Codex exec in JSON mode emits one JSON event per line on stdout.
    cmd = ["codex", "exec", "--json"]
    # Forward a model selection if it looks like one Codex would accept.
    if model and (model.lower().startswith("gpt-") or model.lower().startswith("o")):
        cmd.extend(["-m", model])
    cmd.append(user_question)
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=cwd, text=True, bufsize=1,
        )
    except FileNotFoundError as e:
        emit(AgentEvent(kind="error", content=str(e)))
        return AgentResult(answer="[codex unavailable]", events=events)

    final_text_parts: List[str] = []
    if proc.stdout is not None:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                final_text_parts.append(line)
                emit(AgentEvent(kind="thought", content=line))
                continue
            etype = ev.get("type") or ev.get("event") or ""
            if "tool" in etype.lower() and "call" in etype.lower():
                total_calls += 1
                emit(AgentEvent(
                    kind="tool_call",
                    content=json.dumps(ev.get("arguments") or ev.get("input") or {})[:200],
                    tool_name=ev.get("name") or ev.get("tool") or "?",
                    tool_args=ev.get("arguments") or ev.get("input"),
                ))
            elif "tool" in etype.lower() and "result" in etype.lower():
                emit(AgentEvent(
                    kind="tool_result",
                    content=str(ev.get("output") or ev.get("result") or "")[:_MAX_RESULT_CHARS],
                    tool_name=ev.get("name"),
                ))
            elif etype in ("message", "assistant", "text"):
                txt = ev.get("text") or ev.get("content") or ""
                if txt:
                    final_text_parts.append(txt)
                    emit(AgentEvent(kind="thought", content=txt))
            elif etype == "error":
                emit(AgentEvent(kind="error", content=str(ev)))
            else:
                # Unknown event — keep raw for debugging
                emit(AgentEvent(kind="thought",
                                content=f"[{etype}] {json.dumps(ev)[:200]}"))

    proc.wait()
    final = "\n".join(final_text_parts).strip()
    emit(AgentEvent(kind="answer", content=final))
    return AgentResult(answer=final, events=events,
                       total_tool_calls=total_calls, iterations=0)


# --------------------------------------------------------------------------- #
# Unified entrypoint
# --------------------------------------------------------------------------- #

def list_backends() -> Dict[str, bool]:
    """Which backends are usable right now."""
    return {
        "claude-code": claude_code_available(),
        "codex-cli": codex_cli_available(),
        "langchain": True,  # always available; needs key per-model
    }


def run(
    user_question: str,
    backend: str = "claude-code",
    llm: Any = None,
    max_iterations: int = 8,
    on_event: Optional[Callable[[AgentEvent], None]] = None,
    cwd: Optional[str] = None,
    model: Optional[str] = None,
) -> AgentResult:
    """Top-level dispatcher. Picks the right agent loop based on `backend`.

    `model` is an optional model name to forward to the chosen backend:
      - claude-code: passed via ClaudeAgentOptions(model=...) if it looks
        like a Claude model (starts with 'claude').
      - codex-cli: passed via `codex exec -m <model>` if it looks like an
        OpenAI/Codex model (starts with 'gpt-' or 'o').
      - langchain: the model is already baked into the `llm` instance.
    """
    if backend == "claude-code":
        return run_agent_claude_code(user_question, max_iterations,
                                      on_event=on_event, cwd=cwd, model=model)
    if backend == "codex-cli":
        return run_agent_codex_cli(user_question, max_iterations,
                                    on_event=on_event, cwd=cwd, model=model)
    if backend == "langchain":
        if llm is None:
            raise ValueError("LangChain backend requires an `llm` instance.")
        return run_agent(user_question, llm, max_iterations, on_event=on_event)
    raise ValueError(f"Unknown backend: {backend}")
