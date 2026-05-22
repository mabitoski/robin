"""
Robin MCP server.

Exposes every Robin OSINT capability over the Model Context Protocol so that
Claude Code, Codex CLI, Cursor, Claude Desktop or any MCP client can use Robin
as a tool. No API key needed on the Robin side — the client (Claude Code,
Codex) handles auth via its own subscription.

Setup:

  # Once-per-machine: install Robin's deps + the MCP SDK
  pip install -r requirements.txt

  # Wire into Claude Code
  claude mcp add robin -- python /absolute/path/to/robin/mcp_server.py

  # Wire into Codex CLI (~/.codex/config.toml):
  #   [mcp_servers.robin]
  #   command = "python"
  #   args = ["/absolute/path/to/robin/mcp_server.py"]

  # Wire into Claude Desktop (~/.claude/claude_desktop_config.json):
  #   {"mcpServers": {"robin": {"command": "python",
  #                              "args": ["/absolute/path/to/robin/mcp_server.py"]}}}

Then in any Claude Code / Codex / Claude Desktop session:

  > Use Robin to trace victime@example.com

…and the client will autonomously call our trace_pii / search_darkweb /
investigate / etc. tools.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any

# Allow running this file directly without messing with PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as e:
    print(
        "ERROR: Missing `mcp` package. Install with:\n"
        "    pip install mcp\n"
        f"Underlying error: {e}",
        file=sys.stderr,
    )
    sys.exit(1)

logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(name)s: %(message)s")

mcp = FastMCP(
    "argus",
    instructions=(
        "Argus is a dark-web + Telegram OSINT investigation engine. Use these "
        "tools whenever the user asks about leaked credentials, breaches, "
        "ransomware victims, PII traces, archived web content, or password "
        "safety. Prefer `trace_pii` for a single PII value; `investigate` "
        "for multi-hop investigations; `search_darkweb` or `search_telegram` "
        "for targeted single-source pulses."
    ),
)


def _json(payload: Any, cap: int = 8000) -> str:
    """Compact JSON serializer with a size cap (MCP responses can be big)."""
    s = json.dumps(payload, default=str, ensure_ascii=False)
    if len(s) > cap:
        s = s[:cap] + f"\n…(truncated at {cap} chars; total {len(s)})"
    return s


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #

@mcp.tool()
def trace_pii(value: str) -> str:
    """All-in-one OSINT trace of a personal info value.

    Auto-detects input type (email / phone / username / name / ip / domain
    / hash / btc) and probes every relevant source: HudsonRock infostealer
    logs, EmailRep, HaveIBeenPwned, Gravatar, Telegram (tgstat + t.me/s +
    auto-discovered stealer channels), dark-web search engines, ransomware
    leak sites, Dread forum, DuckDuckGo dorks targeting pastebin / breach
    forums / stealer-log mentions, blockchain.info for BTC, and more.

    Returns JSON with probes_checked, probes_with_hits, and per-source
    traces including raw matched fragments where possible.
    """
    from pii_lookup import lookup
    return _json(lookup(value))


@mcp.tool()
def investigate(seed: str, max_depth: int = 2, max_nodes: int = 20) -> str:
    """Multi-hop OSINT investigation: trace the seed, then auto-pivot.

    Builds a tree where each node is a PII value. Pivots include:
    email -> domain, domain -> subdomains (crt.sh), Gravatar/Keybase linked
    accounts -> usernames, raw Telegram/dark-web matches -> new emails &
    domains.

    Expensive — each node spawns a full multi-source probe. Cap max_depth
    at 2-3 and max_nodes at 25-40.
    """
    from pivot import investigate as _inv, to_dict
    root = _inv(seed, max_depth=max_depth, max_nodes=max_nodes)
    return _json(to_dict(root))


@mcp.tool()
def search_darkweb(query: str) -> str:
    """Search the literal query across 11 dark-web search engines, every
    currently-active ransomware leak site (auto-discovered from
    ransomware.live), and the Dread forum. Scrapes top results via Tor and
    returns raw ±400 chars around each match.
    """
    from darkweb_extras import darkweb_pii_search
    hits = darkweb_pii_search(query)
    return _json({"count": len(hits), "hits": hits[:15]})


@mcp.tool()
def search_telegram(query: str) -> str:
    """Search Telegram channels and posts for the literal query.

    Sources: tgstat post search, tgstat channel search, auto-discovered
    channels for this specific value, topic-discovered stealer/leak
    channels (no hardcoded list), DuckDuckGo dorks on t.me. Returns raw
    snippets with channel handles.
    """
    from telegram_sources import search_telegram as _st
    hits = _st(query)
    return _json({"count": len(hits), "hits": hits[:15]})


@mcp.tool()
def check_pwned_password(password: str) -> str:
    """Check whether a password appears in HaveIBeenPwned's leak corpus
    using k-anonymity (only the first 5 chars of the SHA-1 hash leave the
    machine; plaintext stays local).

    Returns whether it was found and how many times it has appeared across
    known breaches. NEVER repeat the plaintext password in the response.
    """
    from password_check import check_password
    return _json(check_password(password))


@mcp.tool()
def email_recon(name: str, domain: str, smtp_probe: bool = False) -> str:
    """Given a person's name + a company domain, generate ~20 likely email
    patterns and probe each. Stages: MX check, HudsonRock infostealer
    lookup on every candidate, optional SMTP RCPT TO probe, and dark-web
    + Telegram trace on confirmed candidates for raw evidence.
    """
    from email_recon import recon
    return _json(recon(name, domain, smtp_probe_enabled=smtp_probe))


@mcp.tool()
def wayback_snapshots(target: str, limit: int = 15) -> str:
    """List Wayback Machine snapshots of a URL or domain (newest first).
    Useful for finding older versions of pages (team rosters, contact
    pages) that may expose info no longer on the live site.
    """
    from wayback import snapshots
    return _json({"snapshots": snapshots(target, limit=limit)})


@mcp.tool()
def wayback_search(domain: str, query: str) -> str:
    """Grep Wayback Machine archives of `domain` for a literal `query`.
    Fetches up to 10 recent archived pages of common paths (root, /team,
    /about, /contact, /staff, /sitemap.xml) and returns raw ±200 chars
    around each match. Excellent for finding contact emails removed from
    the live site.
    """
    from wayback import search_archived_content
    hits = search_archived_content(domain, query, max_snapshots=10)
    return _json({"matches": hits, "count": len(hits)})


@mcp.tool()
def enrich_domain(domain: str) -> str:
    """Resolve a domain to A records, RDAP WHOIS data, and crt.sh
    subdomains. Use after finding a new domain to expand the attack
    surface."""
    from enrichment import enrich_domain as _ed
    return _json(_ed(domain))


@mcp.tool()
def enrich_ip(ip: str) -> str:
    """Reverse-DNS + geo (country/city/org/ASN via ipapi.co) + AbuseIPDB
    abuse score for an IP address."""
    from enrichment import enrich_ip as _ei
    return _json(_ei(ip))


@mcp.tool()
def enrich_hash(file_hash: str) -> str:
    """Lookup an MD5/SHA1/SHA256 file hash in MalwareBazaar (malware
    family, tags, first-seen) and CIRCL hashlookup (known-good NSRL
    database)."""
    from enrichment import enrich_hash as _eh
    return _json(_eh(file_hash))


@mcp.tool()
def enrich_cve(cve_id: str) -> str:
    """Pull a CVE description and CVSS score from NVD."""
    from enrichment import enrich_cve as _ec
    return _json(_ec(cve_id))


@mcp.tool()
def ransomware_victim_search(name: str) -> str:
    """Search every currently-active ransomware leak site for victims
    matching `name`. Pulls the live group list from ransomware.live, then
    scrapes each leak site landing page for the keyword."""
    from darkweb_extras import search_ransomware_groups
    hits = search_ransomware_groups(name)
    return _json({"victims_found": len(hits), "hits": hits[:15]})


@mcp.tool()
def extract_iocs_from_text(text: str) -> str:
    """Extract structured IOCs from a blob of text: emails, IPs (validated),
    domains (TLD-validated), BTC/ETH/Monero addresses, MD5/SHA1/SHA256
    hashes, CVEs, JWTs, AWS access keys, GitHub PATs, Telegram handles,
    .onion addresses, phone numbers."""
    from iocs import extract_indicators
    return _json(extract_indicators({"_": text}))


@mcp.tool()
def local_db_check(email: str) -> str:
    """Look up an email in Argus's local breach database (SQLite indexed
    dumps the user has ingested). Highest trust — self-hosted data.
    Returns breach names, years, data classes, and masked credentials."""
    from local_breach_db import check_email, get_credentials
    breaches = check_email(email)
    if not breaches:
        return _json({"found": False, "msg": "Not in local DB"})
    return _json({
        "found": True,
        "breaches": breaches,
        "credentials_sample": get_credentials(email)[:10],
    })


@mcp.tool()
def local_db_domain_emails(domain: str, limit: int = 50) -> str:
    """Enumerate every breached email at `domain` in the local breach DB."""
    from local_breach_db import search_domain
    return _json({"domain": domain, "rows": search_domain(domain, limit=limit)})


@mcp.tool()
def local_db_stats() -> str:
    """Local breach DB overview: breaches ingested, total credentials,
    unique emails, DB size on disk."""
    from local_breach_db import stats
    return _json(stats())


@mcp.tool()
def health_check_all() -> str:
    """Check reachability of every onion search engine, dark-web extra
    (Dread, ransomware.live), and clearweb OSINT API. Use this if a
    previous tool call returned suspiciously empty results."""
    from search import healthcheck_engines
    from darkweb_extras import darkweb_health
    from osint_sources import health_check
    return _json({
        "search_engines": healthcheck_engines(timeout=6),
        "darkweb": darkweb_health(),
        "clearweb_osint": health_check(),
    })


# --------------------------------------------------------------------------- #
# Resources (read-only metadata clients can list)
# --------------------------------------------------------------------------- #

@mcp.resource("argus://engines")
def list_search_engines() -> str:
    """List of configured dark-web search engines."""
    from search import list_engines
    return _json(list_engines())


@mcp.resource("argus://ransomware-sites")
def list_active_ransomware() -> str:
    """Currently active ransomware leak sites (live from ransomware.live)."""
    from darkweb_extras import active_ransomware_leak_sites
    return _json(active_ransomware_leak_sites())


@mcp.resource("argus://telegram-channels")
def list_telegram_channels() -> str:
    """Auto-discovered Telegram stealer/leak channels."""
    from telegram_sources import known_channels
    return _json(known_channels())


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    mcp.run()
