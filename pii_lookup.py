"""
Personal Information OSINT engine.

Given any piece of personal info (email, phone, username, full name, IP, domain,
hash, BTC address...), auto-detect its type and probe every relevant free
public service to find traces.

Each lookup function returns a `Trace` (dict) shaped:

    {
      "source": "HudsonRock",
      "found": True | False,
      "summary": "27 045 infected machines reference this email",
      "link": "https://www.hudsonrock.com/...",
      "details": {...}   # raw payload for downstream consumers
    }

`lookup(value)` returns:

    {
      "type": "email",
      "value": "...",
      "traces": [Trace, ...],
      "probes_checked": N,
      "probes_with_hits": M,
    }
"""

from __future__ import annotations

import os
import re
import json
import hashlib
import logging
from typing import Dict, List, Optional, Tuple, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote_plus

import requests

log = logging.getLogger(__name__)

UA = "robin-pii-osint/1.0 (+contact: user)"
DEFAULT_TIMEOUT = 10
SLOW_TIMEOUT = 30


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "application/json, text/html;q=0.8"})
    return s


# --------------------------------------------------------------------------- #
# Input type detection
# --------------------------------------------------------------------------- #

_EMAIL_FULL_RE = re.compile(r"^[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,24}$")
_PHONE_FULL_RE = re.compile(r"^\+?[\d\s().\-/]{6,25}$")
_IP_FULL_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HASH_FULL_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
_BTC_FULL_RE = re.compile(r"^(?:bc1[a-zA-HJ-NP-Z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
_DOMAIN_FULL_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}$"
)
_URL_FULL_RE = re.compile(r"^https?://", re.I)
_USERNAME_FULL_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
_NAME_FULL_RE = re.compile(
    r"^[A-Za-zÀ-ÖØ-öø-ÿ'\-]{2,}(?:\s+[A-Za-zÀ-ÖØ-öø-ÿ'\-]{2,}){1,4}$"
)


def detect_type(value: str) -> str:
    v = value.strip()
    if not v:
        return "unknown"
    if _URL_FULL_RE.match(v):
        return "url"
    if _EMAIL_FULL_RE.match(v):
        return "email"
    if _IP_FULL_RE.match(v):
        return "ip"
    if _HASH_FULL_RE.match(v):
        return "hash"
    if _BTC_FULL_RE.match(v):
        return "btc"
    if _DOMAIN_FULL_RE.match(v) and "." in v:
        return "domain"
    # Phone before username: phone has digits+separators, username is identifier-like.
    if _PHONE_FULL_RE.match(v) and sum(c.isdigit() for c in v) >= 7:
        return "phone"
    if _USERNAME_FULL_RE.match(v):
        return "username"
    if _NAME_FULL_RE.match(v):
        return "name"
    return "unknown"


# --------------------------------------------------------------------------- #
# EMAIL lookups
# --------------------------------------------------------------------------- #

def _hudsonrock_email(email: str) -> Dict:
    try:
        r = _session().get(
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email",
            params={"email": email}, timeout=SLOW_TIMEOUT,
        )
        if r.status_code != 200:
            return {"source": "HudsonRock", "found": False, "summary": f"HTTP {r.status_code}"}
        d = r.json()
        total = d.get("total") or 0
        stealers = d.get("stealers") or []
        if total or stealers:
            return {
                "source": "HudsonRock (infostealer logs)",
                "found": True,
                "summary": f"{total or len(stealers)} infostealer infection(s) referencing this email",
                "link": "https://www.hudsonrock.com/free-tools",
                "details": {"total": total, "stealer_samples": stealers[:3]},
            }
        return {"source": "HudsonRock (infostealer logs)", "found": False,
                "summary": "Not found in HudsonRock stealer logs"}
    except (requests.RequestException, ValueError) as e:
        return {"source": "HudsonRock", "found": False, "summary": f"error: {e}"}


def _emailrep(email: str) -> Dict:
    try:
        r = _session().get(
            f"https://emailrep.io/{quote_plus(email)}",
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code == 429:
            return {"source": "EmailRep.io", "found": False,
                    "summary": "rate-limited (try later or set EMAILREP_KEY)"}
        if r.status_code != 200:
            return {"source": "EmailRep.io", "found": False, "summary": f"HTTP {r.status_code}"}
        d = r.json()
        reputation = d.get("reputation", "?")
        sus = d.get("suspicious", False)
        details = d.get("details", {}) or {}
        profiles = details.get("profiles") or []
        days_old = details.get("days_since_domain_creation", "?")
        blacklisted = details.get("blacklisted")
        data_breach = details.get("data_breach")
        summary = (
            f"reputation={reputation} suspicious={sus} "
            f"days_since_domain_creation={days_old} blacklisted={blacklisted} "
            f"data_breach={data_breach} profiles_seen={len(profiles)}"
        )
        return {
            "source": "EmailRep.io",
            "found": bool(data_breach) or bool(profiles) or bool(blacklisted),
            "summary": summary,
            "details": {"profiles": profiles, **details},
        }
    except (requests.RequestException, ValueError) as e:
        return {"source": "EmailRep.io", "found": False, "summary": f"error: {e}"}


def _hibp_account(email: str) -> Dict:
    """Requires HIBP_API_KEY env (paid). Endpoint returns the breaches list."""
    key = os.getenv("HIBP_API_KEY")
    if not key:
        return {"source": "HaveIBeenPwned", "found": False,
                "summary": "Skipped (set HIBP_API_KEY env to enable)"}
    try:
        r = _session().get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote_plus(email)}",
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": key, "User-Agent": "robin-osint-tool"},
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code == 404:
            return {"source": "HaveIBeenPwned", "found": False, "summary": "No breach"}
        if r.status_code != 200:
            return {"source": "HaveIBeenPwned", "found": False, "summary": f"HTTP {r.status_code}"}
        breaches = r.json()
        names = [b.get("Name") for b in breaches]
        return {
            "source": "HaveIBeenPwned",
            "found": True,
            "summary": f"Pwned in {len(breaches)} breach(es): {', '.join(names[:8])}",
            "details": {"breaches": breaches},
        }
    except (requests.RequestException, ValueError) as e:
        return {"source": "HaveIBeenPwned", "found": False, "summary": f"error: {e}"}


def _gravatar(email: str) -> Dict:
    """Gravatar.com derives a profile from md5(email.lower()). Real-world hit
    rate is low but a positive is a strong signal of where the email is used.
    """
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/{h}.json"
    try:
        r = _session().get(url, timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:
            return {"source": "Gravatar", "found": False, "summary": "no profile"}
        d = r.json()
        entry = (d.get("entry") or [{}])[0]
        accounts = [a.get("url") for a in (entry.get("accounts") or [])]
        return {
            "source": "Gravatar",
            "found": True,
            "summary": (entry.get("preferredUsername") or "profile exists") +
                       (f" — {len(accounts)} linked account(s)" if accounts else ""),
            "link": entry.get("profileUrl"),
            "details": {"linked_accounts": accounts, "name": entry.get("displayName")},
        }
    except (requests.RequestException, ValueError) as e:
        return {"source": "Gravatar", "found": False, "summary": f"error: {e}"}


def _ddg_dork(query: str, dork: str, label: str, limit: int = 5) -> Dict:
    """Run a DuckDuckGo HTML query and ONLY count hits whose title+snippet
    actually contain the literal `query` value. Drops the common false-positive
    case where DDG ranks unrelated pages because the dork side matched.
    """
    try:
        r = _session().post(
            "https://html.duckduckgo.com/html/",
            data={"q": f'"{query}" {dork}'},
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code != 200:
            return {"source": f"DDG dork [{label}]", "found": False,
                    "summary": f"HTTP {r.status_code}"}
        from bs4 import BeautifulSoup
        from urllib.parse import unquote
        soup = BeautifulSoup(r.text, "html.parser")
        hits_kept: List[Dict] = []
        hits_discarded = 0
        q_lower = query.lower()

        for result in soup.select("div.result")[: limit * 4]:
            a = result.select_one("a.result__a")
            if not a:
                continue
            href = a.get("href", "")
            m = re.search(r"uddg=([^&]+)", href)
            if m:
                href = unquote(m.group(1))
            title = a.get_text(strip=True)
            snippet_tag = result.select_one(".result__snippet")
            snippet = snippet_tag.get_text(" ", strip=True) if snippet_tag else ""
            haystack = f"{title} {snippet}".lower()

            if q_lower in haystack:
                hits_kept.append({"title": title, "url": href, "snippet": snippet[:300]})
                if len(hits_kept) >= limit:
                    break
            else:
                hits_discarded += 1

        summary_parts: List[str] = []
        if hits_kept:
            summary_parts.append(f"{len(hits_kept)} confirmed mention(s)")
        if hits_discarded:
            summary_parts.append(f"{hits_discarded} dork match(es) without the value")
        if not summary_parts:
            summary_parts.append("no results")

        return {
            "source": f"DDG dork [{label}]",
            "found": bool(hits_kept),
            "summary": " · ".join(summary_parts),
            "details": {
                "hits": hits_kept,
                "discarded_count": hits_discarded,
                "query": f'"{query}" {dork}',
            },
        }
    except requests.RequestException as e:
        return {"source": f"DDG dork [{label}]", "found": False,
                "summary": f"error: {e}"}


def _telegram_probe(value: str) -> Dict:
    """Aggregate Telegram channels/posts containing the literal value."""
    from telegram_sources import search_telegram
    hits = search_telegram(value)
    return _hits_to_trace(hits, source_name="Telegram (tgstat + t.me)",
                          summary_template="{n} Telegram post/channel mention(s)")


def _darkweb_probe(value: str) -> Dict:
    """Aggregate dark-web hits (onion engines + leak sites + Dread) with raw context."""
    from darkweb_extras import darkweb_pii_search
    hits = darkweb_pii_search(value)
    return _hits_to_trace(hits, source_name="Dark web (engines + leak sites + Dread)",
                          summary_template="{n} dark-web hit(s) (raw matches when scrapeable)")


def _hits_to_trace(hits: List[Dict], source_name: str,
                   summary_template: str = "{n} hit(s)") -> Dict:
    """Convert a list of hit dicts into a single Trace dict."""
    hits = hits or []
    return {
        "source": source_name,
        "found": bool(hits),
        "summary": summary_template.format(n=len(hits)) if hits
                   else "no matches in this source set",
        "details": {"hits": [
            {
                "title": h.get("title", ""),
                "url": h.get("link", ""),
                "raw": h.get("raw", h.get("snippet", ""))[:600],
                "channel": h.get("channel", ""),
                "engine": h.get("source", h.get("engine", "")),
            }
            for h in hits[:25]
        ]},
    }


def _local_db_probe(email: str) -> Dict:
    """Lookup the user's local breach DB. Highest-trust source — it's data
    they ingested themselves."""
    try:
        from local_breach_db import check_email, get_credentials
        breaches = check_email(email)
    except Exception as e:
        return {"source": "Local breach DB", "found": False,
                "summary": f"error: {e}"}
    if not breaches:
        return {"source": "Local breach DB", "found": False,
                "summary": "Not in any locally ingested breach"}
    creds = get_credentials(email, plaintext=False)
    hits = []
    for b in breaches:
        hits.append({
            "title": (f"[LocalDB] {b['breach']} ({b['year']}) — "
                      f"{b['your_credentials_count']} row(s), "
                      f"{b['passwords_present']} with password"),
            "url": f"argus://local-db/breach/{b['breach']}",
            "raw": (
                f"breach     : {b['breach']} ({b['year']})\n"
                f"domain     : {b['domain'] or 'n/a'}\n"
                f"data       : {b['data_classes'] or 'n/a'}\n"
                f"your rows  : {b['your_credentials_count']}\n"
                f"passwords  : {b['passwords_present']} present (masked)\n"
                f"summary    : {(b['description'] or '')[:200]}"
            ),
            "engine": "local-db",
        })
    # Show the masked credentials as well
    for c in creds[:10]:
        hits.append({
            "title": f"[LocalDB] credential from {c['breach']} ({c['year']})",
            "url": "argus://local-db",
            "raw": f"{email}:{c['password']}",
            "engine": "local-db",
        })
    return {
        "source": "Local breach DB",
        "found": True,
        "summary": (f"Found in {len(breaches)} local breach(es), "
                    f"{len(creds)} credential row(s) — your own corpus"),
        "details": {"hits": hits},
    }


def _leakcheck_public_probe(email: str) -> Dict:
    from osint_sources import leakcheck_public
    hits = leakcheck_public(email)
    if not hits:
        return {"source": "LeakCheck.io (public)", "found": False,
                "summary": "Not in LeakCheck.io public index"}
    return {
        "source": "LeakCheck.io (public, free)",
        "found": True,
        "summary": hits[0]["title"].replace("[LeakCheck.io public] ", ""),
        "details": {"hits": [
            {"title": h["title"], "url": h.get("link", ""),
             "raw": h.get("raw", ""), "engine": "leakcheck-public"}
            for h in hits
        ]},
    }


def _leakcheck_api_probe(email: str) -> Dict:
    from osint_sources import leakcheck_api
    hits = leakcheck_api(email)
    if not hits:
        if not os.getenv("LEAKCHECK_API_KEY"):
            return {"source": "LeakCheck.io API", "found": False,
                    "summary": "Skipped (set LEAKCHECK_API_KEY for actual values)"}
        return {"source": "LeakCheck.io API", "found": False,
                "summary": "No paid LeakCheck.io records"}
    return {
        "source": "LeakCheck.io API (paid — actual values)",
        "found": True,
        "summary": f"{len(hits)} records with full field values returned",
        "details": {"hits": [
            {"title": h["title"], "url": h.get("link", ""),
             "raw": h.get("raw", ""), "engine": "leakcheck-api"}
            for h in hits
        ]},
    }


def _dehashed_probe(email: str) -> Dict:
    from osint_sources import dehashed_search
    hits = dehashed_search(email)
    if not hits:
        if not (os.getenv("DEHASHED_API_KEY") and os.getenv("DEHASHED_EMAIL")):
            return {"source": "DeHashed", "found": False,
                    "summary": "Skipped (set DEHASHED_API_KEY + DEHASHED_EMAIL)"}
        return {"source": "DeHashed", "found": False,
                "summary": "No DeHashed records"}
    return {
        "source": "DeHashed (paid — actual values)",
        "found": True,
        "summary": f"{len(hits)} records with passwords/IPs/names/addresses",
        "details": {"hits": [
            {"title": h["title"], "url": h.get("link", ""),
             "raw": h.get("raw", ""), "engine": "dehashed"}
            for h in hits
        ]},
    }


def _snusbase_probe(email: str) -> Dict:
    from osint_sources import snusbase_search
    hits = snusbase_search(email)
    if not hits:
        if not os.getenv("SNUSBASE_API_KEY"):
            return {"source": "Snusbase", "found": False,
                    "summary": "Skipped (set SNUSBASE_API_KEY)"}
        return {"source": "Snusbase", "found": False,
                "summary": "No Snusbase records"}
    return {
        "source": "Snusbase (paid — actual values)",
        "found": True,
        "summary": f"{len(hits)} records across the Snusbase corpus",
        "details": {"hits": [
            {"title": h["title"], "url": h.get("link", ""),
             "raw": h.get("raw", ""), "engine": "snusbase"}
            for h in hits
        ]},
    }


def _intelx_probe(email: str) -> Dict:
    from osint_sources import intelx_search
    hits = intelx_search(email)
    if not hits:
        if not os.getenv("INTELX_API_KEY"):
            return {"source": "IntelX", "found": False,
                    "summary": "Skipped (set INTELX_API_KEY for fragments)"}
        return {"source": "IntelX", "found": False, "summary": "No IntelX hits"}
    return {
        "source": "IntelX (free tier — record fragments)",
        "found": True,
        "summary": f"{len(hits)} archived items reference this email",
        "details": {"hits": [
            {"title": h["title"], "url": h.get("link", ""),
             "raw": h.get("raw", ""), "engine": "intelx"}
            for h in hits
        ]},
    }


def _xposedornot_probe(email: str) -> Dict:
    """Authoritative free breach lookup via xposedornot.com /breach-analytics."""
    from osint_sources import xposedornot_email
    hits = xposedornot_email(email)
    # Anything that isn't the aggregate summary card counts as a breach hit
    breach_hits = [h for h in hits
                   if not (h.get("details") or {}).get("summary")]
    if hits:
        return {
            "source": "XposedOrNot (free breach DB)",
            "found": True,
            "summary": (f"Found in {len(breach_hits)} known breach(es) "
                        "— full data classes returned"),
            "details": {"hits": [
                {
                    "title": h["title"],
                    "url": h.get("link", ""),
                    "raw": h.get("raw", ""),
                    "engine": "xposedornot",
                } for h in hits
            ]},
        }
    return {
        "source": "XposedOrNot (free breach DB)",
        "found": False,
        "summary": "Not found in XposedOrNot breach corpus",
    }


def _proxynova_probe(email: str) -> Dict:
    """Public combolist search — returns email:password lines (masked)."""
    from osint_sources import proxynova_combolist
    hits = proxynova_combolist(email)
    if hits:
        return {
            "source": "ProxyNova combolists (public)",
            "found": True,
            "summary": hits[0].get("title", ""),
            "details": {"hits": [
                {
                    "title": h["title"], "url": h.get("link", ""),
                    "raw": h.get("raw", ""), "engine": "proxynova",
                } for h in hits
            ]},
        }
    return {
        "source": "ProxyNova combolists (public)",
        "found": False,
        "summary": "Email not found in ProxyNova combolist corpus",
    }


def lookup_email(email: str) -> List[Dict]:
    """All lookups for an email, run in parallel.

    Authoritative sources (free) are checked FIRST: XposedOrNot (HIBP-style)
    and ProxyNova (combolists with plaintext credentials). These determine
    the verdict; the other probes add context.
    """
    probes: List[Tuple[str, Callable[[], Dict]]] = [
        # Your own local breach DB (highest trust — your data, exact records)
        ("local-db", lambda: _local_db_probe(email)),
        # Commercial APIs that return ACTUAL record values (need API keys)
        ("leakcheck-api", lambda: _leakcheck_api_probe(email)),
        ("dehashed", lambda: _dehashed_probe(email)),
        ("snusbase", lambda: _snusbase_probe(email)),
        ("intelx", lambda: _intelx_probe(email)),
        # Free authoritative breach databases (metadata only)
        ("xposedornot", lambda: _xposedornot_probe(email)),
        ("leakcheck-public", lambda: _leakcheck_public_probe(email)),
        ("proxynova", lambda: _proxynova_probe(email)),
        # Stealer / paid context
        ("hudsonrock", lambda: _hudsonrock_email(email)),
        ("hibp", lambda: _hibp_account(email)),
        # Identity / reputation context
        ("emailrep", lambda: _emailrep(email)),
        ("gravatar", lambda: _gravatar(email)),
        # Live search across channels
        ("telegram", lambda: _telegram_probe(email)),
        ("darkweb", lambda: _darkweb_probe(email)),
        # DDG dorks
        ("ddg-pastebin", lambda: _ddg_dork(email, "site:pastebin.com OR site:rentry.co OR site:ghostbin.com", "pastebin")),
        ("ddg-forums", lambda: _ddg_dork(email, "site:breachforums.is OR site:exposed.vc OR site:cracked.io OR site:nulled.to", "breach-forums")),
        ("ddg-stealer", lambda: _ddg_dork(email, "stealer logs OR cookies leak OR combolist", "stealer-mentions")),
    ]
    return _run_probes(probes)


# --------------------------------------------------------------------------- #
# PHONE lookups
# --------------------------------------------------------------------------- #

def _normalize_phone(phone: str) -> List[str]:
    """Generate multiple search variants of the phone number."""
    digits = re.sub(r"\D", "", phone)
    variants = {digits}
    if len(digits) >= 9:
        variants.add(f"+{digits}")
        variants.add(phone.strip())
        # French-style 06 12 34 56 78
        if len(digits) >= 10:
            spaced = " ".join(digits[i:i+2] for i in range(0, len(digits), 2))
            variants.add(spaced)
            dashed = "-".join(digits[i:i+2] for i in range(0, len(digits), 2))
            variants.add(dashed)
    return [v for v in variants if v]


def lookup_phone(phone: str) -> List[Dict]:
    variants = _normalize_phone(phone)
    # Telegram + dark web on the canonical variant (most likely to match)
    canonical = variants[0]
    probes: List[Tuple[str, Callable[[], Dict]]] = [
        ("telegram", lambda: _telegram_probe(canonical)),
        ("darkweb",  lambda: _darkweb_probe(canonical)),
    ]
    for v in variants[:3]:
        probes.append((f"ddg-tel-{v}", lambda v=v: _ddg_dork(v, "", f"web:{v}")))
        probes.append((f"ddg-tel-paste-{v}", lambda v=v: _ddg_dork(v, "site:pastebin.com OR site:rentry.co", f"pastes:{v}")))
        probes.append((f"ddg-tel-fraud-{v}", lambda v=v: _ddg_dork(v, "scam OR fraud OR arnaque", f"fraud-reports:{v}")))
    return _run_probes(probes)


# --------------------------------------------------------------------------- #
# USERNAME lookups
# --------------------------------------------------------------------------- #

# Curated high-signal services. Each entry: (name, URL template, "exists" check)
USERNAME_PROBES: List[Tuple[str, str, Callable[[requests.Response], bool]]] = [
    ("GitHub",     "https://api.github.com/users/{u}",                   lambda r: r.status_code == 200),
    ("GitLab",     "https://gitlab.com/api/v4/users?username={u}",       lambda r: r.status_code == 200 and bool(r.json())),
    ("Reddit",     "https://www.reddit.com/user/{u}/about.json",         lambda r: r.status_code == 200 and r.json().get("data", {}).get("name", "").lower() == "{u}".lower()),
    ("HackerNews", "https://hacker-news.firebaseio.com/v0/user/{u}.json", lambda r: r.status_code == 200 and r.text not in ("null", "")),
    ("Keybase",    "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}", lambda r: r.status_code == 200 and bool(r.json().get("them"))),
    ("Telegram",   "https://t.me/{u}",                                    lambda r: r.status_code == 200 and "tgme_page_title" in r.text and "If you have Telegram" not in r.text[:600]),
    ("Pastebin",   "https://pastebin.com/u/{u}",                          lambda r: r.status_code == 200 and "Not Found" not in r.text),
    ("Twitch",     "https://www.twitch.tv/{u}",                           lambda r: r.status_code == 200),
    ("Medium",     "https://medium.com/@{u}",                             lambda r: r.status_code == 200),
    ("DEV.to",     "https://dev.to/{u}",                                  lambda r: r.status_code == 200),
    ("Mastodon",   "https://mastodon.social/@{u}",                        lambda r: r.status_code == 200),
    ("Patreon",    "https://www.patreon.com/{u}",                         lambda r: r.status_code == 200),
    ("Lobsters",   "https://lobste.rs/u/{u}",                             lambda r: r.status_code == 200),
    ("Imgur",      "https://imgur.com/user/{u}",                          lambda r: r.status_code == 200),
    ("ProductHunt","https://www.producthunt.com/@{u}",                    lambda r: r.status_code == 200),
]


def _probe_username(username: str, entry: Tuple) -> Dict:
    name, tpl, check = entry
    url = tpl.format(u=quote_plus(username))
    try:
        r = _session().get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        found = False
        try:
            found = bool(check(r))
        except Exception:
            found = False
        return {
            "source": name,
            "found": found,
            "summary": (f"profile exists at {url}" if found else "not found"),
            "link": url if found else "",
        }
    except requests.RequestException as e:
        return {"source": name, "found": False, "summary": f"error: {e}"}


def _hudsonrock_username(username: str) -> Dict:
    try:
        r = _session().get(
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username",
            params={"username": username}, timeout=SLOW_TIMEOUT,
        )
        if r.status_code != 200:
            return {"source": "HudsonRock (username)", "found": False, "summary": f"HTTP {r.status_code}"}
        d = r.json()
        total = d.get("total") or 0
        if total:
            return {
                "source": "HudsonRock (username)",
                "found": True,
                "summary": f"{total} stealer log(s) reference this username",
                "details": d,
            }
        return {"source": "HudsonRock (username)", "found": False, "summary": "no stealer logs"}
    except (requests.RequestException, ValueError) as e:
        return {"source": "HudsonRock (username)", "found": False, "summary": f"error: {e}"}


def lookup_username(username: str) -> List[Dict]:
    probes: List[Tuple[str, Callable[[], Dict]]] = [
        ("hudsonrock-u", lambda: _hudsonrock_username(username)),
        ("telegram", lambda: _telegram_probe(username)),
        ("darkweb",  lambda: _darkweb_probe(username)),
        ("ddg-paste", lambda: _ddg_dork(username, "site:pastebin.com OR site:ghostbin.com OR site:rentry.co", "pastebin")),
        ("ddg-leaks", lambda: _ddg_dork(username, "site:breachforums.is OR site:exposed.vc OR leak OR dump", "leak-forums")),
        ("ddg-stealer", lambda: _ddg_dork(username, "stealer logs OR cookies leak OR combolist", "stealer-mentions")),
    ]
    for entry in USERNAME_PROBES:
        probes.append((entry[0], lambda e=entry: _probe_username(username, e)))
    return _run_probes(probes)


# --------------------------------------------------------------------------- #
# NAME lookups (free-text full name)
# --------------------------------------------------------------------------- #

def lookup_name(name: str) -> List[Dict]:
    probes: List[Tuple[str, Callable[[], Dict]]] = [
        ("telegram", lambda: _telegram_probe(name)),
        ("darkweb",  lambda: _darkweb_probe(name)),
        ("linkedin", lambda: _ddg_dork(name, "site:linkedin.com/in", "linkedin")),
        ("viadeo",   lambda: _ddg_dork(name, "site:viadeo.com OR site:xing.com", "viadeo")),
        ("societe",  lambda: _ddg_dork(name, "site:societe.com OR site:pappers.fr OR site:infogreffe.fr", "company-registry-fr")),
        ("companies-uk", lambda: _ddg_dork(name, "site:companieshouse.gov.uk OR site:opencorporates.com", "company-registry-uk")),
        ("pastebin", lambda: _ddg_dork(name, "site:pastebin.com OR site:rentry.co OR site:ghostbin.com", "pastebin")),
        ("breach-forums", lambda: _ddg_dork(name, "site:breachforums.is OR site:exposed.vc", "breach-forums")),
        ("press",    lambda: _ddg_dork(name, "site:lemonde.fr OR site:lefigaro.fr OR site:liberation.fr", "fr-press")),
        ("legal-fr", lambda: _ddg_dork(name, "site:legifrance.gouv.fr OR site:dalloz-actualite.fr", "legal-fr")),
    ]
    return _run_probes(probes)


# --------------------------------------------------------------------------- #
# IP / DOMAIN / HASH / BTC lookups (delegate to enrichment when possible)
# --------------------------------------------------------------------------- #

def lookup_ip(ip: str) -> List[Dict]:
    from enrichment import enrich_ip
    d = enrich_ip(ip)
    traces: List[Dict] = []
    geo = d.get("geo") or {}
    if geo:
        traces.append({
            "source": "ipapi.co",
            "found": True,
            "summary": f"{geo.get('country')}/{geo.get('city')} — ASN {geo.get('asn')} — {geo.get('org')}",
            "details": geo,
        })
    if d.get("rdns"):
        traces.append({"source": "Reverse DNS", "found": True, "summary": d["rdns"]})
    if d.get("abuse"):
        traces.append({
            "source": "AbuseIPDB",
            "found": (d["abuse"].get("abuse_score") or 0) > 0,
            "summary": f"score={d['abuse'].get('abuse_score')} reports={d['abuse'].get('reports')}",
            "details": d["abuse"],
        })
    # DDG fraud / scam mentions
    traces.append(_ddg_dork(ip, "scam OR fraud OR botnet OR malware OR C2", "fraud-reports"))
    return traces


def lookup_domain(domain: str) -> List[Dict]:
    from enrichment import enrich_domain
    from osint_sources import hudsonrock_domain, hibp_breach_catalog
    d = enrich_domain(domain)
    traces: List[Dict] = []
    if (d.get("whois") or {}).get("registered"):
        wh = d["whois"]
        traces.append({
            "source": "RDAP WHOIS",
            "found": True,
            "summary": f"Registered: {wh.get('registered')}, expires {wh.get('expires')}",
            "details": wh,
        })
    if d.get("subdomains"):
        traces.append({
            "source": "crt.sh",
            "found": True,
            "summary": f"{len(d['subdomains'])} subdomain(s) found via Certificate Transparency",
            "details": {"sample": d["subdomains"][:10]},
        })
    hr = hudsonrock_domain(domain)
    if hr:
        traces.append({
            "source": "HudsonRock (domain)",
            "found": True,
            "summary": hr[0].get("snippet", ""),
            "details": hr,
        })
    hibp_hits = hibp_breach_catalog(domain)
    if hibp_hits:
        traces.append({
            "source": "HIBP catalog",
            "found": True,
            "summary": f"{len(hibp_hits)} known breach(es) for this domain",
            "details": hibp_hits,
        })
    return traces


def lookup_hash(h: str) -> List[Dict]:
    from enrichment import enrich_hash
    d = enrich_hash(h)
    traces: List[Dict] = []
    mb = d.get("malware_bazaar") or {}
    circl = d.get("circl") or {}
    if mb.get("signature"):
        traces.append({
            "source": "MalwareBazaar",
            "found": True,
            "summary": f"{mb.get('signature')} — {', '.join(mb.get('tags') or [])}",
            "details": mb,
        })
    if circl:
        traces.append({
            "source": "CIRCL hashlookup",
            "found": True,
            "summary": (
                f"known-good ({circl.get('filename') or '?'})" if circl.get("known_good")
                else f"flagged malicious ({circl.get('product')})" if circl.get("malicious")
                else "known to CIRCL"
            ),
            "details": circl,
        })
    return traces


def lookup_btc(addr: str) -> List[Dict]:
    """Blockchain.info free API for address activity."""
    try:
        r = _session().get(f"https://blockchain.info/rawaddr/{addr}?limit=5", timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:
            return [{"source": "blockchain.info", "found": False, "summary": f"HTTP {r.status_code}"}]
        d = r.json()
        n_tx = d.get("n_tx", 0)
        balance_btc = d.get("final_balance", 0) / 1e8
        total_received = d.get("total_received", 0) / 1e8
        return [{
            "source": "blockchain.info",
            "found": n_tx > 0,
            "summary": (f"{n_tx} tx — balance {balance_btc:.6f} BTC — "
                        f"total received {total_received:.6f} BTC"),
            "link": f"https://www.blockchain.com/explorer/addresses/btc/{addr}",
            "details": {"n_tx": n_tx, "balance_btc": balance_btc},
        }]
    except (requests.RequestException, ValueError) as e:
        return [{"source": "blockchain.info", "found": False, "summary": f"error: {e}"}]


# --------------------------------------------------------------------------- #
# Dispatcher
# --------------------------------------------------------------------------- #

def _run_probes(probes: List[Tuple[str, Callable[[], Dict]]]) -> List[Dict]:
    """Execute probes in parallel. Each callable must return a Trace dict."""
    results: List[Dict] = []
    with ThreadPoolExecutor(max_workers=min(len(probes), 12)) as pool:
        future_map = {pool.submit(fn): name for name, fn in probes}
        for fut in as_completed(future_map):
            name = future_map[fut]
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({"source": name, "found": False, "summary": f"error: {e}"})
    return results


def lookup(value: str, kind: Optional[str] = None) -> Dict:
    """Top-level dispatcher: auto-detect type if `kind` not given, then probe."""
    kind = kind or detect_type(value)
    dispatch = {
        "email": lookup_email,
        "phone": lookup_phone,
        "username": lookup_username,
        "name": lookup_name,
        "ip": lookup_ip,
        "domain": lookup_domain,
        "hash": lookup_hash,
        "btc": lookup_btc,
    }
    fn = dispatch.get(kind)
    if not fn:
        return {
            "type": kind,
            "value": value,
            "traces": [],
            "probes_checked": 0,
            "probes_with_hits": 0,
            "error": (
                f"Could not auto-detect a useful lookup for '{value}'. "
                "Try a more specific format (email, phone, IP, domain, hash, username, full name)."
            ),
        }
    traces = fn(value)
    hits = [t for t in traces if t.get("found")]
    return {
        "type": kind,
        "value": value,
        "traces": traces,
        "probes_checked": len(traces),
        "probes_with_hits": len(hits),
    }


# --------------------------------------------------------------------------- #
# Pretty printer
# --------------------------------------------------------------------------- #

def format_report(result: Dict) -> str:
    lines: List[str] = []
    lines.append(f"=== PII trace report ===")
    lines.append(f"Input: {result['value']!r}")
    lines.append(f"Detected type: {result['type']}")
    lines.append(f"Probes: {result['probes_checked']} checked, {result['probes_with_hits']} with hits")
    if result.get("error"):
        lines.append(f"\n{result['error']}")
        return "\n".join(lines)

    hits = sorted(
        [t for t in result["traces"] if t.get("found")],
        key=lambda t: t.get("source", ""),
    )
    misses = [t for t in result["traces"] if not t.get("found")]

    if hits:
        lines.append("\n--- TRACES FOUND ---")
        for t in hits:
            block = [f"  ✅ [{t['source']}] {t.get('summary','')}"]
            if t.get("link"):
                block.append(f"      -> {t['link']}")
            details = t.get("details") or {}
            extra_hits = details.get("hits") if isinstance(details, dict) else None
            if extra_hits:
                for h in extra_hits[:8]:
                    block.append(f"      -> [{h.get('engine','') or 'web'}] {h.get('title','')}")
                    if h.get("url"):
                        block.append(f"         url: {h['url']}")
                    if h.get("channel"):
                        block.append(f"         channel: {h['channel']}")
                    raw = h.get("raw", "").strip()
                    if raw:
                        # Indent raw blob for readability
                        raw_short = raw[:500].replace("\n", " ")
                        block.append(f"         raw: {raw_short}")
                if len(extra_hits) > 8:
                    block.append(f"      ... and {len(extra_hits) - 8} more matches")
            lines.append("\n".join(block))
    else:
        lines.append("\nNo positive traces found across the probes that ran.")

    if misses:
        lines.append("\n--- Probes with no hit ---")
        for t in misses:
            lines.append(f"  ·  [{t['source']}] {t.get('summary','')}")

    return "\n".join(lines)
