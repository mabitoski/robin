"""
Clearweb OSINT sources that return real, structured data.

Each source exposes a `search(query)` function that returns a list of dicts:
    {"title": str, "link": str, "snippet": str, "source": str}

These complement the onion search engines in search.py. Most do not require
an API key; those that do (GitHub, IntelX) gracefully skip when the key is
missing.
"""

import os
import re
import json
import time
import logging
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15
SLOW_TIMEOUT = 60  # crt.sh, HudsonRock are notoriously slow on first hit
DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
)


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": DEFAULT_UA, "Accept": "application/json, text/html;q=0.8"})
    return s


# --------------------------------------------------------------------------- #
# Ransomware victim trackers
# --------------------------------------------------------------------------- #

def ransomware_live(query: str, limit: int = 25) -> List[Dict]:
    """Search ransomware.live for victims matching the query.

    Free public API maintained by Julien Mousqueton. Returns recent victim
    posts from ransomware leak sites.
    """
    out: List[Dict] = []
    endpoints = [
        f"https://api.ransomware.live/v2/searchvictims/{requests.utils.quote(query)}",
        # Fallback v1 endpoint kept for resilience
        f"https://api.ransomware.live/searchvictims/{requests.utils.quote(query)}",
    ]
    for url in endpoints:
        try:
            r = _session().get(url, timeout=DEFAULT_TIMEOUT)
            if r.status_code != 200:
                continue
            data = r.json()
            victims = data if isinstance(data, list) else data.get("victims", [])
            for v in victims[:limit]:
                victim_name = v.get("victim") or v.get("name") or ""
                group = v.get("group") or v.get("group_name") or "?"
                date = v.get("discovered") or v.get("attackdate") or v.get("published", "")
                description = v.get("description") or v.get("post_title") or ""
                post_url = v.get("post_url") or v.get("url") or ""
                out.append({
                    "title": f"[{group}] {victim_name} ({date})",
                    "link": post_url or f"https://www.ransomware.live/#/profiles?id={group}",
                    "snippet": description[:400],
                    "source": "ransomware.live",
                })
            if out:
                return out
        except (requests.RequestException, ValueError) as e:
            log.debug("ransomware.live error: %s", e)
            continue
    return out


def ransomware_recent_groups(query: str) -> List[Dict]:
    """List active ransomware groups whose name matches the query."""
    out: List[Dict] = []
    try:
        r = _session().get("https://api.ransomware.live/v2/groups", timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:
            return out
        groups = r.json()
        q = query.lower()
        for g in groups:
            name = (g.get("name") or "").lower()
            if q in name or name in q:
                out.append({
                    "title": f"Ransomware group: {g.get('name')}",
                    "link": (g.get("locations") or [{}])[0].get("fqdn", ""),
                    "snippet": (g.get("description") or "")[:400],
                    "source": "ransomware.live/groups",
                })
    except (requests.RequestException, ValueError) as e:
        log.debug("ransomware.live groups error: %s", e)
    return out


# --------------------------------------------------------------------------- #
# Certificate transparency (real subdomain enumeration)
# --------------------------------------------------------------------------- #

def crt_sh(query: str, limit: int = 40) -> List[Dict]:
    """Query crt.sh for certificates matching a domain or keyword.

    Excellent for finding subdomains, infra fingerprints and shadow IT.
    """
    out: List[Dict] = []
    try:
        r = _session().get(
            "https://crt.sh/",
            params={"q": query, "output": "json"},
            timeout=SLOW_TIMEOUT,
        )
        if r.status_code != 200 or not r.text.strip():
            return out
        try:
            entries = r.json()
        except ValueError:
            # crt.sh sometimes returns concatenated JSON objects
            entries = json.loads("[" + r.text.replace("}{", "},{") + "]")

        seen = set()
        for entry in entries:
            name = entry.get("name_value") or entry.get("common_name") or ""
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if not sub or sub in seen or "*" in sub:
                    continue
                seen.add(sub)
                issuer = entry.get("issuer_name", "")
                not_before = entry.get("not_before", "")
                out.append({
                    "title": sub,
                    "link": f"https://crt.sh/?id={entry.get('id', '')}",
                    "snippet": f"Issued by: {issuer} | Not before: {not_before}",
                    "source": "crt.sh",
                })
                if len(out) >= limit:
                    return out
    except requests.RequestException as e:
        log.debug("crt.sh error: %s", e)
    return out


# --------------------------------------------------------------------------- #
# HudsonRock - infostealer infection lookup (free public OSINT endpoints)
# --------------------------------------------------------------------------- #

def hudsonrock_domain(domain: str) -> List[Dict]:
    """Check if a domain appears in HudsonRock infostealer logs.

    The free Cavalier endpoint returns counts and (partially masked) lists of
    compromised internal/external URLs. We surface both.
    """
    out: List[Dict] = []
    try:
        r = _session().get(
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain",
            params={"domain": domain},
            timeout=SLOW_TIMEOUT,
        )
        if r.status_code != 200:
            return out
        data = r.json()
        total = data.get("total") or 0
        total_stealers = data.get("totalStealers") or 0
        employees = data.get("employees") or 0
        users = data.get("users") or 0
        third_parties = data.get("third_parties") or 0

        if total or employees or users:
            out.append({
                "title": f"HudsonRock infostealer summary for {domain}",
                "link": f"https://www.hudsonrock.com/threat-intelligence/{domain}",
                "snippet": (
                    f"Total infected machines referencing {domain}: {total} "
                    f"(employees={employees}, users={users}, third-parties={third_parties}). "
                    f"Across {total_stealers} stealer logs."
                ),
                "source": "hudsonrock.com",
            })

        details = (data.get("data") or {})
        for emp in (details.get("employees_urls") or [])[:10]:
            url = emp.get("url") or ""
            occ = emp.get("occurrence", "?")
            out.append({
                "title": f"Compromised internal asset ({occ} infections)",
                "link": url,
                "snippet": f"Employee credentials seen in stealer logs ({domain}).",
                "source": "hudsonrock.com",
            })
        for usr in (details.get("clients_urls") or details.get("users_urls") or [])[:10]:
            url = usr.get("url") or ""
            occ = usr.get("occurrence", "?")
            out.append({
                "title": f"Compromised client/user URL ({occ} infections)",
                "link": url,
                "snippet": f"Customer credentials seen in stealer logs ({domain}).",
                "source": "hudsonrock.com",
            })
    except (requests.RequestException, ValueError) as e:
        log.debug("hudsonrock domain error: %s", e)
    return out


def hudsonrock_email(email: str) -> List[Dict]:
    """Check if an email appears in HudsonRock infostealer logs."""
    out: List[Dict] = []
    try:
        r = _session().get(
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email",
            params={"email": email},
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code != 200:
            return out
        data = r.json()
        if data.get("stealers") or data.get("total"):
            out.append({
                "title": f"HudsonRock stealer hit: {email}",
                "link": "https://www.hudsonrock.com/free-tools",
                "snippet": f"{data.get('total', '?')} infections referencing this email.",
                "source": "hudsonrock.com",
            })
    except (requests.RequestException, ValueError) as e:
        log.debug("hudsonrock email error: %s", e)
    return out


# --------------------------------------------------------------------------- #
# XposedOrNot — FREE email breach lookup (no API key, HIBP-style)
# --------------------------------------------------------------------------- #

def xposedornot_email(email: str) -> List[Dict]:
    """Free authoritative email breach lookup via xposedornot.com.

    Uses the `/v1/breach-analytics` endpoint which returns the FULL details
    per breach (year, data classes leaked, password risk, source description).
    Falls back to the simpler `/v1/check-email/{email}` if analytics is down.

    Each hit is a Dict containing:
      title    : human-readable breach name + year
      link     : XposedOrNot breach page
      snippet  : one-line summary
      raw      : multi-line breakdown of what leaked
      source   : "xposedornot.com"
      details  : structured fields (breach, year, data classes, password_risk)
    """
    out: List[Dict] = []
    try:
        r = _session().get(
            "https://api.xposedornot.com/v1/breach-analytics",
            params={"email": email},
            timeout=DEFAULT_TIMEOUT,
            headers={"User-Agent": "argus-osint"},
        )
        if r.status_code == 404:
            return out
        if r.status_code != 200:
            log.debug("xposedornot analytics HTTP %s", r.status_code)
            return _xposedornot_simple(email)
        data = r.json()
        breaches = (data.get("ExposedBreaches") or {}).get("breaches_details") or []
        metrics = data.get("BreachMetrics") or {}
        risk = (metrics.get("risk") or [{}])[0] or {}
        pwd_strength = (metrics.get("passwords_strength") or [{}])[0] or {}
        plaintext_pwds = pwd_strength.get("PlainText", 0)
        unknown_pwds = pwd_strength.get("Unknown", 0)
        easy_pwds = pwd_strength.get("EasyToCrack", 0)
        strong_pwds = pwd_strength.get("StrongHash", 0)

        # 1) Per-breach detailed records (the main payload)
        for b in breaches:
            name = b.get("breach", "?")
            year = b.get("xposed_date", "?")
            records = b.get("xposed_records", "?")
            data_classes = b.get("xposed_data", "")
            password_risk = b.get("password_risk", "")
            details_txt = b.get("details", "")
            domain = b.get("domain", "")
            verified = "verified" if b.get("verified") == "Yes" else "unverified"

            raw_lines = [
                f"breach     : {name} ({year})",
                f"domain     : {domain or 'n/a'}",
                f"records    : {records:,}" if isinstance(records, int) else f"records    : {records}",
                f"verified   : {verified}",
                f"data leaked: {data_classes.replace(';', ', ')}",
                f"password   : {password_risk or 'n/a'}",
                f"",
                f"summary    : {details_txt}",
            ]
            out.append({
                "title": f"[XposedOrNot] {name} ({year}) — {data_classes.replace(';', ', ')}",
                "link": f"https://xposedornot.com/breach/{requests.utils.quote(name)}",
                "snippet": f"{name} ({year}) — {data_classes.replace(';', ', ')}",
                "raw": "\n".join(raw_lines),
                "source": "xposedornot.com",
                "details": {
                    "breach": name, "year": year, "records": records,
                    "data_classes": data_classes,
                    "password_risk": password_risk,
                    "domain": domain, "verified": b.get("verified"),
                },
            })

        # 2) One aggregate summary card with the overall risk
        if breaches:
            out.append({
                "title": (f"[XposedOrNot] OVERALL — {len(breaches)} breach(es), "
                          f"risk={risk.get('risk_label','?')} ({risk.get('risk_score','?')}/100)"),
                "link": f"https://xposedornot.com/email-report?email={email}",
                "snippet": (
                    f"Email appears in {len(breaches)} known breaches. "
                    f"Plaintext passwords leaked: {plaintext_pwds}. "
                    f"Easy-to-crack: {easy_pwds}. Strong hashes: {strong_pwds}. "
                    f"Unknown: {unknown_pwds}."
                ),
                "raw": (
                    f"Total breaches : {len(breaches)}\n"
                    f"Risk score     : {risk.get('risk_score','?')}/100 ({risk.get('risk_label','?')})\n"
                    f"Plaintext pwds : {plaintext_pwds}\n"
                    f"Easy-to-crack  : {easy_pwds}\n"
                    f"Strong hashes  : {strong_pwds}\n"
                    f"Unknown pwd    : {unknown_pwds}"
                ),
                "source": "xposedornot.com",
                "details": {"summary": True, "risk": risk, "passwords": pwd_strength},
            })
    except (requests.RequestException, ValueError) as e:
        log.debug("xposedornot error: %s", e)
        return _xposedornot_simple(email)
    return out


# --------------------------------------------------------------------------- #
# LeakCheck.io — free public + paid API for actual record values
# --------------------------------------------------------------------------- #

def leakcheck_public(email: str) -> List[Dict]:
    """Free LeakCheck.io public endpoint. Shows breach sources + which fields
    are present (username, password, IP, name, ...). Does NOT return actual
    values — for that you need a paid LEAKCHECK_API_KEY (see leakcheck_api).
    """
    out: List[Dict] = []
    try:
        r = _session().get(
            "https://leakcheck.io/api/public",
            params={"check": email}, timeout=DEFAULT_TIMEOUT,
            headers={"User-Agent": "argus-osint"},
        )
        if r.status_code != 200:
            return out
        data = r.json()
        if not data.get("success") or not data.get("found"):
            return out
        sources = data.get("sources") or []
        fields = data.get("fields") or []
        # Aggregate card
        out.append({
            "title": (f"[LeakCheck.io public] Found in {data['found']} record(s) "
                      f"across {len(sources)} source(s)"),
            "link": f"https://leakcheck.io/?check={requests.utils.quote(email)}",
            "snippet": (
                f"Fields present in dumps: {', '.join(fields)}. "
                f"Sources: {', '.join(s['name'] for s in sources)}."
            ),
            "source": "leakcheck.io",
            "raw": (
                f"records found: {data['found']}\n"
                f"fields leaked: {', '.join(fields)}\n"
                "sources:\n"
                + "\n".join(f"  - {s['name']}  ({s.get('date') or 'no date'})"
                            for s in sources)
            ),
        })
    except (requests.RequestException, ValueError) as e:
        log.debug("leakcheck public: %s", e)
    return out


def leakcheck_api(email: str) -> List[Dict]:
    """Paid LeakCheck.io API — returns the ACTUAL leaked record values
    (passwords, names, IPs, addresses, phones). Requires LEAKCHECK_API_KEY env.
    """
    key = os.getenv("LEAKCHECK_API_KEY")
    if not key:
        return []
    out: List[Dict] = []
    try:
        r = _session().get(
            "https://leakcheck.io/api/v2/query/" + requests.utils.quote(email),
            params={"limit": 100},
            headers={"X-API-Key": key, "User-Agent": "argus-osint"},
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code != 200:
            log.debug("leakcheck api HTTP %s: %s", r.status_code, r.text[:200])
            return out
        data = r.json()
        if not data.get("success"):
            return out
        for entry in (data.get("result") or [])[:50]:
            source_name = (entry.get("source") or {}).get("name") or "?"
            source_date = (entry.get("source") or {}).get("breach_date") or ""
            raw_fields = {
                k: v for k, v in entry.items()
                if k not in ("source",) and v
            }
            field_lines = "\n".join(f"  {k}: {v}" for k, v in raw_fields.items())
            out.append({
                "title": f"[LeakCheck.io] {source_name} ({source_date})",
                "link": "https://leakcheck.io/dashboard",
                "snippet": f"Record from {source_name}: {', '.join(raw_fields.keys())}",
                "source": "leakcheck.io",
                "raw": f"source: {source_name} ({source_date})\n{field_lines}",
            })
    except (requests.RequestException, ValueError) as e:
        log.debug("leakcheck api: %s", e)
    return out


# --------------------------------------------------------------------------- #
# DeHashed API — gives actual record values (paid, ~$5.49/mo)
# --------------------------------------------------------------------------- #

def dehashed_search(email: str) -> List[Dict]:
    """Search DeHashed for records matching `email`. Returns full record
    values (password / hashed_password / name / IP / address / phone / VIN /
    database). Requires DEHASHED_API_KEY and DEHASHED_EMAIL env vars.
    """
    key = os.getenv("DEHASHED_API_KEY")
    user = os.getenv("DEHASHED_EMAIL")
    if not (key and user):
        return []
    out: List[Dict] = []
    try:
        r = _session().get(
            "https://api.dehashed.com/search",
            params={"query": f"email:{email}", "size": 100},
            auth=(user, key),
            headers={"Accept": "application/json", "User-Agent": "argus-osint"},
            timeout=DEFAULT_TIMEOUT * 2,
        )
        if r.status_code != 200:
            log.debug("dehashed HTTP %s: %s", r.status_code, r.text[:200])
            return out
        data = r.json()
        for entry in (data.get("entries") or [])[:50]:
            db = entry.get("database_name") or "?"
            non_empty = {k: v for k, v in entry.items() if v and k != "id"}
            field_lines = "\n".join(f"  {k}: {v}" for k, v in non_empty.items())
            out.append({
                "title": f"[DeHashed] Record from {db}",
                "link": "https://www.dehashed.com/",
                "snippet": (f"Record from {db}: "
                            f"{', '.join(k for k, v in non_empty.items() if v)}"),
                "source": "dehashed.com",
                "raw": f"database: {db}\n{field_lines}",
            })
    except (requests.RequestException, ValueError) as e:
        log.debug("dehashed: %s", e)
    return out


# --------------------------------------------------------------------------- #
# Snusbase API — gives actual record values (paid, ~$30/mo)
# --------------------------------------------------------------------------- #

def snusbase_search(email: str) -> List[Dict]:
    """Search Snusbase for records matching `email`. Returns full record
    values per database. Requires SNUSBASE_API_KEY env."""
    key = os.getenv("SNUSBASE_API_KEY")
    if not key:
        return []
    out: List[Dict] = []
    try:
        r = _session().post(
            "https://api.snusbase.com/data/search",
            json={"terms": [email], "types": ["email"], "wildcard": False},
            headers={"Auth": key, "User-Agent": "argus-osint",
                     "Content-Type": "application/json"},
            timeout=DEFAULT_TIMEOUT * 2,
        )
        if r.status_code != 200:
            log.debug("snusbase HTTP %s: %s", r.status_code, r.text[:200])
            return out
        data = r.json()
        results = data.get("results") or {}
        for db_name, rows in results.items():
            for row in (rows or [])[:25]:
                non_empty = {k: v for k, v in row.items() if v}
                field_lines = "\n".join(f"  {k}: {v}" for k, v in non_empty.items())
                out.append({
                    "title": f"[Snusbase] Record from {db_name}",
                    "link": "https://snusbase.com/",
                    "snippet": f"Record from {db_name}: {', '.join(non_empty.keys())}",
                    "source": "snusbase.com",
                    "raw": f"database: {db_name}\n{field_lines}",
                })
    except (requests.RequestException, ValueError) as e:
        log.debug("snusbase: %s", e)
    return out


# --------------------------------------------------------------------------- #
# IntelX — free tier (50 searches/month) returns record fragments
# --------------------------------------------------------------------------- #

def intelx_search(email: str) -> List[Dict]:
    """Search IntelX (https://intelx.io) for records matching `email`. Returns
    matching record selectors / paste fragments. Free tier: 50 searches/month
    with an INTELX_API_KEY env."""
    key = os.getenv("INTELX_API_KEY")
    if not key:
        return []
    out: List[Dict] = []
    try:
        # Step 1: launch a search
        r = _session().post(
            "https://public.intelx.io/intelligent/search",
            json={"term": email, "buckets": [], "lookuplevel": 0,
                  "maxresults": 50, "timeout": 5, "datefrom": "", "dateto": "",
                  "sort": 4, "media": 0, "terminate": []},
            headers={"x-key": key, "User-Agent": "argus-osint"},
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code != 200:
            return out
        sid = r.json().get("id")
        if not sid:
            return out
        # Step 2: fetch results
        time.sleep(2)
        r2 = _session().get(
            "https://public.intelx.io/intelligent/search/result",
            params={"id": sid, "limit": 50, "statistics": 0, "previewlines": 8},
            headers={"x-key": key, "User-Agent": "argus-osint"},
            timeout=DEFAULT_TIMEOUT,
        )
        if r2.status_code != 200:
            return out
        records = r2.json().get("records") or []
        for rec in records[:25]:
            name = rec.get("name") or rec.get("bucket") or "?"
            date = rec.get("date") or ""
            size = rec.get("size") or "?"
            sysid = rec.get("systemid") or ""
            out.append({
                "title": f"[IntelX] {name} ({date}, {size} bytes)",
                "link": f"https://intelx.io/?did={sysid}",
                "snippet": (f"Record in IntelX archive: {name}"),
                "source": "intelx.io",
                "raw": (f"name: {name}\ndate: {date}\nsize: {size}\n"
                        f"id: {sysid}"),
            })
    except (requests.RequestException, ValueError) as e:
        log.debug("intelx: %s", e)
    return out


def _xposedornot_simple(email: str) -> List[Dict]:
    """Fallback: simple /check-email/{email} endpoint."""
    out: List[Dict] = []
    try:
        r = _session().get(
            f"https://api.xposedornot.com/v1/check-email/{requests.utils.quote(email)}",
            timeout=DEFAULT_TIMEOUT,
            headers={"User-Agent": "argus-osint"},
        )
        if r.status_code != 200:
            return out
        data = r.json()
        names: List[str] = []
        for group in (data.get("breaches") or []):
            if isinstance(group, list):
                names.extend(group)
        for n in dict.fromkeys(names):
            out.append({
                "title": f"[XposedOrNot] Breach: {n}",
                "link": f"https://xposedornot.com/breach/{n}",
                "snippet": f"{email} appears in breach '{n}'.",
                "source": "xposedornot.com",
                "raw": f"breach={n}",
            })
    except (requests.RequestException, ValueError):
        pass
    return out


# --------------------------------------------------------------------------- #
# ProxyNova combolist search — FREE plaintext combolist lookup
# --------------------------------------------------------------------------- #

def proxynova_combolist(email: str, limit: int = 25) -> List[Dict]:
    """Search public combolists indexed by proxynova.com for the email.

    Returns matching lines in the form `email:password`. ProxyNova returns
    fuzzy matches by default; we client-side filter to require the exact
    email (case-insensitive) before counting it as a hit.

    NOTE: ethical/legal grey area — this is a public web tool but the data
    originates from breaches. Use only for authorized OSINT.
    """
    out: List[Dict] = []
    try:
        r = _session().get(
            "https://api.proxynova.com/comb",
            params={"query": email, "start": 0, "limit": 200},
            timeout=DEFAULT_TIMEOUT * 2,
            headers={"User-Agent": "argus-osint"},
        )
        if r.status_code != 200:
            log.debug("proxynova HTTP %s", r.status_code)
            return out
        data = r.json()
        lines = data.get("lines") or []
        q_lower = email.lower()
        matched: List[str] = []
        for line in lines:
            if q_lower in str(line).lower():
                matched.append(line)
                if len(matched) >= limit:
                    break
        if matched:
            out.append({
                "title": f"[ProxyNova] {len(matched)} combolist line(s) match {email}",
                "link": f"https://www.proxynova.com/tools/comb/?query={requests.utils.quote(email)}",
                "snippet": (
                    f"{len(matched)} lines (email:password format) found in "
                    "public combolist corpus."
                ),
                "source": "proxynova.com",
                # Mask the password side in the raw so the UI/LLM doesn't
                # display plaintext credentials by default
                "raw": "\n".join(_mask_combolist_line(l) for l in matched[:10]),
            })
    except (requests.RequestException, ValueError) as e:
        log.debug("proxynova error: %s", e)
    return out


def _mask_combolist_line(line: str) -> str:
    """Mask the password portion of an `email:password` line."""
    if ":" not in line:
        return line
    em, _, pwd = line.partition(":")
    if not pwd:
        return line
    # Keep first and last char of password for verification context
    if len(pwd) <= 2:
        masked = "•" * len(pwd)
    else:
        masked = pwd[0] + "•" * (len(pwd) - 2) + pwd[-1]
    return f"{em}:{masked} ({len(pwd)} chars)"


# --------------------------------------------------------------------------- #
# HaveIBeenPwned - public breach catalog (no API key)
# --------------------------------------------------------------------------- #

_HIBP_CACHE: Dict[str, List[Dict]] = {}


def _hibp_breaches() -> List[Dict]:
    if "all" in _HIBP_CACHE:
        return _HIBP_CACHE["all"]
    try:
        r = _session().get(
            "https://haveibeenpwned.com/api/v3/breaches",
            timeout=DEFAULT_TIMEOUT,
            headers={"User-Agent": "robin-osint-tool"},
        )
        if r.status_code == 200:
            _HIBP_CACHE["all"] = r.json()
            return _HIBP_CACHE["all"]
    except (requests.RequestException, ValueError) as e:
        log.debug("hibp error: %s", e)
    _HIBP_CACHE["all"] = []
    return []


def hibp_breach_catalog(query: str, limit: int = 15) -> List[Dict]:
    """Search the public HIBP breach catalog by name or domain."""
    q = query.lower()
    out: List[Dict] = []
    for b in _hibp_breaches():
        name = (b.get("Name") or "").lower()
        domain = (b.get("Domain") or "").lower()
        title_match = (b.get("Title") or "").lower()
        if q in name or q in domain or q in title_match:
            out.append({
                "title": f"HIBP breach: {b.get('Title')} ({b.get('BreachDate')})",
                "link": f"https://haveibeenpwned.com/PwnedWebsites#{b.get('Name')}",
                "snippet": (
                    f"Domain: {b.get('Domain')} | Accounts: {b.get('PwnCount')} | "
                    f"Data: {', '.join(b.get('DataClasses', [])[:6])}"
                ),
                "source": "haveibeenpwned.com",
            })
            if len(out) >= limit:
                break
    return out


# --------------------------------------------------------------------------- #
# GitHub code search - public leaks / hardcoded secrets discussions
# --------------------------------------------------------------------------- #

def github_code(query: str, limit: int = 15) -> List[Dict]:
    """Search GitHub code for the query. Requires GITHUB_TOKEN env to work
    reliably; without it we degrade to GitHub's much lower unauth limits.
    """
    token = os.getenv("GITHUB_TOKEN")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    out: List[Dict] = []
    try:
        r = _session().get(
            "https://api.github.com/search/code",
            params={"q": query, "per_page": limit},
            headers=headers,
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code != 200:
            log.debug("github code status %s: %s", r.status_code, r.text[:200])
            return out
        for item in r.json().get("items", []):
            out.append({
                "title": f"GitHub: {item['repository']['full_name']}/{item['name']}",
                "link": item.get("html_url", ""),
                "snippet": item.get("path", ""),
                "source": "github.com/code",
            })
    except (requests.RequestException, ValueError) as e:
        log.debug("github error: %s", e)
    return out


# --------------------------------------------------------------------------- #
# DuckDuckGo HTML - clearweb dorking (no API key)
# --------------------------------------------------------------------------- #

def duckduckgo_dork(query: str, dork: str = "", limit: int = 20) -> List[Dict]:
    """Run a Google-style dork through DuckDuckGo's HTML endpoint.

    `dork` is appended to the query (e.g. `site:pastebin.com`).
    """
    full_query = f"{query} {dork}".strip()
    out: List[Dict] = []
    try:
        r = _session().post(
            "https://html.duckduckgo.com/html/",
            data={"q": full_query},
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code != 200:
            return out
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.select("a.result__a")[:limit]:
            href = a.get("href", "")
            # DDG wraps URLs in /l/?uddg=ENCODED
            real = re.search(r"uddg=([^&]+)", href)
            if real:
                from urllib.parse import unquote
                href = unquote(real.group(1))
            snippet_tag = a.find_parent("div").find_next("a", class_="result__snippet")
            snippet = snippet_tag.get_text(" ", strip=True) if snippet_tag else ""
            out.append({
                "title": a.get_text(strip=True),
                "link": href,
                "snippet": snippet[:300],
                "source": f"ddg:{dork or 'web'}",
            })
    except requests.RequestException as e:
        log.debug("ddg error: %s", e)
    return out


# --------------------------------------------------------------------------- #
# Aggregator
# --------------------------------------------------------------------------- #

CLEARWEB_SOURCES = {
    "ransomware.live": lambda q: ransomware_live(q) + ransomware_recent_groups(q),
    "crt.sh": crt_sh,
    "hibp": hibp_breach_catalog,
    "github": github_code,
    "ddg:pastebin": lambda q: duckduckgo_dork(q, "site:pastebin.com"),
    "ddg:ghostbin": lambda q: duckduckgo_dork(q, "site:ghostbin.com OR site:rentry.co"),
    "ddg:telegram": lambda q: duckduckgo_dork(q, "site:t.me OR site:tgstat.com"),
    "ddg:breachforum": lambda q: duckduckgo_dork(
        q, "site:breachforums.is OR site:breached.vc OR site:exposed.vc"
    ),
}


def gather_clearweb(
    query: str,
    enabled: Optional[List[str]] = None,
    max_workers: int = 8,
) -> List[Dict]:
    """Run all enabled clearweb sources in parallel and concatenate results."""
    sources = enabled or list(CLEARWEB_SOURCES.keys())
    fns = [(name, CLEARWEB_SOURCES[name]) for name in sources if name in CLEARWEB_SOURCES]

    results: List[Dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {pool.submit(fn, query): name for name, fn in fns}
        for fut in as_completed(future_map):
            name = future_map[fut]
            try:
                results.extend(fut.result() or [])
            except Exception as e:
                log.warning("OSINT source %s failed: %s", name, e)
    return results


def enrich_iocs(indicators: Dict[str, List[str]]) -> List[Dict]:
    """Run targeted lookups on extracted IOCs.

    - domains -> crt.sh + HudsonRock
    - emails  -> HudsonRock
    """
    out: List[Dict] = []
    domains = indicators.get("domains", [])[:5]
    emails = indicators.get("emails", [])[:5]

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = []
        for d in domains:
            futures.append(pool.submit(crt_sh, d, 10))
            futures.append(pool.submit(hudsonrock_domain, d))
        for e in emails:
            futures.append(pool.submit(hudsonrock_email, e))
        for f in as_completed(futures):
            try:
                out.extend(f.result() or [])
            except Exception as e:
                log.debug("enrichment error: %s", e)
    return out


def health_check(sources: Optional[List[str]] = None) -> Dict[str, bool]:
    """Quick reachability check for each clearweb source.

    Uses GET with stream=True so we only fetch headers + first byte; many of
    these APIs (HIBP, ransomware.live) return 4xx/405 to HEAD requests.
    """
    probes = {
        "ransomware.live": "https://api.ransomware.live/v2/groups",
        "crt.sh": "https://crt.sh/?q=example.com&output=json",
        "hibp": "https://haveibeenpwned.com/api/v3/breaches",
        "github": "https://api.github.com",
        "hudsonrock": "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=example.com",
        "ddg": "https://html.duckduckgo.com/html/",
    }
    if sources:
        probes = {k: v for k, v in probes.items() if k in sources}
    out: Dict[str, bool] = {}
    s = _session()
    s.headers["User-Agent"] = "robin-osint-tool"
    for name, url in probes.items():
        try:
            r = s.get(url, timeout=8, stream=True, allow_redirects=True)
            out[name] = r.status_code < 400
            r.close()
        except requests.RequestException:
            out[name] = False
    return out
