"""
Email reconnaissance: given a person's name + a company domain, generate the
most common email patterns and probe each one.

Probing strategy (cheap → expensive):
  1. MX record lookup for the domain (must exist)
  2. Generate ~25 candidate addresses from the name
  3. For each candidate, run HudsonRock email lookup (real PII signal — if
     HudsonRock has seen the address in stealer logs, it exists for sure)
  4. (Optional) SMTP RCPT TO probe — only if --smtp-probe given. Many providers
     accept-all so this is unreliable; we keep it off by default.

The function returns candidates ranked by how confident we are that the
address actually exists.
"""

from __future__ import annotations

import logging
import re
import socket
import smtplib
import unicodedata
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Pattern generation
# --------------------------------------------------------------------------- #

def _slug(s: str) -> str:
    """Strip accents, lowercase, alpha-only."""
    nfkd = unicodedata.normalize("NFKD", s)
    only_ascii = "".join(c for c in nfkd if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]", "", only_ascii.lower())


def generate_patterns(full_name: str, domain: str) -> List[str]:
    """Return a deduplicated list of plausible email addresses for the name."""
    parts = [p for p in re.split(r"\s+", full_name.strip()) if p]
    if len(parts) < 2:
        # Single name → less to work with
        first = _slug(parts[0]) if parts else ""
        return _dedupe([f"{first}@{domain}"]) if first else []
    first = _slug(parts[0])
    last = _slug(parts[-1])
    middle = "".join(_slug(p) for p in parts[1:-1]) if len(parts) > 2 else ""

    fi, li = first[:1], last[:1]
    patterns = [
        f"{first}.{last}",
        f"{first}{last}",
        f"{first}_{last}",
        f"{first}-{last}",
        f"{last}.{first}",
        f"{last}{first}",
        f"{fi}.{last}",
        f"{fi}{last}",
        f"{first}.{li}",
        f"{first}{li}",
        f"{last}.{fi}",
        f"{last}{fi}",
        f"{first}",
        f"{last}",
        f"{fi}{last}",
        f"{first}{li}",
        f"{first}.{middle}.{last}" if middle else "",
        f"{fi}{middle[:1]}{last}" if middle else "",
        f"{first}{last[:1]}",
        f"{first[:1]}{last}",
    ]
    patterns = [p for p in patterns if p]
    return _dedupe([f"{p}@{domain}" for p in patterns])


def _dedupe(lst: List[str]) -> List[str]:
    seen, out = set(), []
    for x in lst:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# --------------------------------------------------------------------------- #
# MX lookup (stdlib only)
# --------------------------------------------------------------------------- #

def mx_records(domain: str) -> List[str]:
    """Resolve MX records using stdlib. Returns sorted list of MX hosts."""
    try:
        import dns.resolver  # type: ignore
        return sorted(str(r.exchange).rstrip(".") for r in dns.resolver.resolve(domain, "MX"))
    except ImportError:
        pass
    # Fallback: use a public DoH endpoint
    try:
        r = requests.get(
            "https://dns.google/resolve",
            params={"name": domain, "type": "MX"},
            timeout=8,
        )
        if r.status_code != 200:
            return []
        ans = r.json().get("Answer") or []
        out: List[str] = []
        for entry in ans:
            data = entry.get("data", "")
            # data format: "10 mx.example.com."
            parts = data.split()
            if len(parts) >= 2:
                out.append(parts[1].rstrip("."))
        return sorted(out)
    except (requests.RequestException, ValueError):
        return []


# --------------------------------------------------------------------------- #
# SMTP probe (optional, unreliable on accept-all providers)
# --------------------------------------------------------------------------- #

def smtp_probe(email: str, mx_host: str, from_addr: str = "probe@robin.local",
               timeout: int = 8) -> Tuple[bool, str]:
    """RCPT TO probe. Returns (accepted, message).

    Not reliable on accept-all configurations. Use only with explicit consent.
    """
    try:
        with smtplib.SMTP(mx_host, 25, timeout=timeout) as srv:
            srv.helo("robin-recon.local")
            srv.mail(from_addr)
            code, msg = srv.rcpt(email)
            accepted = 200 <= code < 300
            return accepted, f"{code} {msg.decode('utf-8', 'ignore')}"
    except (smtplib.SMTPException, socket.error, OSError) as e:
        return False, str(e)


# --------------------------------------------------------------------------- #
# HudsonRock confirmation per candidate
# --------------------------------------------------------------------------- #

def _hudsonrock_has(email: str, timeout: int = 25) -> Dict:
    """Returns presence + count in HudsonRock stealer logs."""
    try:
        r = requests.get(
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email",
            params={"email": email},
            headers={"User-Agent": "robin-osint-tool"},
            timeout=timeout,
        )
        if r.status_code != 200:
            return {"present": False, "count": 0}
        d = r.json()
        total = d.get("total") or 0
        stealers = d.get("stealers") or []
        present = bool(total) or bool(stealers)
        return {"present": present, "count": total or len(stealers)}
    except (requests.RequestException, ValueError):
        return {"present": False, "count": 0}


# --------------------------------------------------------------------------- #
# Top-level recon
# --------------------------------------------------------------------------- #

def _darkweb_trace_for_email(email: str) -> Dict:
    """Lightweight dark+telegram check for one already-confirmed email.

    Lazy-imported to keep the module independent of search.py / Tor.
    """
    try:
        from darkweb_extras import darkweb_pii_search
        from telegram_sources import search_telegram
    except ImportError as e:
        return {"darkweb_hits": 0, "telegram_hits": 0, "error": str(e)}

    dw, tg = [], []
    try:
        dw = darkweb_pii_search(email) or []
    except Exception as e:
        log.debug("dark check failed for %s: %s", email, e)
    try:
        tg = search_telegram(email) or []
    except Exception as e:
        log.debug("telegram check failed for %s: %s", email, e)
    return {
        "darkweb_hits": len(dw),
        "telegram_hits": len(tg),
        "darkweb_samples": [
            {"title": h.get("title", ""), "url": h.get("link", ""),
             "raw": (h.get("raw") or h.get("snippet") or "")[:300]}
            for h in dw[:5]
        ],
        "telegram_samples": [
            {"title": h.get("title", ""), "url": h.get("link", ""),
             "channel": h.get("channel", ""),
             "raw": (h.get("raw") or h.get("snippet") or "")[:300]}
            for h in tg[:5]
        ],
    }


def recon(
    full_name: str,
    domain: str,
    smtp_probe_enabled: bool = False,
    darkweb_check: bool = True,
    max_workers: int = 6,
) -> Dict:
    """Generate patterns, check MX, HudsonRock all candidates, then dark+telegram
    only on the confirmed ones to avoid blasting Tor with 25 lookups.

    Args:
      darkweb_check: if True, run dark web + Telegram trace on each HudsonRock-
                     positive candidate. Adds ~30-90s but surfaces real evidence.
    """
    mx = mx_records(domain)
    if not mx:
        return {
            "name": full_name, "domain": domain, "mx": [],
            "candidates": [], "confirmed": [],
            "error": f"No MX records for {domain} — domain doesn't accept email.",
        }

    candidates = generate_patterns(full_name, domain)
    results: List[Dict] = []

    # Stage 1: HudsonRock for every candidate (fast, free)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        hr_futures = {pool.submit(_hudsonrock_has, c): c for c in candidates}
        hr_results = {hr_futures[f]: f.result() for f in as_completed(hr_futures)}

    for email in candidates:
        hr = hr_results.get(email, {"present": False, "count": 0})
        score = 0
        evidence: List[str] = []
        if hr["present"]:
            score += 5
            evidence.append(f"HudsonRock: {hr['count']} stealer infection(s)")
        smtp_status = None
        if smtp_probe_enabled:
            accepted, msg = smtp_probe(email, mx[0])
            smtp_status = {"accepted": accepted, "msg": msg}
            if accepted:
                score += 2
                evidence.append(f"SMTP RCPT TO accepted: {msg[:80]}")
        results.append({
            "email": email,
            "score": score,
            "hudsonrock": hr,
            "smtp": smtp_status,
            "darkweb": None,
            "evidence": evidence,
        })

    results.sort(key=lambda r: r["score"], reverse=True)
    confirmed = [r for r in results if r["score"] > 0]

    # Stage 2: dark + Telegram trace on confirmed candidates only
    if darkweb_check and confirmed:
        log.info("Running dark+telegram check on %d confirmed candidate(s)...",
                 len(confirmed))
        with ThreadPoolExecutor(max_workers=min(len(confirmed), 4)) as pool:
            dw_futs = {pool.submit(_darkweb_trace_for_email, c["email"]): c
                       for c in confirmed}
            for f in as_completed(dw_futs):
                cand = dw_futs[f]
                try:
                    dw = f.result()
                except Exception as e:
                    log.debug("dark trace failed: %s", e)
                    continue
                cand["darkweb"] = dw
                if dw["darkweb_hits"] or dw["telegram_hits"]:
                    cand["score"] += 3
                    cand["evidence"].append(
                        f"Dark/Telegram: {dw['darkweb_hits']} dark-web + "
                        f"{dw['telegram_hits']} Telegram hit(s)"
                    )
        confirmed.sort(key=lambda r: r["score"], reverse=True)

    return {
        "name": full_name,
        "domain": domain,
        "mx": mx,
        "candidates": results,
        "confirmed": confirmed,
    }


def format_recon(result: Dict) -> str:
    lines = [f"=== Email recon: '{result['name']}' @ {result['domain']} ==="]
    if result.get("error"):
        lines.append(result["error"])
        return "\n".join(lines)
    lines.append(f"MX: {', '.join(result['mx'])}")
    lines.append(f"Patterns generated: {len(result['candidates'])}")
    lines.append(f"Confirmed candidates ({len(result['confirmed'])}):")
    for c in result["confirmed"]:
        lines.append(f"  ✅ {c['email']}  (score={c['score']})")
        for ev in c["evidence"]:
            lines.append(f"      - {ev}")
        dw = c.get("darkweb") or {}
        for s in (dw.get("darkweb_samples") or [])[:3]:
            lines.append(f"      [dark] {s.get('title','')}")
            if s.get("url"):
                lines.append(f"         url: {s['url']}")
            if s.get("raw"):
                lines.append(f"         raw: {s['raw']}")
        for s in (dw.get("telegram_samples") or [])[:3]:
            lines.append(f"      [tg]  {s.get('title','')}"
                         + (f" ({s['channel']})" if s.get("channel") else ""))
            if s.get("url"):
                lines.append(f"         url: {s['url']}")
            if s.get("raw"):
                lines.append(f"         raw: {s['raw']}")
    if not result["confirmed"]:
        lines.append("  (no candidate matched any confirmation probe)")
    return "\n".join(lines)
