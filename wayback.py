"""
Wayback Machine OSINT helpers.

Three use-cases:

  - `closest(url)`          → latest snapshot of a URL
  - `snapshots(url, limit)` → full snapshot history for a URL
  - `search_archived_content(domain, query)` → grep all snapshots of a domain
                                                for a literal query string

Free, no API key. Uses the public CDX API + Memento timegate.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional
from urllib.parse import quote, urlparse

import requests

log = logging.getLogger(__name__)

UA = "robin-osint-tool/1.0 (Wayback Machine OSINT helper)"
TIMEOUT = 25


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    return s


def closest(url: str) -> Optional[Dict]:
    """Return the most recent archived snapshot for `url`."""
    try:
        r = _session().get(
            "https://archive.org/wayback/available",
            params={"url": url}, timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return None
        snap = (r.json().get("archived_snapshots") or {}).get("closest")
        if not snap:
            return None
        return {
            "timestamp": snap.get("timestamp"),
            "snapshot_url": snap.get("url"),
            "status": snap.get("status"),
            "available": snap.get("available", False),
        }
    except (requests.RequestException, ValueError) as e:
        log.debug("wayback closest %s error: %s", url, e)
        return None


def snapshots(url: str, limit: int = 30) -> List[Dict]:
    """List archived snapshots of `url` (newest first)."""
    out: List[Dict] = []
    try:
        r = _session().get(
            "http://web.archive.org/cdx/search/cdx",
            params={
                "url": url,
                "output": "json",
                "limit": -limit,        # negative = newest first
                "fl": "timestamp,original,statuscode,mimetype,length",
            },
            timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return out
        rows = r.json()
        if not rows or len(rows) < 2:
            return out
        header, *data = rows
        for row in data:
            entry = dict(zip(header, row))
            out.append({
                "timestamp": entry.get("timestamp"),
                "snapshot_url": (
                    f"https://web.archive.org/web/{entry.get('timestamp')}/"
                    f"{entry.get('original')}"
                ),
                "status": entry.get("statuscode"),
                "mimetype": entry.get("mimetype"),
                "length": entry.get("length"),
            })
    except (requests.RequestException, ValueError) as e:
        log.debug("wayback snapshots %s error: %s", url, e)
    return out


def search_archived_content(
    domain: str,
    query: str,
    max_snapshots: int = 10,
    radius: int = 200,
) -> List[Dict]:
    """For `domain`, pull up to `max_snapshots` recent archives of its root +
    /sitemap.xml + /robots.txt, fetch each, grep for `query`. Returns the
    matching snapshots with raw context.

    This is slow but exposes deleted content (e.g. an employee email that
    was on the team page in 2019 but is gone today).
    """
    candidates: List[str] = []
    domain = domain.lstrip("https://").lstrip("http://").rstrip("/")
    for path in ("", "/sitemap.xml", "/team", "/about", "/contact", "/staff"):
        for snap in snapshots(f"https://{domain}{path}", limit=3):
            candidates.append(snap["snapshot_url"])
            if len(candidates) >= max_snapshots:
                break
        if len(candidates) >= max_snapshots:
            break

    out: List[Dict] = []
    s = _session()
    for snap_url in candidates[:max_snapshots]:
        try:
            r = s.get(snap_url, timeout=TIMEOUT)
            if r.status_code != 200:
                continue
            text = r.text
            idx = text.lower().find(query.lower())
            if idx < 0:
                continue
            start, end = max(0, idx - radius), min(len(text), idx + len(query) + radius)
            fragment = re.sub(r"\s+", " ", text[start:end]).strip()
            out.append({
                "snapshot_url": snap_url,
                "raw": fragment,
                "match_offset": idx,
            })
        except requests.RequestException:
            continue
    return out


def format_snapshots(items: List[Dict]) -> str:
    if not items:
        return "No Wayback snapshots found."
    lines = []
    for s in items:
        ts = s.get("timestamp", "?")
        url = s.get("snapshot_url", "")
        meta = f"status={s.get('status','?')} type={s.get('mimetype','?')}"
        lines.append(f"  [{ts}] {meta}\n    {url}")
    return "\n".join(lines)
