"""
Targeted dark-web sources beyond the generic search engines:

- Dread forum search (Reddit-style hidden service)
- Active ransomware leak site discovery via ransomware.live
- Tor circuit rotation via stem (NEWNYM signal)

Everything degrades gracefully if Tor is unreachable or stem isn't installed.
"""

from __future__ import annotations

import os
import re
import random
import logging
import time
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote_plus, urljoin

import requests
from bs4 import BeautifulSoup

log = logging.getLogger(__name__)

TOR_PROXIES = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}
UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
)
_SEARCH_ENGINE_INFRA_RE = re.compile(
    r"(ahmia\.fi|onionsearchengine|onionlandsearchengine|/search(\?|/|$)"
    r"|\.onion/search(\?|/|$))"
)


def _tor_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept-Language": "en-US,en;q=0.7"})
    s.proxies = TOR_PROXIES
    return s


# --------------------------------------------------------------------------- #
# Tor circuit rotation
# --------------------------------------------------------------------------- #

def rotate_tor_circuit(silent: bool = False) -> bool:
    """Ask Tor for a fresh circuit via the control port.

    Tries multiple auth modes (cookie, password from TOR_CONTROL_PASSWORD env,
    no-auth). Returns True on success. No-op if `stem` is missing.
    """
    try:
        from stem import Signal
        from stem.control import Controller
    except ImportError:
        if not silent:
            log.debug("stem not installed; skipping circuit rotation")
        return False
    import os
    port = int(os.getenv("TOR_CONTROL_PORT", "9051"))
    password = os.getenv("TOR_CONTROL_PASSWORD")
    try:
        with Controller.from_port(port=port) as ctrl:
            if password:
                ctrl.authenticate(password=password)
            else:
                try:
                    ctrl.authenticate()
                except Exception:
                    return False
            ctrl.signal(Signal.NEWNYM)
            time.sleep(1.5)  # let Tor build the new circuit
            return True
    except Exception as e:
        log.debug("circuit rotation failed: %s", e)
        return False


# --------------------------------------------------------------------------- #
# Dread forum search
# --------------------------------------------------------------------------- #

# Known stable Dread hidden service. Falls over to mirrors when the primary
# instance is offline (Dread is frequently DDoSed).
DREAD_HOSTS = [
    "dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion",
    "g66ol3eb5ujdckzqqfmjsbpdjufmjd5nsgdipvxmsh7rckzlhywlzlqd.onion",
]


def search_dread(query: str, limit: int = 15) -> List[Dict]:
    """Search Dread post titles for the query. Returns thread links."""
    out: List[Dict] = []
    encoded = quote_plus(query)
    s = _tor_session()
    for host in DREAD_HOSTS:
        url = f"http://{host}/search?q={encoded}"
        try:
            r = s.get(url, timeout=45)
            if r.status_code != 200:
                continue
            soup = BeautifulSoup(r.text, "html.parser")
            for post in soup.select("div.post")[:limit]:
                title_tag = post.select_one("a.title")
                if not title_tag:
                    continue
                href = title_tag.get("href", "")
                if not href.startswith("http"):
                    href = f"http://{host}{href}"
                snippet_tag = post.select_one("div.body") or post.select_one(".post-text")
                snippet = snippet_tag.get_text(" ", strip=True)[:300] if snippet_tag else ""
                meta = post.select_one(".info")
                meta_text = meta.get_text(" ", strip=True) if meta else ""
                out.append({
                    "title": f"[dread] {title_tag.get_text(strip=True)}",
                    "link": href,
                    "snippet": f"{meta_text} — {snippet}".strip(" —"),
                    "engine": "dread",
                })
            if out:
                return out
        except requests.RequestException as e:
            log.debug("dread %s error: %s", host, e)
            continue
    return out


# --------------------------------------------------------------------------- #
# Ransomware leak sites
# --------------------------------------------------------------------------- #

_RW_LIVE_CACHE: Dict[str, List[Dict]] = {}


def active_ransomware_leak_sites(
    min_alive: int = 1,
    only_currently_available: bool = False,
    refresh: bool = False,
) -> List[Dict]:
    """Return list of ransomware leak sites known to ransomware.live.

    By default we INCLUDE sites currently flagged `available: False` because
    that just means the DLS is offline right this minute (these come back up
    routinely). Set `only_currently_available=True` to filter on that flag.

    Each entry: {group, url, host, onion, available}
    """
    if "groups" in _RW_LIVE_CACHE and not refresh:
        cached = _RW_LIVE_CACHE["groups"]
        if only_currently_available:
            return [s for s in cached if s.get("available")]
        return cached
    try:
        r = requests.get("https://api.ransomware.live/v2/groups", timeout=20)
        if r.status_code != 200:
            return []
        groups = r.json()
        sites: List[Dict] = []
        for g in groups:
            name = g.get("name") or "?"
            for loc in (g.get("locations") or []):
                fqdn = loc.get("fqdn") or loc.get("title") or ""
                if not fqdn:
                    continue
                slug = loc.get("slug") or ""
                url = slug if slug.startswith("http") else (
                    fqdn if fqdn.startswith("http") else f"http://{fqdn}"
                )
                sites.append({
                    "group": name,
                    "url": url,
                    "host": fqdn,
                    "onion": ".onion" in fqdn,
                    "available": bool(loc.get("available", False)),
                })
        _RW_LIVE_CACHE["groups"] = sites
        if only_currently_available:
            return [s for s in sites if s.get("available")]
        return sites
    except (requests.RequestException, ValueError) as e:
        log.debug("ransomware.live groups error: %s", e)
        return []


def _scrape_leak_site(site: Dict, query: str, timeout: int = 35) -> List[Dict]:
    """Hit a single ransomware leak site and grep for the query in its index.

    Most ransomware groups expose a flat HTML index of victims. We don't crawl;
    we just fetch the landing page and grep the rendered text for the query.
    """
    url = site["url"]
    needs_tor = site["onion"]
    headers = {"User-Agent": UA}
    sess = requests.Session()
    if needs_tor:
        sess.proxies = TOR_PROXIES
    try:
        r = sess.get(url, headers=headers, timeout=timeout)
        if r.status_code != 200:
            return []
        text = r.text
        if query.lower() not in text.lower():
            return []
        soup = BeautifulSoup(text, "html.parser")
        # Try to extract anchors that mention the query
        hits: List[Dict] = []
        seen_links = set()
        for a in soup.find_all("a", href=True):
            anchor_text = a.get_text(" ", strip=True)
            href = a["href"]
            if query.lower() not in (anchor_text + " " + href).lower():
                continue
            if href.startswith("/"):
                href = url.rstrip("/") + href
            if href in seen_links:
                continue
            seen_links.add(href)
            hits.append({
                "title": f"[ransom:{site['group']}] {anchor_text or '(victim)'}",
                "link": href,
                "snippet": (
                    f"Victim entry on {site['group']} leak site referencing '{query}'."
                ),
                "engine": f"ransomware:{site['group']}",
            })
            if len(hits) >= 5:
                break
        if not hits:
            # Surface the landing page itself if the keyword was on it
            hits.append({
                "title": f"[ransom:{site['group']}] leak site mentions '{query}'",
                "link": url,
                "snippet": f"Keyword '{query}' appears on {site['host']}'s landing page.",
                "engine": f"ransomware:{site['group']}",
            })
        return hits
    except requests.RequestException as e:
        log.debug("leak site %s error: %s", site["host"], e)
        return []


def search_ransomware_groups(
    query: str,
    max_groups: int = 25,
    max_workers: int = 8,
) -> List[Dict]:
    """Search the landing page of every currently-active ransomware leak site
    for a keyword.

    This is the high-value path: instead of relying on dark-web search engines
    to *maybe* index leak sites, we go directly to the source.
    """
    sites = active_ransomware_leak_sites()
    if not sites:
        return []

    # Prefer onion sites (less ephemeral than clearnet redirects), cap count
    sites.sort(key=lambda s: (not s["onion"], s["host"]))
    sites = sites[:max_groups]

    results: List[Dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {pool.submit(_scrape_leak_site, s, query): s for s in sites}
        for fut in as_completed(future_map):
            try:
                results.extend(fut.result() or [])
            except Exception as e:
                log.debug("leak site future error: %s", e)
    return results


# --------------------------------------------------------------------------- #
# Public helpers
# --------------------------------------------------------------------------- #

def _excerpt(text: str, needle: str, radius: int = 200) -> str:
    """±radius chars around first case-insensitive match of needle."""
    idx = text.lower().find(needle.lower())
    if idx < 0:
        return text[:radius * 2]
    start = max(0, idx - radius)
    end = min(len(text), idx + len(needle) + radius)
    fragment = text[start:end].strip()
    if start > 0:
        fragment = "..." + fragment
    if end < len(text):
        fragment = fragment + "..."
    return re.sub(r"\s+", " ", fragment)


def _candidate_mentions_value(hit: Dict, value: str) -> bool:
    """Keep engine hits only when the literal value is present in the
    title/snippet/link that the engine returned.

    This drops infrastructure/self-links such as Ahmia/Tor66 navigation pages
    that happen to appear in search results but do not mention the queried PII.
    """
    haystack = " ".join(
        str(hit.get(field) or "")
        for field in ("title", "link", "snippet", "raw")
    )
    return value.lower() in haystack.lower()


def scrape_and_grep(url: str, value: str, timeout: int = 35) -> Optional[Dict]:
    """Fetch one URL (Tor for onions, direct otherwise), grep for the literal
    PII value, and return the raw matching context if any.
    """
    use_tor = ".onion" in url
    sess = _tor_session() if use_tor else requests.Session()
    sess.headers.update({"User-Agent": UA})
    try:
        r = sess.get(url, timeout=timeout, allow_redirects=True)
        if r.status_code != 200:
            return None
        text = BeautifulSoup(r.text, "html.parser").get_text(" ", strip=True)
        if value.lower() not in text.lower():
            return None
        return {
            "title": f"[darkweb-match] {url[:80]}",
            "link": url,
            "snippet": _excerpt(text, value, radius=150),
            "raw": _excerpt(text, value, radius=400),
            "source": "darkweb-scrape",
        }
    except requests.RequestException as e:
        log.debug("scrape_and_grep %s: %s", url[:60], e)
        return None


def darkweb_pii_search(
    value: str,
    max_workers: int = 8,
    max_results_per_engine: int = 10,
) -> List[Dict]:
    """Search the literal PII value across:

    - All onion search engines (via search.py) using the value as the query
    - Active ransomware leak sites (landing-page grep, already in this module)
    - Dread forum threads

    Then scrape each top result URL and extract the raw matching context.
    """
    from search import fetch_engine, SEARCH_ENGINES

    hits: List[Dict] = []
    quoted = value.replace(" ", "+")

    # Stage 1: feed the literal value into every onion engine
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(fetch_engine, eng, quoted): eng for eng in SEARCH_ENGINES}
        for fut in as_completed(futures):
            try:
                engine_hits = fut.result() or []
                for h in engine_hits[:max_results_per_engine]:
                    link = (h.get("link") or "").rstrip("/").lower()
                    if not link or _SEARCH_ENGINE_INFRA_RE.search(link):
                        continue
                    if not _candidate_mentions_value(h, value):
                        continue
                    h["source"] = "darkweb-engine"
                    hits.append(h)
            except Exception as e:
                log.debug("darkweb engine error: %s", e)

    # Stage 2: ransomware leak sites + Dread
    try:
        hits.extend(search_ransomware_groups(value))
    except Exception as e:
        log.debug("ransomware groups error: %s", e)
    try:
        dread_hits = search_dread(value)
        for h in dread_hits:
            h["source"] = "dread"
        hits.extend(dread_hits)
    except Exception as e:
        log.debug("dread error: %s", e)

    # Dedupe by URL
    seen = set()
    candidates: List[Dict] = []
    for h in hits:
        link = (h.get("link") or "").rstrip("/").lower()
        if not link or link in seen:
            continue
        seen.add(link)
        candidates.append(h)

    # Stage 3: scrape the top hits and extract raw matching context
    enriched: List[Dict] = []
    top = candidates[: max_workers * 3]  # cap scrapes
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        scrape_futures = {pool.submit(scrape_and_grep, c["link"], value): c for c in top}
        for fut in as_completed(scrape_futures):
            base = scrape_futures[fut]
            try:
                raw = fut.result()
            except Exception as e:
                log.debug("scrape future: %s", e)
                raw = None
            if raw:
                enriched.append({**base, **raw})
            else:
                enriched.append(base)
    # Anything we didn't scrape (beyond the cap) still gets returned without raw
    enriched.extend(candidates[len(top):])
    return enriched


def tor_status() -> Dict:
    """Detailed Tor health: SOCKS proxy + ControlPort + exit IP."""
    out = {
        "socks_listening": False,
        "control_listening": False,
        "exit_ip": None,
        "is_tor_confirmed": False,
        "error": None,
    }
    import socket
    # 1) Local SOCKS port
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        out["socks_listening"] = (s.connect_ex(("127.0.0.1", 9050)) == 0)
        s.close()
    except OSError:
        pass
    # 2) Optional ControlPort
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        out["control_listening"] = (s.connect_ex(("127.0.0.1", 9051)) == 0)
        s.close()
    except OSError:
        pass
    # 3) Exit IP via Tor (only if SOCKS up)
    if out["socks_listening"]:
        try:
            r = requests.get(
                "https://check.torproject.org/api/ip",
                proxies=TOR_PROXIES, timeout=15,
                headers={"User-Agent": UA},
            )
            if r.status_code == 200:
                data = r.json()
                out["is_tor_confirmed"] = data.get("IsTor", False)
                out["exit_ip"] = data.get("IP")
        except Exception as e:
            out["error"] = str(e)
    return out


def darkweb_health() -> Dict[str, bool]:
    """Health probe for Tor + Dread + ransomware.live group discovery."""
    health: Dict[str, bool] = {}
    tor = tor_status()
    health["tor SOCKS (127.0.0.1:9050)"] = tor["socks_listening"]
    if tor["control_listening"]:
        health["tor ControlPort (9051, NEWNYM)"] = True
    if tor["is_tor_confirmed"]:
        health[f"tor exit IP ({tor['exit_ip']})"] = True
    elif tor["socks_listening"] and tor.get("error"):
        health["tor exit reachable"] = False

    s = _tor_session()
    for host in DREAD_HOSTS[:1]:
        try:
            r = s.get(f"http://{host}/", timeout=30, stream=True)
            health[f"dread ({host[:18]}...)"] = r.status_code < 500
            r.close()
        except requests.RequestException:
            health[f"dread ({host[:18]}...)"] = False
    sites = active_ransomware_leak_sites()
    health[f"ransomware.live groups ({len(sites)} sites)"] = bool(sites)
    return health
