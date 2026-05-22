"""
Telegram OSINT sources.

Telegram is one of the largest open marketplaces for stealer logs, combolists,
breach announcements and personal-info dumps. The Telegram API requires auth,
but several public indexers expose channel content over HTTPS:

- tgstat.com           — large channel/post search engine
- t.me/s/<channel>     — public preview of a channel (no login)
- telemetr.io          — analytics for public channels
- DuckDuckGo dorks      — fallback when other indexers are flaky

All functions return a list of dicts shaped:

    {
      "title": "...",
      "link": "https://t.me/...",
      "snippet": "raw matching text fragment",
      "channel": "channel_username",
      "raw": "<larger excerpt around the match>",
      "source": "tgstat" | "tme-preview" | "ddg-telegram",
    }
"""

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote_plus, urljoin

import requests
from bs4 import BeautifulSoup

log = logging.getLogger(__name__)

UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
)
TIMEOUT = 15


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": UA,
        "Accept-Language": "en-US,en;q=0.7,fr;q=0.5,ru;q=0.3",
    })
    return s


def _excerpt(text: str, needle: str, radius: int = 200) -> str:
    """Return ±radius chars around the first occurrence of needle (case-insensitive)."""
    idx = text.lower().find(needle.lower())
    if idx < 0:
        return text[:radius]
    start = max(0, idx - radius)
    end = min(len(text), idx + len(needle) + radius)
    fragment = text[start:end].strip()
    if start > 0:
        fragment = "..." + fragment
    if end < len(text):
        fragment = fragment + "..."
    return re.sub(r"\s+", " ", fragment)


# --------------------------------------------------------------------------- #
# tgstat.com — channel + post search
# --------------------------------------------------------------------------- #

def tgstat_post_search(query: str, limit: int = 20) -> List[Dict]:
    """Search public Telegram posts via tgstat.com."""
    out: List[Dict] = []
    url = "https://tgstat.com/en/search"
    try:
        r = _session().get(url, params={"q": query}, timeout=TIMEOUT)
        if r.status_code != 200:
            log.debug("tgstat search HTTP %s", r.status_code)
            return out
        soup = BeautifulSoup(r.text, "html.parser")
        # tgstat renders matches inside .post-block / .card.card-body elements
        cards = soup.select(".post-block, .card.card-body")[:limit]
        for c in cards:
            text_tag = c.select_one(".post-body, .text, .post-text")
            link_tag = c.select_one("a[href*='t.me']") or c.find("a", href=True)
            channel_tag = c.select_one(".channel-name, .text-truncate, .post-info a")
            if not text_tag or not link_tag:
                continue
            text = text_tag.get_text(" ", strip=True)
            if query.lower() not in text.lower():
                continue
            href = link_tag.get("href", "")
            channel = channel_tag.get_text(strip=True) if channel_tag else ""
            out.append({
                "title": f"[telegram:{channel}] {text[:120]}",
                "link": href,
                "snippet": _excerpt(text, query, radius=150),
                "channel": channel,
                "raw": text,
                "source": "tgstat",
            })
        return out
    except requests.RequestException as e:
        log.debug("tgstat error: %s", e)
        return out


def tgstat_channel_search(query: str, limit: int = 10) -> List[Dict]:
    """Find Telegram channels whose name/description matches the query.
    Useful when the input is a person's name or a brand referenced by stealer
    log resellers.
    """
    out: List[Dict] = []
    try:
        r = _session().get(
            "https://tgstat.com/en/channels/search",
            params={"q": query}, timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return out
        soup = BeautifulSoup(r.text, "html.parser")
        for row in soup.select(".peer-item, .channel-row")[:limit]:
            name_tag = row.select_one(".peer-item-name, .channel-name, h5")
            link_tag = row.select_one("a[href*='tgstat.com'], a[href*='t.me']")
            desc_tag = row.select_one(".peer-item-desc, .description, p")
            if not name_tag or not link_tag:
                continue
            name = name_tag.get_text(strip=True)
            href = link_tag.get("href", "")
            desc = desc_tag.get_text(" ", strip=True) if desc_tag else ""
            out.append({
                "title": f"[telegram:channel] {name}",
                "link": href,
                "snippet": desc[:300],
                "channel": name,
                "raw": f"{name} — {desc}",
                "source": "tgstat-channel",
            })
        return out
    except requests.RequestException as e:
        log.debug("tgstat channel error: %s", e)
        return out


# --------------------------------------------------------------------------- #
# t.me/s/<channel> — public channel preview (no login)
# --------------------------------------------------------------------------- #

def tme_channel_preview(channel: str, query: Optional[str] = None) -> List[Dict]:
    """Pull the public preview of one Telegram channel and (optionally) grep
    for a query string in its recent messages.
    """
    out: List[Dict] = []
    channel = channel.lstrip("@").strip("/")
    url = f"https://t.me/s/{quote_plus(channel)}"
    try:
        r = _session().get(url, timeout=TIMEOUT)
        if r.status_code != 200:
            return out
        soup = BeautifulSoup(r.text, "html.parser")
        for msg in soup.select(".tgme_widget_message"):
            text_tag = msg.select_one(".tgme_widget_message_text")
            link = msg.get("data-post", "")
            link = f"https://t.me/{link}" if link else ""
            if not text_tag or not link:
                continue
            text = text_tag.get_text(" ", strip=True)
            if query and query.lower() not in text.lower():
                continue
            out.append({
                "title": f"[telegram:{channel}] {text[:100]}",
                "link": link,
                "snippet": _excerpt(text, query or "", radius=200),
                "channel": channel,
                "raw": text,
                "source": "tme-preview",
            })
        return out
    except requests.RequestException as e:
        log.debug("t.me/s/%s error: %s", channel, e)
        return out


# Telegram channel discovery is 100 % automatic.
#
#   1. Value-driven: tgstat is queried for posts containing the PII value.
#      Every channel that appears in a hit becomes a probe candidate.
#   2. Topic-driven: on the first call, we query tgstat with breach/stealer
#      keywords to surface the channels that habitually post leaks. Cached.
#   3. (Optional) user override: $ROBIN_TELEGRAM_CHANNELS_FILE can add extras.
#
# No hardcoded "trusted" channel list. Telegram nuke them too often for that.

import os

DISCOVERY_KEYWORDS = [
    "stealer logs",
    "combolist",
    "ulp",
    "leak base",
    "data leak",
    "breach forums",
    "redline logs",
    "racoon stealer",
    "lumma logs",
    "cookies leak",
    "credentials dump",
    "logs cloud",
]


def _load_user_channels() -> List[str]:
    """Optional user-curated list of channel handles."""
    path = os.getenv("ROBIN_TELEGRAM_CHANNELS_FILE")
    if not path or not os.path.isfile(path):
        return []
    out: List[str] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lstrip("@").rstrip("/")
                if not line or line.startswith("#"):
                    continue
                out.append(line)
    except OSError as e:
        log.warning("Could not read channels file %s: %s", path, e)
    return out


_TOPIC_CHANNELS_CACHE: Optional[List[str]] = None


def _extract_channel_handles(html: str, limit: int = 100) -> List[str]:
    """Pull unique Telegram handles from an arbitrary HTML blob."""
    handles: List[str] = []
    seen: set = set()
    for pat in (
        r"t\.me/(?:s/)?([A-Za-z0-9_]{5,32})",
        r"tgstat\.com/channel/@([A-Za-z0-9_]{5,32})",
        r"data-username=\"([A-Za-z0-9_]{5,32})\"",
    ):
        for h in re.findall(pat, html):
            key = h.lower()
            if key in seen:
                continue
            seen.add(key)
            handles.append(h)
            if len(handles) >= limit:
                return handles
    return handles


def discover_channels_for_value(value: str, limit: int = 25) -> List[str]:
    """Live discovery: ask tgstat which channels have posts matching `value`."""
    found: List[str] = []
    seen: set = set()
    s = _session()
    endpoints = [
        ("https://tgstat.com/en/search", {"q": value}),
        ("https://tgstat.com/en/channels/search", {"q": value}),
    ]
    for url, params in endpoints:
        try:
            r = s.get(url, params=params, timeout=TIMEOUT)
            if r.status_code != 200:
                continue
            for h in _extract_channel_handles(r.text, limit=limit * 2):
                key = h.lower()
                if key in seen:
                    continue
                seen.add(key)
                found.append(h)
                if len(found) >= limit:
                    return found
        except requests.RequestException as e:
            log.debug("tgstat live discovery error: %s", e)
            continue
    return found


def discover_topic_channels(force_refresh: bool = False) -> List[str]:
    """Cached: channels that habitually post stealer/leak content (topic-based).

    Used to widen the probe set when value-driven discovery returns nothing.
    """
    global _TOPIC_CHANNELS_CACHE
    if _TOPIC_CHANNELS_CACHE is not None and not force_refresh:
        return _TOPIC_CHANNELS_CACHE

    found: List[str] = []
    seen: set = set()
    s = _session()
    for kw in DISCOVERY_KEYWORDS:
        try:
            r = s.get("https://tgstat.com/en/channels/search",
                      params={"q": kw}, timeout=TIMEOUT)
            if r.status_code != 200:
                continue
            for h in _extract_channel_handles(r.text, limit=20):
                key = h.lower()
                if key in seen:
                    continue
                seen.add(key)
                found.append(h)
                if len(found) >= 40:
                    break
            if len(found) >= 40:
                break
        except requests.RequestException as e:
            log.debug("topic discovery error for '%s': %s", kw, e)
            continue
    _TOPIC_CHANNELS_CACHE = found
    return _TOPIC_CHANNELS_CACHE


def known_channels(refresh: bool = False) -> List[str]:
    """Topic + user channels merged. (Value-specific discovery happens in
    `search_known_stealer_channels()` so each query gets fresh per-value hits.)
    """
    user = _load_user_channels()
    topic = discover_topic_channels(force_refresh=refresh)
    merged: List[str] = []
    seen: set = set()
    for ch in user + topic:
        key = ch.lower().lstrip("@")
        if key in seen or not key:
            continue
        seen.add(key)
        merged.append(ch)
    return merged


def search_known_stealer_channels(value: str, max_workers: int = 8) -> List[Dict]:
    """Probe channels for the literal value. Channel set is built dynamically:

      * channels discovered live via tgstat for THIS specific value
      * channels that habitually post stealer/breach content (cached)
      * user-curated handles (env ROBIN_TELEGRAM_CHANNELS_FILE)

    Then for each channel, fetch the public preview via t.me/s/<channel> and
    grep its recent posts for the value.
    """
    value_specific = discover_channels_for_value(value, limit=25)
    topic = discover_topic_channels()
    user = _load_user_channels()

    merged: List[str] = []
    seen: set = set()
    # Value-specific first (most relevant), then topic, then user extras
    for ch in value_specific + topic + user:
        key = ch.lower().lstrip("@")
        if key in seen or not key:
            continue
        seen.add(key)
        merged.append(ch)

    out: List[Dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(tme_channel_preview, ch, value): ch for ch in merged[:50]
        }
        for fut in as_completed(futures):
            try:
                hits = fut.result() or []
                out.extend(hits)
            except Exception as e:
                log.debug("channel %s error: %s", futures[fut], e)
    return out


# --------------------------------------------------------------------------- #
# DDG dorks on t.me as fallback
# --------------------------------------------------------------------------- #

def ddg_telegram_dork(value: str, limit: int = 10) -> List[Dict]:
    """Fallback: Google/DDG-style dork limited to t.me + tgstat."""
    out: List[Dict] = []
    try:
        r = _session().post(
            "https://html.duckduckgo.com/html/",
            data={"q": f'"{value}" site:t.me OR site:tgstat.com'},
            timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return out
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.select("a.result__a")[:limit]:
            href = a.get("href", "")
            m = re.search(r"uddg=([^&]+)", href)
            if m:
                from urllib.parse import unquote
                href = unquote(m.group(1))
            title = a.get_text(strip=True)
            snippet_tag = a.find_parent("div").find_next("a", class_="result__snippet")
            snippet = snippet_tag.get_text(" ", strip=True) if snippet_tag else ""
            out.append({
                "title": f"[telegram:ddg] {title}",
                "link": href,
                "snippet": _excerpt(f"{title} {snippet}", value, radius=180),
                "channel": "",
                "raw": f"{title} — {snippet}",
                "source": "ddg-telegram",
            })
        return out
    except requests.RequestException as e:
        log.debug("ddg telegram error: %s", e)
        return out


# --------------------------------------------------------------------------- #
# Top-level aggregator
# --------------------------------------------------------------------------- #

def search_telegram(value: str, max_workers: int = 4) -> List[Dict]:
    """Aggregate all Telegram sources for one PII value."""
    sources = [
        ("tgstat-posts", lambda: tgstat_post_search(value)),
        ("tgstat-channels", lambda: tgstat_channel_search(value)),
        ("known-channels", lambda: search_known_stealer_channels(value)),
        ("ddg-tg", lambda: ddg_telegram_dork(value)),
    ]
    out: List[Dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(fn): name for name, fn in sources}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                out.extend(fut.result() or [])
            except Exception as e:
                log.debug("telegram source %s error: %s", name, e)

    # Dedupe by link
    seen = set()
    deduped: List[Dict] = []
    for h in out:
        link = (h.get("link") or "").rstrip("/").lower()
        if not link or link in seen:
            continue
        seen.add(link)
        deduped.append(h)
    return deduped
