"""
Threat-intel feeds framework for Argus.

A feed is a configured external source that we poll on demand (or on a
schedule) to ingest events: new ransomware victims, breach announcements,
IOCs, etc. Each polled event is checked against the user's watchlist; matches
get flagged for the UI.

Supported backends:

  - `ransomware-monitor` : polls ransomware.live for new victim postings
  - `misp`               : MISP REST events endpoint (auth via API key)
  - `taxii`              : TAXII 2.1 collection client (auth optional)
  - `rest`               : generic REST endpoint returning JSON (internal feeds,
                          commercial APIs that don't have a dedicated backend)

Storage lives in the shared SQLite (see local_breach_db.SCHEMA: feeds,
watchlist, feed_events).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional

import requests

from local_breach_db import connect

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Data shapes
# --------------------------------------------------------------------------- #

@dataclass
class FeedEvent:
    event_type: str
    timestamp: str
    payload: Dict[str, Any]
    matched_pattern: Optional[str] = None


@dataclass
class PollReport:
    feed_id: str
    fetched: int = 0
    new_events: int = 0
    matched_events: int = 0
    error: Optional[str] = None
    duration_s: float = 0.0

    def __str__(self) -> str:
        if self.error:
            return f"[{self.feed_id}] ERROR: {self.error}"
        return (
            f"[{self.feed_id}] fetched={self.fetched} "
            f"new={self.new_events} matched={self.matched_events} "
            f"in {self.duration_s:.1f}s"
        )


# --------------------------------------------------------------------------- #
# Watchlist storage
# --------------------------------------------------------------------------- #

def list_watchlist() -> List[Dict]:
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT id, pattern, label, added_at FROM watchlist ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def add_watchlist(pattern: str, label: str = "") -> int:
    pattern = pattern.strip()
    if not pattern:
        raise ValueError("pattern is empty")
    conn = connect()
    try:
        cur = conn.execute(
            "INSERT INTO watchlist (pattern, label) VALUES (?, ?)",
            (pattern, label),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def remove_watchlist(pattern_or_id) -> int:
    conn = connect()
    try:
        if isinstance(pattern_or_id, int) or (
            isinstance(pattern_or_id, str) and pattern_or_id.isdigit()
        ):
            cur = conn.execute("DELETE FROM watchlist WHERE id=?",
                                (int(pattern_or_id),))
        else:
            cur = conn.execute("DELETE FROM watchlist WHERE pattern=?",
                                (pattern_or_id,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def _watchlist_matches(text: str, watchlist: List[Dict]) -> Optional[str]:
    """Return the first watchlist pattern that occurs in `text`."""
    if not text or not watchlist:
        return None
    low = text.lower()
    for w in watchlist:
        if w["pattern"].lower() in low:
            return w["pattern"]
    return None


# --------------------------------------------------------------------------- #
# Feed config storage
# --------------------------------------------------------------------------- #

def list_feeds() -> List[Dict]:
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT id, kind, display, config, enabled, last_poll, "
            "last_event_count, last_error, added_at "
            "FROM feeds ORDER BY id"
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["config"] = json.loads(d["config"] or "{}")
            except json.JSONDecodeError:
                d["config"] = {}
            out.append(d)
        return out
    finally:
        conn.close()


def add_feed(
    feed_id: str, kind: str, display: str = "",
    config: Optional[Dict] = None, enabled: bool = True,
) -> None:
    """Insert or update a feed configuration."""
    if kind not in BACKENDS:
        raise ValueError(f"Unknown feed kind: {kind}. "
                         f"Available: {sorted(BACKENDS.keys())}")
    config_json = json.dumps(config or {})
    conn = connect()
    try:
        conn.execute("""
            INSERT INTO feeds (id, kind, display, config, enabled)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                kind    = excluded.kind,
                display = excluded.display,
                config  = excluded.config,
                enabled = excluded.enabled
        """, (feed_id, kind, display or feed_id, config_json,
              1 if enabled else 0))
        conn.commit()
    finally:
        conn.close()


def remove_feed(feed_id: str) -> int:
    conn = connect()
    try:
        cur = conn.execute("DELETE FROM feeds WHERE id=?", (feed_id,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def recent_events(limit: int = 50,
                  feed_id: Optional[str] = None,
                  only_matched: bool = False) -> List[Dict]:
    conn = connect()
    try:
        where = []
        args: List = []
        if feed_id:
            where.append("feed_id = ?")
            args.append(feed_id)
        if only_matched:
            where.append("matched_watchlist = 1")
        where_clause = ("WHERE " + " AND ".join(where)) if where else ""
        rows = conn.execute(
            f"SELECT id, feed_id, event_type, timestamp, payload, "
            f"       matched_watchlist, matched_pattern, seen "
            f"FROM feed_events {where_clause} "
            f"ORDER BY id DESC LIMIT ?", (*args, limit)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["payload"] = json.loads(d["payload"] or "{}")
            except json.JSONDecodeError:
                d["payload"] = {}
            out.append(d)
        return out
    finally:
        conn.close()


def mark_events_seen(event_ids: List[int]) -> int:
    if not event_ids:
        return 0
    conn = connect()
    try:
        placeholders = ",".join("?" for _ in event_ids)
        cur = conn.execute(
            f"UPDATE feed_events SET seen=1 WHERE id IN ({placeholders})",
            event_ids,
        )
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Backends
# --------------------------------------------------------------------------- #

class FeedBackend:
    """Subclass and override `poll`."""

    @staticmethod
    def poll(config: Dict, state: Dict, watchlist: List[Dict]
             ) -> Iterator[FeedEvent]:
        raise NotImplementedError


# --- Ransomware leak site monitor --- #

class RansomwareMonitor(FeedBackend):
    """Polls ransomware.live for recent victim postings. Matches against the
    watchlist (typically client domains / company names)."""

    @staticmethod
    def poll(config, state, watchlist):
        endpoint = config.get(
            "endpoint", "https://api.ransomware.live/v2/recentvictims"
        )
        max_age_days = int(config.get("max_age_days", 30))
        try:
            r = requests.get(endpoint, timeout=20)
            r.raise_for_status()
            victims = r.json() or []
        except Exception as e:
            log.warning("ransomware monitor fetch failed: %s", e)
            return

        last_seen = state.get("last_seen_id")
        new_last = None

        for v in victims:
            post_id = v.get("post_url") or v.get("id") or v.get("post_title")
            if new_last is None:
                new_last = post_id
            if last_seen and post_id == last_seen:
                break

            victim = v.get("victim") or v.get("post_title") or ""
            group = v.get("group_name") or v.get("group") or "?"
            description = v.get("description") or v.get("post_title") or ""
            discovered = (v.get("discovered") or v.get("published") or
                          v.get("attackdate") or "")
            haystack = f"{victim} {description}"
            match = _watchlist_matches(haystack, watchlist)

            yield FeedEvent(
                event_type="ransomware-victim",
                timestamp=discovered or datetime.now(timezone.utc).isoformat(),
                payload={
                    "group": group,
                    "victim": victim,
                    "description": (description or "")[:600],
                    "post_url": v.get("post_url", ""),
                    "discovered": discovered,
                    "country": v.get("country", ""),
                    "activity": v.get("activity", ""),
                },
                matched_pattern=match,
            )

        if new_last:
            state["last_seen_id"] = new_last


# --- MISP REST events --- #

class MISPBackend(FeedBackend):
    """Polls a MISP instance's /events/restSearch endpoint and emits one
    FeedEvent per Attribute that is an IOC type we care about (email-src,
    domain, ip-dst, md5/sha1/sha256, url, ...)."""

    IOC_TYPES = {"email-src", "email-dst", "email", "domain", "hostname",
                 "ip-src", "ip-dst", "md5", "sha1", "sha256", "url",
                 "username", "btc", "btc-address"}

    @staticmethod
    def poll(config, state, watchlist):
        base = config.get("base_url", "").rstrip("/")
        key = config.get("api_key", "")
        if not base or not key:
            log.warning("MISP feed missing base_url or api_key")
            return
        params = {
            "returnFormat": "json",
            "limit": int(config.get("limit", 100)),
            "page": 1,
        }
        if state.get("last_event_id"):
            params["eventid"] = f">{state['last_event_id']}"
        try:
            r = requests.post(
                f"{base}/events/restSearch",
                json=params,
                headers={
                    "Authorization": key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "User-Agent": "argus-feeds",
                },
                timeout=30,
                verify=config.get("verify_tls", True),
            )
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            log.warning("MISP poll failed: %s", e)
            return

        events = data.get("response", [])
        max_event_id = state.get("last_event_id") or 0
        for entry in events:
            ev = entry.get("Event") or entry
            event_id = int(ev.get("id") or 0)
            max_event_id = max(max_event_id, event_id)
            event_info = ev.get("info", "")
            for attr in ev.get("Attribute", []):
                atype = attr.get("type")
                if atype not in MISPBackend.IOC_TYPES:
                    continue
                value = attr.get("value") or ""
                match = _watchlist_matches(value, watchlist)
                yield FeedEvent(
                    event_type=f"misp-ioc:{atype}",
                    timestamp=attr.get("timestamp", ""),
                    payload={
                        "event_id": event_id,
                        "event_info": event_info,
                        "type": atype,
                        "value": value,
                        "comment": attr.get("comment", ""),
                        "to_ids": attr.get("to_ids", False),
                    },
                    matched_pattern=match,
                )
        state["last_event_id"] = max_event_id


# --- TAXII 2.1 collection client --- #

class TAXIIBackend(FeedBackend):
    """Polls a TAXII 2.1 collection. Iterates STIX Observed-Data / Indicator
    objects and emits one FeedEvent per pattern observed."""

    @staticmethod
    def poll(config, state, watchlist):
        api_root = config.get("api_root", "").rstrip("/")
        collection_id = config.get("collection_id", "")
        if not (api_root and collection_id):
            log.warning("TAXII feed missing api_root or collection_id")
            return
        headers = {
            "Accept": "application/taxii+json;version=2.1",
            "User-Agent": "argus-feeds",
        }
        if config.get("api_key"):
            headers["Authorization"] = f"Bearer {config['api_key']}"
        params = {}
        if state.get("added_after"):
            params["added_after"] = state["added_after"]

        url = f"{api_root}/collections/{collection_id}/objects/"
        try:
            r = requests.get(url, headers=headers, params=params, timeout=30,
                              verify=config.get("verify_tls", True))
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            log.warning("TAXII poll failed: %s", e)
            return

        objects = data.get("objects", [])
        latest_added = state.get("added_after") or ""
        for obj in objects:
            otype = obj.get("type")
            added = obj.get("created") or obj.get("modified") or ""
            latest_added = max(latest_added, added)
            if otype == "indicator":
                pattern = obj.get("pattern", "")
                match = _watchlist_matches(pattern, watchlist)
                yield FeedEvent(
                    event_type="taxii-indicator",
                    timestamp=added,
                    payload={
                        "id": obj.get("id"),
                        "name": obj.get("name", ""),
                        "pattern": pattern,
                        "labels": obj.get("labels", []),
                        "valid_from": obj.get("valid_from"),
                    },
                    matched_pattern=match,
                )
            elif otype == "observed-data":
                blob = json.dumps(obj.get("objects", {}))
                match = _watchlist_matches(blob, watchlist)
                yield FeedEvent(
                    event_type="taxii-observation",
                    timestamp=added,
                    payload={
                        "id": obj.get("id"),
                        "first_observed": obj.get("first_observed"),
                        "objects": obj.get("objects", {}),
                    },
                    matched_pattern=match,
                )
        if latest_added:
            state["added_after"] = latest_added


# --- Generic REST endpoint (internal feeds / commercial APIs) --- #

class GenericRESTBackend(FeedBackend):
    """Polls an arbitrary REST endpoint returning a JSON list. The user
    configures:
      - url          : full URL with optional `{since}` placeholder
      - method       : GET or POST (default GET)
      - auth_header  : optional Authorization header value
      - auth_type    : 'bearer' / 'key' / 'basic' (cosmetic; we still emit the
                       header verbatim)
      - items_path   : dotted path inside response, e.g. "data.items"
      - event_type   : label for the emitted FeedEvent.event_type
      - match_fields : list of dotted paths whose values are checked against
                       the watchlist. Defaults to scanning the whole record.

    Suitable for internal threat-intel feeds (your company's STIX/JSON API)
    and commercial APIs (Intel471, KELA, RecordedFuture) when you supply the
    right URL/header.
    """

    @staticmethod
    def _dig(obj: Any, path: str) -> Any:
        cur = obj
        for part in path.split("."):
            if not part:
                continue
            if isinstance(cur, dict):
                cur = cur.get(part)
            elif isinstance(cur, list):
                try:
                    cur = cur[int(part)]
                except (ValueError, IndexError):
                    return None
            else:
                return None
        return cur

    @staticmethod
    def poll(config, state, watchlist):
        url = config.get("url", "")
        if not url:
            log.warning("REST feed missing url")
            return
        method = (config.get("method") or "GET").upper()
        headers = {"User-Agent": "argus-feeds", "Accept": "application/json"}
        if config.get("auth_header"):
            headers["Authorization"] = config["auth_header"]
        if state.get("since"):
            url = url.replace("{since}", state["since"])
        try:
            if method == "POST":
                r = requests.post(url, json=config.get("body") or {},
                                    headers=headers, timeout=30,
                                    verify=config.get("verify_tls", True))
            else:
                r = requests.get(url, headers=headers, timeout=30,
                                   verify=config.get("verify_tls", True))
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            log.warning("REST feed %s failed: %s", url, e)
            return

        items_path = config.get("items_path", "")
        items = GenericRESTBackend._dig(data, items_path) if items_path else data
        if not isinstance(items, list):
            items = [items] if items else []

        match_fields = config.get("match_fields") or []
        event_type = config.get("event_type", "rest-event")

        for item in items:
            if match_fields:
                haystack = " ".join(
                    str(GenericRESTBackend._dig(item, p) or "")
                    for p in match_fields
                )
            else:
                haystack = json.dumps(item, default=str)
            match = _watchlist_matches(haystack, watchlist)
            yield FeedEvent(
                event_type=event_type,
                timestamp=str(item.get("timestamp", "") if isinstance(item, dict) else ""),
                payload=item if isinstance(item, dict) else {"value": item},
                matched_pattern=match,
            )
        # Bump cursor (caller can set it via config["cursor_field"])
        if items and config.get("cursor_field"):
            last = items[-1] if isinstance(items[-1], dict) else {}
            cv = last.get(config["cursor_field"])
            if cv:
                state["since"] = str(cv)


# --- Generic HTML forum crawler (BreachForums / Exposed.vc / Cracked.io …) --- #

class ForumHTMLBackend(FeedBackend):
    """Crawl an HTML forum thread-listing page, ingest each new thread.

    The forum URL, auth cookies, and CSS selectors are all configurable. This
    backend assumes the operator has:
      - obtained a valid authenticated session cookie themselves (login is
        out of scope — we don't bypass auth or handle CAPTCHAs)
      - the legal authority to access the forum from their environment
      - is running Argus from an opsec-appropriate location (Tor / isolated
        VPN / non-attributable infra). We do NOT add this layer; we just
        use whatever proxy is configured.

    Config schema:
      base_url        : forum root, e.g. "http://breachforums...onion"
      list_path       : path to a thread listing, e.g. "/Forum-Leaks"
      needs_tor       : route through socks5h 127.0.0.1:9050 (default true if
                        ".onion" appears in base_url)
      session_cookies : dict of cookies acquired by manual login. Required if
                        the forum gates content behind auth.
      headers         : optional extra HTTP headers (CSRF tokens etc.)
      item_selector   : CSS selector matching each thread row in the listing
      title_selector  : CSS sub-selector for the title element inside an item
      link_attr       : attribute on title element holding the URL ("href")
      date_selector   : optional CSS for posted-at date
      author_selector : optional CSS for OP author
      max_items       : cap on how many threads to ingest per poll (default 50)
      event_type      : event_type tag (default "forum-thread")
    """

    @staticmethod
    def poll(config, state, watchlist):
        base = (config.get("base_url") or "").rstrip("/")
        if not base:
            log.warning("forum-html: missing base_url")
            return
        list_path = config.get("list_path") or "/"
        needs_tor = config.get("needs_tor",
                                ".onion" in base)
        item_sel = config.get("item_selector")
        title_sel = config.get("title_selector")
        if not item_sel or not title_sel:
            log.warning("forum-html: missing item_selector / title_selector")
            return
        link_attr = config.get("link_attr", "href")
        date_sel = config.get("date_selector")
        author_sel = config.get("author_selector")
        max_items = int(config.get("max_items", 50))
        event_type = config.get("event_type", "forum-thread")

        sess = requests.Session()
        if needs_tor:
            sess.proxies = {
                "http": "socks5h://127.0.0.1:9050",
                "https": "socks5h://127.0.0.1:9050",
            }
        cookies = config.get("session_cookies") or {}
        for k, v in cookies.items():
            sess.cookies.set(k, v)
        headers = {
            "User-Agent": config.get(
                "user_agent",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
            ),
            "Accept-Language": "en-US,en;q=0.7",
        }
        headers.update(config.get("headers") or {})

        url = base + list_path
        try:
            r = sess.get(url, headers=headers, timeout=60,
                          verify=config.get("verify_tls", True))
            if r.status_code != 200:
                log.warning("forum-html %s -> HTTP %s", url, r.status_code)
                return
        except Exception as e:
            log.warning("forum-html %s -> %s", url, e)
            return

        from bs4 import BeautifulSoup
        soup = BeautifulSoup(r.text, "html.parser")
        items = soup.select(item_sel)[:max_items]
        seen_urls = set(state.get("seen_urls", [])[-500:])
        new_seen: List[str] = []

        for item in items:
            title_tag = item.select_one(title_sel)
            if not title_tag:
                continue
            title = title_tag.get_text(" ", strip=True)
            link = title_tag.get(link_attr, "")
            if not link:
                continue
            if not link.startswith("http"):
                link = base + ("" if link.startswith("/") else "/") + link.lstrip("/")
            if link in seen_urls:
                continue
            new_seen.append(link)

            date = ""
            if date_sel:
                d = item.select_one(date_sel)
                if d:
                    date = d.get_text(" ", strip=True)
            author = ""
            if author_sel:
                a = item.select_one(author_sel)
                if a:
                    author = a.get_text(" ", strip=True)

            haystack = f"{title} {author} {date}"
            match = _watchlist_matches(haystack, watchlist)
            yield FeedEvent(
                event_type=event_type,
                timestamp=date or datetime.now(timezone.utc).isoformat(),
                payload={
                    "forum": base,
                    "title": title,
                    "url": link,
                    "author": author,
                    "date": date,
                },
                matched_pattern=match,
            )

        # Persist last N seen URLs to dedupe future polls
        keep = list(seen_urls) + new_seen
        state["seen_urls"] = keep[-1000:]


# --- Telegram channel monitor (poll t.me/s/<channel> for new posts) --- #

class TelegramChannelsBackend(FeedBackend):
    """Periodically poll a list of public Telegram channels via t.me/s/<handle>
    and emit one FeedEvent per new post. Watchlist match runs on each post's
    text.

    Config schema:
      channels        : list of channel handles (no @)
      max_per_channel : cap on posts to fetch per channel per poll (default 30)
      event_type      : default "telegram-post"
    """

    @staticmethod
    def poll(config, state, watchlist):
        from telegram_sources import tme_channel_preview
        channels = config.get("channels") or []
        if not channels:
            log.warning("telegram-channels: empty channels list")
            return
        max_per = int(config.get("max_per_channel", 30))
        event_type = config.get("event_type", "telegram-post")
        seen_per_channel = state.get("seen_post_urls") or {}

        for ch in channels:
            ch = str(ch).lstrip("@").strip("/")
            try:
                hits = tme_channel_preview(ch, query=None) or []
            except Exception as e:
                log.debug("tg poll %s: %s", ch, e)
                continue
            seen = set(seen_per_channel.get(ch, [])[-200:])
            new_for_channel: List[str] = []
            for h in hits[:max_per]:
                url = h.get("link") or ""
                text = h.get("raw") or h.get("snippet") or ""
                if url in seen:
                    continue
                new_for_channel.append(url)
                match = _watchlist_matches(text, watchlist)
                yield FeedEvent(
                    event_type=event_type,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    payload={
                        "channel": ch,
                        "url": url,
                        "text": text[:600],
                    },
                    matched_pattern=match,
                )
            if new_for_channel:
                merged = (seen_per_channel.get(ch, []) + new_for_channel)
                seen_per_channel[ch] = merged[-300:]
        state["seen_post_urls"] = seen_per_channel


# --- Backend registry --- #

BACKENDS: Dict[str, type] = {
    "ransomware-monitor": RansomwareMonitor,
    "misp": MISPBackend,
    "taxii": TAXIIBackend,
    "rest": GenericRESTBackend,
    "forum-html": ForumHTMLBackend,
    "telegram-channels": TelegramChannelsBackend,
}


# --------------------------------------------------------------------------- #
# Polling driver
# --------------------------------------------------------------------------- #

def poll_feed(feed_id: str) -> PollReport:
    """Poll a single feed by id. Persists new events + updates state."""
    import time
    t0 = time.time()
    report = PollReport(feed_id=feed_id)

    conn = connect()
    try:
        row = conn.execute(
            "SELECT id, kind, config, state, enabled FROM feeds WHERE id=?",
            (feed_id,),
        ).fetchone()
        if not row:
            report.error = f"feed not found: {feed_id}"
            return report
        if not row["enabled"]:
            report.error = "feed disabled"
            return report
        kind = row["kind"]
        backend_cls = BACKENDS.get(kind)
        if not backend_cls:
            report.error = f"unknown backend kind: {kind}"
            return report
        try:
            config = json.loads(row["config"] or "{}")
        except json.JSONDecodeError:
            config = {}
        try:
            state = json.loads(row["state"] or "{}")
        except (json.JSONDecodeError, TypeError):
            state = {}

        watchlist = list_watchlist()
    finally:
        conn.close()

    # Run the poll outside the connection scope to keep the DB lock short
    try:
        events: List[FeedEvent] = []
        for ev in backend_cls.poll(config, state, watchlist):
            events.append(ev)
            report.fetched += 1
            if ev.matched_pattern:
                report.matched_events += 1
    except Exception as e:
        report.error = f"{type(e).__name__}: {e}"

    # Persist events + new state
    conn = connect()
    try:
        if events:
            for ev in events:
                conn.execute("""
                    INSERT INTO feed_events
                        (feed_id, event_type, timestamp, payload,
                         matched_watchlist, matched_pattern)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    feed_id, ev.event_type, ev.timestamp,
                    json.dumps(ev.payload, default=str),
                    1 if ev.matched_pattern else 0,
                    ev.matched_pattern,
                ))
            report.new_events = len(events)
        conn.execute("""
            UPDATE feeds SET
                last_poll = ?,
                last_event_count = ?,
                last_error = ?,
                state = ?
            WHERE id = ?
        """, (
            datetime.now(timezone.utc).isoformat(),
            len(events),
            report.error,
            json.dumps(state, default=str),
            feed_id,
        ))
        conn.commit()
    finally:
        conn.close()

    report.duration_s = time.time() - t0
    return report


def poll_all(only_enabled: bool = True) -> List[PollReport]:
    """Poll every configured feed."""
    reports: List[PollReport] = []
    for f in list_feeds():
        if only_enabled and not f["enabled"]:
            continue
        reports.append(poll_feed(f["id"]))
    return reports
