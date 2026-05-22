"""
Dark-web + clearweb search aggregator.

Each engine is declared as a config dict with per-engine HTML selectors so we
extract clean title + URL + snippet instead of every <a> tag on the page.
Engines that don't match a selector fall back to a generic parser.
"""

import re
import random
import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import warnings
warnings.filterwarnings("ignore")

from osint_sources import gather_clearweb
from darkweb_extras import (
    active_ransomware_leak_sites,
    search_ransomware_groups,
    search_dread,
    rotate_tor_circuit,
)

log = logging.getLogger(__name__)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (X11; Linux i686; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
]


@dataclass
class Engine:
    """Declarative configuration for one search engine."""
    name: str
    url: str                                # {query} placeholder, can include {page} for pagination
    result_selector: Optional[str] = None   # CSS selector for result <a> tags
    snippet_selector: Optional[str] = None  # sibling/child selector relative to each result
    page_param: Optional[str] = None        # e.g. "&p={n}" or "?page={n}"
    max_pages: int = 1
    needs_tor: bool = True
    label: str = ""                         # short tag shown in result titles


SEARCH_ENGINES: List[Engine] = [
    Engine(
        name="Ahmia",
        url="http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}",
        result_selector="li.result h4 a",
        snippet_selector="li.result p",
        page_param="&page={n}", max_pages=3,
        label="ahmia",
    ),
    Engine(
        name="Ahmia (clearnet)",
        url="https://ahmia.fi/search/?q={query}",
        result_selector="li.result h4 a",
        snippet_selector="li.result p",
        page_param="&page={n}", max_pages=3,
        needs_tor=False, label="ahmia",
    ),
    Engine(
        name="Tor66",
        url="http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={query}",
        result_selector="b a.titles",
        snippet_selector="font[size='2']",
        label="tor66",
    ),
    Engine(
        name="Torch v3",
        url="http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/?q={query}",
        result_selector="dt a",
        snippet_selector="dd",
        label="torch",
    ),
    Engine(
        name="Haystack",
        url="http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/?q={query}",
        result_selector="div.result a",
        snippet_selector="div.description",
        label="haystack",
    ),
    Engine(
        name="OnionLand",
        url="http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={query}",
        result_selector="div.result-block a.title",
        snippet_selector="div.result-block span.description",
        label="onionland",
    ),
    Engine(
        name="The Deep Searches",
        url="http://searchgf7gdtauh7bhnbyed4ivxqmuoat3nm6zfrg3ymkq6mtnpye3ad.onion/search?q={query}",
        result_selector="div.result h5 a",
        snippet_selector="div.result p",
        label="deep",
    ),
    Engine(
        name="Excavator",
        url="http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/search?query={query}",
        label="excavator",
    ),
    Engine(
        name="Tornado",
        url="http://tornadoxn3viscgz647shlysdy7ea5zqzwda7hierekeuokh5eh5b3qd.onion/search?q={query}",
        label="tornado",
    ),
    Engine(
        name="Amnesia",
        url="http://amnesia7u5odx5xbwtpnqk3edybgud5bmiagu75bnqx2crntw5kry7ad.onion/search?query={query}",
        label="amnesia",
    ),
    Engine(
        name="OnionSearch (clearnet)",
        url="https://onionsearchengine.com/search?q={query}",
        result_selector="div.search_result a",
        snippet_selector="div.search_result p",
        needs_tor=False, label="ose",
    ),
]


# Track engines that have failed this run so subsequent calls skip them.
_DEAD_ENGINES: set = set()

BREACH_KEYWORDS = [
    "breach", "leak", "dump", "database", "db",
    "forum", "discussion", "thread", "paste", "chat", "topic",
    "ransom", "stealer", "combolist", "credentials", "cred", "leaks",
]

# Engines link to themselves in their own results - skip those.
_SEARCH_DOMAIN_BLOCKLIST = re.compile(
    r"(ahmia\.fi|onionsearchengine|onionlandsearchengine|/search(\?|/|$)"
    r"|\.onion/search(\?|/|$))"
)


def get_tor_proxies() -> Dict[str, str]:
    return {
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050",
    }


def _build_session(use_tor: bool) -> requests.Session:
    """Session with retry + Tor proxy. Reused per-engine to keep keep-alive."""
    s = requests.Session()
    retry = Retry(
        total=2, connect=2, read=2,
        backoff_factor=0.5,
        status_forcelist=[502, 503, 504, 429],
        allowed_methods=["GET", "HEAD"],
    )
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    if use_tor:
        s.proxies = get_tor_proxies()
    return s


def _fetch_page(session: requests.Session, url: str, timeout: int) -> Optional[str]:
    headers = {"User-Agent": random.choice(USER_AGENTS), "Accept-Language": "en-US,en;q=0.7"}
    try:
        r = session.get(url, headers=headers, timeout=timeout)
        if r.status_code != 200:
            log.debug("engine HTTP %s: %s", r.status_code, url[:80])
            return None
        return r.text
    except requests.exceptions.RequestException as e:
        log.debug("fetch error %s: %s", url[:80], e)
        return None


def _parse_engine_results(html: str, engine: Engine) -> List[Dict]:
    """Use engine-specific selectors first, fall back to generic parser."""
    soup = BeautifulSoup(html, "html.parser")
    results: List[Dict] = []

    if engine.result_selector:
        try:
            result_links = soup.select(engine.result_selector)
            snippets_iter = (
                soup.select(engine.snippet_selector) if engine.snippet_selector else []
            )
            for i, a in enumerate(result_links):
                href = a.get("href", "")
                title = a.get_text(strip=True)
                if not title or not href:
                    continue
                # Strip Ahmia's redirect wrapper
                if "/redirect?" in href or "uddg=" in href:
                    m = re.search(r"(?:redirect_url|uddg)=([^&]+)", href)
                    if m:
                        from urllib.parse import unquote
                        href = unquote(m.group(1))
                snippet = ""
                if i < len(snippets_iter):
                    snippet = snippets_iter[i].get_text(" ", strip=True)[:400]
                results.append({"title": title, "link": href, "snippet": snippet})
            if results:
                return results
        except Exception as e:
            log.debug("selector parse failed for %s: %s", engine.name, e)

    # Generic fallback: any <a> with an onion or http URL, skip navigation links.
    for a in soup.find_all("a"):
        try:
            href = a.get("href") or ""
            title = a.get_text(strip=True)
            if not title or len(title) < 4:
                continue
            link_match = re.search(r"https?://[^\s\"']+|[a-z2-7]{16,56}\.onion[^\s\"']*", href)
            if not link_match:
                continue
            candidate = link_match.group(0).rstrip(").,;\"'>")
            if _SEARCH_DOMAIN_BLOCKLIST.search(candidate):
                continue
            results.append({"title": title, "link": candidate, "snippet": ""})
        except Exception:
            continue
    return results


def fetch_engine(engine: Engine, query: str) -> List[Dict]:
    """Fetch all configured pages from one engine and return cleaned hits."""
    if engine.name in _DEAD_ENGINES:
        return []

    session = _build_session(engine.needs_tor)
    timeout = 40 if engine.needs_tor else 15
    results: List[Dict] = []

    for page in range(1, max(1, engine.max_pages) + 1):
        url = engine.url.format(query=query)
        if page > 1 and engine.page_param:
            url += engine.page_param.format(n=page)
        html = _fetch_page(session, url, timeout)
        if html is None and page == 1:
            _DEAD_ENGINES.add(engine.name)
            break
        if not html:
            break
        page_results = _parse_engine_results(html, engine)
        if not page_results and page > 1:
            break
        for r in page_results:
            r["title"] = f"[{engine.label or engine.name}] {r['title']}"
            r["engine"] = engine.name
        results.extend(page_results)
        if engine.max_pages > 1 and page < engine.max_pages:
            time.sleep(0.4)  # be polite

    return results


def _score_result(item: Dict, focus_terms: List[str]) -> int:
    """Score a hit: more is better. Used to rank results before LLM filtering."""
    haystack = (
        f"{item.get('title','')} {item.get('link','')} {item.get('snippet','')}"
    ).lower()
    score = 0
    for kw in BREACH_KEYWORDS:
        if kw in haystack:
            score += 2
    for term in focus_terms or []:
        if term.lower() in haystack:
            score += 5
    if ".onion" in item.get("link", ""):
        score += 1
    if item.get("snippet"):
        score += 1
    if item.get("source"):  # comes from structured clearweb source
        score += 3
    return score


def get_search_results(
    refined_query: str,
    max_workers: int = 5,
    focus_terms: Optional[List[str]] = None,
    include_clearweb_osint: bool = True,
    clearweb_sources: Optional[List[str]] = None,
    include_dread: bool = True,
    include_ransomware_sites: bool = True,
    rotate_circuit: bool = True,
) -> List[Dict]:
    """Aggregate dark-web search engines + clearweb OSINT + targeted dark-web sources."""
    all_results: List[Dict] = []
    decoded_query = refined_query.replace("+", " ")

    # Optionally request a fresh Tor circuit before flooding requests
    if rotate_circuit:
        rotate_tor_circuit(silent=True)

    # 1. Aggregate dark-web search engines (per-engine parsers)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(fetch_engine, engine, refined_query): engine for engine in SEARCH_ENGINES}
        for fut in as_completed(futures):
            try:
                all_results.extend(fut.result() or [])
            except Exception as e:
                log.debug("engine future error: %s", e)

    # 2. Targeted dark-web sources (Dread + active ransomware leak sites)
    targeted: List[Dict] = []
    if include_dread:
        try:
            targeted.extend(search_dread(decoded_query))
        except Exception as e:
            log.warning("dread search failed: %s", e)
    if include_ransomware_sites:
        try:
            targeted.extend(search_ransomware_groups(decoded_query))
        except Exception as e:
            log.warning("ransomware groups search failed: %s", e)
    all_results.extend(targeted)

    # 3. Clearweb OSINT (ransomware.live API, crt.sh, HIBP, ...)
    if include_clearweb_osint:
        try:
            for hit in gather_clearweb(decoded_query, enabled=clearweb_sources):
                all_results.append({
                    "title": hit.get("title", ""),
                    "link": hit.get("link", ""),
                    "snippet": hit.get("snippet", ""),
                    "source": hit.get("source", ""),
                })
        except Exception as e:
            log.warning("clearweb OSINT gather failed: %s", e)

    # Deduplicate by normalized link
    seen = set()
    unique: List[Dict] = []
    for r in all_results:
        link = (r.get("link") or "").rstrip("/").lower()
        if not link or link in seen:
            continue
        # Drop self-referential engine links
        if _SEARCH_DOMAIN_BLOCKLIST.search(link):
            continue
        seen.add(link)
        unique.append(r)

    # Score + rank: structured sources first, then by breach/focus score
    unique.sort(key=lambda r: _score_result(r, focus_terms or []), reverse=True)

    # If focus_terms given, prefer hits that mention them but never drop everything
    if focus_terms:
        lowered = [t.lower() for t in focus_terms if t]
        focused = [
            r for r in unique
            if any(t in f"{r.get('title','')} {r.get('link','')} {r.get('snippet','')}".lower()
                   for t in lowered)
        ]
        return focused or unique
    return unique


def healthcheck_engines(timeout: int = 8) -> Dict[str, bool]:
    """Reachability check for each search engine. Tor calls take longer."""
    out: Dict[str, bool] = {}
    for engine in SEARCH_ENGINES:
        url = engine.url.split("?", 1)[0].split("/search", 1)[0]
        sess = _build_session(engine.needs_tor)
        eff_timeout = 30 if engine.needs_tor else timeout
        try:
            r = sess.get(url, timeout=eff_timeout, allow_redirects=True, stream=True)
            out[engine.name] = r.status_code < 500
            r.close()
        except requests.RequestException:
            out[engine.name] = False
    return out


def list_engines() -> List[Dict]:
    """Snapshot of engine config — used by UI/CLI to display source coverage."""
    return [
        {"name": e.name, "label": e.label, "tor": e.needs_tor,
         "pages": e.max_pages, "url": e.url.split("?", 1)[0]}
        for e in SEARCH_ENGINES
    ]
