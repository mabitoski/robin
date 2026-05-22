"""
Tor-aware scraper with optional 1-hop "deep" mode that follows promising
forum/thread links on the landing page before extracting text.
"""

import re
import random
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

import warnings
warnings.filterwarnings("ignore")

log = logging.getLogger(__name__)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (X11; Linux i686; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
]

THREAD_KEYWORDS = [
    "thread", "topic", "post", "showthread", "view-thread", "victim", "leak",
    "dump", "release", "breach", "viewtopic", "discussion", "/t/",
]


def get_tor_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=3, read=3, connect=3,
        backoff_factor=0.4,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.proxies = {
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050",
    }
    return s


def _is_thread_link(href: str, anchor_text: str, base_host: str) -> bool:
    """Heuristic: does this link look like a forum thread or victim entry?"""
    if not href:
        return False
    parsed = urlparse(href)
    if parsed.netloc and parsed.netloc != base_host:
        return False  # stay on the same host for the 1-hop pivot
    combined = f"{href.lower()} {anchor_text.lower()}"
    return any(kw in combined for kw in THREAD_KEYWORDS)


def _extract_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.extract()
    text = soup.get_text(separator=" ")
    return " ".join(text.split())


def _fetch(url: str, session: requests.Session, timeout: int) -> Optional[str]:
    headers = {"User-Agent": random.choice(USER_AGENTS), "Accept-Language": "en-US,en;q=0.7"}
    try:
        r = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        if r.status_code != 200:
            log.debug("scrape %s -> HTTP %s", url[:80], r.status_code)
            return None
        return r.text
    except requests.RequestException as e:
        log.debug("scrape error %s: %s", url[:80], e)
        return None


def scrape_single(
    url_data: Dict,
    deep: bool = False,
    max_followups: int = 2,
) -> Tuple[str, str]:
    """Scrape one URL. In deep mode, follow up to `max_followups` on-host
    thread-looking links and append their text to the parent page text.
    """
    url = url_data.get("link", "")
    title = url_data.get("title", "")
    snippet = url_data.get("snippet", "")
    use_tor = ".onion" in url
    session = get_tor_session() if use_tor else requests.Session()
    timeout = 45 if use_tor else 25

    html = _fetch(url, session, timeout)
    if html is None:
        # Keep title + snippet so the LLM still has *some* context
        return url, f"{title}\n{snippet}".strip()

    main_text = _extract_text(html)
    sections = [f"{title}\n{snippet}\n{main_text}"]

    if deep and max_followups > 0:
        try:
            soup = BeautifulSoup(html, "html.parser")
            base_host = urlparse(url).netloc
            picked: List[str] = []
            for a in soup.find_all("a", href=True):
                href = urljoin(url, a["href"])
                anchor_text = a.get_text(" ", strip=True)[:120]
                if _is_thread_link(href, anchor_text, base_host) and href not in picked:
                    picked.append(href)
                if len(picked) >= max_followups:
                    break
            for child_url in picked:
                child_html = _fetch(child_url, session, timeout)
                if child_html:
                    sections.append(f"--- thread {child_url} ---\n{_extract_text(child_html)}")
        except Exception as e:
            log.debug("deep crawl failed for %s: %s", url[:80], e)

    return url, "\n\n".join(sections).strip()


def scrape_multiple(
    urls_data: List[Dict],
    max_workers: int = 5,
    deep: bool = False,
    max_chars: int = 4000,
) -> Dict[str, str]:
    """Scrape many URLs concurrently."""
    results: Dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_url = {
            pool.submit(scrape_single, u, deep=deep): u for u in urls_data
        }
        for fut in as_completed(future_to_url):
            try:
                url, content = fut.result()
                if len(content) > max_chars:
                    content = content[:max_chars] + "...(truncated)"
                results[url] = content
            except Exception as e:
                log.debug("scrape future error: %s", e)
                continue
    return results


def filter_content_by_terms(content: Dict[str, str], focus_terms: List[str]) -> Dict[str, str]:
    """Keep only entries that mention at least one focus term."""
    if not content:
        return {}
    normalized = [t.lower() for t in (focus_terms or []) if t]
    if not normalized:
        return content
    return {
        u: t for u, t in content.items()
        if any(term in f"{u} {t}".lower() for term in normalized)
    }
