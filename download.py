import os
import re
import time
import uuid
import pathlib
import requests
from typing import List, Dict

from search import get_tor_proxies


SAFE_EXTENSIONS = {
    ".txt",
    ".csv",
    ".json",
    ".log",
    ".md",
    ".sql",
    ".yaml",
    ".yml",
    ".tsv",
    ".xml",
    ".pdf",
}

SAFE_CONTENT_TYPES = {
    "text/plain",
    "text/csv",
    "text/markdown",
    "text/xml",
    "application/json",
    "application/xml",
    "application/pdf",
}


def _slugify(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9_-]+", "-", value)
    return value.strip("-").lower() or "file"


def _looks_safe(url: str, content_type: str | None) -> bool:
    ext = pathlib.Path(url.split("?", 1)[0]).suffix.lower()
    if ext in SAFE_EXTENSIONS:
        return True
    if content_type:
        for safe in SAFE_CONTENT_TYPES:
            if safe in content_type:
                return True
    return False


def _shorten(url: str, length: int = 80) -> str:
    return url if len(url) <= length else url[:length] + "..."


def download_safe_files(
    results: List[Dict],
    query: str,
    max_size_mb: int = 5,
    download_root: str = "downloads",
):
    """
    Download text-like files from the result set into an isolated per-query folder.

    Returns list of dicts with metadata about downloaded files.
    """
    if not results:
        return []

    proxies = get_tor_proxies()
    session = requests.Session()
    session.proxies = proxies
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    os.makedirs(download_root, exist_ok=True)
    safe_query = _slugify(query) or "query"
    run_id = f"{safe_query}_{int(time.time())}_{uuid.uuid4().hex[:6]}"
    target_dir = os.path.join(download_root, run_id)
    os.makedirs(target_dir, exist_ok=True)

    downloaded = []
    for item in results:
        url = item.get("link") or ""
        if not url:
            continue

        # Skip obvious binaries / archives
        ext = pathlib.Path(url.split("?", 1)[0]).suffix.lower()
        if ext in {".exe", ".dll", ".apk", ".bin", ".iso", ".msi", ".dmg", ".xz", ".gz"}:
            continue

        # Quick HEAD check for size + content-type
        try:
            head = session.head(url, timeout=20, allow_redirects=True)
            size = int(head.headers.get("Content-Length", 0))
            ctype = head.headers.get("Content-Type", "")
        except Exception:
            size = 0
            ctype = ""

        if size and size > max_size_mb * 1024 * 1024:
            continue
        if not _looks_safe(url, ctype):
            continue

        fname = pathlib.Path(url.split("?", 1)[0]).name or _slugify(url)
        dest_path = os.path.join(target_dir, fname)

        try:
            resp = session.get(url, timeout=60, allow_redirects=True)
            if resp.status_code != 200:
                continue
            data = resp.content
            if len(data) > max_size_mb * 1024 * 1024:
                continue
            with open(dest_path, "wb") as f:
                f.write(data)
            downloaded.append(
                {
                    "url": url,
                    "path": dest_path,
                    "bytes": len(data),
                    "content_type": resp.headers.get("Content-Type", ctype),
                    "title": item.get("title", ""),
                }
            )
        except Exception:
            continue

    # If nothing got downloaded, clean empty dir
    if not downloaded:
        try:
            os.rmdir(target_dir)
        except OSError:
            pass
    return downloaded
