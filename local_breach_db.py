"""
Local breach database for Argus.

Indexes breach dumps you've obtained locally and exposes a HIBP/XposedOrNot-
style lookup API. SQLite under the hood — handles up to a few hundred
million credentials on a single file without sharding.

Schema:

  breaches(id, name, year, domain, description, data_classes, records, added_at)
  credentials(id, email COLLATE NOCASE, password, breach_id)
  INDEX idx_email_credentials(email)
  INDEX idx_breach_credentials(breach_id)

Workflow:

  1. obtain a breach dump (e.g. leaked combolist `email:password\\n` lines)
  2. `ingest_file("dump.txt", breach_name="ExampleCorp_2024", year=2024,
                  domain="example.com", data_classes="emails,passwords")`
  3. `check_email("victime@example.com")` returns the breach metadata
  4. `get_credentials("victime@example.com")` returns the leaked rows
     (passwords masked by default; pass plaintext=True for raw)

Ethics / legal:
  Possessing breach data for security research / personal account monitoring
  is legal in most jurisdictions. Distributing it is often not. This module
  provides storage + indexing; the user supplies the data they are entitled
  to use.
"""

from __future__ import annotations

import gzip
import io
import logging
import os
import re
import sqlite3
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

log = logging.getLogger(__name__)

DB_PATH = Path(os.getenv(
    "ARGUS_BREACH_DB",
    str(Path(__file__).parent / "data" / "breaches.db"),
))

SCHEMA = """
CREATE TABLE IF NOT EXISTS breaches (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT UNIQUE NOT NULL,
    year          INTEGER,
    domain        TEXT,
    description   TEXT,
    data_classes  TEXT,
    source_file   TEXT,
    records       INTEGER DEFAULT 0,
    added_at      TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS credentials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT NOT NULL COLLATE NOCASE,
    password    TEXT,
    breach_id   INTEGER NOT NULL,
    FOREIGN KEY (breach_id) REFERENCES breaches(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_email_credentials   ON credentials(email);
CREATE INDEX IF NOT EXISTS idx_breach_credentials  ON credentials(breach_id);

CREATE TABLE IF NOT EXISTS feeds (
    id                TEXT PRIMARY KEY,
    kind              TEXT NOT NULL,
    display           TEXT,
    config            TEXT,
    enabled           INTEGER DEFAULT 1,
    last_poll         TEXT,
    last_event_count  INTEGER DEFAULT 0,
    last_error        TEXT,
    state             TEXT,
    added_at          TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS watchlist (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern   TEXT NOT NULL,
    label     TEXT,
    added_at  TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_watchlist_pattern ON watchlist(pattern);

CREATE TABLE IF NOT EXISTS feed_events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_id           TEXT NOT NULL,
    event_type        TEXT,
    timestamp         TEXT,
    payload           TEXT,
    matched_watchlist INTEGER DEFAULT 0,
    matched_pattern   TEXT,
    seen              INTEGER DEFAULT 0,
    FOREIGN KEY (feed_id) REFERENCES feeds(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_feed_events_feed    ON feed_events(feed_id);
CREATE INDEX IF NOT EXISTS idx_feed_events_matched ON feed_events(matched_watchlist);
CREATE INDEX IF NOT EXISTS idx_feed_events_ts      ON feed_events(timestamp DESC);
"""


# --------------------------------------------------------------------------- #
# Connection management
# --------------------------------------------------------------------------- #

def _ensure_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    _ensure_db()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-200000")  # ~200 MB cache
    conn.row_factory = sqlite3.Row
    for stmt in SCHEMA.strip().split(";"):
        s = stmt.strip()
        if s:
            conn.execute(s)
    conn.commit()
    return conn


# --------------------------------------------------------------------------- #
# Ingest
# --------------------------------------------------------------------------- #

_EMAIL_LINE_RE = re.compile(
    r"^([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24})[\s:;,|\t]+(.+?)\s*$"
)


def _open_text(path: str) -> Iterable[str]:
    """Yield lines from a .txt / .gz / .zip file, decoded permissively."""
    p = Path(path)
    if p.suffix.lower() == ".gz":
        with gzip.open(p, mode="rt", encoding="utf-8", errors="replace") as f:
            yield from f
    elif p.suffix.lower() == ".zip":
        with zipfile.ZipFile(p) as z:
            for name in z.namelist():
                if name.endswith("/"):
                    continue
                with z.open(name) as fh:
                    yield from io.TextIOWrapper(fh, encoding="utf-8",
                                                 errors="replace")
    else:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            yield from f


@dataclass
class IngestReport:
    breach: str
    lines_read: int = 0
    rows_inserted: int = 0
    skipped: int = 0
    duration_s: float = 0.0

    def __str__(self) -> str:
        rate = self.rows_inserted / self.duration_s if self.duration_s > 0 else 0
        return (
            f"[{self.breach}] {self.rows_inserted:,} rows ingested in "
            f"{self.duration_s:.1f}s ({rate:.0f} rows/s, "
            f"{self.skipped:,} skipped, {self.lines_read:,} lines read)"
        )


def ingest_file(
    path: str,
    breach_name: str,
    year: Optional[int] = None,
    domain: Optional[str] = None,
    description: str = "",
    data_classes: str = "emails,passwords",
    batch_size: int = 10000,
    progress_cb: Optional[callable] = None,
) -> IngestReport:
    """Ingest one breach file into the local DB.

    Each line is expected to be `email<sep>password` where <sep> is one of
    `:` `;` `,` `|` or tab. Lines that don't match are skipped.

    Returns an IngestReport with counts.
    """
    report = IngestReport(breach=breach_name)
    t0 = time.time()

    conn = connect()
    try:
        # Upsert the breach row
        conn.execute("""
            INSERT INTO breaches (name, year, domain, description, data_classes,
                                   source_file)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
              year         = COALESCE(excluded.year, breaches.year),
              domain       = COALESCE(excluded.domain, breaches.domain),
              description  = COALESCE(NULLIF(excluded.description,''), breaches.description),
              data_classes = COALESCE(NULLIF(excluded.data_classes,''), breaches.data_classes),
              source_file  = excluded.source_file
        """, (breach_name, year, domain, description, data_classes, str(path)))
        breach_id = conn.execute(
            "SELECT id FROM breaches WHERE name=?", (breach_name,),
        ).fetchone()[0]
        conn.commit()

        batch: List[Tuple[str, str, int]] = []
        cursor = conn.cursor()
        for line in _open_text(path):
            report.lines_read += 1
            m = _EMAIL_LINE_RE.match(line)
            if not m:
                report.skipped += 1
                continue
            email, password = m.group(1).strip().lower(), m.group(2).strip()
            batch.append((email, password, breach_id))
            if len(batch) >= batch_size:
                cursor.executemany(
                    "INSERT INTO credentials (email, password, breach_id) VALUES (?,?,?)",
                    batch,
                )
                report.rows_inserted += len(batch)
                batch.clear()
                conn.commit()
                if progress_cb:
                    progress_cb(report)
        if batch:
            cursor.executemany(
                "INSERT INTO credentials (email, password, breach_id) VALUES (?,?,?)",
                batch,
            )
            report.rows_inserted += len(batch)
        conn.execute("UPDATE breaches SET records = records + ? WHERE id = ?",
                      (report.rows_inserted, breach_id))
        conn.commit()
    finally:
        conn.close()

    report.duration_s = time.time() - t0
    return report


# --------------------------------------------------------------------------- #
# Query
# --------------------------------------------------------------------------- #

def _mask_password(pwd: str) -> str:
    if not pwd:
        return ""
    if len(pwd) <= 2:
        return "•" * len(pwd)
    return pwd[0] + "•" * (len(pwd) - 2) + pwd[-1] + f" ({len(pwd)})"


def check_email(email: str) -> List[Dict]:
    """Return the list of breaches the email is in (HIBP-style summary).

    Each entry: {breach, year, domain, data_classes, records_in_breach,
                 your_credentials_count, password_seen}.
    """
    out: List[Dict] = []
    conn = connect()
    try:
        rows = conn.execute("""
            SELECT b.name, b.year, b.domain, b.description, b.data_classes,
                   b.records AS breach_records,
                   COUNT(c.id) AS user_rows,
                   SUM(CASE WHEN c.password IS NOT NULL AND c.password != ''
                            THEN 1 ELSE 0 END) AS user_with_pwd
            FROM breaches b
            JOIN credentials c ON c.breach_id = b.id
            WHERE c.email = ?
            GROUP BY b.id
            ORDER BY b.year DESC
        """, (email.lower(),)).fetchall()
        for r in rows:
            out.append({
                "breach": r["name"],
                "year": r["year"],
                "domain": r["domain"],
                "description": r["description"],
                "data_classes": r["data_classes"],
                "breach_records": r["breach_records"],
                "your_credentials_count": r["user_rows"],
                "passwords_present": r["user_with_pwd"],
            })
    finally:
        conn.close()
    return out


def get_credentials(email: str, plaintext: bool = False) -> List[Dict]:
    """Return the raw credential rows for `email`. Passwords are masked by
    default (only first + last char visible)."""
    out: List[Dict] = []
    conn = connect()
    try:
        rows = conn.execute("""
            SELECT b.name AS breach, b.year, c.password
            FROM credentials c
            JOIN breaches b ON b.id = c.breach_id
            WHERE c.email = ?
            ORDER BY b.year DESC
        """, (email.lower(),)).fetchall()
        for r in rows:
            pwd = r["password"] or ""
            out.append({
                "breach": r["breach"], "year": r["year"],
                "password": pwd if plaintext else _mask_password(pwd),
            })
    finally:
        conn.close()
    return out


def search_domain(domain: str, limit: int = 100) -> List[Dict]:
    """Find all distinct breached emails for a given domain (e.g. acme.com)."""
    out: List[Dict] = []
    conn = connect()
    try:
        rows = conn.execute("""
            SELECT c.email, COUNT(DISTINCT c.breach_id) AS breach_count,
                   GROUP_CONCAT(DISTINCT b.name) AS breaches
            FROM credentials c
            JOIN breaches b ON b.id = c.breach_id
            WHERE c.email LIKE ?
            GROUP BY c.email
            ORDER BY breach_count DESC
            LIMIT ?
        """, (f"%@{domain.lower()}", limit)).fetchall()
        for r in rows:
            out.append({
                "email": r["email"],
                "breach_count": r["breach_count"],
                "breaches": r["breaches"],
            })
    finally:
        conn.close()
    return out


def stats() -> Dict:
    """High-level DB stats for the UI / health check."""
    conn = connect()
    try:
        breach_count = conn.execute("SELECT COUNT(*) FROM breaches").fetchone()[0]
        cred_count = conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
        unique_emails = conn.execute(
            "SELECT COUNT(DISTINCT email) FROM credentials"
        ).fetchone()[0]
        db_size_bytes = DB_PATH.stat().st_size if DB_PATH.exists() else 0
        breaches = [dict(r) for r in conn.execute(
            "SELECT name, year, domain, records, added_at FROM breaches "
            "ORDER BY added_at DESC"
        ).fetchall()]
    finally:
        conn.close()
    return {
        "db_path": str(DB_PATH),
        "db_size_bytes": db_size_bytes,
        "breach_count": breach_count,
        "credential_count": cred_count,
        "unique_emails": unique_emails,
        "breaches": breaches,
    }


def delete_breach(breach_name: str) -> int:
    """Remove a breach and all its credentials. Returns number of rows
    deleted from `credentials`."""
    conn = connect()
    try:
        row = conn.execute("SELECT id FROM breaches WHERE name=?",
                            (breach_name,)).fetchone()
        if not row:
            return 0
        bid = row[0]
        cur = conn.execute("DELETE FROM credentials WHERE breach_id=?", (bid,))
        deleted = cur.rowcount
        conn.execute("DELETE FROM breaches WHERE id=?", (bid,))
        conn.commit()
        return deleted
    finally:
        conn.close()


def vacuum() -> None:
    """Reclaim disk space after deleting breaches."""
    conn = connect()
    try:
        conn.execute("VACUUM")
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Scratch extract — download a dump, extract matching lines, purge the dump
# --------------------------------------------------------------------------- #

@dataclass
class ScratchReport:
    breach: str
    source_url: str
    bytes_downloaded: int = 0
    lines_scanned: int = 0
    lines_matched: int = 0
    duration_s: float = 0.0
    purged: bool = False
    purge_method: str = ""
    error: Optional[str] = None

    def __str__(self) -> str:
        if self.error:
            return f"[scratch:{self.breach}] ERROR: {self.error}"
        return (
            f"[scratch:{self.breach}] {self.bytes_downloaded/1e6:.1f} MB downloaded, "
            f"{self.lines_scanned:,} lines scanned, "
            f"{self.lines_matched:,} matched, "
            f"purged via {self.purge_method} "
            f"({self.duration_s:.1f}s)"
        )


def _secure_delete(path: Path, passes: int = 1) -> str:
    """Overwrite the file with zeros then delete. Returns the method used."""
    try:
        size = path.stat().st_size
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                # Write in 4MB chunks so big files don't OOM
                CHUNK = 4 * 1024 * 1024
                remaining = size
                while remaining > 0:
                    f.write(b"\x00" * min(CHUNK, remaining))
                    remaining -= CHUNK
                f.flush()
                os.fsync(f.fileno())
        path.unlink()
        return f"zero-overwrite-{passes}pass"
    except Exception as e:
        log.warning("secure delete failed for %s: %s — falling back to unlink", path, e)
        try:
            path.unlink()
        except OSError:
            pass
        return "unlink-fallback"


def fetch_and_extract(
    source_url: str,
    breach_name: str,
    watchlist: List[str],
    year: Optional[int] = None,
    domain: Optional[str] = None,
    description: str = "",
    data_classes: str = "emails,passwords",
    use_tor: bool = False,
    max_size_mb: int = 5000,
    secure_delete_passes: int = 1,
    progress_cb=None,
) -> ScratchReport:
    """Download a breach dump, scan it for lines matching `watchlist`, ingest
    ONLY the matching lines into the local DB, then securely delete the dump.

    The watchlist can be:
      - exact emails ("alice@acme.com")
      - domain wildcards ("@acme.com" — matches any email at acme.com)

    Lines are streamed (no full-file load in memory). After scan, the temp
    file is overwritten with zeros and unlinked.

    Args:
      source_url: HTTPS or http://...onion URL pointing at a breach file
                  (.txt / .gz / .zip). The user is responsible for the
                  legality of accessing this URL.
      watchlist : emails / domain patterns to keep
      use_tor   : route the download through SOCKS5h 127.0.0.1:9050
      max_size_mb: hard cap on download size (defensive); aborts if exceeded

    Returns a ScratchReport summarizing what happened.
    """
    import requests as _r
    import tempfile

    report = ScratchReport(breach=breach_name, source_url=source_url)
    t0 = time.time()

    # Normalize watchlist
    exact_emails = {w.lower().strip() for w in watchlist
                    if "@" in w and not w.startswith("@")}
    domain_patterns = {w.lower().strip().lstrip("@") for w in watchlist
                       if w.startswith("@") or (w.startswith(".") and "." in w[1:])}
    # If a watchlist entry is "acme.com" without @, treat as a domain match too
    for w in watchlist:
        ws = w.lower().strip()
        if ws and "@" not in ws and "." in ws:
            domain_patterns.add(ws)
    if not exact_emails and not domain_patterns:
        report.error = "Empty watchlist"
        return report

    # Download to tmp file
    tmp_dir = Path(__file__).parent / "data" / "scratch"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    suffix = Path(source_url).suffix or ".tmp"
    fh = tempfile.NamedTemporaryFile(
        delete=False, dir=str(tmp_dir), suffix=suffix,
    )
    tmp_path = Path(fh.name)
    fh.close()

    proxies = (
        {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
        if use_tor else None
    )

    try:
        with _r.get(source_url, stream=True, proxies=proxies, timeout=120) as r:
            r.raise_for_status()
            with open(tmp_path, "wb") as out:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if not chunk:
                        continue
                    out.write(chunk)
                    report.bytes_downloaded += len(chunk)
                    if report.bytes_downloaded > max_size_mb * 1024 * 1024:
                        raise RuntimeError(
                            f"Aborted: size > max_size_mb={max_size_mb}"
                        )
                    if progress_cb and report.bytes_downloaded % (10 * 1024 * 1024) < 1024 * 1024:
                        progress_cb(report)
    except Exception as e:
        report.error = f"Download failed: {e}"
        report.duration_s = time.time() - t0
        if tmp_path.exists():
            report.purge_method = _secure_delete(tmp_path, secure_delete_passes)
            report.purged = True
        return report

    # Stream-scan the downloaded file for matches
    conn = connect()
    try:
        conn.execute("""
            INSERT INTO breaches (name, year, domain, description, data_classes,
                                   source_file)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
              year         = COALESCE(excluded.year, breaches.year),
              domain       = COALESCE(excluded.domain, breaches.domain),
              description  = COALESCE(NULLIF(excluded.description,''), breaches.description),
              data_classes = COALESCE(NULLIF(excluded.data_classes,''), breaches.data_classes),
              source_file  = excluded.source_file
        """, (breach_name, year, domain, description, data_classes,
              f"scratch:{source_url}"))
        breach_id = conn.execute(
            "SELECT id FROM breaches WHERE name=?", (breach_name,)
        ).fetchone()[0]
        conn.commit()

        batch: List[Tuple[str, str, int]] = []
        cur = conn.cursor()
        for line in _open_text(str(tmp_path)):
            report.lines_scanned += 1
            m = _EMAIL_LINE_RE.match(line)
            if not m:
                continue
            email = m.group(1).strip().lower()
            password = m.group(2).strip()
            email_domain = email.split("@", 1)[-1] if "@" in email else ""
            if email in exact_emails or any(
                email_domain == d or email_domain.endswith("." + d)
                for d in domain_patterns
            ):
                batch.append((email, password, breach_id))
                report.lines_matched += 1
                if len(batch) >= 5000:
                    cur.executemany(
                        "INSERT INTO credentials (email, password, breach_id) VALUES (?,?,?)",
                        batch,
                    )
                    batch.clear()
                    conn.commit()
                    if progress_cb:
                        progress_cb(report)
        if batch:
            cur.executemany(
                "INSERT INTO credentials (email, password, breach_id) VALUES (?,?,?)",
                batch,
            )
        conn.execute("UPDATE breaches SET records = records + ? WHERE id = ?",
                      (report.lines_matched, breach_id))
        conn.commit()
    finally:
        conn.close()

    # ALWAYS purge the temp file
    report.purge_method = _secure_delete(tmp_path, secure_delete_passes)
    report.purged = True
    report.duration_s = time.time() - t0
    return report
