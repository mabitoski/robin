"""
Check a password against HIBP's Pwned Passwords API using k-anonymity.

This is a free, keyless endpoint: we send only the first 5 chars of the
SHA-1 hash, HIBP returns ~500 suffixes with hit counts, we match locally.
The plaintext password never leaves the local machine.

Reference: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""

from __future__ import annotations

import hashlib
import logging
from typing import Dict, Optional

import requests

log = logging.getLogger(__name__)

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"


def check_password(password: str, timeout: int = 8) -> Dict:
    """Return {pwned: bool, count: int, hash: str}.

    `count` is HIBP's seen-count across known breaches. `hash` is the full
    SHA-1 (so users can verify externally if they want).
    """
    if not password:
        return {"pwned": False, "count": 0, "hash": "", "error": "empty password"}

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = requests.get(
            API_URL.format(prefix=prefix),
            headers={"Add-Padding": "true", "User-Agent": "robin-osint-tool"},
            timeout=timeout,
        )
        if r.status_code != 200:
            return {"pwned": False, "count": 0, "hash": sha1,
                    "error": f"HTTP {r.status_code}"}
        for line in r.text.splitlines():
            try:
                sfx, count = line.strip().split(":", 1)
            except ValueError:
                continue
            if sfx == suffix:
                return {"pwned": True, "count": int(count), "hash": sha1}
        return {"pwned": False, "count": 0, "hash": sha1}
    except requests.RequestException as e:
        return {"pwned": False, "count": 0, "hash": sha1, "error": str(e)}


def check_many(passwords) -> Dict[str, Dict]:
    """Bulk check, sequential (HIBP is fast, no need to parallelize)."""
    return {p: check_password(p) for p in passwords}


def format_check(result: Dict) -> str:
    if result.get("error"):
        return f"[?] HIBP check failed: {result['error']}"
    if result["pwned"]:
        return (
            f"[!] PWNED — seen in {result['count']:,} known breaches\n"
            f"    SHA-1: {result['hash']}"
        )
    return f"[OK] Not found in HIBP Pwned Passwords (SHA-1: {result['hash']})"
