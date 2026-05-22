"""
IOC extraction and validation.

Pure regex / stdlib code with no LLM dependencies — kept in its own module so
it can be unit-tested in isolation and reused by enrichment.py / pdf_report.py.
"""

import re
from typing import Dict, List


# Conservative TLD whitelist used to filter junk like `index.html`, `foo.bar`.
VALID_TLDS = {
    "com", "net", "org", "io", "co", "info", "biz", "dev", "app", "ai",
    "xyz", "site", "online", "tech", "store", "club", "me", "tv", "us",
    "uk", "de", "fr", "it", "es", "ru", "cn", "jp", "br", "pl", "nl", "be",
    "ca", "au", "in", "tr", "se", "no", "fi", "ch", "at", "dk", "cz", "kr",
    "mx", "ar", "il", "za", "ua", "ro", "hu", "gr", "pt", "ie", "sg", "hk",
    "tw", "th", "vn", "id", "my", "ph", "nz", "ae", "sa", "eg", "ma",
    "onion", "to", "is", "im", "cc", "ws", "su", "by", "kz", "lt", "lv",
    "ee", "sk", "si", "bg", "hr", "rs", "ng", "ke", "gh", "ml", "tk",
}

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}")
_BTC_RE = re.compile(r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_MONERO_RE = re.compile(r"\b4[0-9AB][a-zA-Z0-9]{93}\b")
_DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b",
    re.IGNORECASE,
)
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_AWS_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_GH_TOKEN_RE = re.compile(r"\bghp_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b")
_TG_RE = re.compile(r"(?:https?://)?t\.me/[A-Za-z0-9_+/]+|@[A-Za-z][A-Za-z0-9_]{4,31}")
# Require + prefix OR a separator (space/dash/dot/parens) to avoid catching IPs
# and long hex strings. 7-15 digits total per E.164.
_PHONE_RE = re.compile(r"\+\d[\d\s().-]{6,18}\d|\b\d{1,4}[ .-]\d{2,4}[ .-]\d{2,4}[ .-]\d{2,4}\b")
_ONION_RE = re.compile(r"\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b")


def valid_ip(ip: str) -> bool:
    """True if `ip` looks like a real public-ish IPv4 (not version-string, not broadcast)."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if any(o > 255 or o < 0 for o in octets):
        return False
    if octets == [0, 0, 0, 0] or octets == [255, 255, 255, 255]:
        return False
    # Reject likely version numbers (e.g. "1.2.3.4" inside text)
    if all(o < 16 for o in octets):
        return False
    return True


def valid_domain(domain: str) -> bool:
    """True if `domain` has a real TLD and isn't a filename / version string."""
    domain = domain.lower().strip(".")
    if "." not in domain or len(domain) < 4 or len(domain) > 253:
        return False
    tld = domain.rsplit(".", 1)[-1]
    if tld not in VALID_TLDS:
        return False
    if re.match(r"^\d+(?:\.\d+){2,}$", domain):
        return False
    return True


def dedupe_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def extract_indicators(content) -> Dict[str, List[str]]:
    """Structured IOC extraction with validation to reduce noise."""
    if not content:
        return {}

    text_blob = " ".join(content.values()) if isinstance(content, dict) else str(content)

    emails = list(_EMAIL_RE.findall(text_blob))
    ips = [m for m in _IP_RE.findall(text_blob) if valid_ip(m)]
    btc = _BTC_RE.findall(text_blob)
    eth = _ETH_RE.findall(text_blob)
    xmr = _MONERO_RE.findall(text_blob)

    onions = _ONION_RE.findall(text_blob)
    onion_set = {o.lower() for o in onions}

    raw_domains = _DOMAIN_RE.findall(text_blob)
    email_domains = {e.split("@", 1)[-1].lower() for e in emails}
    domains = [
        d.lower() for d in raw_domains
        if valid_domain(d)
        and d.lower() not in email_domains
        and d.lower() not in onion_set
    ]

    sha256 = _SHA256_RE.findall(text_blob)
    sha256_set = set(sha256)
    sha1 = [h for h in _SHA1_RE.findall(text_blob) if h not in sha256_set]
    sha1_set = set(sha1) | sha256_set
    md5 = [h for h in _MD5_RE.findall(text_blob) if h not in sha1_set]

    cves = [c.upper() for c in _CVE_RE.findall(text_blob)]
    jwts = _JWT_RE.findall(text_blob)
    aws_keys = _AWS_RE.findall(text_blob)
    gh_tokens = _GH_TOKEN_RE.findall(text_blob)
    telegram = _TG_RE.findall(text_blob)
    phones = [
        p.strip() for p in _PHONE_RE.findall(text_blob)
        if 7 <= sum(c.isdigit() for c in p) <= 15
    ]

    return {
        "emails": dedupe_preserve_order(emails)[:50],
        "ip_addresses": dedupe_preserve_order(ips)[:50],
        "btc_addresses": dedupe_preserve_order(btc)[:50],
        "eth_addresses": dedupe_preserve_order(eth)[:50],
        "monero_addresses": dedupe_preserve_order(xmr)[:25],
        "domains": dedupe_preserve_order(domains)[:50],
        "onion_addresses": dedupe_preserve_order(onions)[:50],
        "cves": dedupe_preserve_order(cves)[:50],
        "md5": dedupe_preserve_order(md5)[:30],
        "sha1": dedupe_preserve_order(sha1)[:30],
        "sha256": dedupe_preserve_order(sha256)[:30],
        "jwt_tokens": dedupe_preserve_order(jwts)[:10],
        "aws_keys": dedupe_preserve_order(aws_keys)[:10],
        "github_tokens": dedupe_preserve_order(gh_tokens)[:10],
        "telegram_handles": dedupe_preserve_order(telegram)[:25],
        "phone_numbers": dedupe_preserve_order(phones)[:25],
    }


def format_indicators(indicators: Dict[str, List[str]]) -> str:
    if not indicators:
        return "No indicators were automatically extracted."
    lines: List[str] = []
    for key, values in indicators.items():
        if values:
            label = key.replace("_", " ").title()
            lines.append(f"{label}: {', '.join(values)}")
    return "\n".join(lines) if lines else "No indicators were automatically extracted."
