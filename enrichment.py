"""
IOC enrichment.

Given extracted indicators (domains, IPs, emails, hashes...), enrich them with
context from free public services:

- Domain  -> DNS A/MX, WHOIS, crt.sh subdomains, HudsonRock infection count
- IP      -> rDNS, geo (ipapi.co), AbuseIPDB if API key
- Email   -> HudsonRock infostealer logs
- Hash    -> CIRCL hashlookup (free, no key), Malware Bazaar tag lookup
- CVE     -> NVD short description

All services are best-effort: any failure degrades silently to "no enrichment".
"""

from __future__ import annotations

import os
import socket
import logging
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10
UA = "robin-osint-tool/2.0"


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "application/json"})
    return s


# --------------------------------------------------------------------------- #
# Domain enrichment
# --------------------------------------------------------------------------- #

def resolve_domain(domain: str) -> Dict:
    """Return A records via stdlib socket (no DNS dep)."""
    out: Dict[str, List[str]] = {"a": [], "error": None}
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        out["a"] = ips
    except socket.gaierror as e:
        out["error"] = str(e)
    return out


def whois_via_rdap(domain: str) -> Dict:
    """Use the free RDAP bootstrap to get domain registration metadata."""
    try:
        r = _session().get(f"https://rdap.org/domain/{domain}", timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:
            return {}
        data = r.json()
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        nameservers = [ns.get("ldhName") for ns in data.get("nameservers", [])]
        entities = []
        for ent in data.get("entities", []):
            for role in ent.get("roles", []):
                entities.append(f"{role}: {ent.get('handle', '?')}")
        return {
            "registered": events.get("registration"),
            "last_changed": events.get("last changed"),
            "expires": events.get("expiration"),
            "nameservers": nameservers,
            "entities": entities[:6],
        }
    except (requests.RequestException, ValueError) as e:
        log.debug("rdap %s error: %s", domain, e)
        return {}


def crt_subdomains(domain: str, limit: int = 30) -> List[str]:
    try:
        r = _session().get(
            "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code != 200 or not r.text.strip():
            return []
        try:
            data = r.json()
        except ValueError:
            return []
        seen = set()
        for entry in data:
            name = entry.get("name_value", "")
            for n in name.split("\n"):
                n = n.strip().lower()
                if n and "*" not in n and n.endswith(domain.lower()):
                    seen.add(n)
        return sorted(seen)[:limit]
    except requests.RequestException:
        return []


def enrich_domain(domain: str) -> Dict:
    info: Dict = {"domain": domain}
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_dns = pool.submit(resolve_domain, domain)
        f_rdap = pool.submit(whois_via_rdap, domain)
        f_crt = pool.submit(crt_subdomains, domain)
        info["dns"] = f_dns.result()
        info["whois"] = f_rdap.result()
        info["subdomains"] = f_crt.result()
    return info


# --------------------------------------------------------------------------- #
# IP enrichment
# --------------------------------------------------------------------------- #

def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def ip_geo(ip: str) -> Dict:
    try:
        r = _session().get(f"https://ipapi.co/{ip}/json/", timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:
            return {}
        data = r.json()
        return {
            "country": data.get("country_name"),
            "region": data.get("region"),
            "city": data.get("city"),
            "org": data.get("org"),
            "asn": data.get("asn"),
            "is_tor": data.get("threat", {}).get("is_tor"),
        }
    except (requests.RequestException, ValueError):
        return {}


def abuseipdb(ip: str) -> Dict:
    key = os.getenv("ABUSEIPDB_API_KEY")
    if not key:
        return {}
    try:
        r = _session().get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code != 200:
            return {}
        d = r.json().get("data", {})
        return {
            "abuse_score": d.get("abuseConfidenceScore"),
            "reports": d.get("totalReports"),
            "last_reported": d.get("lastReportedAt"),
            "usage": d.get("usageType"),
        }
    except (requests.RequestException, ValueError):
        return {}


def enrich_ip(ip: str) -> Dict:
    out: Dict = {"ip": ip}
    with ThreadPoolExecutor(max_workers=3) as pool:
        out["rdns"] = pool.submit(reverse_dns, ip).result()
        out["geo"] = pool.submit(ip_geo, ip).result()
        out["abuse"] = pool.submit(abuseipdb, ip).result()
    return out


# --------------------------------------------------------------------------- #
# Hash enrichment via CIRCL hashlookup (free, no API key)
# --------------------------------------------------------------------------- #

def circl_hash(hash_value: str) -> Dict:
    h = hash_value.lower()
    algo = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h))
    if not algo:
        return {}
    try:
        r = _session().get(
            f"https://hashlookup.circl.lu/lookup/{algo}/{h}",
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code != 200:
            return {}
        d = r.json()
        return {
            "filename": d.get("FileName"),
            "filesize": d.get("FileSize"),
            "product": d.get("ProductCode") or d.get("source"),
            "known_good": d.get("KnownMalicious") is False,
            "malicious": d.get("KnownMalicious") is True,
        }
    except (requests.RequestException, ValueError):
        return {}


def malware_bazaar(hash_value: str) -> Dict:
    try:
        r = _session().post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": hash_value},
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code != 200:
            return {}
        d = r.json()
        if d.get("query_status") != "ok":
            return {}
        item = (d.get("data") or [{}])[0]
        return {
            "signature": item.get("signature"),
            "filename": item.get("file_name"),
            "filetype": item.get("file_type"),
            "first_seen": item.get("first_seen"),
            "tags": item.get("tags"),
        }
    except (requests.RequestException, ValueError):
        return {}


def enrich_hash(hash_value: str) -> Dict:
    circl = circl_hash(hash_value)
    mb = malware_bazaar(hash_value)
    return {"hash": hash_value, "circl": circl, "malware_bazaar": mb}


# --------------------------------------------------------------------------- #
# CVE enrichment via NVD
# --------------------------------------------------------------------------- #

def enrich_cve(cve_id: str) -> Dict:
    try:
        r = _session().get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id.upper()},
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code != 200:
            return {}
        items = r.json().get("vulnerabilities", [])
        if not items:
            return {}
        cve = items[0]["cve"]
        descs = cve.get("descriptions", [])
        en = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        metric = (cve.get("metrics", {}).get("cvssMetricV31") or [{}])[0].get("cvssData", {})
        return {
            "id": cve.get("id"),
            "summary": en[:500],
            "cvss": metric.get("baseScore"),
            "severity": metric.get("baseSeverity"),
        }
    except (requests.RequestException, ValueError):
        return {}


# --------------------------------------------------------------------------- #
# Email enrichment via HudsonRock
# --------------------------------------------------------------------------- #

def enrich_email(email: str) -> Dict:
    try:
        r = _session().get(
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email",
            params={"email": email},
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code != 200:
            return {}
        d = r.json()
        return {
            "email": email,
            "total_infections": d.get("total") or d.get("stealers", []),
        }
    except (requests.RequestException, ValueError):
        return {}


# --------------------------------------------------------------------------- #
# Aggregate
# --------------------------------------------------------------------------- #

def enrich_all(indicators: Dict[str, List[str]]) -> Dict:
    """Top-level enrichment. Returns nested results for each IOC type."""
    out: Dict = {"domains": [], "ips": [], "hashes": [], "cves": [], "emails": []}

    domains = (indicators.get("domains") or [])[:5]
    ips = (indicators.get("ip_addresses") or [])[:5]
    hashes = (
        (indicators.get("sha256") or [])
        + (indicators.get("sha1") or [])
        + (indicators.get("md5") or [])
    )[:5]
    cves = (indicators.get("cves") or [])[:5]
    emails = (indicators.get("emails") or [])[:3]

    with ThreadPoolExecutor(max_workers=8) as pool:
        f_domains = [pool.submit(enrich_domain, d) for d in domains]
        f_ips = [pool.submit(enrich_ip, i) for i in ips]
        f_hashes = [pool.submit(enrich_hash, h) for h in hashes]
        f_cves = [pool.submit(enrich_cve, c) for c in cves]
        f_emails = [pool.submit(enrich_email, e) for e in emails]

        for f in as_completed(f_domains):
            try: out["domains"].append(f.result())
            except Exception as e: log.debug("enrich domain: %s", e)
        for f in as_completed(f_ips):
            try: out["ips"].append(f.result())
            except Exception as e: log.debug("enrich ip: %s", e)
        for f in as_completed(f_hashes):
            try: out["hashes"].append(f.result())
            except Exception as e: log.debug("enrich hash: %s", e)
        for f in as_completed(f_cves):
            try: out["cves"].append(f.result())
            except Exception as e: log.debug("enrich cve: %s", e)
        for f in as_completed(f_emails):
            try: out["emails"].append(f.result())
            except Exception as e: log.debug("enrich email: %s", e)

    return out


def format_enrichment(enr: Dict) -> str:
    """Render enrichment as a human-readable block for CLI/PDF/markdown."""
    lines: List[str] = []

    if enr.get("domains"):
        lines.append("== DOMAINS ==")
        for d in enr["domains"]:
            lines.append(f"\n[{d.get('domain')}]")
            dns = d.get("dns") or {}
            if dns.get("a"):
                lines.append(f"  A: {', '.join(dns['a'])}")
            wh = d.get("whois") or {}
            if wh.get("registered"):
                lines.append(f"  Registered: {wh.get('registered')}  Expires: {wh.get('expires')}")
            if wh.get("nameservers"):
                lines.append(f"  NS: {', '.join(wh['nameservers'][:4])}")
            subs = d.get("subdomains") or []
            if subs:
                lines.append(f"  Subdomains ({len(subs)}): {', '.join(subs[:8])}{' ...' if len(subs) > 8 else ''}")

    if enr.get("ips"):
        lines.append("\n== IP ADDRESSES ==")
        for ip in enr["ips"]:
            geo = ip.get("geo") or {}
            ab = ip.get("abuse") or {}
            line = f"\n[{ip.get('ip')}] rDNS={ip.get('rdns') or '-'}"
            if geo:
                line += f"  geo={geo.get('country')}/{geo.get('city')} org={geo.get('org')} asn={geo.get('asn')}"
            if ab:
                line += f"  abuse_score={ab.get('abuse_score')} reports={ab.get('reports')}"
            lines.append(line)

    if enr.get("hashes"):
        lines.append("\n== FILE HASHES ==")
        for h in enr["hashes"]:
            mb = h.get("malware_bazaar") or {}
            circl = h.get("circl") or {}
            verdict = []
            if mb.get("signature"):
                verdict.append(f"MalwareBazaar: {mb['signature']} ({', '.join(mb.get('tags') or [])})")
            if circl.get("known_good"):
                verdict.append(f"CIRCL: known-good ({circl.get('filename') or '?'})")
            if not verdict:
                verdict.append("no public verdict")
            lines.append(f"\n[{h.get('hash')}] {' | '.join(verdict)}")

    if enr.get("cves"):
        lines.append("\n== CVEs ==")
        for c in enr["cves"]:
            if c.get("id"):
                lines.append(f"\n[{c['id']}] CVSS={c.get('cvss')}/{c.get('severity')}")
                lines.append(f"  {c.get('summary')}")

    if enr.get("emails"):
        lines.append("\n== EMAILS ==")
        for e in enr["emails"]:
            t = e.get("total_infections")
            lines.append(f"\n[{e.get('email')}] HudsonRock infections: {t}")

    return "\n".join(lines) if lines else "No enrichment data available."
