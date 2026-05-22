"""Lightweight sanity tests for the IOC extractor.

Run with:  python -m pytest tests/
or:        python tests/test_iocs.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from iocs import extract_indicators as _extract_indicators
from iocs import valid_ip as _valid_ip
from iocs import valid_domain as _valid_domain


def test_valid_ip_filters_garbage():
    assert _valid_ip("192.168.1.10")
    assert _valid_ip("8.8.8.8") is False  # all small, version-like
    assert _valid_ip("999.1.1.1") is False
    assert _valid_ip("0.0.0.0") is False
    assert _valid_ip("255.255.255.255") is False
    assert _valid_ip("203.0.113.42")


def test_valid_domain_filters_garbage():
    assert _valid_domain("acme.com")
    assert _valid_domain("foo.bar") is False    # 'bar' not a real TLD
    assert _valid_domain("index.html") is False
    assert _valid_domain("1.2.3.4") is False    # looks like version
    assert _valid_domain("payload.exe") is False
    assert _valid_domain("threat-actor.onion")


def test_extract_indicators_full():
    text = {
        "https://example.com/post": (
            "Contact: admin@acme.com. Also visit corporate site mycorp.io for press kits. "
            "C2 IPs: 203.0.113.42, 198.51.100.7. Some junk: 1.2.3.4. "
            "BTC wallet: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 "
            "ETH: 0xAbC1234567890123456789012345678901234567 "
            "Hashes: 098f6bcd4621d373cade4e832627b4f6 "
            "(MD5), 356a192b7913b04c54574d18c28d46e6395428ab (SHA1), "
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 (SHA256). "
            "CVE-2024-12345. Hidden service: facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion "
            "Channel: t.me/breach_channel and @leak_admin. "
            "JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c "
            "Email contact +33 6 12 34 56 78 for the source."
        ),
    }
    ind = _extract_indicators(text)
    assert "mycorp.io" in ind["domains"]
    assert any(e.endswith("@acme.com") for e in ind["emails"])
    assert "203.0.113.42" in ind["ip_addresses"]
    assert "1.2.3.4" not in ind["ip_addresses"]  # filtered as version-like
    assert ind["btc_addresses"]
    assert ind["eth_addresses"]
    assert ind["md5"]
    assert ind["sha1"]
    assert ind["sha256"]
    assert "CVE-2024-12345" in ind["cves"]
    assert ind["onion_addresses"]
    assert ind["jwt_tokens"]
    assert ind["telegram_handles"]
    print("OK - all assertions passed")
    print("Indicators extracted:")
    for k, v in ind.items():
        if v:
            print(f"  {k}: {v[:3]}{' ...' if len(v) > 3 else ''}")


if __name__ == "__main__":
    test_valid_ip_filters_garbage()
    test_valid_domain_filters_garbage()
    test_extract_indicators_full()
