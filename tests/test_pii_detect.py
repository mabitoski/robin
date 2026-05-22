"""Tests for the PII type detector — purely regex, no network."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pii_lookup import detect_type


def test_email():
    assert detect_type("john.doe@example.com") == "email"
    assert detect_type("foo+bar@subdomain.acme.io") == "email"


def test_phone():
    assert detect_type("+33 6 12 34 56 78") == "phone"
    assert detect_type("0612345678") == "phone"
    assert detect_type("+1 (415) 555-2671") == "phone"


def test_ip():
    assert detect_type("203.0.113.42") == "ip"
    assert detect_type("8.8.8.8") == "ip"


def test_hash():
    assert detect_type("098f6bcd4621d373cade4e832627b4f6") == "hash"
    assert detect_type("356a192b7913b04c54574d18c28d46e6395428ab") == "hash"
    assert detect_type("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08") == "hash"


def test_btc():
    assert detect_type("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") == "btc"
    assert detect_type("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh") == "btc"


def test_domain():
    assert detect_type("acme.com") == "domain"
    assert detect_type("sub.example.io") == "domain"


def test_url():
    assert detect_type("https://example.com/path?q=1") == "url"


def test_username():
    assert detect_type("john_doe") == "username"
    assert detect_type("h4ck3r-zero") == "username"


def test_name():
    assert detect_type("Jean Dupont") == "name"
    assert detect_type("John Smith O'Connor") == "name"


def test_unknown():
    assert detect_type("") == "unknown"
    assert detect_type("@#%!") == "unknown"


if __name__ == "__main__":
    for name in [k for k in globals() if k.startswith("test_")]:
        globals()[name]()
    print("OK - all PII detection tests passed")
