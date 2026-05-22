"""Structural tests for the pivot engine — no network calls."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pivot import PivotNode, _extract_pivots, _username_from_linked_url, _domain_from_email, _host_from_url


def test_email_to_domain_pivot():
    node = PivotNode(kind="email", value="alice@acme.com", depth=0)
    children = _extract_pivots(node)
    kinds_values = {(c.kind, c.value) for c in children}
    assert ("domain", "acme.com") in kinds_values
    assert ("username", "alice") in kinds_values


def test_url_to_host_pivot():
    node = PivotNode(kind="url", value="https://sub.acme.com/path", depth=0)
    children = _extract_pivots(node)
    assert any(c.kind == "domain" and c.value == "sub.acme.com" for c in children)


def test_username_from_linked_urls():
    cases = [
        ("https://github.com/johndoe123", "johndoe123"),
        ("https://twitter.com/jd_official", "jd_official"),
        ("https://www.reddit.com/user/some_redditor", "some_redditor"),
        ("https://keybase.io/cryptokid", "cryptokid"),
        ("https://t.me/leak_admin", "leak_admin"),
    ]
    for url, expected in cases:
        assert _username_from_linked_url(url) == expected, f"failed: {url}"


def test_trace_raw_match_extraction():
    """Telegram/darkweb raw matches should produce new email/domain pivots."""
    node = PivotNode(kind="email", value="alice@acme.com", depth=0)
    node.traces = [{
        "source": "Telegram (tgstat + t.me)",
        "found": True,
        "details": {"hits": [{
            "raw": "alice@acme.com:Password123! also referenced @ bob@evil.tld and victim.com",
        }]},
    }]
    children = _extract_pivots(node)
    children_sig = {(c.kind, c.value) for c in children}
    assert ("email", "bob@evil.tld") in children_sig
    assert ("domain", "victim.com") in children_sig
    # And of course the email->domain pivot
    assert ("domain", "acme.com") in children_sig


if __name__ == "__main__":
    for k, v in list(globals().items()):
        if k.startswith("test_") and callable(v):
            v()
            print(f"  ok  {k}")
    print("All pivot structure tests passed.")
