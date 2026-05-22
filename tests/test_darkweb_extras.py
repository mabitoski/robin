"""Regression tests for dark-web search result filtering."""
import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import darkweb_extras
import search


def test_darkweb_pii_search_filters_engine_infra_and_non_matching_hits(monkeypatch):
    query = "mateo.constant@gmail.com"

    monkeypatch.setattr(
        search,
        "SEARCH_ENGINES",
        [SimpleNamespace(name="Ahmia test")],
    )

    def fake_fetch_engine(engine, quoted):
        assert quoted == "mateo.constant@gmail.com"
        return [
            {
                "title": "contribute to the source code",
                "link": "https://github.com/ahmia/ahmia-site",
                "snippet": "",
            },
            {
                "title": "Interesting thread",
                "link": "http://validexampleabcd.onion/thread/2",
                "snippet": "generic forum teaser without the searched value",
            },
            {
                "title": "Combo leak for mateo.constant@gmail.com",
                "link": "http://validexampleabcd.onion/thread/1",
                "snippet": "contains mateo.constant@gmail.com in the preview",
            },
        ]

    monkeypatch.setattr(search, "fetch_engine", fake_fetch_engine)
    monkeypatch.setattr(darkweb_extras, "search_ransomware_groups",
                        lambda value: [])
    monkeypatch.setattr(darkweb_extras, "search_dread", lambda value: [])
    monkeypatch.setattr(darkweb_extras, "scrape_and_grep",
                        lambda url, value, timeout=35: None)

    hits = darkweb_extras.darkweb_pii_search(query, max_workers=1)

    assert len(hits) == 1
    assert hits[0]["link"] == "http://validexampleabcd.onion/thread/1"
    assert hits[0]["source"] == "darkweb-engine"


def test_main_uses_dynamic_feed_backend_choices():
    import feeds

    main_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "main.py",
    )
    with open(main_path, "r", encoding="utf-8") as fh:
        source = fh.read()

    assert "click.Choice(sorted(FEED_BACKENDS.keys()))" in source
    assert "forum-html" in feeds.BACKENDS
    assert "telegram-channels" in feeds.BACKENDS
