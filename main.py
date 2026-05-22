import json
import logging
import os
import click
from yaspin import yaspin
from datetime import datetime

from scrape import scrape_multiple, filter_content_by_terms
from search import get_search_results, healthcheck_engines, list_engines
from download import download_safe_files
from pdf_report import build_pdf_report
from osint_sources import CLEARWEB_SOURCES, health_check as osint_health
from darkweb_extras import darkweb_health, active_ransomware_leak_sites
from enrichment import enrich_all, format_enrichment
from pii_lookup import lookup as pii_lookup, detect_type as pii_detect, format_report as pii_format
from pivot import investigate as pivot_investigate, render_tree as pivot_render, summary_stats, to_dict as pivot_to_dict
from password_check import check_password, format_check as password_format
from wayback import snapshots as wb_snapshots, search_archived_content as wb_search, format_snapshots as wb_format
from email_recon import recon as email_recon, format_recon as email_format
from feeds import BACKENDS as FEED_BACKENDS
from agent import (
    run_agent, format_event as agent_format_event, ROBIN_TOOLS,
    list_backends, run as agent_run,
)
from llm import (
    get_llm,
    refine_query,
    filter_results,
    generate_summary,
    build_indicator_block,
    extract_focus_terms,
    _extract_indicators,
)
from llm_utils import get_model_choices

logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(name)s: %(message)s")

MODEL_CHOICES = get_model_choices()
CLEARWEB_KEYS = list(CLEARWEB_SOURCES.keys())


@click.group()
@click.version_option()
def robin():
    """Robin: AI-Powered Dark Web OSINT Tool."""
    pass


@robin.command()
@click.option(
    "--model", "-m",
    default="gpt-5-mini",
    show_default=True,
    type=click.Choice(MODEL_CHOICES),
    help="LLM model to use.",
)
@click.option("--query", "-q", required=True, type=str, help="OSINT search query")
@click.option("--threads", "-t", default=8, show_default=True, type=int,
              help="Concurrent workers for scraping.")
@click.option("--output", "-o", type=str,
              help="Base filename for output (.md/.pdf). Defaults to a timestamp.")
@click.option("--download-files/--no-download-files", default=False, show_default=True,
              help="Download text-like files (txt/csv/json/pdf) into downloads/.")
@click.option("--max-download-mb", default=5, show_default=True, type=int)
@click.option("--pdf-report/--no-pdf-report", default=False, show_default=True)
@click.option("--enrich/--no-enrich", default=True, show_default=True,
              help="Enrich extracted IOCs with DNS/WHOIS/geo/hashlookup.")
@click.option("--no-clearweb-osint", is_flag=True, default=False,
              help="Skip clearweb OSINT sources (ransomware.live, crt.sh, HIBP, ...).")
@click.option("--clearweb-sources", default=None,
              help=f"Comma-list of OSINT sources to enable. Available: {', '.join(CLEARWEB_KEYS)}")
@click.option("--no-dread", is_flag=True, default=False,
              help="Skip Dread forum search.")
@click.option("--no-ransomware-sites", is_flag=True, default=False,
              help="Skip direct scraping of active ransomware leak sites.")
@click.option("--no-circuit-rotation", is_flag=True, default=False,
              help="Skip Tor NEWNYM circuit rotation before searching.")
@click.option("--deep-scrape/--no-deep-scrape", default=False, show_default=True,
              help="Follow one level of forum/thread links per result (slower, richer).")
@click.option("--verbose", "-v", is_flag=True, default=False)
def cli(model, query, threads, output, download_files, max_download_mb,
        pdf_report, enrich, no_clearweb_osint, clearweb_sources,
        no_dread, no_ransomware_sites, no_circuit_rotation, deep_scrape, verbose):
    """Run Robin OSINT pipeline.

    Examples:

      robin cli -m gpt-5-mini -q "acme corp leak"
      robin cli -q "lockbit victim" --enrich --pdf-report
      robin cli -q acme.com --clearweb-sources crt.sh,hibp,ransomware.live
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Auto-detect PII inputs (email/phone/username/...) and trace them first.
    pii_block = ""
    detected_kind = pii_detect(query)
    if detected_kind in {"email", "phone", "username", "ip", "domain", "hash", "btc", "name"}:
        click.echo(f"[TRACE] Auto-detected '{detected_kind}' input — probing OSINT sources first...\n")
        result = pii_lookup(query, kind=detected_kind)
        pii_block = pii_format(result)
        click.echo(pii_block + "\n")

    llm = get_llm(model)
    sources_enabled = (
        [s.strip() for s in clearweb_sources.split(",") if s.strip()]
        if clearweb_sources else None
    )

    with yaspin(text="Processing...", color="cyan") as sp:
        refined_query = refine_query(llm, query)
        focus_terms = extract_focus_terms(query)
        sp.write(f"  Refined query: {refined_query}")

        search_results = get_search_results(
            refined_query.replace(" ", "+"),
            max_workers=threads,
            focus_terms=focus_terms,
            include_clearweb_osint=not no_clearweb_osint,
            clearweb_sources=sources_enabled,
            include_dread=not no_dread,
            include_ransomware_sites=not no_ransomware_sites,
            rotate_circuit=not no_circuit_rotation,
        )
        sp.write(f"  Aggregated {len(search_results)} candidate hits.")

        search_filtered = filter_results(llm, refined_query, search_results)
        sp.write(f"  LLM kept {len(search_filtered)} relevant hits.")

        scraped_results = scrape_multiple(
            search_filtered, max_workers=threads, deep=deep_scrape
        )
        scraped_results = filter_content_by_terms(scraped_results, focus_terms)
        sp.ok("✔")

    # IOC view first
    raw_indicators = _extract_indicators(scraped_results)
    indicators_block = build_indicator_block(scraped_results)
    click.echo("\n[INDICATORS]\n" + indicators_block + "\n")

    # Enrichment (validated IOCs -> real lookups)
    enrichment_block = ""
    if enrich:
        with yaspin(text="Enriching IOCs (DNS, WHOIS, hash lookups)...", color="cyan") as sp:
            enr = enrich_all(raw_indicators)
            enrichment_block = format_enrichment(enr)
            sp.ok("✔")
        click.echo("\n[ENRICHMENT]\n" + enrichment_block + "\n")

    # Optional safe downloads
    downloaded = []
    if download_files:
        downloaded = download_safe_files(search_filtered, query, max_size_mb=max_download_mb)
        if downloaded:
            click.echo("[DOWNLOADS]")
            for item in downloaded:
                click.echo(f"- {item['path']} ({item['bytes']} bytes) <- {item['url']}")
            click.echo("")
        else:
            click.echo("[DOWNLOADS] No safe files detected for this query.\n")

    # LLM summary
    summary = generate_summary(llm, query, scraped_results)

    base = output or f"summary_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
    md_path = f"{base}.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Robin OSINT report — {query}\n\n")
        if pii_block:
            f.write("## PII trace\n\n```\n" + pii_block + "\n```\n\n")
        f.write("## Sources used\n\n")
        for r in search_filtered:
            f.write(f"- [{r.get('title','(no title)')}]({r.get('link','')})"
                    + (f" — *{r['source']}*" if r.get("source") else "") + "\n")
        f.write("\n## Indicators\n\n```\n" + indicators_block + "\n```\n")
        if enrichment_block:
            f.write("\n## Enrichment\n\n```\n" + enrichment_block + "\n```\n")
        f.write("\n## Summary\n\n" + summary + "\n")
    click.echo(f"\n[OUTPUT] Markdown summary saved to {md_path}")

    if pdf_report:
        pdf_path = f"{base}.pdf"
        build_pdf_report(
            query=query,
            indicators_text=indicators_block + (("\n\n" + enrichment_block) if enrichment_block else ""),
            summary_text=summary,
            sources=search_filtered,
            output_path=pdf_path,
        )
        click.echo(f"[OUTPUT] PDF report saved to {pdf_path}")


@robin.command()
def doctor():
    """Run reachability checks on every search engine and OSINT source."""
    click.echo("Checking onion + clearweb search engines via Tor...\n")
    engines = healthcheck_engines()
    for name, ok in engines.items():
        click.echo(f"  [{'OK ' if ok else 'KO '}] {name}")

    click.echo("\nChecking targeted dark-web sources...\n")
    dw = darkweb_health()
    for name, ok in dw.items():
        click.echo(f"  [{'OK ' if ok else 'KO '}] {name}")

    click.echo("\nChecking clearweb OSINT APIs...\n")
    osint = osint_health()
    for name, ok in osint.items():
        click.echo(f"  [{'OK ' if ok else 'KO '}] {name}")

    all_status = {**engines, **dw, **osint}
    ok_count = sum(1 for v in all_status.values() if v)
    click.echo(f"\n{ok_count}/{len(all_status)} sources reachable.")


@robin.command()
def list_sources():
    """List configured dark-web search engines and active ransomware leak sites."""
    click.echo("Dark-web search engines configured:\n")
    for e in list_engines():
        tag = "tor" if e["tor"] else "clearnet"
        click.echo(f"  [{tag:8s}] {e['name']:25s} pages={e['pages']}  {e['url']}")

    sites = active_ransomware_leak_sites()
    click.echo(f"\nActive ransomware leak sites (live from ransomware.live): {len(sites)}\n")
    for s in sites[:20]:
        loc = "onion" if s["onion"] else "clear"
        click.echo(f"  [{loc}] {s['group']:20s} {s['host']}")
    if len(sites) > 20:
        click.echo(f"  ... ({len(sites) - 20} more)")


@robin.command()
@click.argument("question", nargs=-1, required=True)
@click.option("--backend", default="claude-code", show_default=True,
              type=click.Choice(["claude-code", "codex-cli", "langchain"]),
              help="claude-code (no key, uses Claude Code subscription) | "
                   "codex-cli (no key, uses Codex CLI) | langchain (needs API key)")
@click.option("--model", "-m", default="gpt-5-mini",
              type=click.Choice(MODEL_CHOICES),
              help="Only used with --backend langchain.")
@click.option("--max-iterations", default=10, show_default=True, type=int)
def agent(question, backend, model, max_iterations):
    """Ask Robin in natural language; the LLM autonomously calls Robin's
    15 OSINT tools and answers.

    Backends:

      --backend claude-code  : uses your Claude Code subscription (NO key)
      --backend codex-cli    : uses your Codex CLI subscription (NO key)
      --backend langchain    : classic LangChain (needs API key in .env)

    Examples:

      robin agent "Cherche si victime@example.com a leak"

      robin agent "Trouve l'email de Jean Dupont chez acme.com" --backend codex-cli

      robin agent "..." --backend langchain --model claude-sonnet-4-5
    """
    q = " ".join(question)
    click.echo(f"🤖 Agent ({backend}): {q}\n")
    click.echo(f"Tools available: {len(ROBIN_TOOLS)}\n")

    available = list_backends()
    if not available.get(backend):
        msg = {
            "claude-code": "Need `claude` CLI + `pip install claude-agent-sdk`.",
            "codex-cli": "Need `codex` CLI installed and logged in.",
            "langchain": "Need an API key in .env.",
        }.get(backend, "")
        click.echo(f"❌ Backend '{backend}' unavailable. {msg}")
        click.echo(f"Available backends: {[k for k,v in available.items() if v]}")
        raise click.Abort()

    def on_event(ev):
        click.echo(agent_format_event(ev))

    llm = get_llm(model) if backend == "langchain" else None
    result = agent_run(q, backend=backend, llm=llm,
                      max_iterations=max_iterations, on_event=on_event)
    click.echo(f"\n--- {result.total_tool_calls} tool call(s), "
               f"{result.iterations} iteration(s) ---")


@robin.group()
def db():
    """Manage the local breach database (your own indexed breach dumps)."""
    pass


@db.command(name="ingest")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--breach", "-b", required=True, help="Breach name (unique key).")
@click.option("--year", "-y", type=int, help="Year of the breach.")
@click.option("--domain", "-d", help="Affected domain (e.g. acme.com).")
@click.option("--description", default="", help="Free-text description.")
@click.option("--data-classes", default="emails,passwords",
              help="Comma-list of data classes leaked.")
def db_ingest(path, breach, year, domain, description, data_classes):
    """Ingest a breach dump (`email:password` lines, .txt/.gz/.zip).

      argus db ingest leak.txt -b "Acme_2024" -y 2024 -d acme.com
    """
    from local_breach_db import ingest_file
    last_report_print = 0

    def progress(report):
        nonlocal last_report_print
        now = time.time()
        if now - last_report_print > 2:
            click.echo(f"  … {report.rows_inserted:,} rows so far "
                       f"({report.lines_read:,} lines read)")
            last_report_print = now

    import time
    click.echo(f"Ingesting {path} as '{breach}'...")
    report = ingest_file(
        path, breach_name=breach, year=year, domain=domain,
        description=description, data_classes=data_classes,
        progress_cb=progress,
    )
    click.echo(report)


@db.command(name="check")
@click.argument("email")
@click.option("--plaintext", is_flag=True, default=False,
              help="Show passwords in plaintext (default: masked).")
def db_check(email, plaintext):
    """Check whether `EMAIL` is in any locally-ingested breach."""
    from local_breach_db import check_email, get_credentials
    breaches = check_email(email)
    if not breaches:
        click.echo(f"[OK] {email} is not in any locally-ingested breach.")
        return
    click.echo(f"[!] {email} found in {len(breaches)} local breach(es):\n")
    for b in breaches:
        click.echo(f"  - {b['breach']} ({b['year']}) — {b['data_classes']}")
        click.echo(f"      your rows: {b['your_credentials_count']}  "
                   f"passwords: {b['passwords_present']}")
    click.echo("\nCredentials:")
    for c in get_credentials(email, plaintext=plaintext):
        click.echo(f"  [{c['breach']}/{c['year']}] {c['password']}")


@db.command(name="domain")
@click.argument("domain")
@click.option("--limit", default=50, show_default=True, type=int)
def db_domain(domain, limit):
    """Enumerate every breached email at `DOMAIN`."""
    from local_breach_db import search_domain
    rows = search_domain(domain, limit=limit)
    if not rows:
        click.echo(f"No breached email found at {domain} in local DB.")
        return
    click.echo(f"Found {len(rows)} breached email(s) at {domain}:\n")
    for r in rows:
        click.echo(f"  - {r['email']}  ({r['breach_count']} breach(es): "
                   f"{r['breaches']})")


@db.command(name="stats")
def db_stats():
    """Show overview of the local breach DB."""
    from local_breach_db import stats
    s = stats()
    click.echo(f"DB path        : {s['db_path']}")
    click.echo(f"DB size        : {s['db_size_bytes'] / 1e6:.1f} MB")
    click.echo(f"Breaches       : {s['breach_count']}")
    click.echo(f"Credentials    : {s['credential_count']:,}")
    click.echo(f"Unique emails  : {s['unique_emails']:,}")
    click.echo("")
    click.echo("Breaches indexed:")
    for b in s["breaches"]:
        click.echo(f"  - {b['name']:30s} year={b['year']:>5}  "
                   f"records={b['records']:,}  domain={b['domain'] or '-'}")


@db.command(name="delete")
@click.argument("breach_name")
@click.confirmation_option(prompt="Are you sure you want to delete this breach?")
def db_delete(breach_name):
    """Remove a breach + all its credentials from the local DB."""
    from local_breach_db import delete_breach, vacuum
    n = delete_breach(breach_name)
    click.echo(f"Deleted {n:,} credential rows from breach '{breach_name}'.")
    vacuum()


@db.command(name="fetch-extract")
@click.argument("url")
@click.option("--breach", "-b", required=True, help="Breach name to register.")
@click.option("--watchlist", "-w", required=True,
              help="Comma-list of emails OR @domain patterns to keep.")
@click.option("--year", "-y", type=int)
@click.option("--domain", "-d")
@click.option("--description", default="")
@click.option("--tor", is_flag=True, default=False,
              help="Route the download through Tor SOCKS5h.")
@click.option("--max-size-mb", default=5000, show_default=True, type=int,
              help="Hard cap on download size.")
@click.option("--secure-passes", default=1, show_default=True, type=int,
              help="Number of zero-overwrite passes before unlink.")
def db_fetch_extract(url, breach, watchlist, year, domain, description,
                      tor, max_size_mb, secure_passes):
    """Download a breach dump, extract only lines matching your watchlist,
    then SECURELY DELETE the source file. The full dump is never retained.

    Watchlist entries can be exact emails (alice@acme.com) or domain
    patterns (acme.com / @acme.com).

      argus db fetch-extract https://example.com/leak.txt.gz \\
         -b "AcmeLeak_2024" -w "alice@acme.com,bob@acme.com,@acme.com" \\
         -y 2024 -d acme.com

      argus db fetch-extract http://onion.../dump.txt --tor \\
         -b "DarkLeak_2024" -w "victim@target.com"
    """
    from local_breach_db import fetch_and_extract
    wl = [w.strip() for w in watchlist.split(",") if w.strip()]
    click.echo(f"Fetching {url} via {'Tor' if tor else 'clearnet'}...")
    click.echo(f"Watchlist: {wl}")
    click.echo(f"Will purge the dump after extraction (zero-overwrite "
               f"{secure_passes} pass).\n")
    last = [0]

    def progress(report):
        if time.time() - last[0] > 2:
            click.echo(
                f"  … {report.bytes_downloaded/1e6:.1f} MB downloaded, "
                f"{report.lines_scanned:,} lines scanned, "
                f"{report.lines_matched:,} matched"
            )
            last[0] = time.time()

    import time
    report = fetch_and_extract(
        url, breach_name=breach, watchlist=wl,
        year=year, domain=domain, description=description,
        use_tor=tor, max_size_mb=max_size_mb,
        secure_delete_passes=secure_passes, progress_cb=progress,
    )
    click.echo("")
    click.echo(report)
    if report.error:
        raise click.Abort()


@robin.group()
def feeds():
    """Manage threat-intel feeds (ransomware, MISP, TAXII, REST, forum, Telegram)."""
    pass


@feeds.command(name="list")
def feeds_list():
    """List configured feeds."""
    from feeds import list_feeds
    feeds = list_feeds()
    if not feeds:
        click.echo("(no feeds configured)")
        return
    for f in feeds:
        status = "✓" if f["enabled"] else "○"
        click.echo(f"  {status} [{f['kind']:18s}] {f['id']:30s} — "
                    f"{f['display'] or ''}")
        if f["last_poll"]:
            click.echo(f"      last poll: {f['last_poll']} · "
                        f"events: {f['last_event_count']}")
        if f["last_error"]:
            click.echo(f"      ⚠ {f['last_error']}")


@feeds.command(name="add")
@click.argument("feed_id")
@click.argument("kind", type=click.Choice(sorted(FEED_BACKENDS.keys())))
@click.option("--display", default="", help="Display label for the UI.")
@click.option("--config", default="{}",
              help="JSON config for the backend.")
@click.option("--disabled", is_flag=True, default=False)
def feeds_add(feed_id, kind, display, config, disabled):
    """Add or update a feed.

    Examples:
      argus feeds add rw-public ransomware-monitor --display "Ransomware live"

      argus feeds add misp-soc misp --config '{
        "base_url": "https://misp.internal/", "api_key": "..." }'

      argus feeds add intel471 rest --config '{
        "url": "https://api.intel471.com/v1/...", "auth_header": "Bearer XX" }'

      argus feeds add bf-leaks forum-html --config '{
        "base_url": "http://forum.onion", "list_path": "/Forum-Leaks" }'

      argus feeds add tg-stealers telegram-channels --config '{
        "channels": ["leakbase", "BradMaxLogs"] }'
    """
    from feeds import add_feed
    try:
        cfg = json.loads(config)
    except json.JSONDecodeError as e:
        click.echo(f"Invalid --config JSON: {e}", err=True)
        raise click.Abort()
    add_feed(feed_id, kind, display=display, config=cfg, enabled=not disabled)
    click.echo(f"Feed '{feed_id}' ({kind}) saved.")


@feeds.command(name="remove")
@click.argument("feed_id")
def feeds_remove(feed_id):
    """Remove a feed and all its events."""
    from feeds import remove_feed
    n = remove_feed(feed_id)
    click.echo(f"Removed {n} feed config(s).")


@feeds.command(name="poll")
@click.argument("feed_id", required=False)
def feeds_poll(feed_id):
    """Poll one feed (or all if FEED_ID is omitted)."""
    from feeds import poll_feed, poll_all
    if feed_id:
        click.echo(str(poll_feed(feed_id)))
    else:
        for r in poll_all():
            click.echo(str(r))


@feeds.command(name="events")
@click.option("--feed", default=None, help="Filter on a feed id.")
@click.option("--matched", is_flag=True, default=False,
              help="Show only events that matched the watchlist.")
@click.option("--limit", default=20, show_default=True, type=int)
def feeds_events(feed, matched, limit):
    """Show recent events from the feeds."""
    from feeds import recent_events
    events = recent_events(limit=limit, feed_id=feed, only_matched=matched)
    if not events:
        click.echo("(no events)")
        return
    for e in events:
        marker = "🚨" if e["matched_watchlist"] else "  "
        ts = e["timestamp"][:19] if e["timestamp"] else "(no ts)"
        click.echo(f"  {marker} [{ts}] {e['feed_id']:20s} "
                    f"{e['event_type']:25s} "
                    + (f"match={e['matched_pattern']}"
                       if e["matched_pattern"] else ""))
        pl = e["payload"]
        if isinstance(pl, dict):
            for k in ("victim", "group", "value", "name", "url",
                      "post_url", "event_info"):
                if pl.get(k):
                    click.echo(f"        {k}: {str(pl[k])[:120]}")


@robin.group()
def watch():
    """Manage the watchlist: patterns to match across feed events."""
    pass


@watch.command(name="list")
def watch_list():
    """List the watchlist."""
    from feeds import list_watchlist
    rows = list_watchlist()
    if not rows:
        click.echo("(watchlist empty)")
        return
    for r in rows:
        click.echo(f"  [{r['id']}] {r['pattern']:40s} {r['label'] or ''}")


@watch.command(name="add")
@click.argument("pattern")
@click.option("--label", default="", help="Optional display label.")
def watch_add(pattern, label):
    """Add a pattern to the watchlist (email / domain / company name)."""
    from feeds import add_watchlist
    pid = add_watchlist(pattern, label=label)
    click.echo(f"Added [{pid}] {pattern}")


@watch.command(name="remove")
@click.argument("pattern_or_id")
def watch_remove(pattern_or_id):
    """Remove by id or by exact pattern."""
    from feeds import remove_watchlist
    n = remove_watchlist(pattern_or_id)
    click.echo(f"Removed {n} entry/entries.")


@robin.command(name="mcp")
def mcp_serve():
    """Run Robin as an MCP server (stdio transport).

    Wire into Claude Code:
        claude mcp add robin -- python <path>/mcp_server.py

    Wire into Codex CLI (~/.codex/config.toml):
        [mcp_servers.robin]
        command = "python"
        args = ["<path>/mcp_server.py"]
    """
    import sys, os
    here = os.path.dirname(os.path.abspath(__file__))
    server = os.path.join(here, "mcp_server.py")
    os.execv(sys.executable, [sys.executable, server])


@robin.command(name="mcp-install")
@click.option("--client", type=click.Choice(["claude-code", "codex-cli", "claude-desktop"]),
              default="claude-code", show_default=True)
def mcp_install(client):
    """Print the exact command/config to register Robin in your MCP client."""
    import os
    server = os.path.abspath(os.path.join(os.path.dirname(__file__), "mcp_server.py"))
    python = os.popen("which python3 || which python").read().strip() or "python"
    if client == "claude-code":
        click.echo("Run this once:\n")
        click.echo(f"  claude mcp add robin -- {python} {server}\n")
        click.echo("Then in any Claude Code session: ask it to use Robin.")
    elif client == "codex-cli":
        click.echo("Add to ~/.codex/config.toml:\n")
        click.echo("[mcp_servers.robin]")
        click.echo(f'command = "{python}"')
        click.echo(f'args = ["{server}"]')
    elif client == "claude-desktop":
        click.echo("Add to ~/.claude/claude_desktop_config.json:\n")
        click.echo(json.dumps({
            "mcpServers": {"robin": {"command": python, "args": [server]}}
        }, indent=2))


@robin.command()
@click.argument("seed")
@click.option("--max-depth", default=2, show_default=True, type=int,
              help="How many pivot hops to follow.")
@click.option("--max-nodes", default=25, show_default=True, type=int,
              help="Hard cap on total investigation nodes.")
@click.option("--kind", default=None, type=click.Choice(
    ["email", "phone", "username", "name", "ip", "domain", "hash", "btc", "url"]))
@click.option("--json", "as_json", is_flag=True, default=False)
def investigate(seed, max_depth, max_nodes, kind, as_json):
    """Run a multi-hop OSINT investigation seeded from `seed`.

    Starts from one piece of PII, traces it across all sources, then pivots
    on whatever new candidates pop up (email -> domain -> employees -> ...).

    Examples:

      robin investigate victime@example.com
      robin investigate acme.com --max-depth 3
      robin investigate john_doe
    """
    import json as _json
    root = pivot_investigate(seed, max_depth=max_depth, max_nodes=max_nodes, kind=kind)
    if as_json:
        click.echo(_json.dumps(pivot_to_dict(root), indent=2, default=str))
    else:
        click.echo(pivot_render(root))
        click.echo("\n--- Investigation stats ---")
        s = summary_stats(root)
        click.echo(f"  Total nodes explored: {s['total_nodes']}")
        click.echo(f"  Max depth reached:    {s['max_depth']}")
        click.echo(f"  Nodes with hits:      {s['nodes_with_hits']}")
        click.echo(f"  Total hits across all sources: {s['total_hits']}")
        click.echo(f"  Breakdown by kind:    {s['by_kind']}")


@robin.command()
@click.argument("password", required=False)
def pwned(password):
    """Check whether a password has appeared in HIBP's leak corpus (k-anonymity)."""
    if not password:
        password = click.prompt("Password (hidden)", hide_input=True)
    click.echo(password_format(check_password(password)))


@robin.command()
@click.argument("target")
@click.option("--limit", default=15, show_default=True, type=int)
@click.option("--query", default=None,
              help="If given with a domain, search archived snapshots for this literal text.")
def wayback(target, limit, query):
    """Pull Wayback Machine snapshots for a URL or domain.

    Examples:

      robin wayback https://example.com/team
      robin wayback example.com --query "victime@example.com"
    """
    if query:
        # Domain-wide content search
        hits = wb_search(target, query, max_snapshots=limit)
        if not hits:
            click.echo(f"No archived snapshot of {target} mentions '{query}'.")
            return
        click.echo(f"Archived snapshots mentioning '{query}':")
        for h in hits:
            click.echo(f"\n  {h['snapshot_url']}")
            click.echo(f"    raw: {h['raw'][:400]}")
    else:
        snaps = wb_snapshots(target, limit=limit)
        click.echo(wb_format(snaps))


@robin.command(name="email-recon")
@click.argument("name")
@click.argument("domain")
@click.option("--smtp-probe", is_flag=True, default=False,
              help="Also send SMTP RCPT TO probes (unreliable on accept-all).")
@click.option("--no-darkweb", is_flag=True, default=False,
              help="Skip dark web + Telegram check on confirmed candidates.")
def email_recon_cmd(name, domain, smtp_probe, no_darkweb):
    """Generate likely emails for `NAME` at `DOMAIN`, probe HudsonRock + (opt)
    SMTP, then dark web + Telegram on each confirmed candidate.

      robin email-recon "Jean Dupont" acme.com
      robin email-recon "John Doe" example.com --smtp-probe --no-darkweb
    """
    result = email_recon(name, domain,
                         smtp_probe_enabled=smtp_probe,
                         darkweb_check=not no_darkweb)
    click.echo(email_format(result))


@robin.command()
@click.argument("value")
@click.option("--kind", type=click.Choice(
    ["email", "phone", "username", "name", "ip", "domain", "hash", "btc"]),
    default=None, help="Override the auto-detected input type.")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Output raw JSON instead of a human-readable report.")
def trace(value, kind, as_json):
    """Trace a personal info (email, phone, username, name, IP...) across free OSINT services.

    Examples:

      robin trace victime@example.com

      robin trace +33612345678

      robin trace john_doe          # username probes (GitHub, Reddit, Telegram, ...)

      robin trace "Jean Dupont"     # FR press / company registry / LinkedIn dorks
    """
    import json as _json
    result = pii_lookup(value, kind=kind)
    if as_json:
        click.echo(_json.dumps(result, indent=2, default=str))
    else:
        click.echo(pii_format(result))


@robin.command()
@click.option("--ui-port", default=8501, show_default=True, type=int)
@click.option("--ui-host", default="localhost", show_default=True, type=str)
def ui(ui_port, ui_host):
    """Run Robin in Web UI mode."""
    import sys
    import os
    from streamlit.web import cli as stcli

    base = sys._MEIPASS if getattr(sys, "frozen", False) else os.path.dirname(__file__)
    ui_script = os.path.join(base, "ui.py")
    sys.argv = [
        "streamlit", "run", ui_script,
        f"--server.port={ui_port}",
        f"--server.address={ui_host}",
        "--global.developmentMode=false",
    ]
    sys.exit(stcli.main())


if __name__ == "__main__":
    robin()
