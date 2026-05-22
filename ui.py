"""
Robin OSINT — Streamlit UI v3.

Tab-based navigation. Each tool has its own self-contained tab. Global config
(LLM model, threads, dark/clearweb toggles) lives in a compact sidebar.

Tabs:
  🔍 Search        — full LLM pipeline (engines + scrape + summary)
  🕵️  Trace        — auto-detected PII (email/phone/username/...) trace
  🕸️  Investigate  — multi-hop pivot engine
  👤 Email Recon  — name + domain → likely emails + dark/Telegram check
  🔑 Password     — HIBP Pwned Passwords (k-anonymity)
  🗄️  Wayback     — archived content search
  🩺 Health       — source/engine reachability
"""

import os
import base64
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import streamlit as st

from scrape import scrape_multiple, filter_content_by_terms
from search import get_search_results, healthcheck_engines, list_engines
from download import download_safe_files
from osint_sources import CLEARWEB_SOURCES, health_check as osint_health
from darkweb_extras import darkweb_health, active_ransomware_leak_sites
from telegram_sources import known_channels
from enrichment import enrich_all, format_enrichment
from llm_utils import BufferedStreamingHandler, get_model_choices
from llm import (
    get_llm, refine_query, filter_results, generate_summary,
    build_indicator_block, extract_focus_terms, _extract_indicators,
)
from pdf_report import build_pdf_report
from pii_lookup import lookup as pii_lookup, detect_type as pii_detect, format_report as pii_format
from pivot import investigate as pivot_investigate, summary_stats, PivotNode
from password_check import check_password
from wayback import snapshots as wb_snapshots, search_archived_content as wb_search
from email_recon import recon as email_recon
from agent import run_agent, ROBIN_TOOLS, AgentEvent, list_backends, run as agent_run
from connectors import (
    current_status, test_provider, save_keys, clear_key, PROVIDERS,
    CLI_CONNECTORS, cli_connector_status, test_cli_connector,
)

logging.basicConfig(level=logging.WARNING)


# --------------------------------------------------------------------------- #
# Page config + global CSS
# --------------------------------------------------------------------------- #

st.set_page_config(
    page_title="Argus — Dark-web OSINT",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
        :root {
            --robin-red: #FF4B4B;
            --robin-bg: #0e1117;
        }
        .argus-title {
            color: var(--robin-red);
            font-weight: 800;
            font-size: 2.2rem;
            letter-spacing: -0.5px;
            margin: 0;
        }
        .argus-sub {
            color: #aaa;
            font-size: 0.95rem;
            margin-top: -8px;
            margin-bottom: 16px;
        }
        div[data-testid="stMetricValue"] { font-size: 1.5rem !important; }
        .stTabs [data-baseweb="tab-list"] button {
            font-size: 1rem;
            padding: 0.6rem 1rem;
        }
        .stTabs [data-baseweb="tab"] [data-baseweb="tab-highlight"] {
            background-color: var(--robin-red) !important;
        }
        .stTabs [aria-selected="true"] {
            color: var(--robin-red) !important;
        }
        .pivot-node {
            border-left: 2px solid #444;
            margin-left: 8px;
            padding-left: 16px;
            margin-bottom: 4px;
        }
        .pivot-node-hit { border-left-color: var(--robin-red); }
        .raw-fragment {
            background: #1a1d23;
            border-left: 3px solid #FF4B4B;
            padding: 8px 12px;
            font-family: monospace;
            font-size: 0.85rem;
            white-space: pre-wrap;
            word-break: break-all;
            margin: 4px 0;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------------------------------- #
# Sidebar: global config only
# --------------------------------------------------------------------------- #

with st.sidebar:
    st.markdown("<h2 style='color:#FF4B4B;margin-bottom:0;'>🕵️  Argus</h2>",
                unsafe_allow_html=True)
    st.caption("AI-powered dark-web OSINT")

    st.divider()
    st.subheader("LLM")
    model_options = get_model_choices() + ["✏️ custom..."]
    default_idx = next(
        (i for i, n in enumerate(model_options) if "gpt-5-mini" in n.lower()), 0
    ) if model_options else 0
    model_choice = st.selectbox("Model", model_options, index=default_idx, key="g_model")
    if model_choice == "✏️ custom...":
        model = st.text_input(
            "Custom model name", placeholder="e.g. gpt-5.4 / claude-opus-4-7",
            key="g_model_custom",
        )
    else:
        model = model_choice
    st.caption(
        "Used by the **Search** tab, and by the **Agent** tab when forwarded "
        "to Claude Code (Claude models) or Codex CLI (GPT/o models)."
    )

    st.subheader("Pipeline")
    threads = st.slider("Concurrent workers", 1, 16, 8, key="g_threads")

    with st.expander("Dark-web options"):
        include_dread = st.checkbox("Search Dread forum", True, key="g_dread")
        include_ransomware_sites = st.checkbox(
            "Scrape active ransomware leak sites", True, key="g_ransom"
        )
        rotate_circuit = st.checkbox(
            "Rotate Tor circuit before search", True, key="g_circuit"
        )
        deep_scrape = st.checkbox(
            "Deep scrape (+1 hop on forums)", False, key="g_deep"
        )

    with st.expander("Clearweb OSINT"):
        include_clearweb = st.checkbox(
            "Query clearweb OSINT APIs", True, key="g_clearweb"
        )
        all_sources = list(CLEARWEB_SOURCES.keys())
        selected_sources = st.multiselect(
            "Active sources", all_sources, default=all_sources,
            disabled=not include_clearweb, key="g_sources",
        )

    with st.expander("Outputs"):
        download_files = st.checkbox("Download safe files (txt/csv/json/pdf)",
                                      False, key="g_dl")
        max_download_mb = st.slider("Max file size (MB)", 1, 20, 5, key="g_dl_mb")
        enrich_iocs = st.checkbox("Enrich IOCs (DNS/WHOIS/geo/hash)", True,
                                   key="g_enrich")

    st.divider()
    st.caption("Argus v1 · all signals · zero compromise")


# --------------------------------------------------------------------------- #
# Header
# --------------------------------------------------------------------------- #

st.markdown("<p class='argus-title'>Argus — Dark-web OSINT engine</p>",
            unsafe_allow_html=True)
st.markdown(
    "<p class='argus-sub'>Search · trace · investigate · pivot — "
    "across onion engines, ransomware leak sites, Telegram, and clearweb APIs.</p>",
    unsafe_allow_html=True,
)

# --------------------------------------------------------------------------- #
# Tabs
# --------------------------------------------------------------------------- #

(tab_agent, tab_search, tab_trace, tab_invest, tab_email,
 tab_pwd, tab_wb, tab_localdb, tab_feeds, tab_health, tab_conn) = st.tabs([
    "🤖 Agent",
    "🔍 Search",
    "🕵️  Trace PII",
    "🕸️  Investigate",
    "👤 Email recon",
    "🔑 Pwned password",
    "🗄️  Wayback",
    "📊 Local DB",
    "📡 Feeds",
    "🩺 Health",
    "🔌 Connectors",
])


# --------------------------------------------------------------------------- #
# Tab 0 — Agent (LLM with full tool access)
# --------------------------------------------------------------------------- #

with tab_agent:
    st.subheader("Ask Robin in natural language")
    available = list_backends()

    backend_options = []
    if available.get("claude-code"):
        backend_options.append(("claude-code", "🟢 Claude Code (no key)"))
    if available.get("codex-cli"):
        backend_options.append(("codex-cli", "🟢 Codex CLI (no key)"))
    backend_options.append(("langchain", "🔑 LangChain (needs API key)"))

    backend_keys = [b[0] for b in backend_options]
    backend_labels = [b[1] for b in backend_options]

    c1, c2 = st.columns([2, 1])
    backend_label = c1.radio(
        "Backend",
        backend_labels,
        index=0,
        horizontal=True,
        help=(
            "Claude Code / Codex CLI authenticate via their own subscription "
            "(no API key in .env). LangChain uses the model/key in the sidebar."
        ),
    )
    backend = backend_keys[backend_labels.index(backend_label)]
    max_iter = c2.number_input("Max iterations", 1, 20, 10, key="agent_iter")

    if not available.get("claude-code") and not available.get("codex-cli"):
        st.info(
            "💡 To run the agent **without an API key**, install one of:\n"
            "- [Claude Code](https://docs.claude.com/claude-code) + `pip install claude-agent-sdk`\n"
            "- [Codex CLI](https://github.com/openai/codex) (run `codex login` once)"
        )

    with st.expander(f"🛠️  Available Robin tools ({len(ROBIN_TOOLS)})"):
        for t in ROBIN_TOOLS:
            doc = (t.description or "").split("\n")[0]
            st.markdown(f"- **`{t.name}`** — {doc}")

    with st.expander("📡 Use Robin from your own Claude Code / Codex / Cursor"):
        import os as _os
        server_path = _os.path.abspath(
            _os.path.join(_os.path.dirname(__file__), "mcp_server.py")
        )
        st.markdown("**Claude Code (recommended):**")
        st.code(f"claude mcp add robin -- python {server_path}", language="bash")
        st.markdown("**Codex CLI** — add to `~/.codex/config.toml`:")
        st.code(
            f'[mcp_servers.robin]\ncommand = "python"\nargs = ["{server_path}"]',
            language="toml",
        )
        st.markdown("**Claude Desktop** — add to `~/.claude/claude_desktop_config.json`:")
        st.code(
            '{"mcpServers": {"robin": {"command": "python", "args": ["' +
            server_path + '"]}}}', language="json",
        )

    with st.form("agent_form"):
        agent_q = st.text_area(
            "Your question",
            placeholder=(
                "Examples:\n"
                "  - Cherche si victime@example.com a leak, dans le dark et sur Telegram\n"
                "  - Trouve l'email de Jean Dupont chez acme.com\n"
                "  - acme.com est-elle listée par un groupe ransomware ?\n"
                "  - Build a full picture of @some_username from public sources"
            ),
            height=120, key="agent_q",
        )
        deep_mode = st.checkbox(
            "🔬 Deep investigation (force multi-hop pivots, no early stop)",
            value=False, key="agent_deep",
            help=(
                "Adds an explicit instruction telling the agent to pivot at "
                "least 3 times (investigate, search_darkweb, search_telegram, "
                "email_recon, wayback_search) before concluding. ~2-3× slower "
                "but catches what a single trace_pii misses."
            ),
        )
        run_agent_btn = st.form_submit_button(
            f"🤖 Run agent ({backend})", type="primary", use_container_width=True,
        )

    if run_agent_btn and agent_q.strip():
        events_container = st.container()
        progress = st.empty()
        rendered_events: List = []

        def _render_event(ev: AgentEvent):
            rendered_events.append(ev)
            with events_container:
                if ev.kind == "thought":
                    with st.chat_message("assistant"):
                        st.markdown(f"_{ev.content}_")
                elif ev.kind == "tool_call":
                    args_str = ", ".join(
                        f"{k}={v!r}" for k, v in (ev.tool_args or {}).items()
                    )
                    st.markdown(f"🛠  **`{ev.tool_name}`**({args_str})")
                elif ev.kind == "tool_result":
                    with st.expander(f"↳ result of `{ev.tool_name}`", expanded=False):
                        st.code(ev.content[:3000], language="json")
                elif ev.kind == "answer":
                    st.markdown("---")
                    with st.chat_message("assistant"):
                        st.markdown(f"### 📝 Final answer\n\n{ev.content}")
                elif ev.kind == "error":
                    st.error(ev.content)
            progress.caption(f"… {len(rendered_events)} events so far")

        try:
            llm_for_lc = None
            if backend == "langchain":
                llm_for_lc = get_llm(model)

            question = agent_q.strip()
            if deep_mode:
                question = (
                    question + "\n\n"
                    "[INVESTIGATION DIRECTIVE — DEEP MODE]\n"
                    "Do not stop after one trace_pii. You MUST call at least "
                    "3 different Argus tools before concluding, including at "
                    "minimum one of {investigate, search_darkweb, "
                    "search_telegram} and one enrichment tool. Show the raw "
                    "matched fragment for every positive hit. If the value is "
                    "an email, also pivot to the localpart as a username and "
                    "to the domain via enrich_domain + wayback_search."
                )

            result = agent_run(
                question, backend=backend, llm=llm_for_lc,
                max_iterations=int(max_iter), on_event=_render_event,
                model=model if backend != "langchain" else None,
            )
            progress.empty()
            st.success(
                f"✅ Done — {result.total_tool_calls} tool call(s)"
                + (f" over {result.iterations} iteration(s)"
                   if result.iterations else "")
            )
        except RuntimeError as e:
            progress.empty()
            st.error(f"Backend error: {e}")
        except Exception as e:
            progress.empty()
            st.exception(e)


# --------------------------------------------------------------------------- #
# Tab 1 — Search (LLM pipeline)
# --------------------------------------------------------------------------- #

@st.cache_data(ttl=300, show_spinner=False)
def _cached_search(refined: str, threads: int, focus_terms: list,
                   clearweb_sources: list, include_clearweb: bool,
                   include_dread: bool, include_ransomware: bool,
                   rotate_circuit: bool):
    return get_search_results(
        refined.replace(" ", "+"),
        max_workers=threads, focus_terms=focus_terms,
        include_clearweb_osint=include_clearweb,
        clearweb_sources=clearweb_sources or None,
        include_dread=include_dread,
        include_ransomware_sites=include_ransomware,
        rotate_circuit=rotate_circuit,
    )


@st.cache_data(ttl=300, show_spinner=False)
def _cached_scrape(filtered: list, threads: int, deep: bool):
    return scrape_multiple(filtered, max_workers=threads, deep=deep)


with tab_search:
    st.subheader("Run the full LLM-powered pipeline")
    with st.form("search_form", clear_on_submit=False):
        c1, c2 = st.columns([8, 1])
        query = c1.text_input(
            "Target",
            placeholder="e.g. acme corp leak, lockbit, victime@acme.com",
            label_visibility="collapsed",
            key="search_query",
        )
        run_search = c2.form_submit_button("Run", use_container_width=True)

    status_slot = st.empty()
    metrics_slot = st.container()
    summary_slot_container = st.empty()

    if run_search and query:
        # PII auto-detection → recommend the right tab
        detected = pii_detect(query.strip())
        if detected in {"email", "phone", "username", "ip", "hash", "btc"}:
            st.info(
                f"🕵️  Your query looks like a **{detected}**. "
                "Switch to the **Trace PII** tab for a tighter, faster lookup."
            )

        focus_terms = extract_focus_terms(query)

        # Pipeline stages
        with status_slot.container():
            with st.spinner("🔄 Loading LLM..."):
                llm = get_llm(model)

        with status_slot.container():
            with st.spinner("🔄 Refining query..."):
                refined = refine_query(llm, query)
        with metrics_slot:
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Refined query", refined[:30] + ("…" if len(refined) > 30 else ""))

        with status_slot.container():
            with st.spinner("🔍 Searching dark web + Dread + leak sites + OSINT..."):
                results = _cached_search(
                    refined, threads, focus_terms,
                    selected_sources, include_clearweb,
                    include_dread, include_ransomware_sites, rotate_circuit,
                )
        m2.metric("Candidates", len(results))

        with status_slot.container():
            with st.spinner("🗂️  LLM filtering..."):
                filtered = filter_results(llm, refined, results)
        m3.metric("Filtered", len(filtered))

        with status_slot.container():
            spin = "📜 Deep scraping..." if deep_scrape else "📜 Scraping..."
            with st.spinner(spin):
                scraped = _cached_scrape(filtered, threads, deep_scrape)
                scraped = filter_content_by_terms(scraped, focus_terms)
        m4.metric("Scraped", len(scraped))

        # IOCs + enrichment
        raw_indicators = _extract_indicators(scraped)
        indicator_block = build_indicator_block(scraped)
        with st.expander("📌 Extracted IOCs", expanded=True):
            st.code(indicator_block, language="text")

        enrichment_block = ""
        if enrich_iocs and any(raw_indicators.get(k) for k in
                                ("domains", "ip_addresses", "sha256", "sha1",
                                 "md5", "cves", "emails")):
            with status_slot.container():
                with st.spinner("🔬 Enriching IOCs..."):
                    enr = enrich_all(raw_indicators)
                    enrichment_block = format_enrichment(enr)
            with st.expander("🔬 IOC enrichment", expanded=False):
                st.code(enrichment_block, language="text")

        # Optional safe downloads
        downloaded = []
        if download_files:
            with status_slot.container():
                with st.spinner("⬇️  Downloading safe files..."):
                    downloaded = download_safe_files(filtered, query,
                                                      max_size_mb=max_download_mb)
            if downloaded:
                with st.expander(f"📥 {len(downloaded)} file(s) downloaded"):
                    for d in downloaded:
                        st.write(f"`{d['path']}` ({d['bytes']} B) ← {d['url']}")

        # Streamed summary
        st.session_state["search_summary"] = ""
        with summary_slot_container.container(border=True):
            st.subheader(":red[📝 Investigation summary]", anchor=False, divider="gray")
            summary_slot = st.empty()

        def emit(chunk: str):
            st.session_state["search_summary"] += chunk
            summary_slot.markdown(st.session_state["search_summary"])

        with status_slot.container():
            with st.spinner("✍️  Generating summary..."):
                handler = BufferedStreamingHandler(ui_callback=emit)
                llm.callbacks = [handler]
                _ = generate_summary(llm, query, scraped)
        status_slot.success("✅ Pipeline completed")

        # Downloads (md + pdf)
        now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        b64 = base64.b64encode(st.session_state["search_summary"].encode()).decode()
        col_md, col_pdf = st.columns(2)
        col_md.markdown(
            f'<a href="data:file/markdown;base64,{b64}" download="robin_{now}.md">'
            f'📄 Download Markdown</a>',
            unsafe_allow_html=True,
        )
        try:
            pdf_bytes = build_pdf_report(
                query=query,
                indicators_text=indicator_block + (
                    ("\n\n" + enrichment_block) if enrichment_block else ""
                ),
                summary_text=st.session_state["search_summary"],
                sources=filtered,
                output_path=None,
            )
            col_pdf.download_button(
                "📑 Download PDF", data=pdf_bytes,
                file_name=f"robin_{now}.pdf", mime="application/pdf",
            )
        except Exception as e:
            col_pdf.error(f"PDF error: {e}")


# --------------------------------------------------------------------------- #
# Tab 2 — Trace PII
# --------------------------------------------------------------------------- #

def _render_pii_traces(result: Dict):
    hits = [t for t in result["traces"] if t.get("found")]
    misses = [t for t in result["traces"] if not t.get("found")]
    c1, c2, c3 = st.columns(3)
    c1.metric("Probes", result["probes_checked"])
    c2.metric("Hits", result["probes_with_hits"])
    c3.metric("Detected", result["type"])

    if hits:
        st.markdown("### ✅ Traces found")
        for t in hits:
            with st.container(border=True):
                head = f"**{t['source']}** — {t.get('summary','')}"
                if t.get("link"):
                    head += f" — [{t['link']}]({t['link']})"
                st.markdown(head)
                details = t.get("details") or {}
                extra_hits = details.get("hits") if isinstance(details, dict) else None
                if extra_hits:
                    st.markdown(f"**Raw matches** ({len(extra_hits)})")
                    for h in extra_hits[:10]:
                        tag = h.get("engine", "web") or "web"
                        sub = f"[{tag}] [{h.get('title','(no title)')}]({h.get('url','')})"
                        if h.get("channel"):
                            sub += f" — channel `{h['channel']}`"
                        st.markdown(sub)
                        if h.get("raw"):
                            st.markdown(
                                f"<div class='raw-fragment'>{h['raw']}</div>",
                                unsafe_allow_html=True,
                            )
    else:
        st.info("No positive trace found across the probes that ran.")

    with st.expander(f"Probes with no result ({len(misses)})"):
        for t in misses:
            st.markdown(f"·  **{t['source']}** — {t.get('summary','')}")


with tab_trace:
    st.subheader("Trace a piece of personal info across all OSINT sources")
    st.caption(
        "Auto-detects input type (email / phone / username / name / IP / "
        "domain / hash / BTC) and runs every relevant clearweb + dark-web + "
        "Telegram probe in parallel, returning raw matches."
    )
    with st.form("trace_form", clear_on_submit=False):
        c1, c2 = st.columns([8, 1])
        pii_input = c1.text_input(
            "PII value",
            placeholder="victime@example.com  /  +33612345678  /  john_doe",
            label_visibility="collapsed",
            key="trace_input",
        )
        run_trace = c2.form_submit_button("Trace", use_container_width=True)

    if run_trace and pii_input:
        kind = pii_detect(pii_input.strip())
        st.write(f"→ Detected type: **{kind}**")
        if kind == "unknown":
            st.error("Could not detect a useful type. Try a clearer format.")
        else:
            with st.spinner(
                f"Probing all sources (clearweb + dark + Telegram) for this {kind}..."
            ):
                result = pii_lookup(pii_input.strip(), kind=kind)
            _render_pii_traces(result)


# --------------------------------------------------------------------------- #
# Tab 3 — Investigate (pivot engine)
# --------------------------------------------------------------------------- #

def _render_pivot(node: PivotNode, level: int = 0):
    """Recursive renderer for a pivot tree."""
    if node.probes_with_hits > 0:
        node_cls = "pivot-node pivot-node-hit"
        icon = "✅"
    elif node.probes_checked > 0:
        node_cls = "pivot-node"
        icon = "·"
    else:
        node_cls = "pivot-node"
        icon = "○"

    st.markdown(
        f"<div class='{node_cls}'>"
        f"<b>{icon} [{node.kind}]</b> <code>{node.value}</code>"
        + (f" <span style='color:#888'>(via {node.reason})</span>"
           if node.reason != "seed" else "")
        + f" — <span style='color:#bbb'>{node.probes_with_hits}/{node.probes_checked} hits"
        f" · depth {node.depth}</span>"
        f"</div>",
        unsafe_allow_html=True,
    )
    # Show hits as bullets
    hits = [t for t in (node.traces or []) if t.get("found")]
    for t in hits[:5]:
        st.markdown(
            f"<div class='pivot-node' style='margin-left: {level*20+24}px'>"
            f"✓ <b>{t.get('source','')}</b>: {t.get('summary','')[:200]}"
            f"</div>",
            unsafe_allow_html=True,
        )
    # Recurse on children
    for child in node.pivoted_to:
        _render_pivot(child, level + 1)


with tab_invest:
    st.subheader("Multi-hop OSINT investigation")
    st.caption(
        "Seeds from one PII value, traces it everywhere, then auto-pivots on "
        "new candidates (email → domain → employees → ...) up to N hops."
    )
    with st.form("invest_form"):
        c1, c2, c3 = st.columns([6, 1, 1])
        seed = c1.text_input(
            "Seed",
            placeholder="victime@example.com  /  acme.com",
            label_visibility="collapsed",
            key="invest_seed",
        )
        depth = c2.number_input("Depth", 1, 4, 2, key="invest_depth")
        max_nodes = c3.number_input("Max nodes", 5, 80, 25, key="invest_nodes")
        run_invest = st.form_submit_button("🕸️  Investigate", type="primary",
                                            use_container_width=True)

    if run_invest and seed:
        with st.spinner(
            f"Investigating {seed} (depth={depth}, max_nodes={max_nodes})..."
        ):
            root = pivot_investigate(seed,
                                     max_depth=int(depth),
                                     max_nodes=int(max_nodes))
        stats = summary_stats(root)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Nodes", stats["total_nodes"])
        c2.metric("Depth", stats["max_depth"])
        c3.metric("Hits", stats["total_hits"])
        c4.metric("Nodes w/ hits", stats["nodes_with_hits"])

        st.markdown("### Investigation tree")
        _render_pivot(root)

        with st.expander("📊 Breakdown by kind"):
            for k, v in stats["by_kind"].items():
                st.write(f"  {k}: {v}")

        # JSON export
        import json
        from pivot import to_dict
        st.download_button(
            "📥 Download as JSON",
            data=json.dumps(to_dict(root), indent=2, default=str),
            file_name=f"investigation_{datetime.now():%Y%m%d_%H%M%S}.json",
            mime="application/json",
        )


# --------------------------------------------------------------------------- #
# Tab 4 — Email Recon
# --------------------------------------------------------------------------- #

with tab_email:
    st.subheader("Generate likely emails + probe each one")
    st.caption(
        "Given a person's name + a company domain, generates ~20 patterns "
        "(`first.last`, `flast`, `last.first`, ...) then probes MX, "
        "HudsonRock infostealer logs, optional SMTP RCPT TO, and (on confirmed "
        "candidates) dark web + Telegram for raw evidence."
    )
    with st.form("recon_form"):
        c1, c2 = st.columns(2)
        er_name = c1.text_input("Full name", placeholder="Jean Dupont", key="er_name")
        er_domain = c2.text_input("Domain", placeholder="acme.com", key="er_domain")
        c3, c4 = st.columns(2)
        er_smtp = c3.checkbox("SMTP RCPT TO probe (unreliable on accept-all)",
                              False, key="er_smtp")
        er_dark = c4.checkbox("Dark+Telegram trace on confirmed", True, key="er_dark")
        run_er = st.form_submit_button("👤 Run recon", type="primary",
                                        use_container_width=True)

    if run_er and er_name and er_domain:
        with st.spinner("Probing patterns (HudsonRock + dark + Telegram)..."):
            result = email_recon(er_name, er_domain,
                                  smtp_probe_enabled=er_smtp,
                                  darkweb_check=er_dark)
        if result.get("error"):
            st.error(result["error"])
        else:
            c1, c2, c3 = st.columns(3)
            c1.metric("Patterns", len(result["candidates"]))
            c2.metric("Confirmed", len(result["confirmed"]))
            c3.metric("MX hosts", len(result["mx"]))
            st.caption(f"MX: {', '.join(result['mx'])}")

            if not result["confirmed"]:
                st.info("No pattern matched any confirmation signal.")
            for c in result["confirmed"][:10]:
                with st.container(border=True):
                    st.markdown(
                        f"### ✅ `{c['email']}`  *(score {c['score']})*"
                    )
                    for ev in c["evidence"]:
                        st.markdown(f"- {ev}")
                    dw = c.get("darkweb") or {}
                    samples = (dw.get("darkweb_samples") or []) + \
                              (dw.get("telegram_samples") or [])
                    if samples:
                        st.markdown(f"**Raw samples ({len(samples)}):**")
                        for s in samples[:6]:
                            tag = "tg" if "channel" in s else "dark"
                            head = f"`[{tag}]` [{s.get('title','(no title)')}]({s.get('url','')})"
                            if s.get("channel"):
                                head += f" — `{s['channel']}`"
                            st.markdown(head)
                            if s.get("raw"):
                                st.markdown(
                                    f"<div class='raw-fragment'>{s['raw']}</div>",
                                    unsafe_allow_html=True,
                                )


# --------------------------------------------------------------------------- #
# Tab 5 — Pwned Password
# --------------------------------------------------------------------------- #

with tab_pwd:
    st.subheader("Check a password against HIBP Pwned Passwords")
    st.caption(
        "Uses k-anonymity: we send only the first 5 chars of the SHA-1 hash "
        "to HIBP. The plaintext password never leaves this machine."
    )
    with st.form("pwd_form"):
        pwd = st.text_input("Password", type="password",
                            placeholder="Enter password to check",
                            key="pwd_check_input")
        run_pwd = st.form_submit_button("🔑 Check", type="primary",
                                         use_container_width=True)

    if run_pwd and pwd:
        with st.spinner("Querying HIBP range API..."):
            result = check_password(pwd)
        if result.get("error"):
            st.error(f"HIBP error: {result['error']}")
        elif result["pwned"]:
            st.error(
                f"### ❌  PWNED — seen in {result['count']:,} known breaches\n"
                f"This password is in widely-circulated leak corpuses. "
                f"Anyone running a credential-stuffing attack will try it."
            )
        else:
            st.success(
                "### ✅  Not found in HIBP Pwned Passwords\n"
                "But absence of evidence ≠ evidence of absence. "
                "Long randomly-generated passwords remain best."
            )
        st.caption(f"SHA-1: `{result['hash']}` (only first 5 chars sent to HIBP)")


# --------------------------------------------------------------------------- #
# Tab 6 — Wayback
# --------------------------------------------------------------------------- #

with tab_wb:
    st.subheader("Wayback Machine — archived content search")
    st.caption(
        "List snapshots of a URL, or grep all snapshots of a domain for a "
        "literal query (great for finding deleted contact pages, old team "
        "rosters, employee emails, etc.)."
    )
    with st.form("wb_form"):
        c1, c2 = st.columns([3, 2])
        wb_url = c1.text_input("URL or domain",
                                placeholder="acme.com OR https://acme.com/team",
                                key="wb_url")
        wb_query = c2.text_input("Optional: text to grep in archives",
                                  placeholder="victim@acme.com",
                                  key="wb_query")
        run_wb = st.form_submit_button("🗄️  Fetch", type="primary",
                                        use_container_width=True)

    if run_wb and wb_url:
        if wb_query:
            with st.spinner("Searching archived content..."):
                hits = wb_search(wb_url, wb_query, max_snapshots=15)
            if not hits:
                st.info("No archived snapshot matches that query.")
            for h in hits:
                with st.container(border=True):
                    st.markdown(f"[{h['snapshot_url']}]({h['snapshot_url']})")
                    st.markdown(
                        f"<div class='raw-fragment'>{h['raw']}</div>",
                        unsafe_allow_html=True,
                    )
        else:
            with st.spinner("Fetching snapshot history..."):
                snaps = wb_snapshots(wb_url, limit=30)
            if not snaps:
                st.info("No snapshots found.")
            for s in snaps:
                st.write(
                    f"`{s['timestamp']}` — "
                    f"[{s['snapshot_url']}]({s['snapshot_url']}) "
                    f"({s.get('mimetype','?')}, {s.get('status','?')})"
                )


# --------------------------------------------------------------------------- #
# Tab 7 — Health
# --------------------------------------------------------------------------- #

with tab_health:
    st.subheader("Source reachability")
    st.caption(
        "Live probe of every onion engine, dark-web target, and clearweb OSINT "
        "API. Use this before launching long investigations to see what's up."
    )

    if st.button("🔄 Run full health check", type="primary"):
        with st.spinner("Probing onion engines via Tor..."):
            engines = healthcheck_engines(timeout=6)
        with st.spinner("Probing dark-web extras..."):
            dw = darkweb_health()
        with st.spinner("Probing clearweb OSINT APIs..."):
            osint = osint_health()

        c1, c2, c3 = st.columns(3)
        c1.metric("Engines OK", f"{sum(engines.values())}/{len(engines)}")
        c2.metric("Dark targets OK", f"{sum(dw.values())}/{len(dw)}")
        c3.metric("OSINT APIs OK", f"{sum(osint.values())}/{len(osint)}")

        col_a, col_b, col_c = st.columns(3)
        with col_a:
            st.markdown("**Dark-web engines**")
            for name, ok in engines.items():
                st.write(("✅ " if ok else "❌ ") + name)
        with col_b:
            st.markdown("**Dark-web targets**")
            for name, ok in dw.items():
                st.write(("✅ " if ok else "❌ ") + name)
        with col_c:
            st.markdown("**Clearweb OSINT**")
            for name, ok in osint.items():
                st.write(("✅ " if ok else "❌ ") + name)

    st.divider()
    st.subheader("Source inventory")
    c1, c2 = st.columns(2)
    with c1:
        with st.expander(f"🌑 Search engines ({len(list_engines())})", expanded=False):
            for e in list_engines():
                tag = "tor" if e["tor"] else "clearnet"
                st.write(f"`[{tag}]` **{e['name']}** — `{e['url']}`")
        sites = active_ransomware_leak_sites()
        with st.expander(f"💀 Active ransomware leak sites ({len(sites)})"):
            for s in sites[:50]:
                loc = "onion" if s["onion"] else "clear"
                st.write(f"`[{loc}]` **{s['group']}** — `{s['host']}`")
            if len(sites) > 50:
                st.caption(f"… {len(sites) - 50} more")
    with c2:
        channels = known_channels()
        with st.expander(f"💬 Telegram channels watched ({len(channels)})"):
            st.caption(
                "Auto-discovered via tgstat + merged with your file "
                "(set `ROBIN_TELEGRAM_CHANNELS_FILE` env to override)."
            )
            for ch in channels:
                st.write(f"- @{ch}  ([t.me/{ch}](https://t.me/{ch}))")
        with st.expander(f"🌐 Clearweb OSINT sources ({len(CLEARWEB_SOURCES)})"):
            for name in CLEARWEB_SOURCES:
                st.write(f"- `{name}`")


# --------------------------------------------------------------------------- #
# Tab 8 — Local breach DB (self-hosted index of ingested breach dumps)
# --------------------------------------------------------------------------- #

with tab_localdb:
    from local_breach_db import (
        stats as ldb_stats, ingest_file as ldb_ingest,
        check_email as ldb_check, get_credentials as ldb_creds,
        search_domain as ldb_domain, delete_breach as ldb_delete, vacuum as ldb_vacuum,
    )

    st.subheader("Local breach database")
    st.caption(
        "A SQLite index of breach dumps you've ingested yourself. Highest "
        "trust source — your own data. The DB sits at "
        f"`{Path(__file__).parent / 'data' / 'breaches.db'}`. "
        "Possession of breach data for security research / personal account "
        "monitoring is legal in most jurisdictions; distribution generally "
        "is not. You supply the data."
    )

    s = ldb_stats()
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Breaches", s["breach_count"])
    m2.metric("Credentials", f"{s['credential_count']:,}")
    m3.metric("Unique emails", f"{s['unique_emails']:,}")
    m4.metric("DB size", f"{s['db_size_bytes'] / 1e6:.1f} MB")

    st.markdown("### 🔍 Quick query")
    q_col1, q_col2 = st.columns([3, 1])
    q_email = q_col1.text_input(
        "Email to look up",
        placeholder="victime@example.com", label_visibility="collapsed",
        key="ldb_q_email",
    )
    show_plaintext = q_col2.checkbox("Plaintext passwords", value=False,
                                       key="ldb_plaintext")
    if q_email:
        breaches = ldb_check(q_email.strip())
        if not breaches:
            st.info(f"`{q_email}` is not in any locally-ingested breach.")
        else:
            st.error(f"`{q_email}` found in **{len(breaches)} breach(es)**:")
            for b in breaches:
                with st.container(border=True):
                    st.markdown(
                        f"**{b['breach']}** ({b['year']}) — "
                        f"`{b['data_classes']}` — "
                        f"domain `{b['domain'] or 'n/a'}`"
                    )
                    st.caption(f"Your rows: {b['your_credentials_count']} · "
                                f"Passwords present: {b['passwords_present']}")
                    if b["description"]:
                        st.caption(b["description"][:300])
            with st.expander("Show credential rows"):
                for c in ldb_creds(q_email.strip(), plaintext=show_plaintext):
                    st.code(f"[{c['breach']}/{c['year']}] "
                             f"{q_email}:{c['password']}", language="text")

    st.markdown("### 🏢 Domain enumeration")
    d_col1, d_col2 = st.columns([3, 1])
    q_domain = d_col1.text_input(
        "Domain to enumerate",
        placeholder="acme.com — every breached email at this domain",
        label_visibility="collapsed", key="ldb_q_domain",
    )
    d_limit = d_col2.number_input("Limit", 10, 1000, 50, key="ldb_q_dlimit")
    if q_domain:
        rows = ldb_domain(q_domain.strip(), limit=int(d_limit))
        if not rows:
            st.info(f"No breached email at `{q_domain}` in local DB.")
        else:
            st.success(f"{len(rows)} breached email(s) at `{q_domain}`:")
            for r in rows:
                st.markdown(
                    f"- `{r['email']}` — **{r['breach_count']}** breach(es): "
                    f"{r['breaches']}"
                )

    st.divider()
    st.markdown("### 🎯 Fetch & extract — targeted, no full retention")
    st.caption(
        "Workflow: provide a URL pointing at a breach dump, give a watchlist "
        "(emails OR `@domain` patterns), Argus downloads, scans line-by-line, "
        "keeps **only** the matching credentials, then **securely deletes** "
        "the source dump (zero-overwrite + unlink). The full dump never "
        "stays on disk. Use Tor for `.onion` URLs."
    )
    with st.form("fetch_extract_form", clear_on_submit=False):
        fx_url = st.text_input(
            "Source URL",
            placeholder="https://… or http://…onion/dump.txt",
            key="fx_url",
        )
        fx_watchlist = st.text_area(
            "Watchlist (one per line — email or @domain or bare domain)",
            placeholder=("victime@example.com\n"
                          "@acme.com\n"
                          "yourcompany.com"),
            key="fx_watchlist", height=90,
        )
        fc1, fc2, fc3 = st.columns(3)
        fx_breach = fc1.text_input("Breach name", placeholder="Naz.API_2023",
                                     key="fx_breach")
        fx_year = fc2.number_input("Year", min_value=1990, max_value=2100,
                                     value=2024, key="fx_year")
        fx_max_mb = fc3.number_input("Max size (MB)", min_value=1,
                                       max_value=200_000, value=5000,
                                       key="fx_max_mb")
        fc4, fc5, fc6 = st.columns(3)
        fx_tor = fc4.checkbox("Route via Tor (SOCKS5h)", value=False, key="fx_tor")
        fx_passes = fc5.number_input("Secure-delete passes", min_value=1,
                                       max_value=7, value=1, key="fx_passes")
        fx_purge_ack = fc6.checkbox(
            "I confirm I am authorized to access this URL",
            value=False, key="fx_ack",
        )
        do_fetch = st.form_submit_button(
            "🎯 Fetch → extract → purge", type="primary",
            use_container_width=True,
        )

    if do_fetch:
        if not fx_url or not fx_watchlist or not fx_breach:
            st.error("URL, watchlist, and breach name are required.")
        elif not fx_purge_ack:
            st.error("Check the authorization box to proceed.")
        else:
            from local_breach_db import fetch_and_extract
            wl = [w.strip() for w in fx_watchlist.splitlines() if w.strip()]
            progress = st.empty()

            def _on_progress(report):
                progress.caption(
                    f"… {report.bytes_downloaded/1e6:.1f} MB · "
                    f"{report.lines_scanned:,} scanned · "
                    f"{report.lines_matched:,} matched"
                )

            with st.spinner(
                f"Fetching via {'Tor' if fx_tor else 'clearnet'}, "
                "scanning, extracting matches, purging source..."
            ):
                report = fetch_and_extract(
                    fx_url.strip(), breach_name=fx_breach,
                    watchlist=wl,
                    year=int(fx_year),
                    use_tor=fx_tor, max_size_mb=int(fx_max_mb),
                    secure_delete_passes=int(fx_passes),
                    progress_cb=_on_progress,
                )
            progress.empty()
            if report.error:
                st.error(f"❌ {report.error}")
                if report.purged:
                    st.caption(
                        f"Temp file was still purged via {report.purge_method}."
                    )
            else:
                st.success(
                    f"✅ Done. **{report.lines_matched:,} matching credential(s)** "
                    f"extracted from {report.bytes_downloaded/1e6:.1f} MB "
                    f"({report.lines_scanned:,} lines scanned) in "
                    f"{report.duration_s:.1f}s."
                )
                st.caption(
                    f"🗑 Source dump purged via `{report.purge_method}` — "
                    "the full dump no longer exists on disk."
                )

    st.divider()
    st.markdown("### 📥 Ingest a local breach dump")
    st.caption(
        "Upload a `.txt` / `.gz` / `.zip` file with `email:password` lines. "
        "Other separators supported: `;` `,` `|` `tab`."
    )
    with st.form("ingest_form", clear_on_submit=True):
        f_col1, f_col2 = st.columns(2)
        bname = f_col1.text_input("Breach name (unique key)",
                                    placeholder="Acme_2024_combolist", key="ldb_bname")
        byear = f_col2.number_input("Year", min_value=1990, max_value=2100,
                                      value=2024, step=1, key="ldb_byear")
        bdomain = f_col1.text_input("Affected domain (optional)",
                                      placeholder="acme.com", key="ldb_bdomain")
        bdata = f_col2.text_input("Data classes",
                                    value="emails,passwords", key="ldb_bdata")
        bdesc = st.text_area("Description (optional)", key="ldb_bdesc", height=70)
        bfile = st.file_uploader(
            "Breach dump", type=["txt", "csv", "log", "gz", "zip"],
            key="ldb_bfile",
        )
        do_ingest = st.form_submit_button("🚀 Ingest", type="primary",
                                            use_container_width=True)

    if do_ingest:
        if not bname:
            st.error("Breach name is required.")
        elif not bfile:
            st.error("Pick a file to ingest.")
        else:
            tmp_path = Path(__file__).parent / "data" / "uploads"
            tmp_path.mkdir(parents=True, exist_ok=True)
            target = tmp_path / bfile.name
            target.write_bytes(bfile.getbuffer())
            progress = st.empty()

            def _on_progress(report):
                progress.caption(
                    f"… {report.rows_inserted:,} rows ingested "
                    f"({report.lines_read:,} lines read)"
                )

            with st.spinner(f"Ingesting {bfile.name}..."):
                report = ldb_ingest(
                    str(target), breach_name=bname,
                    year=int(byear), domain=bdomain or None,
                    description=bdesc, data_classes=bdata,
                    progress_cb=_on_progress,
                )
            progress.empty()
            st.success(
                f"✅ Ingested **{report.rows_inserted:,} rows** in "
                f"{report.duration_s:.1f}s ({report.skipped:,} skipped, "
                f"{report.lines_read:,} lines read)"
            )
            try:
                target.unlink()
            except OSError:
                pass

    st.divider()
    st.markdown("### 📋 Ingested breaches")
    if not s["breaches"]:
        st.info("No breaches ingested yet. Use the form above.")
    else:
        for b in s["breaches"]:
            cols = st.columns([4, 2, 2, 1])
            cols[0].markdown(f"**{b['name']}** ({b['year']})")
            cols[1].caption(b["domain"] or "—")
            cols[2].caption(f"{b['records']:,} rows")
            if cols[3].button("🗑", key=f"ldb_del_{b['name']}",
                                help="Delete this breach"):
                ldb_delete(b["name"])
                ldb_vacuum()
                st.rerun()


# --------------------------------------------------------------------------- #
# Tab 9 — Feeds (threat-intel)
# --------------------------------------------------------------------------- #

with tab_feeds:
    import json as _json
    from feeds import (
        list_feeds as _list_feeds, add_feed as _add_feed,
        remove_feed as _remove_feed, poll_feed as _poll_feed,
        poll_all as _poll_all, recent_events as _recent_events,
        list_watchlist as _list_wl, add_watchlist as _add_wl,
        remove_watchlist as _rm_wl, BACKENDS as _FEED_BACKENDS,
    )

    st.subheader("Threat-intel feeds")
    st.caption(
        "Polled sources that ingest events (ransomware victims, MISP IOCs, "
        "TAXII indicators, internal feeds). Watchlist patterns highlight "
        "matches — perfect for monitoring your clients / your own org."
    )

    # ----- Watchlist editor (top, compact) -----
    with st.container(border=True):
        wlc1, wlc2 = st.columns([3, 1])
        wlc1.markdown("### 👁️  Watchlist")
        wlc1.caption(
            "Patterns matched against every incoming feed event "
            "(case-insensitive substring). Add company names, domains, emails."
        )
        wl = _list_wl()
        wlc2.metric("Patterns", len(wl))

        wl_col_left, wl_col_right = st.columns([3, 2])
        with wl_col_left:
            new_pattern = st.text_input(
                "Add pattern",
                placeholder="acme.com / @client.org / Acme Corp",
                key="wl_pattern", label_visibility="collapsed",
            )
            new_label = st.text_input(
                "Label (optional)", placeholder="label", key="wl_label",
                label_visibility="collapsed",
            )
            if st.button("➕ Add to watchlist", key="wl_add",
                          use_container_width=True,
                          disabled=not new_pattern):
                _add_wl(new_pattern.strip(), label=new_label.strip())
                st.rerun()
        with wl_col_right:
            if wl:
                for w in wl:
                    c1, c2 = st.columns([4, 1])
                    c1.markdown(
                        f"`{w['pattern']}`"
                        + (f" — *{w['label']}*" if w['label'] else "")
                    )
                    if c2.button("🗑", key=f"wl_rm_{w['id']}",
                                   help="Remove"):
                        _rm_wl(w['id'])
                        st.rerun()
            else:
                st.caption("No patterns yet.")

    st.divider()

    # ----- Feeds: list + poll -----
    feeds_now = _list_feeds()
    fc1, fc2, fc3 = st.columns(3)
    fc1.metric("Feeds configured", len(feeds_now))
    enabled = sum(1 for f in feeds_now if f["enabled"])
    fc2.metric("Enabled", enabled)
    matched_count = len(_recent_events(limit=500, only_matched=True))
    fc3.metric("Matched events", matched_count)

    if st.button("🔄 Poll all enabled feeds NOW", type="primary",
                  use_container_width=True):
        with st.spinner("Polling feeds..."):
            reports = _poll_all()
        if not reports:
            st.info("No enabled feeds to poll.")
        for r in reports:
            if r.error:
                st.error(f"[{r.feed_id}] {r.error}")
            else:
                st.success(
                    f"[{r.feed_id}] fetched={r.fetched} "
                    f"new={r.new_events} matched={r.matched_events} "
                    f"({r.duration_s:.1f}s)"
                )

    st.markdown("### Configured feeds")
    if not feeds_now:
        st.info("No feeds yet. Use the form below to add one.")
    for f in feeds_now:
        with st.container(border=True):
            ch, ci, ce = st.columns([3, 2, 1])
            ch.markdown(
                f"**{f['display'] or f['id']}** — `{f['id']}` "
                f"({f['kind']})"
            )
            ci.caption(
                f"Last poll: {f['last_poll'] or 'never'} · "
                f"Events last run: {f['last_event_count']}"
            )
            if f["last_error"]:
                ch.caption(f"⚠ {f['last_error']}")
            ce_col1, ce_col2 = ce.columns(2)
            if ce_col1.button("Poll", key=f"poll_{f['id']}"):
                with st.spinner(f"Polling {f['id']}..."):
                    r = _poll_feed(f["id"])
                if r.error:
                    st.error(str(r))
                else:
                    st.success(str(r))
                    st.rerun()
            if ce_col2.button("🗑", key=f"rm_feed_{f['id']}",
                                help="Remove"):
                _remove_feed(f["id"])
                st.rerun()
            with st.expander("Config (JSON)"):
                st.code(_json.dumps(f["config"], indent=2), language="json")

    st.divider()
    st.markdown("### ➕ Add / update a feed")
    with st.form("add_feed_form", clear_on_submit=False):
        af1, af2 = st.columns(2)
        af_id = af1.text_input("Feed ID (unique)",
                                  placeholder="rw-public / misp-soc / intel471",
                                  key="af_id")
        af_kind = af2.selectbox("Backend kind",
                                   options=list(_FEED_BACKENDS.keys()),
                                   key="af_kind")
        af_display = st.text_input("Display label", key="af_display")

        # Show a sensible default config template per kind
        templates = {
            "ransomware-monitor": {
                "endpoint": "https://api.ransomware.live/v2/recentvictims",
                "max_age_days": 30,
            },
            "misp": {
                "base_url": "https://your-misp.internal/",
                "api_key": "PASTE_MISP_API_KEY",
                "limit": 100,
                "verify_tls": True,
            },
            "taxii": {
                "api_root": "https://taxii.example.com/api1/",
                "collection_id": "PASTE_UUID",
                "api_key": "",
                "verify_tls": True,
            },
            "rest": {
                "url": "https://your-feed.example.com/breaches?since={since}",
                "method": "GET",
                "auth_header": "Bearer YOUR_TOKEN",
                "items_path": "data.items",
                "match_fields": ["victim", "domain", "email"],
                "event_type": "rest-event",
                "cursor_field": "timestamp",
                "verify_tls": True,
            },
            "forum-html": {
                "_comment": (
                    "Replace base_url, list_path, and selectors with your "
                    "target forum's actual values. Acquire session_cookies "
                    "by logging in manually then copy from browser DevTools."
                ),
                "base_url": "http://CHANGE_ME.onion",
                "list_path": "/Forum-Leaks",
                "needs_tor": True,
                "session_cookies": {"session_id": "PASTE_FROM_BROWSER"},
                "item_selector": "tr.inline_row",
                "title_selector": "span.subject_new a, span.subject_old a",
                "link_attr": "href",
                "date_selector": "span.lastpost.smalltext",
                "author_selector": "span.author a",
                "max_items": 30,
                "event_type": "forum-thread",
            },
            "telegram-channels": {
                "channels": [
                    "BradMaxLogs", "ULP_combolist", "leakbase",
                ],
                "max_per_channel": 30,
                "event_type": "telegram-post",
            },
        }
        default_cfg = _json.dumps(templates.get(af_kind, {}), indent=2)

        # Op guidance for the dark-forum backend
        if af_kind == "forum-html":
            st.warning(
                "**Operational guidance for forum-html.** This backend does "
                "not bypass authentication or CAPTCHAs. It expects you to:\n"
                "1. **Run Argus from an opsec-appropriate environment** "
                "(isolated VM, residential proxy, fresh Tor circuit). Your "
                "machine's IP/fingerprint will appear in the forum's logs.\n"
                "2. **Acquire `session_cookies` manually** — log in once "
                "from your isolated env, copy the relevant cookies from "
                "browser DevTools (Network tab → Request Headers → Cookie).\n"
                "3. **Adjust CSS selectors** per forum — BreachForums, "
                "Cracked.io, Nulled.to, Exposed.vc each use different HTML.\n"
                "4. **Keep poll cadence low** (every 30-60 min) to avoid "
                "rate-limiting and not stand out in their access logs.\n"
                "5. **Honeypot risk**: at least one current BreachForums "
                "mirror is widely suspected to be LE-monitored. Use a "
                "throwaway account, not your professional persona."
            )
        if af_kind == "telegram-channels":
            st.info(
                "**Telegram channels backend.** Uses the public `t.me/s/` "
                "preview endpoint — no Telegram API key needed. Best for "
                "monitoring stealer-log resellers and breach announcers who "
                "post publicly. For private channels you'd need the full "
                "Telethon SDK (not in Argus)."
            )
        af_config = st.text_area(
            "Config (JSON)", value=default_cfg,
            key=f"af_config_{af_kind}", height=200,
        )
        af_enabled = st.checkbox("Enabled", value=True, key="af_enabled")
        do_save = st.form_submit_button("💾 Save feed",
                                            type="primary",
                                            use_container_width=True)

    if do_save and af_id:
        try:
            cfg = _json.loads(af_config)
            _add_feed(af_id.strip(), af_kind, display=af_display.strip(),
                      config=cfg, enabled=af_enabled)
            st.success(f"Feed `{af_id}` saved.")
            st.rerun()
        except _json.JSONDecodeError as e:
            st.error(f"Invalid JSON: {e}")
        except Exception as e:
            st.exception(e)

    st.divider()
    st.markdown("### Recent events")
    rec_c1, rec_c2 = st.columns([1, 3])
    only_matched = rec_c1.checkbox("Only matched", value=True,
                                      key="rec_only_matched")
    rec_limit = rec_c2.slider("How many", 10, 200, 30, key="rec_limit")
    events = _recent_events(limit=int(rec_limit), only_matched=only_matched)
    if not events:
        st.info(
            "No events to show. Poll a feed first, or untick 'Only matched'."
        )
    for e in events:
        marker = "🚨" if e["matched_watchlist"] else "·"
        ts = (e["timestamp"] or "")[:19]
        with st.container(border=True):
            header = (f"{marker} **[{ts}]** `{e['feed_id']}` "
                      f"_{e['event_type']}_")
            if e["matched_pattern"]:
                header += f" — match `{e['matched_pattern']}`"
            st.markdown(header)
            pl = e["payload"] or {}
            if isinstance(pl, dict):
                # Surface key fields if present
                for k in ("victim", "group", "value", "type", "name",
                          "post_url", "url", "event_info", "description"):
                    if pl.get(k):
                        st.markdown(f"  - **{k}**: {str(pl[k])[:300]}")


# --------------------------------------------------------------------------- #
# Tab 10 — Connectors (LLM accounts)
# --------------------------------------------------------------------------- #

with tab_conn:
    st.subheader("Sign in to AI providers")
    st.caption(
        "Connect your subscription accounts the same way VSCode or Continue do — "
        "by signing in once with the provider's CLI. No API key to manage."
    )

    # --------------------------------------------------------------------- #
    # PRIMARY — CLI sign-in connectors
    # --------------------------------------------------------------------- #

    for c in CLI_CONNECTORS:
        st_c = cli_connector_status(c)
        with st.container(border=True):
            head, badge = st.columns([5, 1])
            head.markdown(f"### {c.display}")
            head.caption(c.description)

            if not st_c["installed"]:
                badge.markdown(
                    "<span style='background:#5a3a1f;color:#fbb24f;"
                    "padding:4px 12px;border-radius:12px;font-size:0.85rem;'>"
                    "⬇ Not installed</span>",
                    unsafe_allow_html=True,
                )
            elif st_c["logged_in"]:
                badge.markdown(
                    "<span style='background:#1f7a3a;color:white;"
                    "padding:4px 12px;border-radius:12px;font-size:0.85rem;'>"
                    "✓ Signed in</span>",
                    unsafe_allow_html=True,
                )
            else:
                badge.markdown(
                    "<span style='background:#5a1f1f;color:#ff9b9b;"
                    "padding:4px 12px;border-radius:12px;font-size:0.85rem;'>"
                    "○ Not signed in</span>",
                    unsafe_allow_html=True,
                )

            st.caption(f"Status: {st_c['msg']}")

            if not st_c["installed"]:
                st.markdown("**1. Install the CLI**")
                st.code(c.install_cmd, language="bash")
                st.caption(f"Docs: [{c.install_doc_url}]({c.install_doc_url})")
                if st.button("🔄 I've installed it, re-check", key=f"recheck_inst_{c.id}"):
                    st.rerun()
            elif not st_c["logged_in"]:
                st.markdown("**Sign in** — run this command in your terminal:")
                st.code(c.login_cmd, language="bash")
                st.caption(
                    "A browser window will open for OAuth. After you finish, "
                    "click the re-check button below."
                )
                col_a, col_b = st.columns(2)
                if col_a.button("🔄 I've signed in, re-check", key=f"recheck_login_{c.id}",
                                  type="primary", use_container_width=True):
                    st.rerun()
                if col_b.button("🧪 Test connection now", key=f"test_now_{c.id}",
                                  use_container_width=True):
                    with st.spinner(f"Testing {c.display}..."):
                        result = test_cli_connector(c.id)
                    if result["ok"]:
                        st.success(result["msg"])
                    else:
                        st.error(result["msg"])
            else:
                col_a, col_b = st.columns(2)
                if col_a.button("🧪 Test connection", key=f"test_cli_{c.id}",
                                  use_container_width=True):
                    with st.spinner(f"Testing {c.display}..."):
                        result = test_cli_connector(c.id)
                    if result["ok"]:
                        st.success(result["msg"])
                    else:
                        st.error(result["msg"])
                if c.logout_cmd:
                    with col_b.expander("Disconnect"):
                        st.markdown("Run this in your terminal to sign out:")
                        st.code(c.logout_cmd, language="bash")
                        if st.button("🔄 I've signed out, re-check",
                                      key=f"recheck_logout_{c.id}"):
                            st.rerun()

    st.divider()

    # --------------------------------------------------------------------- #
    # ADVANCED — raw API keys (collapsed by default)
    # --------------------------------------------------------------------- #

    status = current_status()
    n_keys = sum(1 for s in status.values() if s["configured"])
    with st.expander(
        f"⚙️  Advanced — raw API keys ({n_keys}/{len(PROVIDERS)} configured)",
        expanded=False,
    ):
        st.caption(
            "Only needed if you don't want to use a CLI subscription. Keys are "
            f"stored locally in `{Path(__file__).parent / '.env'}` and never "
            "transmitted except to the provider you're authenticating with."
        )
        for p in PROVIDERS:
            st_p = status[p.key_env]
            with st.container(border=True):
                head_col, badge_col = st.columns([5, 1])
                head_col.markdown(f"**{p.display}**")
                if st_p["configured"]:
                    badge_col.markdown(
                        "<span style='background:#1f7a3a;color:white;"
                        "padding:3px 10px;border-radius:10px;font-size:0.8rem;'>"
                        "✓ Set</span>",
                        unsafe_allow_html=True,
                    )
                if st_p["configured"]:
                    st.caption(f"Current key: `{st_p['masked']}`")
                st.caption(f"Unlocks: {', '.join(p.models_unlocked)}")
                if p.docs_url:
                    st.caption(f"Get a key: [{p.docs_url}]({p.docs_url})")
                key_input = st.text_input(
                    "API key", type="password",
                    placeholder="Paste key to update" if st_p["configured"]
                                else "sk-... / sk-ant-... / ...",
                    key=f"key_input_{p.key_env}",
                    label_visibility="collapsed",
                )
                c_test, c_save, c_clear = st.columns(3)
                if c_test.button("🧪 Test", key=f"test_{p.key_env}",
                                   use_container_width=True,
                                   disabled=not key_input):
                    with st.spinner(f"Testing {p.display}..."):
                        result = test_provider(p.key_env, key_input)
                    if result["ok"]:
                        st.success(result["msg"])
                    else:
                        st.error(result["msg"])
                if c_save.button("💾 Save", key=f"save_{p.key_env}", type="primary",
                                   use_container_width=True,
                                   disabled=not key_input):
                    save_keys({p.key_env: key_input})
                    st.success("Saved to .env.")
                    st.rerun()
                if c_clear.button("🗑  Remove", key=f"clear_{p.key_env}",
                                    use_container_width=True,
                                    disabled=not st_p["configured"]):
                    clear_key(p.key_env)
                    st.warning(f"{p.display} key removed.")
                    st.rerun()
