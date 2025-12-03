import base64
import streamlit as st
from datetime import datetime
from scrape import scrape_multiple, filter_content_by_terms
from download import download_safe_files
from search import get_search_results
from llm_utils import BufferedStreamingHandler, get_model_choices
from llm import (
    get_llm,
    refine_query,
    filter_results,
    generate_summary,
    build_indicator_block,
    extract_focus_terms,
)
from pdf_report import build_pdf_report


# Cache expensive backend calls
@st.cache_data(ttl=200, show_spinner=False)
def cached_search_results(refined_query: str, threads: int, focus_terms: list):
    return get_search_results(
        refined_query.replace(" ", "+"), max_workers=threads, focus_terms=focus_terms
    )


@st.cache_data(ttl=200, show_spinner=False)
def cached_scrape_multiple(filtered: list, threads: int):
    return scrape_multiple(filtered, max_workers=threads)


# Streamlit page configuration
st.set_page_config(
    page_title="Robin: AI-Powered Dark Web OSINT Tool",
    page_icon="🕵️‍♂️",
    initial_sidebar_state="expanded",
)

# Custom CSS for styling
st.markdown(
    """
    <style>
            .colHeight {
                max-height: 40vh;
                overflow-y: auto;
                text-align: center;
            }
            .pTitle {
                font-weight: bold;
                color: #FF4B4B;
                margin-bottom: 0.5em;
            }
            .aStyle {
                font-size: 18px;
                font-weight: bold;
                padding: 5px;
                padding-left: 0px;
                text-align: center;
            }
    </style>""",
    unsafe_allow_html=True,
)


# Sidebar
st.sidebar.title("Robin")
st.sidebar.text("AI-Powered Dark Web OSINT Tool")
st.sidebar.markdown(
    """Made by [Apurv Singh Gautam](https://www.linkedin.com/in/apurvsinghgautam/)"""
)
st.sidebar.subheader("Settings")
model_options = get_model_choices()
default_model_index = (
    next(
        (idx for idx, name in enumerate(model_options) if name.lower() == "gpt4o"),
        0,
    )
    if model_options
    else 0
)
model = st.sidebar.selectbox(
    "Select LLM Model",
    model_options,
    index=default_model_index,
    key="model_select",
)
if any(name not in {"gpt4o", "gpt-4.1", "claude-3-5-sonnet-latest", "llama3.1", "gemini-2.5-flash"} for name in model_options):
    st.sidebar.caption("Locally detected Ollama models are automatically added to this list.")
threads = st.sidebar.slider("Scraping Threads", 1, 16, 8, key="thread_slider")

download_files = st.sidebar.checkbox(
    "Télécharger les fichiers sûrs (txt/csv/json/pdf)", value=False
)
max_download_mb = st.sidebar.slider("Taille max fichier (MB)", 1, 20, 5)

# Roadmap / search history
st.sidebar.markdown("---")
st.sidebar.subheader("Roadmap des recherches")
if "roadmap" not in st.session_state:
    st.session_state.roadmap = []

def _add_to_roadmap(query: str, refined: str, filtered_count: int, indicators: str):
    preview = indicators.strip().split("\n")
    preview = preview[0] if preview else ""
    st.session_state.roadmap.insert(0, {
        "query": query,
        "refined": refined,
        "filtered": filtered_count,
        "indicators": indicators,
        "preview": preview[:140]
    })
    st.session_state.roadmap = st.session_state.roadmap[:10]

for i, item in enumerate(st.session_state.roadmap):
    with st.sidebar.expander(f"🔎 {item['query']}"):
        st.caption(f"Refined: {item['refined']}")
        st.caption(f"Résultats filtrés: {item['filtered']}")
        if item.get("preview"):
            st.text(item['preview'])
        follow = st.text_input(
            "Affiner",
            placeholder="Ajouter un détail",
            key=f"roadmap_follow_{i}"
        )
        if st.button("🔍 Relancer", key=f"roadmap_btn_{i}"):
            new_q = item['query'] if not follow else f"{item['query']} {follow}"
            st.session_state.query_input = new_q
            st.experimental_rerun()


# Main UI - logo and input
_, logo_col, _ = st.columns(3)
with logo_col:
    st.image(".github/assets/robin_logo.png", width=200)

# Display text box and button
with st.form("search_form", clear_on_submit=True):
    col_input, col_button = st.columns([10, 1])
    query = col_input.text_input(
        "Check leaks & forum discussions",
        placeholder="Ex: heliaq data breach / leak",
        label_visibility="collapsed",
        key="query_input",
    )
    run_button = col_button.form_submit_button("Run")

# Display a status message
status_slot = st.empty()
# Pre-allocate three placeholders-one per card
cols = st.columns(3)
p1, p2, p3 = [col.empty() for col in cols]
# Summary placeholders
summary_container_placeholder = st.empty()


# Process the query
if run_button and query:
    # clear old state
    for k in ["refined", "results", "filtered", "scraped", "streamed_summary"]:
        st.session_state.pop(k, None)
    focus_terms = extract_focus_terms(query)

    # Stage 1 - Load LLM
    with status_slot.container():
        with st.spinner("🔄 Loading LLM..."):
            llm = get_llm(model)

    # Stage 2 - Refine query
    with status_slot.container():
        with st.spinner("🔄 Refining query..."):
            st.session_state.refined = refine_query(llm, query)
    p1.container(border=True).markdown(
        f"<div class='colHeight'><p class='pTitle'>Refined Query</p><p>{st.session_state.refined}</p></div>",
        unsafe_allow_html=True,
    )

    # Stage 3 - Search dark web
    with status_slot.container():
        with st.spinner("🔍 Searching dark web..."):
            st.session_state.results = cached_search_results(
                st.session_state.refined, threads, focus_terms
            )
    p2.container(border=True).markdown(
        f"<div class='colHeight'><p class='pTitle'>Search Results</p><p>{len(st.session_state.results)}</p></div>",
        unsafe_allow_html=True,
    )

    # Stage 4 - Filter results
    with status_slot.container():
        with st.spinner("🗂️ Filtering results..."):
            st.session_state.filtered = filter_results(
                llm, st.session_state.refined, st.session_state.results
            )
    p3.container(border=True).markdown(
        f"<div class='colHeight'><p class='pTitle'>Filtered Results</p><p>{len(st.session_state.filtered)}</p></div>",
        unsafe_allow_html=True,
    )

    # Stage 5 - Scrape content
    with status_slot.container():
        with st.spinner("📜 Scraping content..."):
            st.session_state.scraped = cached_scrape_multiple(
                st.session_state.filtered, threads
            )
            st.session_state.scraped = filter_content_by_terms(
                st.session_state.scraped, focus_terms
            )

    # Optional safe file downloads
    downloaded = []
    if download_files:
        with status_slot.container():
            with st.spinner("⬇️ Téléchargement des fichiers sûrs..."):
                downloaded = download_safe_files(
                    st.session_state.filtered, query, max_size_mb=max_download_mb
                )
        if downloaded:
            st.success(f"{len(downloaded)} fichier(s) téléchargé(s) dans le dossier downloads/.")
            with st.expander("Fichiers téléchargés"):
                for item in downloaded:
                    st.write(
                        f"- {item['path']} ({item['bytes']} bytes) ← {item['url']}"
                    )
        else:
            st.info("Aucun fichier sûr détecté pour cette requête.")

    # Quick indicator view for the user
    indicator_block = build_indicator_block(st.session_state.scraped)
    with st.expander("Voir les indicateurs extraits (IOCs)", expanded=True):
        st.code(indicator_block, language="text")

    # Save to roadmap/history
    _add_to_roadmap(query, st.session_state.refined, len(st.session_state.filtered), indicator_block)

    # Stage 6 - Summarize
    # 6a) Prepare session state for streaming text
    st.session_state.streamed_summary = ""

    # 6c) UI callback for each chunk
    def ui_emit(chunk: str):
        st.session_state.streamed_summary += chunk
        summary_slot.markdown(st.session_state.streamed_summary)

    with summary_container_placeholder.container():  # border=True, height=450):
        hdr_col, btn_col = st.columns([4, 1], vertical_alignment="center")
        with hdr_col:
            st.subheader(":red[Investigation Summary]", anchor=None, divider="gray")
        summary_slot = st.empty()

    # 6d) Inject your two callbacks and invoke exactly as before
    with status_slot.container():
        with st.spinner("✍️ Generating summary..."):
            stream_handler = BufferedStreamingHandler(ui_callback=ui_emit)
            llm.callbacks = [stream_handler]
            _ = generate_summary(llm, query, st.session_state.scraped)

    with btn_col:
        now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        fname = f"summary_{now}.md"
        b64 = base64.b64encode(st.session_state.streamed_summary.encode()).decode()
        href = f'<div class="aStyle">📥 <a href="data:file/markdown;base64,{b64}" download="{fname}">Download</a></div>'
        st.markdown(href, unsafe_allow_html=True)

        try:
            pdf_bytes = build_pdf_report(
                query=query,
                indicators_text=indicator_block,
                summary_text=st.session_state.streamed_summary,
                sources=st.session_state.filtered,
                output_path=None,
            )
            st.download_button(
                "📄 Télécharger PDF",
                data=pdf_bytes,
                file_name=f"summary_{now}.pdf",
                mime="application/pdf",
            )
        except Exception as e:
            st.error(f"Erreur génération PDF: {e}")
    status_slot.success("✔️ Pipeline completed successfully!")
