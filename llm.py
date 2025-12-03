import re
import openai
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from llm_utils import _common_llm_params, resolve_model_config, get_model_choices
from config import OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY
import logging
import re

import warnings

warnings.filterwarnings("ignore")


def get_llm(model_choice):
    # Look up the configuration (cloud or local Ollama)
    config = resolve_model_config(model_choice)

    if config is None:  # Extra error check
        supported_models = get_model_choices()
        raise ValueError(
            f"Unsupported LLM model: '{model_choice}'. "
            f"Supported models (case-insensitive match) are: {', '.join(supported_models)}"
        )

    # Extract the necessary information from the configuration
    llm_class = config["class"]
    model_specific_params = config["constructor_params"]

    # Combine common parameters with model-specific parameters
    # Model-specific parameters will override common ones if there are any conflicts
    all_params = {**_common_llm_params, **model_specific_params}

    # Create the LLM instance using the gathered parameters
    llm_instance = llm_class(**all_params)

    return llm_instance


def refine_query(llm, user_input):
    system_prompt = """
    You are a Cybercrime Threat Intelligence Expert. Your task is to refine the provided user query for darkweb search engines with a strict focus on data breaches and forum discussions about the target.

    Rules:
    1. Preserve the core entity or keyword from the user input.
    2. Add or swap in terms that emphasize leaks, dumps, data breaches, or forum/thread discussions (e.g., "data breach", "leak", "dump", "forum", "discussion").
    3. Do NOT use logical operators (AND, OR, etc.) or quotes.
    4. Keep the query short (under 8 words) and output only the refined query text.

    INPUT:
    """
    prompt_template = ChatPromptTemplate(
        [("system", system_prompt), ("user", "{query}")]
    )
    chain = prompt_template | llm | StrOutputParser()
    refined = chain.invoke({"query": user_input})

    # Ensure breach/forum intent even if the LLM keeps the query too short
    focus_terms = ["breach", "leak", "dump", "forum", "discussion"]
    if not any(term in refined.lower() for term in focus_terms):
        refined = f"{refined} data breach leak forum"

    return refined


def filter_results(llm, query, results):
    if not results:
        return []

    system_prompt = """
    You are a Cybercrime Threat Intelligence Expert. You are given a dark web search query and a list of search results in the form of index, link and title.
    Your job is to pick only results that look like data breaches, leak dumps, or forum/thread discussions about the query.
    Rules:
    1. Prefer forum threads, discussion boards, paste sites, and breach/dump announcements. Avoid generic marketplaces or unrelated content.
    2. Output ONLY the indices (comma-separated) for at most the top 20 relevant results.

    Search Query: {query}
    Search Results:
    """

    final_str = _generate_final_string(results)

    prompt_template = ChatPromptTemplate(
        [("system", system_prompt), ("user", "{results}")]
    )
    chain = prompt_template | llm | StrOutputParser()
    try:
        result_indices = chain.invoke({"query": query, "results": final_str})
    except openai.RateLimitError as e:
        print(
            f"Rate limit error: {e} \n Truncating to Web titles only with 30 characters"
        )
        final_str = _generate_final_string(results, truncate=True)
        result_indices = chain.invoke({"query": query, "results": final_str})

    # Select top_k results using original (non-truncated) results
    parsed_indices = []
    for match in re.findall(r"\d+", result_indices):
        try:
            idx = int(match)
            if 1 <= idx <= len(results):
                parsed_indices.append(idx)
        except ValueError:
            continue

    # Remove duplicates while preserving order
    seen = set()
    parsed_indices = [
        i for i in parsed_indices if not (i in seen or seen.add(i))
    ]

    if not parsed_indices:
        logging.warning(
            "Unable to interpret LLM result selection ('%s'). "
            "Defaulting to the top %s results.",
            result_indices,
            min(len(results), 20),
        )
        parsed_indices = list(range(1, min(len(results), 20) + 1))

    top_results = [results[i - 1] for i in parsed_indices[:20]]

    return top_results


def _generate_final_string(results, truncate=False):
    """
    Generate a formatted string from the search results for LLM processing.
    """

    if truncate:
        # Use only the first 35 characters of the title
        max_title_length = 30
        # Do not use link at all
        max_link_length = 0

    final_str = []
    for i, res in enumerate(results):
        # Truncate link at .onion for display
        truncated_link = re.sub(r"(?<=\.onion).*", "", res["link"])
        title = re.sub(r"[^0-9a-zA-Z\-\.]", " ", res["title"])
        if truncated_link == "" and title == "":
            continue

        if truncate:
            # Truncate title to max_title_length characters
            title = (
                title[:max_title_length] + "..."
                if len(title) > max_title_length
                else title
            )
            # Truncate link to max_link_length characters
            truncated_link = (
                truncated_link[:max_link_length] + "..."
                if len(truncated_link) > max_link_length
                else truncated_link
            )

        final_str.append(f"{i+1}. {truncated_link} - {title}")

    return "\n".join(s for s in final_str)


def _format_scraped_content(content):
    """
    Turn the scraped results dict into a readable string with URL context.
    """
    if not content:
        return "No content scraped."

    blocks = []
    for url, text in content.items():
        blocks.append(f"URL: {url}\nCONTENT: {text}")
    return "\n\n".join(blocks)


def _dedupe_preserve_order(items):
    seen = set()
    ordered = []
    for it in items:
        if it not in seen:
            seen.add(it)
            ordered.append(it)
    return ordered


def _extract_indicators(content):
    """
    Lightweight IOC extraction so the user sees indicators directly.
    """
    if not content:
        return {}

    text_blob = " ".join(content.values())

    emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text_blob)
    ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text_blob)
    btc = re.findall(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", text_blob)
    eth = re.findall(r"\b0x[a-fA-F0-9]{40}\b", text_blob)
    domains = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text_blob)

    # Remove emails from domains to avoid duplicates
    domain_only = [d for d in domains if d not in {e.split('@')[-1] for e in emails}]

    return {
        "emails": _dedupe_preserve_order(emails)[:50],
        "ip_addresses": _dedupe_preserve_order(ips)[:50],
        "btc_addresses": _dedupe_preserve_order(btc)[:50],
        "eth_addresses": _dedupe_preserve_order(eth)[:50],
        "domains": _dedupe_preserve_order(domain_only)[:50],
    }


def _format_indicators(indicators):
    if not indicators:
        return "No indicators were automatically extracted."

    lines = []
    for key, values in indicators.items():
        label = key.replace("_", " ").title()
        if values:
            lines.append(f"{label}: {', '.join(values)}")
    if not lines:
        return "No indicators were automatically extracted."
    return "\n".join(lines)


def build_indicator_block(content):
    """Public helper to expose extracted indicators for direct display."""
    indicators = _extract_indicators(content)
    return _format_indicators(indicators)


def generate_summary(llm, query, content):
    system_prompt = """
    You are an Cybercrime Threat Intelligence Expert tasked with generating context-based technical investigative insights from dark web OSINT search engine results.

    Rules:
    1. Focus strictly on evidence of data breaches, credential dumps, or forum/thread discussions mentioning the query.
    2. Analyze only the provided dark web OSINT data (links + raw text). Do not invent or speculate beyond it.
    3. Use the [EXTRACTED INDICATORS] block to list indicators directly; tie them to context seen in the scraped text.
    4. Output the Source Links referenced for the analysis.
    5. Provide a concise, evidence-based analysis only. If something is not present in the data, state "Not observed in provided data".
    6. Provide intelligence artifacts with context visible in the data (usernames, emails, phone numbers, crypto, domains, markets, forums, threat actor info, malware names, TTPs, etc.).
    7. Generate 3-5 factual findings based only on observed data, explicitly noting if no breach/discussion evidence is found.
    8. Do NOT include speculative next steps or guesses. No recommendations—only observed results.
    9. Ignore not safe for work texts from the analysis.

    Output Format:
    1. Input Query: {query}
    2. Source Links Referenced for Analysis - include all source links used for the analysis
    3. Investigation Artifacts - technical artifacts identified (with brief observed context)
    4. Key Findings - evidence-only statements; if absent, say "Not observed in provided data"

    Format your response in a structured way with clear section headings.

    INPUT:
    """
    formatted_content = _format_scraped_content(content)
    indicator_block = build_indicator_block(content)

    combined_input = f"[SCRAPED DATA]\n{formatted_content}\n\n[EXTRACTED INDICATORS]\n{indicator_block}"
    prompt_template = ChatPromptTemplate(
        [("system", system_prompt), ("user", "{content}")]
    )
    chain = prompt_template | llm | StrOutputParser()
    return chain.invoke({"query": query, "content": combined_input})
