"""
Pivot / investigation engine.

Starting from a seed PII value (email, domain, username, ...), runs
`pii_lookup()` then automatically extracts new pivot candidates from the
returned traces and re-investigates them until a depth/node budget is hit.

Returns a tree of PivotNode that the CLI/UI can walk to render the
investigation graph.

Pivot rules implemented:

  email      -> domain  (the email's domain)
             -> username (the localpart, when it looks like one)
  domain     -> subdomains (each becomes a domain node)
             -> employee URLs from HudsonRock (each yields a host)
  username   -> linked profiles (from Gravatar / Keybase / linked accounts)
  hash       -> related malware family (no further pivot for now)
  btc        -> recipient addresses on first txs (skipped by default - too noisy)
  ip         -> reverse DNS (a domain node)
  name       -> none (we don't auto-pivot ambiguous names)
  url        -> host extracted into a domain node

All pivots respect a `(kind, value)` seen-set to avoid cycles, and depth +
node caps so an investigation never explodes.
"""

from __future__ import annotations

import logging
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from pii_lookup import lookup as pii_lookup, detect_type

log = logging.getLogger(__name__)


@dataclass
class PivotNode:
    kind: str
    value: str
    depth: int = 0
    parent: Optional["PivotNode"] = None
    reason: str = "seed"           # why we explored this node (for the tree label)
    traces: List[Dict] = field(default_factory=list)
    probes_checked: int = 0
    probes_with_hits: int = 0
    pivoted_to: List["PivotNode"] = field(default_factory=list)

    def signature(self) -> Tuple[str, str]:
        return (self.kind, self.value.lower().strip())


def _domain_from_email(email: str) -> Optional[str]:
    if "@" in email:
        d = email.split("@", 1)[-1].strip().lower()
        if "." in d:
            return d
    return None


def _username_from_email(email: str) -> Optional[str]:
    if "@" not in email:
        return None
    local = email.split("@", 1)[0]
    # Sherlock-style usernames must be plain identifier-like
    if re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", local):
        return local
    return None


def _host_from_url(url: str) -> Optional[str]:
    try:
        p = urlparse(url)
        host = p.netloc or p.path
        host = host.split(":", 1)[0]
        if "." in host and not host.endswith(".onion"):
            return host.lower()
    except Exception:
        pass
    return None


def _extract_pivots(node: PivotNode) -> List[PivotNode]:
    """Decide what new nodes to spawn from a node's traces."""
    children: List[PivotNode] = []

    def add(kind: str, value: str, reason: str):
        children.append(PivotNode(
            kind=kind, value=value,
            depth=node.depth + 1, parent=node, reason=reason,
        ))

    # 1. Universal: from email seeds, pivot to the domain and the local username
    if node.kind == "email":
        d = _domain_from_email(node.value)
        if d:
            add("domain", d, f"email -> domain")
        u = _username_from_email(node.value)
        if u:
            add("username", u, f"email -> username (localpart)")

    # 2. From URL seeds, pivot to host
    if node.kind == "url":
        h = _host_from_url(node.value)
        if h:
            add("domain", h, "url -> host")

    # 3. Mining the traces for additional pivot candidates
    for trace in node.traces or []:
        source = (trace.get("source") or "").lower()
        details = trace.get("details") or {}

        # 3a. Gravatar returns linked accounts → username pivots
        linked = details.get("linked_accounts") if isinstance(details, dict) else None
        if linked:
            for url in linked[:5]:
                u = _username_from_linked_url(url)
                if u:
                    add("username", u, f"gravatar linked account ({url})")

        # 3b. crt.sh / domain enrich returns subdomains → domain pivots
        sample_subs = details.get("sample") if isinstance(details, dict) else None
        if sample_subs and "crt" in source:
            for sub in sample_subs[:5]:
                if isinstance(sub, str) and "." in sub:
                    add("domain", sub, "crt.sh subdomain")

        # 3c. HudsonRock domain returns compromised internal URLs → domain pivots
        hr_hits = details if isinstance(details, list) else None
        if "hudsonrock" in source and hr_hits:
            seen_hosts: Set[str] = set()
            for h in hr_hits:
                url = (h.get("link") or "") if isinstance(h, dict) else ""
                host = _host_from_url(url)
                if host and host not in seen_hosts:
                    seen_hosts.add(host)
                    add("domain", host, "hudsonrock compromised asset")

        # 3d. Dark-web / Telegram raw hits sometimes embed pivotable strings
        extra_hits = details.get("hits") if isinstance(details, dict) else None
        if extra_hits and ("darkweb" in source or "telegram" in source.lower()):
            for h in extra_hits[:5]:
                raw = (h.get("raw") or "") if isinstance(h, dict) else ""
                # Extract emails from raw text
                for em in re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,24}", raw)[:3]:
                    if em.lower() != node.value.lower():
                        add("email", em, f"raw match in {source}")
                # Extract domains
                for dom in re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", raw, re.I)[:3]:
                    dom = dom.lower()
                    if dom != node.value.lower() and "@" not in dom:
                        add("domain", dom, f"raw match in {source}")

    return children


def _username_from_linked_url(url: str) -> Optional[str]:
    """Best-effort: pull the username from common social URLs."""
    if not isinstance(url, str):
        return None
    patterns = [
        r"github\.com/([A-Za-z0-9._-]{2,32})",
        r"twitter\.com/([A-Za-z0-9_]{3,15})",
        r"x\.com/([A-Za-z0-9_]{3,15})",
        r"reddit\.com/user/([A-Za-z0-9_-]{3,32})",
        r"keybase\.io/([A-Za-z0-9_]{3,32})",
        r"linkedin\.com/in/([A-Za-z0-9-]{3,64})",
        r"t\.me/([A-Za-z0-9_]{5,32})",
        r"instagram\.com/([A-Za-z0-9_.]{3,30})",
    ]
    for p in patterns:
        m = re.search(p, url)
        if m:
            return m.group(1)
    return None


def investigate(
    seed: str,
    max_depth: int = 2,
    max_nodes: int = 25,
    kind: Optional[str] = None,
) -> PivotNode:
    """BFS pivot exploration starting from `seed`.

    Returns the root PivotNode with `.pivoted_to` populated recursively.
    """
    root = PivotNode(
        kind=kind or detect_type(seed), value=seed, depth=0, reason="seed",
    )
    seen: Set[Tuple[str, str]] = {root.signature()}
    queue: deque = deque([root])
    node_count = 1

    while queue and node_count < max_nodes:
        node = queue.popleft()
        if node.depth > max_depth:
            continue
        if node.kind == "unknown":
            continue

        log.info("Investigating depth=%d %s:%s (%s)", node.depth, node.kind, node.value[:60], node.reason)
        try:
            result = pii_lookup(node.value, kind=node.kind)
        except Exception as e:
            log.warning("lookup failed for %s:%s — %s", node.kind, node.value, e)
            result = {"traces": [], "probes_checked": 0, "probes_with_hits": 0}

        node.traces = result.get("traces") or []
        node.probes_checked = result.get("probes_checked", 0)
        node.probes_with_hits = result.get("probes_with_hits", 0)

        if node.depth >= max_depth:
            continue

        for child in _extract_pivots(node):
            sig = child.signature()
            if sig in seen:
                continue
            if not child.value or len(child.value) > 253:
                continue
            seen.add(sig)
            node.pivoted_to.append(child)
            queue.append(child)
            node_count += 1
            if node_count >= max_nodes:
                break

    return root


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def render_tree(root: PivotNode, indent: int = 0) -> str:
    """ASCII tree of the investigation. Each node shows hits/probes counts."""
    pad = "  " * indent
    line = (
        f"{pad}[{root.kind}] {root.value}  "
        f"({root.probes_with_hits}/{root.probes_checked} hits"
        f"{', via ' + root.reason if root.reason != 'seed' else ''})"
    )
    blocks = [line]
    # Show top 3 trace summaries for this node
    hits = [t for t in (root.traces or []) if t.get("found")]
    for t in hits[:3]:
        blocks.append(f"{pad}  ✓ {t.get('source','')}: {t.get('summary','')[:120]}")
    if len(hits) > 3:
        blocks.append(f"{pad}  … {len(hits) - 3} more hits")
    for child in root.pivoted_to:
        blocks.append(render_tree(child, indent + 1))
    return "\n".join(blocks)


def flatten(root: PivotNode) -> List[PivotNode]:
    """DFS flatten the tree."""
    out: List[PivotNode] = []
    stack = [root]
    while stack:
        n = stack.pop()
        out.append(n)
        stack.extend(reversed(n.pivoted_to))
    return out


def to_dict(root: PivotNode) -> Dict:
    """Serialize tree to JSON-friendly dict."""
    return {
        "kind": root.kind,
        "value": root.value,
        "depth": root.depth,
        "reason": root.reason,
        "probes_checked": root.probes_checked,
        "probes_with_hits": root.probes_with_hits,
        "traces": root.traces,
        "pivoted_to": [to_dict(c) for c in root.pivoted_to],
    }


def summary_stats(root: PivotNode) -> Dict:
    nodes = flatten(root)
    return {
        "total_nodes": len(nodes),
        "max_depth": max(n.depth for n in nodes),
        "by_kind": {
            k: sum(1 for n in nodes if n.kind == k)
            for k in {n.kind for n in nodes}
        },
        "total_hits": sum(n.probes_with_hits for n in nodes),
        "nodes_with_hits": sum(1 for n in nodes if n.probes_with_hits > 0),
    }
