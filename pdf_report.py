from fpdf import FPDF
from typing import List, Dict, Optional
import textwrap


class _Report(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.cell(0, 10, "Robin Dark Web OSINT Report", ln=True, align="C")
        self.ln(4)


def _add_section(pdf: _Report, title: str, body: str):
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, title, ln=True)
    pdf.set_font("Helvetica", "", 11)
    for line in textwrap.wrap(body, width=100):
        pdf.cell(0, 6, line, ln=True)
    pdf.ln(4)


def _format_sources(sources: List[Dict]) -> str:
    if not sources:
        return "Aucune source listée."
    lines = []
    for item in sources:
        title = item.get("title") or "(sans titre)"
        link = item.get("link") or ""
        lines.append(f"- {title} :: {link}")
    return "\n".join(lines)


def build_pdf_report(
    query: str,
    indicators_text: str,
    summary_text: str,
    sources: Optional[List[Dict]] = None,
    output_path: Optional[str] = None,
):
    """
    Build a concise PDF report. If output_path is provided, writes to disk and returns path.
    Otherwise returns PDF bytes.
    """

    pdf = _Report()
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, f"Input Query: {query}", ln=True)
    pdf.ln(2)

    _add_section(pdf, "Source Links", _format_sources(sources or []))
    _add_section(pdf, "Indicators", indicators_text or "(aucun)")
    _add_section(pdf, "Summary", summary_text or "(vide)")

    if output_path:
        pdf.output(output_path)
        return output_path

    pdf_bytes = pdf.output(dest="S").encode("latin1")
    return pdf_bytes
