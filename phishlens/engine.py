"""One entry point used by both the command line and the web UI."""
from __future__ import annotations

from .intel import enrich
from .parser import analyze_bytes
from .report import extract_iocs, to_markdown
from .scoring import score_email


def run(data: bytes, name: str = "email.eml", use_intel: bool = False,
        vt_key: str | None = None, abuse_key: str | None = None, max_lookups: int = 4) -> dict:
    analysis = analyze_bytes(data, name)
    intel = enrich(analysis, max_lookups, vt_key, abuse_key) if use_intel else None
    risk = score_email(analysis, intel)
    return {
        "analysis": analysis,
        "risk": risk,
        "intel": intel,
        "iocs": extract_iocs(analysis),
        "report_md": to_markdown(analysis, risk, intel),
    }
