"""Command-line interface."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .intel import enrich
from .parser import analyze_file
from .report import to_json, to_markdown
from .scoring import score_email


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="phishing-analyzer", description="Triage a .eml phishing email.")
    p.add_argument("eml", help="path to the .eml file")
    p.add_argument("-o", "--output", help="write the report to this file")
    p.add_argument("--format", choices=["md", "json"], default="md")
    p.add_argument("--no-intel", action="store_true", help="skip VirusTotal/AbuseIPDB lookups")
    p.add_argument("--max-lookups", type=int, default=4, help="max VirusTotal lookups (default 4)")
    args = p.parse_args(argv)

    if not Path(args.eml).is_file():
        print(f"Error: file not found: {args.eml}", file=sys.stderr)
        return 1

    analysis = analyze_file(args.eml)
    intel = None if args.no_intel else enrich(analysis, args.max_lookups)
    result = score_email(analysis, intel)
    report = to_json(analysis, result, intel) if args.format == "json" else to_markdown(analysis, result, intel)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"Report written to {args.output} (verdict: {result['level']}, score {result['score']})")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
