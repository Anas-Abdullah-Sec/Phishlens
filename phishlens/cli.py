"""Command line: `phishlens analyze FILE` and `phishlens gui`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .engine import run
from .report import to_json

COMMANDS = {"analyze", "gui"}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishlens",
        description="Check a suspicious email (.eml) and see why it looks safe or dangerous.",
        epilog="Tip: `phishlens email.eml` is shorthand for `phishlens analyze email.eml`.",
    )
    p.add_argument("--version", action="version", version="PhishLens " + __version__)
    sub = p.add_subparsers(dest="command", metavar="{analyze,gui}")

    a = sub.add_parser("analyze", help="analyze one .eml file and print a report")
    a.add_argument("eml", help="path to the .eml file")
    a.add_argument("-o", "--output", help="write the report to this file instead of printing it")
    a.add_argument("--format", choices=["md", "json"], default="md", help="report format (default: md)")
    a.add_argument("--no-intel", action="store_true", help="skip VirusTotal / AbuseIPDB lookups")
    a.add_argument("--max-lookups", type=int, default=4, help="maximum VirusTotal lookups (default: 4)")

    g = sub.add_parser("gui", help="open the PhishLens window in your browser")
    g.add_argument("--port", type=int, default=8765, help="port to listen on (default: 8765)")
    g.add_argument("--no-browser", action="store_true", help="do not open the browser automatically")
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    for stream in (sys.stdout, sys.stderr):  # Windows consoles choke on unusual characters in subjects
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    if argv and argv[0] not in COMMANDS and not argv[0].startswith("-"):
        argv.insert(0, "analyze")  # allow `phishlens email.eml`

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "gui":
        from .server import serve
        serve(port=args.port, open_browser=not args.no_browser)
        return 0

    if args.command == "analyze":
        path = Path(args.eml)
        if not path.is_file():
            print("Error: file not found: %s" % args.eml, file=sys.stderr)
            return 1
        result = run(path.read_bytes(), path.name, use_intel=not args.no_intel, max_lookups=args.max_lookups)
        if args.format == "json":
            text = to_json(result["analysis"], result["risk"], result["intel"])
        else:
            text = result["report_md"]
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
            print("Report saved to %s (%s, score %d)" % (args.output, result["risk"]["level"], result["risk"]["score"]))
        else:
            print(text)
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
