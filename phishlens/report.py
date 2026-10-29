"""Turn results into Markdown, JSON and a copy-paste list of indicators."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from .parser import defang

_IP = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def extract_iocs(a: dict) -> dict:
    """Indicators of compromise, defanged so they are safe to share."""
    domains, ips = set(), set()
    for d in (a["from"]["domain"], a["reply_to"]["domain"], a["return_path"]["domain"]):
        if d:
            domains.add(d)
    for u in a["urls"]:
        if u["host"]:
            (ips if _IP.match(u["host"]) else domains).add(u["host"])
    if a.get("origin_ip"):
        ips.add(a["origin_ip"])
    return {
        "urls": [u["defanged"] for u in a["urls"]],
        "domains": sorted(defang(d) for d in domains),
        "ips": sorted(defang(i) for i in ips),
        "sha256": [t["sha256"] for t in a["attachments"]],
    }


def iocs_text(a: dict) -> str:
    iocs = extract_iocs(a)
    lines = ["Indicators from %s" % a["file"], ""]
    for title, key in (("URLs", "urls"), ("Domains", "domains"), ("IP addresses", "ips"), ("File hashes (SHA256)", "sha256")):
        if iocs[key]:
            lines += [title] + ["  " + v for v in iocs[key]] + [""]
    return "\n".join(lines).rstrip() + "\n"


def to_json(a: dict, result: dict, intel: dict | None) -> str:
    return json.dumps({"analysis": a, "risk": result, "intel": intel, "iocs": extract_iocs(a)}, indent=2)


def to_markdown(a: dict, result: dict, intel: dict | None) -> str:
    L: list[str] = []
    L.append("# PhishLens report: %s" % a["file"])
    L.append("_Generated %s_\n" % datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    L.append("## Verdict: **%s** (score %d/100)\n" % (result["level"], result["score"]))
    L.append(result["summary"] + "\n")

    L.append("## What raised the score")
    if result["findings"]:
        L += ["| Points | Finding | MITRE ATT&CK |", "|---|---|---|"]
        L += ["| +%d | %s | %s |" % (f["points"], f["reason"], f["attack"]) for f in result["findings"]]
    else:
        L.append("Nothing suspicious was found.")

    au = a["auth"]
    L.append("\n## Sender")
    L.append("- **Subject:** %s" % (a["subject"] or "-"))
    L.append("- **From:** %s <%s>" % (a["from"]["display"], a["from"]["address"]))
    L.append("- **Reply-To:** %s" % (a["reply_to"]["address"] or "-"))
    L.append("- **Return-Path:** %s" % (a["return_path"]["address"] or "-"))
    L.append("- **SPF / DKIM / DMARC:** %s / %s / %s" % (au["spf"], au["dkim"], au["dmarc"]))
    origin = a["origin_ip"] or ("%s (reserved range)" % a["origin_ip_reserved"] if a["origin_ip_reserved"] else "not found")
    L.append("- **Origin IP:** %s" % origin)

    L.append("\n## Links")
    if a["urls"]:
        for u in a["urls"]:
            shown = " (shown as `%s`)" % u["text"] if u["text"] else ""
            L.append("- `%s`%s" % (u["defanged"], shown))
    else:
        L.append("None.")

    L.append("\n## Attachments")
    if a["attachments"]:
        for t in a["attachments"]:
            L.append("- `%s` | %s | %d bytes | SHA256 `%s`" % (t["filename"], t["content_type"], t["size"], t["sha256"]))
    else:
        L.append("None.")

    if intel:
        L.append("\n## Threat intelligence")
        L += ["- " + r for r in intel["results"]]
        L += ["- _%s_" % n for n in intel["notes"]]

    L.append("\n## Suggested next steps")
    if result["level"] in ("HIGH", "CRITICAL"):
        L += ["- Do not click links or open attachments.",
              "- Block the sender domain and the listed URLs and hashes.",
              "- Search mailboxes for the same subject or sender and remove copies.",
              "- Tell anyone who opened it and report it to your security team."]
    elif result["level"] == "MEDIUM":
        L += ["- Confirm with the sender through another channel.",
              "- Run links and attachments through a sandbox before opening."]
    else:
        L.append("- No action needed beyond normal caution.")

    L.append("\n---\n_PhishLens is a heuristic tool. A low score does not guarantee an email is safe._")
    return "\n".join(L)
