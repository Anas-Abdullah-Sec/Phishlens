"""Render results as Markdown or JSON."""
from __future__ import annotations

import json
from datetime import datetime, timezone


def to_json(a: dict, result: dict, intel: dict | None) -> str:
    return json.dumps({"analysis": a, "risk": result, "intel": intel}, indent=2)


def to_markdown(a: dict, result: dict, intel: dict | None) -> str:
    L: list[str] = []
    L.append(f"# Phishing Analysis Report: {a['file']}")
    L.append(f"_Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_\n")
    L.append(f"## Verdict: **{result['level']}** (score {result['score']}/100)\n")

    L.append("## Why")
    if result["findings"]:
        L.append("| Points | Finding | MITRE ATT&CK |")
        L.append("|---|---|---|")
        for f in result["findings"]:
            L.append(f"| +{f['points']} | {f['reason']} | {f['attack']} |")
    else:
        L.append("No suspicious indicators found.")

    L.append("\n## Headers")
    L.append(f"- **Subject:** {a['subject']}")
    L.append(f"- **From:** {a['from']['display']} <{a['from']['address']}>")
    L.append(f"- **Reply-To:** {a['reply_to']['address'] or '-'}")
    L.append(f"- **Return-Path:** {a['return_path']['address'] or '-'}")
    au = a["auth"]
    L.append(f"- **SPF / DKIM / DMARC:** {au['spf']} / {au['dkim']} / {au['dmarc']}")
    L.append(f"- **Origin IP:** {a['origin_ip'] or 'not found'}")

    L.append("\n## URLs")
    if a["urls"]:
        for u in a["urls"]:
            shown = f" (shown as: `{u['text']}`)" if u["text"] else ""
            # defang so the report is safe to open and share
            L.append(f"- `{u['url'].replace('http', 'hxxp').replace('.', '[.]')}`{shown}")
    else:
        L.append("None found.")

    L.append("\n## Attachments")
    if a["attachments"]:
        for t in a["attachments"]:
            L.append(f"- `{t['filename']}` | {t['content_type']} | {t['size']} bytes | SHA256 `{t['sha256']}`")
    else:
        L.append("None.")

    if intel:
        L.append("\n## Threat Intelligence")
        for r in intel["results"]:
            L.append(f"- {r}")
        for n in intel["notes"]:
            L.append(f"- _Note: {n}_")

    L.append("\n## Recommended actions")
    if result["level"] in ("HIGH", "CRITICAL"):
        L += ["- Do not click links or open attachments.",
              "- Block sender domain and listed URLs/hashes at the gateway.",
              "- Search mailboxes for the same subject/sender and purge.",
              "- Report to the security team and notify any recipients who interacted."]
    elif result["level"] == "MEDIUM":
        L += ["- Treat as suspicious; verify with the sender through another channel.",
              "- Submit URLs/attachments to a sandbox for further analysis."]
    else:
        L.append("- No action needed beyond normal user awareness.")

    L.append("\n---\n_Heuristic tool: a LOW score does not guarantee an email is safe._")
    return "\n".join(L)
