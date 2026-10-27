"""Rule-based risk scoring with MITRE ATT&CK mapping."""
from __future__ import annotations

import re

from .parser import DOMAIN_RE, URL_SHORTENERS, same_org

LEVELS = [(75, "CRITICAL"), (50, "HIGH"), (25, "MEDIUM"), (0, "LOW")]


def _level(score: int) -> str:
    return next(name for threshold, name in LEVELS if score >= threshold)


def score_email(a: dict, intel: dict | None = None) -> dict:
    """Return {"score", "level", "findings": [{"points","reason","attack"}]}."""
    findings: list[dict] = []

    def add(points: int, reason: str, attack: str = "T1566") -> None:
        findings.append({"points": points, "reason": reason, "attack": attack})

    auth = a["auth"]
    if auth["spf"] in ("fail", "softfail"):
        add(20, f"SPF {auth['spf']}", "T1566.001")
    if auth["dkim"] == "fail":
        add(15, "DKIM verification failed", "T1566.001")
    if auth["dmarc"] == "fail":
        add(20, "DMARC failed", "T1566.001")
    if all(v == "none" for v in auth.values()):
        add(5, "No SPF/DKIM/DMARC results found in headers")

    f, rt, rp = a["from"], a["return_path"], a["reply_to"]
    if rp["domain"] and not same_org(f["domain"], rp["domain"]):
        add(15, f"Reply-To domain ({rp['domain']}) differs from From ({f['domain']})", "T1566.001")
    if rt["domain"] and not same_org(f["domain"], rt["domain"]):
        add(10, f"Return-Path domain ({rt['domain']}) differs from From ({f['domain']})", "T1566.001")

    shown = DOMAIN_RE.search(f["display"] or "")
    if shown and not same_org(shown.group(0).lower(), f["domain"]):
        add(15, f"Display name mentions '{shown.group(0)}' but sender domain is {f['domain']}", "T1656")

    if a["mismatched_links"]:
        add(25, f"{len(a['mismatched_links'])} link(s) where visible text differs from real destination", "T1566.002")

    for u in a["urls"]:
        host = u["host"]
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
            add(15, f"URL uses a raw IP address: {host}", "T1566.002")
        elif host in URL_SHORTENERS:
            add(10, f"URL shortener used: {host}", "T1566.002")
        elif "xn--" in host:
            add(15, f"Punycode (possible homograph) domain: {host}", "T1566.002")

    for att in a["attachments"]:
        if att["double_extension"]:
            add(30, f"Double extension attachment: {att['filename']}", "T1566.001")
        elif att["risky_extension"]:
            add(25, f"Risky attachment type: {att['filename']}", "T1566.001")

    if a["urgency_hits"]:
        add(10, "Urgency/pressure language: " + ", ".join(a["urgency_hits"][:3]), "T1566")

    if intel:
        for item in intel.get("flagged", []):
            add(30, f"Threat intel hit: {item}", "T1566")

    seen, unique = set(), []
    for item in findings:
        if item["reason"] not in seen:
            seen.add(item["reason"])
            unique.append(item)

    total = min(100, sum(i["points"] for i in unique))
    return {"score": total, "level": _level(total), "findings": unique}
