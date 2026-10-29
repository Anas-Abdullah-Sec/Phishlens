"""Rule-based risk scoring. Every point can be traced to one rule and one ATT&CK technique."""
from __future__ import annotations

from .parser import DOMAIN_RE, same_org

LEVELS = [(75, "CRITICAL"), (50, "HIGH"), (25, "MEDIUM"), (0, "LOW")]

SUMMARY = {
    "LOW": "No strong phishing indicators. Treat it normally, but stay alert.",
    "MEDIUM": "Some warning signs. Confirm with the sender through another channel before acting.",
    "HIGH": "Looks like phishing. Do not click anything or open attachments.",
    "CRITICAL": "Almost certainly malicious. Block the sender and report it.",
}

URL_FLAG_RULES = {
    "ip-host": (15, "Link points to a raw IP address: {host}"),
    "shortener": (10, "Link uses a URL shortener: {host}"),
    "punycode": (15, "Link uses a lookalike (punycode) domain: {host}"),
}


def _level(score: int) -> str:
    return next(name for threshold, name in LEVELS if score >= threshold)


def score_email(a: dict, intel: dict | None = None) -> dict:
    """Return {"score", "level", "summary", "findings": [{"points", "reason", "attack"}]}."""
    findings: list[dict] = []

    def add(points: int, reason: str, attack: str = "T1566", targets: tuple = ()) -> None:
        findings.append({"points": points, "reason": reason, "attack": attack, "targets": list(targets)})

    auth = a["auth"]
    if auth["spf"] in ("fail", "softfail"):
        add(20, "SPF check %s" % ("failed" if auth["spf"] == "fail" else "softfailed"), "T1566.001", ("auth",))
    if auth["dkim"] == "fail":
        add(15, "DKIM signature check failed", "T1566.001", ("auth",))
    if auth["dmarc"] == "fail":
        add(20, "DMARC check failed", "T1566.001", ("auth",))
    if all(v == "none" for v in auth.values()):
        add(5, "No SPF, DKIM or DMARC results in the headers", "T1566", ("auth",))

    sender = a["from"]
    if a["mismatch"]["reply_to"]:
        add(15, "Replies go to %s, not the sender's domain %s" % (a["reply_to"]["domain"], sender["domain"]), "T1566.001", ("reply_to",))
    if a["mismatch"]["return_path"]:
        add(10, "Bounce address domain (%s) differs from sender (%s)" % (a["return_path"]["domain"], sender["domain"]), "T1566.001", ("return_path",))

    shown = DOMAIN_RE.search(sender["display"] or "")
    if shown and not same_org(shown.group(0).lower(), sender["domain"]):
        add(15, "Display name mentions %s but the real sender domain is %s" % (shown.group(0), sender["domain"]), "T1656", ("from",))

    if a["mismatched_links"]:
        n = len(a["mismatched_links"])
        text = "A link shows one address but leads somewhere else" if n == 1 else "%d links show one address but lead somewhere else" % n
        bad = tuple("link:%d" % i for i, u in enumerate(a["urls"]) if "text-mismatch" in u["flags"])
        add(25, text, "T1566.002", bad)

    for i, u in enumerate(a["urls"]):
        for flag in u["flags"]:
            if flag in URL_FLAG_RULES:
                points, template = URL_FLAG_RULES[flag]
                add(points, template.format(host=u["host"]), "T1566.002", ("link:%d" % i,))

    for i, att in enumerate(a["attachments"]):
        if att["double_extension"]:
            add(30, "Attachment hides its type with a double extension: %s" % att["filename"], "T1566.001", ("att:%d" % i,))
        elif att["risky_extension"]:
            add(25, "Attachment is a risky file type: %s" % att["filename"], "T1566.001", ("att:%d" % i,))

    if a["urgency_hits"]:
        add(10, "Pressure language: " + ", ".join(a["urgency_hits"][:3]), "T1566", ("urgency",))

    if intel:
        for item in intel.get("flagged", []):
            add(30, "Threat intelligence: %s" % item, "T1566")

    seen, unique = set(), []
    for item in findings:
        if item["reason"] not in seen:
            seen.add(item["reason"])
            unique.append(item)

    total = min(100, sum(i["points"] for i in unique))
    level = _level(total)
    return {"score": total, "level": level, "summary": SUMMARY[level], "findings": unique}
