"""Parse an .eml file into a structured analysis dict."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
IP_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")
DOMAIN_RE = re.compile(r"\b[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}\b", re.I)

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar",
    ".lnk", ".iso", ".img", ".hta", ".docm", ".xlsm", ".pptm", ".html", ".htm",
}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly"}
URGENCY_WORDS = [
    "urgent", "immediately", "verify your account", "suspended", "act now",
    "password expires", "confirm your identity", "unusual activity", "final notice",
]


class _LinkParser(HTMLParser):
    """Collect (href, visible_text) pairs from <a> tags."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower().strip(" >") if "@" in address else ""


def same_org(a: str, b: str) -> bool:
    """Loose domain match (exact or parent/subdomain). No public-suffix list."""
    if not a or not b:
        return True  # nothing to compare
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _addr_info(value: str | None) -> dict:
    display, addr = parseaddr(value or "")
    return {"display": display, "address": addr.lower(), "domain": domain_of(addr)}


def _auth_results(msg) -> dict:
    blob = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))
    blob += " " + " ".join(str(h) for h in msg.get_all("Received-SPF", []))
    out = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", blob, re.I)
        if not m and mech == "spf":
            m = re.match(r"\s*(\w+)", str(msg.get("Received-SPF", "")))
        out[mech] = m.group(1).lower() if m else "none"
    return out


def _origin_ip(msg) -> str | None:
    """Walk Received headers from oldest to newest, return first public IP."""
    for header in reversed(msg.get_all("Received", [])):
        for candidate in IP_RE.findall(str(header)):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if ip.is_global:
                return candidate
    return None


def analyze_file(path: str | Path) -> dict:
    path = Path(path)
    with path.open("rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)

    urls: dict[str, dict] = {}
    mismatched: list[dict] = []
    attachments: list[dict] = []
    body_text = ""

    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        filename = part.get_filename()

        if filename or part.get_content_disposition() == "attachment":
            data = part.get_payload(decode=True) or b""
            name = filename or "(unnamed)"
            suffixes = [s.lower() for s in Path(name).suffixes]
            attachments.append({
                "filename": name,
                "content_type": ctype,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "risky_extension": bool(suffixes) and suffixes[-1] in RISKY_EXTENSIONS,
                "double_extension": len(suffixes) >= 2 and suffixes[-1] in RISKY_EXTENSIONS,
            })
            continue

        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except Exception:
            continue

        if ctype == "text/plain":
            body_text += "\n" + content
            for u in URL_RE.findall(content):
                urls.setdefault(u, {"url": u, "host": urlparse(u).hostname or "", "text": ""})
        else:
            parser = _LinkParser()
            parser.feed(content)
            for href, text in parser.links:
                if not href.lower().startswith("http"):
                    continue
                host = urlparse(href).hostname or ""
                urls.setdefault(href, {"url": href, "host": host, "text": text})
                shown = DOMAIN_RE.search(text)
                if shown and shown.group(0).lower().lstrip("www.") != host.lstrip("www."):
                    mismatched.append({"shown": text, "actual": href})
            body_text += "\n" + re.sub(r"<[^>]+>", " ", content)
            for u in URL_RE.findall(content):
                urls.setdefault(u, {"url": u, "host": urlparse(u).hostname or "", "text": ""})

    subject = str(msg.get("Subject", ""))
    haystack = (subject + " " + body_text).lower()

    return {
        "file": path.name,
        "subject": subject,
        "date": str(msg.get("Date", "")),
        "from": _addr_info(msg.get("From")),
        "reply_to": _addr_info(msg.get("Reply-To")),
        "return_path": _addr_info(msg.get("Return-Path")),
        "auth": _auth_results(msg),
        "origin_ip": _origin_ip(msg),
        "urls": list(urls.values()),
        "mismatched_links": mismatched,
        "attachments": attachments,
        "urgency_hits": [w for w in URGENCY_WORDS if w in haystack],
    }
