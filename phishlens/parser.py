"""Turn a raw .eml message into a plain dict of evidence."""
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
# Link text that is itself a URL or bare domain, e.g. "paypal.com/login"
LINK_TEXT_RE = re.compile(r"^(?:https?://)?(?:www\.)?[\w-]+(?:\.[\w-]+)+(?:[/:?#]\S*)?$", re.I)
IPV4_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar",
    ".lnk", ".iso", ".img", ".hta", ".docm", ".xlsm", ".pptm", ".html", ".htm",
}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly"}
URGENCY_WORDS = [
    "urgent", "immediately", "verify your account", "suspended", "act now",
    "password expires", "confirm your identity", "unusual activity", "final notice",
]


def defang(text: str) -> str:
    """Make a URL or domain safe to paste into tickets and chats."""
    return text.replace("http", "hxxp").replace(".", "[.]")


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower().strip(" >") if "@" in address else ""


def same_org(a: str, b: str) -> bool:
    """Loose domain match: equal, or one is a subdomain of the other."""
    if not a or not b:
        return True  # nothing to compare
    return a == b or a.endswith("." + b) or b.endswith("." + a)


BLOCK_TAGS = {"p", "div", "br", "li", "tr", "table", "ul", "ol", "blockquote",
              "h1", "h2", "h3", "h4", "h5", "h6"}
SKIP_TAGS = {"script", "style", "head", "title"}
BODY_LIMIT = 6000


class _HtmlBody(HTMLParser):
    """Walk an HTML body once, collecting links and a readable text/link sequence."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.segments: list[dict] = []
        self._href: str | None = None
        self._text: list[str] = []
        self._skip = 0

    def _add_text(self, text: str) -> None:
        if text:
            self.segments.append({"type": "text", "text": text})

    def handle_starttag(self, tag, attrs):
        if tag in SKIP_TAGS:
            self._skip += 1
            return
        if tag in BLOCK_TAGS:
            self._add_text("\n")
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_endtag(self, tag):
        if tag in SKIP_TAGS:
            self._skip = max(0, self._skip - 1)
            return
        if tag in BLOCK_TAGS:
            self._add_text("\n")
        if tag == "a" and self._href is not None:
            text = " ".join("".join(self._text).split())
            self.links.append((self._href, text))
            self.segments.append({"type": "link", "text": text or "[link]", "href": self._href})
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        if self._href is not None:
            self._text.append(data)
        else:
            self.segments.extend(_plain_segments(re.sub(r"\s+", " ", data)))


def _plain_segments(text: str) -> list[dict]:
    segments, pos = [], 0
    for m in URL_RE.finditer(text):
        if m.start() > pos:
            segments.append({"type": "text", "text": text[pos:m.start()]})
        segments.append({"type": "link", "text": m.group(0), "href": m.group(0)})
        pos = m.end()
    if pos < len(text):
        segments.append({"type": "text", "text": text[pos:]})
    return segments


def _finish_body(segments: list[dict], index_of: dict) -> tuple[list[dict], bool]:
    """Tidy whitespace, defang link text, point links at the url list, cap the length."""
    merged: list[dict] = []
    for seg in segments:
        if seg["type"] == "text" and merged and merged[-1]["type"] == "text":
            merged[-1]["text"] += seg["text"]
        else:
            merged.append(dict(seg))
    for seg in merged:
        if seg["type"] == "text":
            t = re.sub(r"[ \t\r\f\v]+", " ", seg["text"])
            t = re.sub(r" ?\n ?", "\n", t)
            seg["text"] = re.sub(r"\n{3,}", "\n\n", t)
        else:
            seg["index"] = index_of.get(seg.pop("href"))
            if LINK_TEXT_RE.match(seg["text"]):
                seg["text"] = defang(seg["text"])
    if merged and merged[0]["type"] == "text":
        merged[0]["text"] = merged[0]["text"].lstrip()
    if merged and merged[-1]["type"] == "text":
        merged[-1]["text"] = merged[-1]["text"].rstrip()

    final, used, truncated = [], 0, False
    for seg in merged:
        if seg["type"] == "text" and not seg["text"]:
            continue
        if used + len(seg["text"]) > BODY_LIMIT:
            if seg["type"] == "text":
                seg["text"] = seg["text"][:max(0, BODY_LIMIT - used)] + "..."
                final.append(seg)
            truncated = True
            break
        used += len(seg["text"])
        final.append(seg)
    return final, truncated


def _addr_info(value) -> dict:
    display, addr = parseaddr(str(value or ""))
    return {"display": display, "address": addr.lower(), "domain": domain_of(addr)}


def _auth_results(msg) -> dict:
    blob = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))
    blob += " " + " ".join(str(h) for h in msg.get_all("Received-SPF", []))
    out = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(r"\b%s=(\w+)" % mech, blob, re.I)
        if not m and mech == "spf":
            m = re.match(r"\s*(\w+)", str(msg.get("Received-SPF", "")))
        out[mech] = m.group(1).lower() if m else "none"
    return out


def _origin_ip(msg):
    """Oldest Received hop first. Returns (ip, 'public' | 'reserved') or (None, None)."""
    reserved = None
    for header in reversed(msg.get_all("Received", [])):
        for candidate in IP_RE.findall(str(header)):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if ip.is_global:
                return candidate, "public"
            if reserved is None and not ip.is_loopback:
                reserved = candidate
    return (reserved, "reserved") if reserved else (None, None)


def _url_entry(url: str, text: str = "", mismatch: bool = False) -> dict:
    host = (urlparse(url).hostname or "").lower()
    flags = []
    if mismatch:
        flags.append("text-mismatch")
    if IPV4_HOST_RE.match(host):
        flags.append("ip-host")
    elif host in URL_SHORTENERS:
        flags.append("shortener")
    elif "xn--" in host:
        flags.append("punycode")
    return {"url": url, "defanged": defang(url), "host": host, "text": text, "flags": flags}


def analyze_bytes(data: bytes, name: str = "email.eml") -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(data)

    urls: dict[str, dict] = {}
    mismatched: list[dict] = []
    attachments: list[dict] = []
    body_text = ""
    html_segments: list[dict] = []
    plain_segments: list[dict] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        filename = part.get_filename()

        if filename or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            fname = filename or "(unnamed)"
            suffixes = [s.lower() for s in Path(fname).suffixes]
            attachments.append({
                "filename": fname,
                "content_type": ctype,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
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
            plain_segments.extend(_plain_segments(content))
        else:
            parser = _HtmlBody()
            parser.feed(content)
            parser.close()
            html_segments.extend(parser.segments)
            for href, text in parser.links:
                if not href.lower().startswith("http"):
                    continue
                host = (urlparse(href).hostname or "").lower()
                bad = bool(text) and bool(LINK_TEXT_RE.match(text))
                if bad:
                    shown_host = (urlparse(text if "://" in text else "http://" + text).hostname or "").lower()
                    bad = not same_org(shown_host, host)
                if bad:
                    mismatched.append({"shown": text, "actual": href})
                urls[href] = _url_entry(href, text, mismatch=bad)
            body_text += "\n" + re.sub(r"<[^>]+>", " ", content)
            content = re.sub(r"<a\b.*?</a>", " ", content, flags=re.I | re.S)

        for u in URL_RE.findall(content):
            if u not in urls:
                urls[u] = _url_entry(u)

    url_list = list(urls.values())
    index_of = {u["url"]: i for i, u in enumerate(url_list)}
    has_html = any(seg["type"] == "link" or seg["text"].strip() for seg in html_segments)
    body, body_truncated = _finish_body(html_segments if has_html else plain_segments, index_of)

    subject = str(msg.get("Subject", ""))
    haystack = (subject + " " + body_text).lower()
    origin, kind = _origin_ip(msg)
    sender, reply_to, return_path = (_addr_info(msg.get(h)) for h in ("From", "Reply-To", "Return-Path"))

    return {
        "file": name,
        "subject": subject,
        "to": " ".join(str(msg.get("To", "")).split())[:200],
        "date": str(msg.get("Date", "")),
        "from": sender,
        "reply_to": reply_to,
        "return_path": return_path,
        "mismatch": {
            "reply_to": bool(reply_to["domain"]) and not same_org(sender["domain"], reply_to["domain"]),
            "return_path": bool(return_path["domain"]) and not same_org(sender["domain"], return_path["domain"]),
        },
        "auth": _auth_results(msg),
        "origin_ip": origin if kind == "public" else None,
        "origin_ip_reserved": origin if kind == "reserved" else None,
        "urls": url_list,
        "body": body,
        "body_truncated": body_truncated,
        "mismatched_links": mismatched,
        "attachments": attachments,
        "urgency_hits": [w for w in URGENCY_WORDS if w in haystack],
    }


def analyze_file(path) -> dict:
    path = Path(path)
    return analyze_bytes(path.read_bytes(), path.name)
