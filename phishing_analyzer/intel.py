"""Optional threat-intel enrichment (VirusTotal, AbuseIPDB). Free API keys work."""
from __future__ import annotations

import base64
import os
import time

try:
    import requests
except ImportError:  # keep the tool usable without requests
    requests = None

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
VT_DELAY = 16  # free tier: 4 requests per minute


def _vt_get(path: str, key: str) -> dict | None:
    try:
        r = requests.get(f"{VT_BASE}/{path}", headers={"x-apikey": key}, timeout=15)
        if r.status_code == 200:
            return r.json()["data"]["attributes"]
    except Exception:
        pass
    return None


def enrich(a: dict, max_lookups: int = 4) -> dict:
    """Return {"results": [...], "flagged": [...], "notes": [...]}."""
    out = {"results": [], "flagged": [], "notes": []}
    vt_key = os.getenv("VT_API_KEY")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")

    if requests is None:
        out["notes"].append("'requests' not installed - intel skipped")
        return out
    if not vt_key and not abuse_key:
        out["notes"].append("No API keys set (VT_API_KEY / ABUSEIPDB_API_KEY) - intel skipped")
        return out

    lookups = 0

    if abuse_key and a["origin_ip"]:
        try:
            r = requests.get(
                ABUSE_URL,
                headers={"Key": abuse_key, "Accept": "application/json"},
                params={"ipAddress": a["origin_ip"], "maxAgeInDays": 90},
                timeout=15,
            )
            if r.status_code == 200:
                d = r.json()["data"]
                out["results"].append(
                    f"AbuseIPDB {a['origin_ip']}: confidence {d['abuseConfidenceScore']}%, "
                    f"{d['totalReports']} reports, country {d.get('countryCode')}"
                )
                if d["abuseConfidenceScore"] >= 50:
                    out["flagged"].append(f"Origin IP {a['origin_ip']} abuse score {d['abuseConfidenceScore']}%")
        except Exception:
            out["notes"].append("AbuseIPDB lookup failed")

    if vt_key:
        targets = [("files", att["sha256"], att["filename"]) for att in a["attachments"]]
        for u in a["urls"]:
            uid = base64.urlsafe_b64encode(u["url"].encode()).decode().strip("=")
            targets.append(("urls", uid, u["url"]))
        for kind, ident, label in targets:
            if lookups >= max_lookups:
                out["notes"].append(f"Stopped at {max_lookups} VirusTotal lookups (free-tier limit)")
                break
            if lookups:
                time.sleep(VT_DELAY)
            lookups += 1
            attrs = _vt_get(f"{kind}/{ident}", vt_key)
            if not attrs:
                out["results"].append(f"VirusTotal {label}: not found")
                continue
            stats = attrs.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            out["results"].append(f"VirusTotal {label}: {mal} malicious / {stats.get('suspicious', 0)} suspicious")
            if mal >= 3:
                out["flagged"].append(f"{label} flagged by {mal} engines")
    return out
