"""Optional threat-intel lookups (VirusTotal, AbuseIPDB). Standard library only."""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
VT_DELAY = 16  # free tier allows 4 requests per minute


def _http_json(url: str, headers: dict | None = None, params: dict | None = None, timeout: int = 15):
    """GET a JSON document. Returns (status, data); status is None on network failure."""
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except Exception:
        return None, None


def _explain(service: str, status) -> str:
    if status is None:
        return "%s: could not connect" % service
    if status in (401, 403):
        return "%s: the API key was rejected" % service
    if status == 429:
        return "%s: rate limit reached, try again in a minute" % service
    return "%s: unexpected response (%s)" % (service, status)


def enrich(a: dict, max_lookups: int = 4, vt_key: str | None = None, abuse_key: str | None = None) -> dict:
    """Return {"results": [...], "flagged": [...], "notes": [...]}.

    Keys can be passed in (the web UI does this per request) or read from the
    VT_API_KEY / ABUSEIPDB_API_KEY environment variables.
    """
    out = {"results": [], "flagged": [], "notes": []}
    vt_key = vt_key or os.getenv("VT_API_KEY")
    abuse_key = abuse_key or os.getenv("ABUSEIPDB_API_KEY")

    if not vt_key and not abuse_key:
        out["notes"].append("No API keys were provided, so no lookups were made.")
        return out

    if abuse_key and a.get("origin_ip"):
        status, data = _http_json(
            ABUSE_URL,
            headers={"Key": abuse_key, "Accept": "application/json"},
            params={"ipAddress": a["origin_ip"], "maxAgeInDays": 90},
        )
        if status == 200 and data:
            d = data["data"]
            out["results"].append("AbuseIPDB %s: %s%% abuse confidence, %s reports, country %s" % (
                a["origin_ip"], d["abuseConfidenceScore"], d["totalReports"], d.get("countryCode") or "unknown"))
            if d["abuseConfidenceScore"] >= 50:
                out["flagged"].append("origin IP %s has an abuse score of %s%%" % (a["origin_ip"], d["abuseConfidenceScore"]))
        else:
            out["notes"].append(_explain("AbuseIPDB", status))
    elif abuse_key:
        out["notes"].append("AbuseIPDB: no public origin IP was found in the headers.")

    if vt_key:
        targets = [("files", att["sha256"], att["filename"]) for att in a["attachments"]]
        for u in a["urls"]:
            ident = base64.urlsafe_b64encode(u["url"].encode()).decode().strip("=")
            targets.append(("urls", ident, u["defanged"]))
        lookups = 0
        for kind, ident, label in targets:
            if lookups >= max_lookups:
                out["notes"].append("Stopped after %d VirusTotal lookups (free-tier limit)." % max_lookups)
                break
            if lookups:
                time.sleep(VT_DELAY)
            lookups += 1
            status, data = _http_json("%s/%s/%s" % (VT_BASE, kind, ident), headers={"x-apikey": vt_key})
            if status == 404:
                out["results"].append("VirusTotal has never seen %s" % label)
            elif status == 200 and data:
                stats = data["data"]["attributes"].get("last_analysis_stats", {})
                bad, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
                out["results"].append("VirusTotal %s: %d malicious, %d suspicious" % (label, bad, sus))
                if bad >= 3:
                    out["flagged"].append("%s flagged malicious by %d engines" % (label, bad))
            else:
                out["notes"].append(_explain("VirusTotal", status))
                if status in (401, 403, 429):
                    break
    return out
