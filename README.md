# Phishing Email Analyzer

A Python CLI that triages suspicious `.eml` files the way a SOC analyst would:
it inspects headers, extracts and checks URLs, hashes attachments, optionally
enriches indicators with threat intel, and produces a risk-scored report mapped
to MITRE ATT&CK.

> Built for learning and defensive triage. It never opens or executes attachments.

## Features

| Area | What it checks |
|---|---|
| Headers | SPF / DKIM / DMARC results, From vs Reply-To vs Return-Path mismatch, display-name spoofing, origin IP from `Received` chain |
| URLs | Extraction from text and HTML, visible-text vs real-href mismatch, raw-IP hosts, URL shorteners, punycode domains |
| Attachments | Filename, type, size, SHA256, risky and double extensions (`invoice.pdf.exe`) |
| Threat intel | VirusTotal (URLs, file hashes) and AbuseIPDB (origin IP), optional |
| Scoring | 0-100 score with LOW / MEDIUM / HIGH / CRITICAL verdict and an explanation table |
| Output | Markdown or JSON report, URLs are defanged (`hxxp://example[.]com`) |

## Install

```bash
git clone https://github.com/<your-username>/phishing-analyzer.git
cd phishing-analyzer
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
# Quick analysis without network lookups
python -m phishing_analyzer samples/sample_phish.eml --no-intel

# Save a report
python -m phishing_analyzer samples/sample_phish.eml --no-intel -o reports/report.md

# JSON output for automation
python -m phishing_analyzer samples/sample_phish.eml --no-intel --format json

# With threat intel (free API keys)
export VT_API_KEY="your_virustotal_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
python -m phishing_analyzer path/to/email.eml
```

Windows PowerShell: `$env:VT_API_KEY="your_key"`

## Scoring rules (examples)

| Signal | Points | ATT&CK |
|---|---|---|
| SPF fail / softfail | +20 | T1566.001 |
| DMARC fail | +20 | T1566.001 |
| Reply-To domain differs from From | +15 | T1566.001 |
| Link text differs from real destination | +25 | T1566.002 |
| Double-extension attachment | +30 | T1566.001 |
| Threat-intel hit | +30 | T1566 |

Scores are capped at 100. All rules live in `phishing_analyzer/scoring.py`.

## Project layout

```
phishing_analyzer/
  parser.py    # headers, URLs, attachments
  scoring.py   # rules + MITRE mapping
  intel.py     # VirusTotal / AbuseIPDB
  report.py    # Markdown / JSON
  cli.py       # argparse entry point
samples/       # safe demo emails
tests/         # unit tests
```

## Tests

```bash
pytest -q
```

## Limitations

- Heuristic scoring: a LOW score does not prove an email is safe.
- Domain comparison is simple (no public-suffix list), so rare false positives are possible.
- Relies on `Authentication-Results` added by the receiving server; forwarded or locally generated emails may lack it.
- Only `.eml` is supported; Outlook `.msg` is on the roadmap.
- VirusTotal free tier allows 4 requests/minute, so lookups are capped and throttled.

## Roadmap

- `.msg` support
- Streamlit upload UI
- Dockerfile
- YARA / Sigma rule export for detected indicators

## Disclaimer

Use only on emails you are authorized to analyze. Sample emails use reserved
example domains and a harmless text file as the "attachment".
