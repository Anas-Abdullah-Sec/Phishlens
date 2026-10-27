from pathlib import Path

from phishing_analyzer.parser import analyze_file
from phishing_analyzer.scoring import score_email

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_phishing_sample_is_flagged():
    a = analyze_file(SAMPLES / "sample_phish.eml")
    r = score_email(a)
    assert a["auth"]["spf"] == "fail"
    assert a["mismatched_links"]
    assert a["attachments"][0]["double_extension"]
    assert r["level"] in ("HIGH", "CRITICAL")


def test_benign_sample_is_low():
    a = analyze_file(SAMPLES / "sample_benign.eml")
    r = score_email(a)
    assert r["level"] == "LOW"
    assert r["score"] == 0
