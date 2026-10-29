import http.client
import json
import threading
import unittest
from pathlib import Path
from unittest import mock

from phishlens import intel
from phishlens.cli import main as cli_main
from phishlens.engine import run
from phishlens.parser import analyze_bytes, defang, same_org
from phishlens.report import extract_iocs, iocs_text
from phishlens.server import make_server

SAMPLES = Path(__file__).resolve().parent.parent / "phishlens" / "samples"
PHISH = (SAMPLES / "sample_phish.eml").read_bytes()
BENIGN = (SAMPLES / "sample_benign.eml").read_bytes()


class ParserTests(unittest.TestCase):
    def test_header_checks(self):
        a = analyze_bytes(PHISH, "p.eml")
        self.assertEqual(a["auth"], {"spf": "fail", "dkim": "none", "dmarc": "fail"})
        self.assertTrue(a["mismatch"]["reply_to"])
        self.assertTrue(a["mismatch"]["return_path"])
        self.assertEqual(a["origin_ip_reserved"], "203.0.113.45")
        self.assertIsNone(a["origin_ip"])

    def test_links_and_attachments(self):
        a = analyze_bytes(PHISH, "p.eml")
        flags = {u["host"]: u["flags"] for u in a["urls"]}
        self.assertEqual(len(a["urls"]), 2)  # anchor text is not a second link
        self.assertIn("text-mismatch", flags["198.51.100.7"])
        self.assertIn("ip-host", flags["198.51.100.7"])
        self.assertIn("shortener", flags["bit.ly"])
        att = a["attachments"][0]
        self.assertTrue(att["double_extension"])
        self.assertEqual(len(att["sha256"]), 64)

    def test_body_is_rendered_as_text_and_links(self):
        a = analyze_bytes(PHISH, "p.eml")
        kinds = [seg["type"] for seg in a["body"]]
        self.assertEqual(kinds, ["text", "link", "text", "link"])
        first_link = a["body"][1]
        self.assertEqual(a["urls"][first_link["index"]]["host"], "198.51.100.7")
        self.assertTrue(first_link["text"].startswith("hxxps://"))  # link text is defanged too
        self.assertIn("Final notice", a["body"][0]["text"])
        self.assertEqual(a["to"], "victim@victim.example")

    def test_benign_email_has_no_flags(self):
        a = analyze_bytes(BENIGN, "b.eml")
        self.assertFalse(a["mismatch"]["reply_to"])
        self.assertEqual(a["attachments"], [])
        self.assertEqual(a["origin_ip"], "93.184.216.34")

    def test_domain_helpers(self):
        self.assertTrue(same_org("login.paypal.com", "paypal.com"))
        self.assertFalse(same_org("paypal.com.evil.example", "paypal.com"))
        self.assertFalse(same_org("evilpaypal.com", "paypal.com"))
        self.assertEqual(defang("http://a.b/c"), "hxxp://a[.]b/c")

    def test_garbage_input_does_not_crash(self):
        a = analyze_bytes(b"\x00\x01 not an email at all", "junk.eml")
        self.assertEqual(a["urls"], [])


class ScoringTests(unittest.TestCase):
    def test_phishing_sample_is_critical(self):
        r = run(PHISH, "p.eml")["risk"]
        self.assertEqual(r["level"], "CRITICAL")
        self.assertEqual(r["score"], 100)
        self.assertTrue(all("attack" in f for f in r["findings"]))

    def test_findings_point_at_the_part_of_the_email_they_come_from(self):
        findings = {f["reason"].split(":")[0][:22]: f["targets"] for f in run(PHISH, "p.eml")["risk"]["findings"]}
        by_start = lambda text: next(v for k, v in findings.items() if k.startswith(text))
        self.assertEqual(by_start("SPF check failed"), ["auth"])
        self.assertEqual(by_start("Replies go to"), ["reply_to"])
        self.assertEqual(by_start("Bounce address"), ["return_path"])
        self.assertEqual(by_start("Display name"), ["from"])
        self.assertEqual(by_start("A link shows one"), ["link:0"])
        self.assertEqual(by_start("Link uses a URL short"), ["link:1"])
        self.assertEqual(by_start("Attachment hides"), ["att:0"])
        self.assertEqual(by_start("Pressure language"), ["urgency"])

    def test_benign_sample_is_low(self):
        r = run(BENIGN, "b.eml")["risk"]
        self.assertEqual((r["level"], r["score"]), ("LOW", 0))

    def test_intel_hit_adds_points(self):
        base = run(BENIGN, "b.eml")["risk"]["score"]
        with mock.patch.object(intel, "_http_json", return_value=(200, {"data": {"attributes": {
                "last_analysis_stats": {"malicious": 9, "suspicious": 0}}}})), \
                mock.patch.object(intel.time, "sleep"):
            out = run(BENIGN, "b.eml", use_intel=True, vt_key="k", max_lookups=1)
        self.assertEqual(len(out["intel"]["flagged"]), 1)
        self.assertEqual(out["risk"]["score"], base + 30)


class IntelTests(unittest.TestCase):
    def test_no_keys_is_explained(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            out = intel.enrich(analyze_bytes(PHISH, "p.eml"))
        self.assertEqual(out["results"], [])
        self.assertIn("No API keys", out["notes"][0])

    def test_rejected_key_is_reported(self):
        with mock.patch.object(intel, "_http_json", return_value=(401, None)), mock.patch.object(intel.time, "sleep"):
            out = intel.enrich(analyze_bytes(PHISH, "p.eml"), vt_key="bad")
        self.assertTrue(any("rejected" in n for n in out["notes"]))


class ReportTests(unittest.TestCase):
    def test_iocs_are_defanged(self):
        a = analyze_bytes(PHISH, "p.eml")
        iocs = extract_iocs(a)
        self.assertIn("198[.]51[.]100[.]7", iocs["ips"])
        self.assertTrue(all(u.startswith("hxxp") for u in iocs["urls"]))
        self.assertNotIn("http://", iocs_text(a))


class CliTests(unittest.TestCase):
    def test_shorthand_and_exit_codes(self):
        self.assertEqual(cli_main([str(SAMPLES / "sample_benign.eml"), "--no-intel"]), 0)
        self.assertEqual(cli_main(["analyze", "does-not-exist.eml"]), 1)


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = make_server(0)
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def request(self, method, path, body=None, headers=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest(method, path, skip_host=True)
        conn.putheader("Host", host or "127.0.0.1:%d" % self.port)
        for k, v in (headers or {}).items():
            conn.putheader(k, v)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, dict(resp.getheaders()), data

    def test_serves_the_page_with_strict_headers(self):
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"PhishLens", body)
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(self.request("GET", "/static/app.js")[0], 200)
        self.assertEqual(self.request("GET", "/static/style.css")[0], 200)
        self.assertEqual(self.request("GET", "/nope")[0], 404)

    def test_analyze_roundtrip(self):
        status, _, body = self.request("POST", "/api/analyze", PHISH, {"X-PhishLens": "1", "X-Filename": "x.eml"})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["risk"]["level"], "CRITICAL")
        self.assertEqual(data["analysis"]["file"], "x.eml")

    def test_demo_endpoint(self):
        status, _, body = self.request("GET", "/api/demo", headers={"X-PhishLens": "1"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["risk"]["level"], "CRITICAL")

    def test_rejects_requests_without_the_custom_header(self):
        self.assertEqual(self.request("POST", "/api/analyze", PHISH)[0], 403)
        self.assertEqual(self.request("GET", "/api/demo")[0], 403)

    def test_rejects_foreign_host_and_origin(self):
        ok = {"X-PhishLens": "1"}
        self.assertEqual(self.request("GET", "/", host="evil.example")[0], 403)
        self.assertEqual(self.request("POST", "/api/analyze", PHISH, ok, host="evil.example:80")[0], 403)
        bad_origin = dict(ok, Origin="http://evil.example")
        self.assertEqual(self.request("POST", "/api/analyze", PHISH, bad_origin)[0], 403)
        good_origin = dict(ok, Origin="http://127.0.0.1:%d" % self.port)
        self.assertEqual(self.request("POST", "/api/analyze", PHISH, good_origin)[0], 200)

    def test_quit_stops_the_server(self):
        srv = make_server(0)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        port = srv.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("POST", "/api/quit", headers={"X-PhishLens": "1"})
        self.assertEqual(conn.getresponse().status, 200)
        conn.close()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        srv.server_close()

    def test_quit_needs_the_custom_header(self):
        self.assertEqual(self.request("POST", "/api/quit")[0], 403)

    def test_rejects_empty_body(self):
        self.assertEqual(self.request("POST", "/api/analyze", b"", {"X-PhishLens": "1"})[0], 400)


if __name__ == "__main__":
    unittest.main()
