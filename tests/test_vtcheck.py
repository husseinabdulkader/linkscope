import base64
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError, URLError
import vtcheck as vt


def fixture(name="flagged"):
    return json.loads((Path(__file__).resolve().parents[1] / "fixtures" / f"{name}.json").read_text())


class Inputs(unittest.TestCase):
    def test_url_encoding_preserves_query(self):
        url = "https://example.com/path?a=1&b=2"
        encoded = vt.url_id(url)
        self.assertNotIn("=", encoded)
        self.assertEqual(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode(), url)

    def test_bad_urls(self):
        for value in ("file:///secret", "example.com", "https://user:pass@example.com", "https://example.com:99999", "https://example.com/\n", "https://[broken"):
            with self.subTest(value=value), self.assertRaises(vt.LookupError):
                vt.url_id(value)

    def test_hash_validation(self):
        self.assertEqual(vt.validate_hash("A" * 64), "a" * 64)
        for value in ("a" * 63, "a" * 65, "g" * 64, "../report", ""):
            with self.subTest(value=value), self.assertRaises(vt.LookupError):
                vt.validate_hash(value)

    def test_hash_empty_and_multiple_chunks(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sample.bin"
            for content in (b"", b"abc", b"x" * (1024 * 1024 + 7)):
                path.write_bytes(content)
                self.assertEqual(vt.hash_file(path), hashlib.sha256(content).hexdigest())

    def test_nonfile(self):
        with tempfile.TemporaryDirectory() as folder, self.assertRaises(vt.LookupError):
            vt.hash_file(folder)


class Reports(unittest.TestCase):
    def summary(self, payload):
        return vt.summarize(payload, "url", vt.url_id("https://example.com"), datetime(2026, 11, 10, tzinfo=timezone.utc))

    def test_flagged(self):
        self.assertEqual(self.summary(fixture())["assessment"], "detections_reported")

    def test_zero_does_not_claim_safe(self):
        result = self.summary(fixture("zero-detections"))
        self.assertEqual(result["assessment"], "no_detections_reported")
        self.assertIn("not a guarantee", result["caution"])

    def test_incomplete_unknown(self):
        self.assertEqual(self.summary(fixture("incomplete"))["assessment"], "unknown")

    def test_no_report(self):
        self.assertEqual(self.summary(None)["status"], "not_found")

    def test_missing_time(self):
        payload = fixture()
        del payload["data"]["attributes"]["last_analysis_date"]
        self.assertIsNone(self.summary(payload)["report_age_days"])

    def test_future_time(self):
        payload = fixture()
        payload["data"]["attributes"]["last_analysis_date"] = 2000000000
        self.assertTrue(self.summary(payload)["future_timestamp"])

    def test_invalid_stats_and_schema(self):
        for payload in ([], {}, {"data": None}):
            with self.subTest(payload=payload), self.assertRaises(vt.LookupError):
                self.summary(payload)
        for count in (-1, True, "3", 1.5):
            payload = fixture()
            payload["data"]["attributes"]["last_analysis_stats"]["malicious"] = count
            with self.subTest(count=count), self.assertRaises(vt.LookupError):
                self.summary(payload)

    def test_file_identity_mismatch(self):
        payload = fixture()
        payload["data"]["type"] = "file"
        with self.assertRaises(vt.LookupError):
            vt.summarize(payload, "file", "b" * 64)


class Transport(unittest.TestCase):
    def setUp(self):
        self.patcher = patch("vtcheck.urllib.request.build_opener")
        self.factory = self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.opener = self.factory.return_value
        self.response = self.opener.open.return_value.__enter__.return_value
        self.response.read.return_value = json.dumps(fixture()).encode()

    def test_only_get_fixed_host_no_body(self):
        for kind, identifier in (("url", vt.url_id("https://example.com")), ("file", "a" * 64)):
            vt.fetch_report(kind, identifier, "test-only-key")
            request = self.opener.open.call_args.args[0]
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(request.full_url, f"{vt.API}/{kind}s/{identifier}")
            self.assertIsNone(request.data)
            self.assertEqual(request.get_header("X-apikey"), "test-only-key")
            self.assertEqual(self.opener.open.call_args.kwargs["timeout"], 20)
            self.assertIsInstance(self.factory.call_args.args[0], vt.NoRedirect)

    def test_no_key_no_network(self):
        with self.assertRaises(vt.LookupError):
            vt.fetch_report("file", "a" * 64, "")
        self.opener.open.assert_not_called()

    def test_http_errors_no_retry_or_secret(self):
        for code in (401, 403, 429, 500):
            self.opener.open.reset_mock()
            self.opener.open.side_effect = HTTPError(vt.API, code, "secret-body", {}, None)
            with self.subTest(code=code), self.assertRaises(vt.LookupError) as caught:
                vt.fetch_report("file", "a" * 64, "test-only-key")
            self.assertNotIn("secret", str(caught.exception))
            self.opener.open.assert_called_once()

    def test_404_unknown(self):
        self.opener.open.side_effect = HTTPError(vt.API, 404, "missing", {}, None)
        self.assertIsNone(vt.fetch_report("file", "a" * 64, "test-only-key"))

    def test_network_errors(self):
        for error in (TimeoutError(), URLError("secret-url")):
            self.opener.open.side_effect = error
            with self.assertRaises(vt.LookupError):
                vt.fetch_report("file", "a" * 64, "test-only-key")

    def test_invalid_json(self):
        self.response.read.return_value = b"<html>"
        with self.assertRaises(vt.LookupError):
            vt.fetch_report("file", "a" * 64, "test-only-key")

    def test_oversized_response(self):
        with patch("vtcheck.MAX_RESPONSE", 2), self.assertRaises(vt.LookupError):
            vt.fetch_report("file", "a" * 64, "test-only-key")

    def test_redirect_blocked(self):
        with self.assertRaises(vt.LookupError):
            vt.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.example")


class CLI(unittest.TestCase):
    def test_missing_key_json(self):
        output = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), redirect_stdout(output):
            self.assertEqual(vt.main(["--json", "hash", "a" * 64]), 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "error")

    def test_invalid_input_before_network(self):
        with patch("vtcheck.fetch_report") as fetch, redirect_stderr(io.StringIO()):
            self.assertEqual(vt.main(["url", "file:///secret"]), 2)
        fetch.assert_not_called()

    def test_file_command_sends_hash_only(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sample.txt"
            path.write_bytes(b"abc")
            with patch("vtcheck.fetch_report", return_value=None) as fetch, redirect_stdout(io.StringIO()):
                self.assertEqual(vt.main(["file", str(path)]), 1)
            self.assertEqual(fetch.call_args.args[:2], ("file", hashlib.sha256(b"abc").hexdigest()))

    def test_found_exit_zero(self):
        with patch("vtcheck.fetch_report", return_value=fixture()), redirect_stdout(io.StringIO()):
            self.assertEqual(vt.main(["url", "https://example.com"]), 0)


if __name__ == "__main__":
    unittest.main()
