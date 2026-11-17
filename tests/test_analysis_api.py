import json
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import parse_qs
import analysis_api
import vtcheck
import presentation


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.patch = patch('vtcheck.urllib.request.build_opener')
        self.opener = self.patch.start().return_value
        self.addCleanup(self.patch.stop)
        self.response = self.opener.open.return_value.__enter__.return_value

    def payload(self, status=None, identifier='u-synthetic-123'):
        data = {'type': 'analysis', 'id': identifier}
        if status:
            data['attributes'] = {'status': status, 'date': 1794268800,
                                  'stats': {'malicious': 1, 'suspicious': 0, 'undetected': 5}}
        self.response.read.return_value = json.dumps({'data': data}).encode()

    def test_submit_form_and_accepted_not_completed(self):
        self.payload()
        url = 'https://example.com/?a=1&b=two'
        result = analysis_api.submit(url, 'test-key')
        req = self.opener.open.call_args.args[0]
        self.assertEqual(req.full_url, vtcheck.API + '/urls')
        self.assertEqual(req.get_method(), 'POST')
        self.assertEqual(parse_qs(req.data.decode()), {'url': [url]})
        self.assertEqual(result['status'], 'submitted')
        self.assertEqual(result['assessment'], 'unknown')

    def test_refresh_get_not_resubmit(self):
        self.payload('queued', 'abc/def==')
        result = analysis_api.refresh('abc/def==', 'test-key')
        req = self.opener.open.call_args.args[0]
        self.assertEqual(req.get_method(), 'GET')
        self.assertTrue(req.full_url.endswith('/analyses/abc%2Fdef%3D%3D'))
        self.assertIsNone(req.data)
        self.assertEqual(result['status'], 'queued')

    def test_partial_detections_not_final(self):
        self.payload('in-progress')
        result = analysis_api.refresh('u-synthetic-123', 'test-key')
        self.assertEqual(result['assessment'], 'unknown')
        self.assertNotIn('stats', result)

    def test_completed_counts(self):
        self.payload('completed')
        result = analysis_api.refresh('u-synthetic-123', 'test-key')
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['assessment'], 'detections_reported')
        self.assertNotIn('report_url', result)

    def test_invalid_and_mismatched_analysis(self):
        for status, identifier in [('unexpected', 'u-synthetic-123'), ('completed', 'different')]:
            self.payload(status, identifier)
            with self.assertRaises(vtcheck.LookupError):
                analysis_api.refresh('u-synthetic-123', 'test-key')

    def test_missing_id(self):
        self.response.read.return_value = b'{"data":{"type":"analysis"}}'
        with self.assertRaises(vtcheck.LookupError):
            analysis_api.submit('https://example.com/', 'test-key')

    def test_404_analysis_is_error_not_no_report(self):
        self.opener.open.side_effect = HTTPError(vtcheck.API, 404, 'missing', {}, None)
        with self.assertRaises(vtcheck.LookupError):
            analysis_api.refresh('u-synthetic-123', 'test-key')

    def test_timeout_and_429_no_retry(self):
        for error in (TimeoutError(), HTTPError(vtcheck.API, 429, 'quota', {}, None)):
            self.opener.open.reset_mock()
            self.opener.open.side_effect = error
            with self.assertRaises(vtcheck.LookupError):
                analysis_api.submit('https://example.com/', 'test-key')
            self.opener.open.assert_called_once()

    def test_invalid_url_no_request(self):
        with self.assertRaises(vtcheck.LookupError):
            analysis_api.submit('file:///secret', 'test-key')
        self.opener.open.assert_not_called()

    def test_status_no_report_not_received(self):
        self.assertEqual(presentation.result_status({'status': 'not_found'}), 'Lookup complete · No report found')
        self.assertEqual(presentation.result_label({'status': 'not_found'}), 'No existing report')

    def test_pending_text_not_completed(self):
        for status in ('submitted', 'queued', 'in-progress'):
            self.assertIn('not provided a completed analysis', presentation.describe({'status': status}))
