import unittest
from unittest.mock import patch
import monitor


class MonitorTests(unittest.TestCase):
    def test_address_bar_icon_prefix_does_not_block_url(self):
        url = 'https://github.com/example/windows-soc-investigation-lab'
        payload = {'passes': [{'text': 'o— ' + url, 'edge': False},
                              {'text': 'o--\n' + url, 'edge': False}]}
        self.assertEqual(monitor.interpret_capture(payload)[0], [url])

    def test_countdown_and_limit_are_distinct(self):
        now = [100]
        schedule = monitor.Schedule(lambda: now[0])
        self.assertEqual(schedule.availability(), 'API ready')
        schedule.reserve()
        now[0] = 105
        self.assertEqual(schedule.availability(), 'Next API request in 11s')
        schedule.requests = 100
        self.assertIn('Session limit reached', schedule.availability())
    def test_two_scales_must_agree(self):
        payload = {'passes': [{'text': 'https://example.com/right', 'edge': False},
                              {'text': 'https://example.com/wrong', 'edge': False}]}
        urls, message = monitor.interpret_capture(payload)
        self.assertEqual(urls, [])
        self.assertIn('disagree', message)

    def test_clipped_region_not_submitted(self):
        payload = {'passes': [{'text': 'https://example.com/', 'edge': True}] * 2}
        self.assertEqual(monitor.interpret_capture(payload)[0], [])

    def test_consistent_scales_accepted(self):
        payload = {'passes': [{'text': 'https://example.com/', 'edge': False}] * 2}
        self.assertEqual(monitor.interpret_capture(payload)[0], ['https://example.com/'])

    def test_missing_second_pass_held(self):
        self.assertEqual(monitor.interpret_capture({'text': 'https://example.com/'})[0], [])

    def test_split_path_not_silently_truncated(self):
        payload = {'passes': [{'text': 'https://example.com/test page', 'edge': False}] * 2}
        self.assertEqual(monitor.interpret_capture(payload)[0], [])

    def test_stable_reads_require_consecutive_frames(self):
        stable = monitor.StableReads()
        url = ['https://example.com/']
        self.assertEqual(stable.observe(url), [])
        self.assertEqual(stable.observe([]), [])
        self.assertEqual(stable.observe(url), [])
        self.assertEqual(stable.observe(url), url)

    def test_changing_url_resets_stability(self):
        stable = monitor.StableReads()
        stable.observe(['https://example.com/a'])
        self.assertEqual(stable.observe(['https://example.com/b']), [])

    def test_hidden_scheme_has_actionable_diagnostic(self):
        text = 'example.com'
        urls = monitor.extract_urls(text)
        self.assertEqual(urls, [])
        self.assertIn('Ctrl+L', monitor.recognition_status(text, urls))

    def test_blank_capture_diagnostic(self):
        self.assertIn('no text recognized', monitor.recognition_status('  ', []))

    def test_success_diagnostic_without_captured_text(self):
        result = monitor.recognition_status('private extra text https://example.com/', ['https://example.com/'])
        self.assertIn('1 URL', result)
        self.assertNotIn('private extra text', result)

    def test_extract_explicit_urls_deduplicated(self):
        self.assertEqual(monitor.extract_urls('See https://example.com/test and https://example.com/test'), ['https://example.com/test'])

    def test_no_guessed_scheme(self):
        self.assertEqual(monitor.extract_urls('www.example.com mail@example.com file:///tmp/a'), [])

    def test_credentials_excluded(self):
        self.assertEqual(monitor.extract_urls('https://user:secret@example.com/'), [])

    def test_private_and_token_urls_held(self):
        for url in ['https://localhost/', 'http://192.168.1.1/', 'http://127.0.0.1/',
                    'http://[::1]/', 'https://host.internal/', 'https://example.com/?token=a', 'https://example.com/#secret']:
            with self.subTest(url=url):
                self.assertFalse(monitor.automatic_eligible(url))

    def test_public_eligible(self):
        self.assertTrue(monitor.automatic_eligible('https://example.com/public'))

    def test_pacing_boundary(self):
        now = [100]
        schedule = monitor.Schedule(lambda: now[0])
        self.assertTrue(schedule.reserve())
        now[0] = 115.99
        self.assertFalse(schedule.reserve())
        now[0] = 116
        self.assertTrue(schedule.reserve())

    def test_stop_clears_pending_keeps_pacing(self):
        schedule = monitor.Schedule(lambda: 100)
        schedule.add(['https://example.com/'])
        schedule.reserve()
        schedule.stop()
        self.assertFalse(schedule.pending)
        self.assertFalse(schedule.reserve())
        self.assertEqual(schedule.add(['https://example.com/']), [])

    def test_bounded_pending_and_seen(self):
        schedule = monitor.Schedule()
        schedule.add([f'https://example.com/{i}' for i in range(600)])
        self.assertEqual(len(schedule.pending), 50)
        self.assertEqual(len(schedule.seen), 500)

    def test_session_limit(self):
        schedule = monitor.Schedule(lambda: 100)
        schedule.requests = 100
        self.assertFalse(schedule.reserve())

    def test_invalid_region_no_capture(self):
        with patch('monitor.subprocess.run') as run, self.assertRaises(Exception):
            monitor.read_region((0, 0, 5, 5))
        run.assert_not_called()

    def test_ocr_command_and_utf8(self):
        with patch('monitor.subprocess.run') as run:
            run.return_value.returncode = 0
            run.return_value.stdout = b'{"text":"https://example.com/"}'
            self.assertEqual(monitor.read_region((10, 20, 300, 100)), 'https://example.com/')
            self.assertEqual(run.call_args.kwargs['timeout'], 25)


if __name__ == '__main__':
    unittest.main()
