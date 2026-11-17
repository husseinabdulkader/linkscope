import unittest
from presentation import detected_state, describe


class PresentationTests(unittest.TestCase):
    def test_detection_only_explains_no_submission(self):
        state = detected_state(False, True, True)
        self.assertEqual(state, 'Not checked · Auto checks off')
        self.assertIn('Nothing was sent', describe({'status': state}))

    def test_privacy_hold_and_queue_distinct(self):
        self.assertEqual(detected_state(True, False, False), 'Not checked · Privacy hold')
        self.assertEqual(detected_state(True, True, False), 'Not checked · Queue full')
        self.assertEqual(detected_state(True, True, True), 'Waiting for lookup')

    def test_missing_report_unknown(self):
        self.assertIn('risk is unknown', describe({'status': 'not_found'}))

    def test_absent_counts_not_zero(self):
        self.assertIn('Malicious: unknown', describe({'status': 'found', 'stats': {}}))

    def test_zero_is_not_safe(self):
        self.assertIn('does not establish safety', describe({'assessment': 'no_detections_reported', 'stats': {'malicious': 0}}))

    def test_error_not_assessment(self):
        self.assertIn('No risk assessment', describe({'error': 'API quota reached'}))
