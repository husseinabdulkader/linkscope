"""Plain-language result presentation, independent of the desktop toolkit."""
LABELS = {
    'detections_reported': 'Potential risk reported',
    'no_detections_reported': 'No detections reported',
    'unknown': 'Not enough information',
}


def result_label(report):
    return {'not_found': 'No existing report', 'submitted': 'Submitted · Awaiting analysis',
            'queued': 'Analysis queued', 'in-progress': 'Analysis in progress'}.get(
                report.get('status'), LABELS.get(report.get('assessment'), 'Not enough information'))


def result_status(report):
    return {'not_found': 'Lookup complete · No report found', 'submitted': 'Submission accepted · Use Refresh analysis for progress',
            'queued': 'Analysis queued · Not completed', 'in-progress': 'Analysis in progress · Not completed',
            'completed': 'Analysis completed'}.get(report.get('status'), 'Lookup complete · Existing report received')


def detected_state(auto, eligible, queued):
    if not auto:
        return 'Not checked · Auto checks off'
    if not eligible:
        return 'Not checked · Privacy hold'
    if not queued:
        return 'Not checked · Queue full'
    return 'Waiting for lookup'


def describe(report):
    if 'error' in report:
        return 'Lookup failed\n\n' + report['error'] + '\nNo risk assessment is available.'
    state = report.get('status', '')
    if state == 'Confirming URL · Read 1 of 2':
        return 'URL detected · First read\n\nWaiting for the same URL in the next screen capture. No lookup has been sent for this detection yet.'
    if state == 'Checking existing report…':
        return 'Lookup in progress\n\nRequesting an existing VirusTotal report. This does not submit a new scan. The result will replace this row.'
    if state in {'submitted', 'queued', 'in-progress'}:
        return (result_label(report) + '\n\nVirusTotal has not provided a completed analysis yet. '
                'Choose Refresh analysis after at least 16 seconds. Each refresh uses one API request. '
                'The URL will not be resubmitted.\n\nRisk remains unknown until results are available.')
    if state.startswith('Not checked') or state == 'Waiting for lookup':
        reasons = {
            'Not checked · Auto checks off': 'The screen reader found this link, but automatic checks are off. Nothing was sent to VirusTotal. Select Check selected link, or enable automatic checks and restart monitoring.',
            'Not checked · Privacy hold': 'This URL may contain private information, such as a query string, fragment or private hostname. It was not sent automatically. Review it before choosing Check selected link.',
            'Not checked · Queue full': 'The automatic queue is full. This link has not been sent. You can check it individually.',
            'Waiting for lookup': 'The link is waiting for the next available lookup slot. Requests are spaced 16 seconds apart.',
        }
        return state + '\n\n' + reasons[state] + '\n\nDetection alone is not a risk verdict.'
    if report.get('status') == 'not_found':
        return 'No existing report\n\nVirusTotal returned no report for this indicator. Its risk is unknown. No new scan was submitted.\n\nFor a public URL, choose Submit URL for analysis to request a new scan.'
    title = LABELS.get(report.get('assessment'), 'Not enough information')
    stats = report.get('stats', {})
    count = lambda key: str(stats[key]) if key in stats else 'unknown'
    lines = [title, '', f"Malicious: {count('malicious')}     Suspicious: {count('suspicious')}     Undetected: {count('undetected')}",
             f"Last analysis: {report.get('last_analysis_utc') or 'Unknown'}",
             'Next step: inspect context and report age. Zero detections does not establish safety.']
    if report.get('future_timestamp'):
        lines.append('The report timestamp is in the future. Check the clock and report metadata.')
    if report.get('source') == 'synthetic_fixture':
        lines.insert(0, 'DEMO · Synthetic evidence')
    if report.get('report_url'):
        lines.append('Report: ' + report['report_url'])
    return '\n'.join(lines)
