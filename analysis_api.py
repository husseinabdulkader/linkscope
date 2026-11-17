"""Explicit URL submissions and analysis retrieval; never called by screen detection."""
import re
from urllib.parse import urlencode, quote
import vtcheck


def analysis_id(payload):
    try:
        data = payload['data']
        value = data['id']
        if data['type'] != 'analysis' or not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_+=:/-]{1,512}', value):
            raise ValueError
        return value
    except (KeyError, TypeError, ValueError):
        raise vtcheck.LookupError('Invalid analysis response; submission outcome may be unknown. Do not immediately resubmit.') from None


def submit(url, key):
    vtcheck.url_id(url)
    payload = vtcheck.api_request('/urls', key, data=urlencode({'url': url}).encode('utf-8'))
    return {'source': 'virustotal', 'kind': 'url', 'status': 'submitted',
            'assessment': 'unknown', 'analysis_id': analysis_id(payload)}


def refresh(identifier, key):
    analysis_id({'data': {'type': 'analysis', 'id': identifier}})
    payload = vtcheck.api_request('/analyses/' + quote(identifier, safe=''), key)
    if analysis_id(payload) != identifier:
        raise vtcheck.LookupError('Analysis response identity mismatch.')
    try:
        attrs = payload['data']['attributes']
        status = attrs['status']
        if status not in {'queued', 'in-progress', 'completed'}:
            raise ValueError
        result = {'source': 'virustotal', 'kind': 'url', 'status': status,
                  'assessment': 'unknown', 'analysis_id': identifier}
        if status == 'completed':
            # Reuse validated count/timestamp interpretation, without inventing a URL report ID/link.
            normalized = vtcheck.summarize({'data': {'id': '0' * 64, 'type': 'url', 'attributes': {
                'last_analysis_stats': attrs.get('stats', {}), 'last_analysis_date': attrs.get('date')}}}, 'url', '')
            normalized.pop('report_url', None)
            normalized.pop('lookup_id', None)
            result.update(normalized, status='completed', analysis_id=identifier)
        return result
    except (KeyError, TypeError, ValueError):
        raise vtcheck.LookupError('Unexpected analysis state or schema.') from None
