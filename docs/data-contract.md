# Data contract

`fixtures/*.json` contains invented, explicitly synthetic API-shaped responses. The top-level `synthetic: true` marker is local metadata, not a VirusTotal API field. IDs made of repeated `a` characters are placeholders, not observed report identifiers.

| Input field | Validation/use |
| --- | --- |
| `data.type` | Must equal `url` or `file`, matching the requested type |
| `data.id` | 64 hexadecimal characters; file ID must match requested SHA-256 |
| `data.attributes.last_analysis_stats` | Dictionary of nonnegative integer counts; booleans rejected; missing/empty counts mean unknown |
| `data.attributes.last_analysis_date` | Optional nonnegative integer Unix timestamp, converted to UTC; missing means unknown |

URL lookup identifiers are unpadded URL-safe base64 of the original URL's UTF-8 bytes. Returned URL IDs are server-generated SHA-256 IDs; the client does not implement VirusTotal canonicalization. Unknown extra fields are ignored. All reported count categories are retained, including failure/timeout categories; they are not interpreted as clean results.

Output JSON contains `source`, `kind`, `lookup_id`, `status`, `assessment`, `caution`. Found reports additionally contain `stats`, `last_analysis_utc`, `report_age_days`, `future_timestamp`, `report_url`. Missing dates use JSON null. Report age is rounded to two decimal days and may be negative when metadata is ahead of the reference clock. Errors contain `status: error` and a sanitized `message`. CLI argument syntax errors use argparse's standard stderr output and exit code 2.

Synthetic demo output sets `source: synthetic_fixture` and suppresses report links. Live CLI output sets `source: virustotal`; this describes its data path, not a claim that a live test has been completed. A 404 is modeled as `None` internally, not as an invented API response body.
