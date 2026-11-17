"""Read-only VirusTotal URL and SHA-256 report lookup. Python standard library only."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://www.virustotal.com/api/v3"
MAX_RESPONSE = 8 * 1024 * 1024
CAUTION = "Detection counts are evidence for investigation, not a guarantee of safety or proof of compromise."


class LookupError(Exception):
    """An actionable error safe to display without credentials or response bodies."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise LookupError("Unexpected API redirect blocked; no credentials forwarded.")


def url_id(value):
    try:
        parsed = urllib.parse.urlsplit(value)
        valid = (parsed.scheme in {"http", "https"} and parsed.hostname
                 and parsed.username is None and parsed.password is None)
        parsed.port  # Reject invalid port syntax/range.
    except ValueError:
        valid = False
    if not valid or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise LookupError("Use an absolute HTTP(S) URL without embedded credentials or whitespace.")
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")


def validate_hash(value):
    if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
        raise LookupError("Provide a SHA-256 hash containing exactly 64 hexadecimal characters.")
    return value.lower()


def hash_file(value):
    path = Path(value)
    if not path.is_file():
        raise LookupError("File must be an existing regular file.")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_report(kind, identifier, key):
    if kind == "file":
        validate_hash(identifier)
    elif kind != "url" or not re.fullmatch(r"[A-Za-z0-9_-]+", identifier):
        raise LookupError("Invalid lookup identifier.")
    return api_request(f"/{kind}s/{identifier}", key, allow_missing=True)


def api_request(path, key, data=None, allow_missing=False):
    if not key or not key.strip():
        raise LookupError("Set an API key locally before a live request.")
    if any(ord(c) < 33 or ord(c) > 126 for c in key):
        raise LookupError("API key contains invalid characters.")
    request = urllib.request.Request(
        API + path, data=data, method="POST" if data is not None else "GET",
        headers={"x-apikey": key, "Accept": "application/json",
                 **({"Content-Type": "application/x-www-form-urlencoded"} if data is not None else {})})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
            raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise LookupError("API response exceeded the size limit.")
        return json.loads(raw)
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code == 404 and allow_missing:
            return None
        messages = {401: "API key rejected.", 403: "API access forbidden; check account permissions.",
                    429: "API quota/rate limit reached. Wait before trying again; no automatic retry."}
        raise LookupError(messages.get(exc.code, f"API request failed (HTTP {exc.code}).")) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise LookupError("Network request failed or timed out. Check connectivity and retry later.") from None
    except (ValueError, UnicodeError):
        raise LookupError("API returned invalid JSON.") from None


def summarize(payload, kind, identifier, now=None):
    result = {"source": "virustotal", "kind": kind, "lookup_id": identifier,
              "status": "not_found", "assessment": "unknown", "caution": CAUTION}
    if payload is None:
        return result
    try:
        data = payload["data"]
        report_id = data["id"]
        if data["type"] != kind or not re.fullmatch(r"[a-fA-F0-9]{64}", report_id):
            raise ValueError
        if kind == "file" and report_id.lower() != identifier.lower():
            raise ValueError
        attrs = data["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        if not isinstance(stats, dict) or any(type(v) is not int or v < 0 for v in stats.values()):
            raise ValueError
        stamp = attrs.get("last_analysis_date")
        when = None
        age = None
        if stamp is not None:
            if type(stamp) is not int or stamp < 0:
                raise ValueError
            when = datetime.fromtimestamp(stamp, timezone.utc)
            current = now or datetime.now(timezone.utc)
            age = round((current - when).total_seconds() / 86400, 2)
        flagged = stats.get("malicious", 0) + stats.get("suspicious", 0)
        assessment = "detections_reported" if flagged else "unknown"
        if not flagged and sum(stats.values()) > 0 and all(k in stats for k in ("malicious", "suspicious")):
            assessment = "no_detections_reported"
        result.update(status="found", assessment=assessment, stats=stats,
                      last_analysis_utc=when.isoformat() if when else None,
                      report_age_days=age, future_timestamp=age is not None and age < 0,
                      report_url=f"https://www.virustotal.com/gui/{kind}/{report_id.lower()}")
        return result
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError, OSError):
        raise LookupError("API report has an unexpected schema or mismatched file identity.") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Look up existing VirusTotal reports; no uploads, downloads or scan submissions.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    sub = parser.add_subparsers(dest="command", required=True)
    for command, help_text in [("url", "Discloses the supplied URL to VirusTotal; avoid private URLs"),
                               ("hash", "Look up a SHA-256 hash"),
                               ("file", "Hash a local file and send only its SHA-256")]:
        child = sub.add_parser(command, help=help_text)
        child.add_argument("value")
    args = parser.parse_args(argv)
    try:
        kind = "url" if args.command == "url" else "file"
        identifier = {"url": url_id, "hash": validate_hash, "file": hash_file}[args.command](args.value)
        result = summarize(fetch_report(kind, identifier, os.environ.get("VT_API_KEY", "")), kind, identifier)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Status: {result['status']} | Assessment: {result['assessment']}")
            if result["status"] == "found":
                print(f"Counts: {json.dumps(result['stats'], sort_keys=True)}")
                print(f"Last analysis UTC: {result['last_analysis_utc']} | Age (days): {result['report_age_days']}")
                if result["future_timestamp"]:
                    print("Report timestamp is in the future; check the report and local clock.")
                print(f"Report: {result['report_url']}")
            print(CAUTION)
        return 0 if result["status"] == "found" else 1
    except (LookupError, OSError):
        exc = sys.exception()
        message = str(exc) if isinstance(exc, LookupError) else "Unable to read the local file. Check its path and permissions."
        if args.json:
            print(json.dumps({"status": "error", "message": message}))
        else:
            print(f"Error: {message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
