"""Offline demonstration using explicitly synthetic API-shaped fixtures."""
import json
from pathlib import Path
from datetime import datetime, timezone
from vtcheck import summarize, url_id


def main():
    identifier = url_id("https://example.com/synthetic-demo")
    for name in ("flagged", "zero-detections", "incomplete", "not-found"):
        payload = None if name == "not-found" else json.loads(
            (Path(__file__).parent / "fixtures" / f"{name}.json").read_text(encoding="utf-8"))
        report = summarize(payload, "url", identifier, datetime(2026, 11, 10, tzinfo=timezone.utc))
        report["source"] = "synthetic_fixture"
        report.pop("report_url", None)  # Invented IDs must not appear to be real reports.
        print(json.dumps({"scenario": name, "report": report}, indent=2))


if __name__ == "__main__":
    main()
