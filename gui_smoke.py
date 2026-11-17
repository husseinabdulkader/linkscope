"""Windows GUI smoke check; synthetic data, mocked network, no screen capture."""
import ctypes
import os
import tkinter as tk
import time
from unittest.mock import patch
from app import LinkScope


def main():
    if os.name == "nt":
        ctypes.windll.user32.SetProcessDPIAware()
    root = tk.Tk()
    app = LinkScope(root)
    try:
        root.update()
        assert not app.running and not app.auto.get()
        app.demo()
        assert len(app.rows) == 3
        app.region = (100, 100, 200, 50)
        app.start()
        assert app.running
        old = app.generation
        app.stop()
        app.events.put(("ocr", old, ["https://example.com/stale"]))
        app.tick()
        assert not app.schedule.pending and len(app.rows) == 3
        app.key.set("synthetic-key")
        app.auto.set(True)
        with patch("app.messagebox.askokcancel", return_value=True):
            app.start()
        with patch("app.vtcheck.fetch_report", return_value=None) as fetch:
            app.events.put(("ocr", app.generation, ["https://example.com/test"]))
            app.tick()
            fetch.assert_not_called()
            app.events.put(("ocr", app.generation, ["https://example.com/test"]))
            app.tick()
            deadline = time.monotonic() + 3
            while app.lookup_busy and time.monotonic() < deadline:
                root.update()
                time.sleep(0.01)
            assert not app.lookup_busy
            fetch.assert_called_once()
            assert fetch.call_args.args[0] == "url"
        app.stop()
        before = len(app.rows)
        app.add_row("https://example.com/selected", "Not checked · Auto checks off")
        with patch.object(app, "lookup") as lookup:
            app.check_selected()
            lookup.assert_called_once_with("url", "https://example.com/selected")
        app.add_row("https://example.com/selected", "Not checked · Auto checks off")
        assert len(app.rows) == before + 1
        app.schedule.next_request = 0
        url = "https://example.com/new"
        app.add_row(url, "No existing report", {"kind": "url", "status": "not_found", "assessment": "unknown"})
        with patch("app.messagebox.askokcancel", return_value=False), patch("app.analysis_api.submit") as submit:
            app.submit_selected()
            submit.assert_not_called()
        accepted = {"source": "virustotal", "kind": "url", "status": "submitted", "assessment": "unknown", "analysis_id": "u-demo-123"}
        with patch("app.messagebox.askokcancel", return_value=True), patch("app.analysis_api.submit", return_value=accepted) as submit:
            app.submit_selected()
            deadline = time.monotonic() + 3
            while app.lookup_busy and time.monotonic() < deadline:
                root.update()
                time.sleep(0.01)
            submit.assert_called_once_with(url, "synthetic-key")
        assert app.submit_button.cget("text") == "Refresh analysis"
        app.schedule.next_request = 0
        completed = {**accepted, "status": "completed", "stats": {"malicious": 0, "suspicious": 0, "undetected": 5}, "assessment": "no_detections_reported"}
        with patch("app.analysis_api.refresh", return_value=completed) as refresh, patch("app.analysis_api.submit") as submit:
            app.submit_selected()
            deadline = time.monotonic() + 3
            while app.lookup_busy and time.monotonic() < deadline:
                root.update()
                time.sleep(0.01)
            refresh.assert_called_once_with("u-demo-123", "synthetic-key")
            submit.assert_not_called()
        assert app.status.get() == "Analysis completed"
        root.update()
        for widget in (app.detail, app.table):
            assert widget.winfo_y() + widget.winfo_height() <= widget.master.winfo_height()
        print("GUI smoke passed: offline demo, start/stop, stale OCR rejection, automatic lookup, submission cancellation, submission and refresh with mocked API, layout.")
    finally:
        app.close()


if __name__ == "__main__":
    main()
