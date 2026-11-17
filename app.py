"""LinkScope desktop application. Screen monitoring is always off at startup."""
import ctypes
import json
import os
from pathlib import Path
import queue
import threading
import time
import math
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import monitor
import vtcheck
import desktop_ui
import presentation
import analysis_api


class LinkScope:
    def __init__(self, root):
        self.root = root
        root.title("LinkScope | URL & File Reputation")
        root.geometry("980x760")
        root.minsize(940, 740)
        self.events = queue.Queue()
        self.schedule = monitor.Schedule()
        self.stable_reads = monitor.StableReads()
        self.region = None
        self.running = False
        self.ocr_busy = False
        self.lookup_busy = False
        self.generation = 0
        self.capture_count = 0
        self.last_capture = None
        self.next_capture = time.monotonic() + 5
        self.request_target = ""
        self.rows = {}
        self.analyses = {}
        self.key = tk.StringVar(value=os.environ.get("VT_API_KEY", ""))
        self.value = tk.StringVar()
        self.kind = tk.StringVar(value="URL")
        self.status = tk.StringVar(value="Ready · Screen monitoring is off")
        self.region_label = tk.StringVar(value="No region selected")
        self.scan_status = tk.StringVar(value="Screen reader idle · Full http:// or https:// address required")
        self.monitor_badge = tk.StringVar(value="STOPPED")
        self.capture_activity = tk.StringVar(value="Screen reader stopped")
        self.request_activity = tk.StringVar(value="API ready · 0 requests · 0 queued")
        self.auto = tk.BooleanVar(value=False)
        self._build()
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.bind("<Escape>", lambda _: self.stop())
        root.after(150, self.tick)
        root.after(5000, self.capture_tick)

    def _build(self):
        desktop_ui.build(self)

    def show_detail(self, text):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", text)
        self.detail.configure(state="disabled")

    def add_row(self, value, label, report=None):
        label = presentation.LABELS.get(label, label)
        payload = dict(report) if report else {"indicator": value, "status": label}
        payload["display_indicator"] = value
        existing = next((row for row, item in self.rows.items()
                         if item.get("display_indicator") == value), None)
        if existing:
            row = existing
            self.table.item(row, values=(value, label, time.strftime("%H:%M:%S")))
        else:
            if len(self.rows) >= 500:
                oldest = next(iter(self.rows))
                self.table.delete(oldest)
                del self.rows[oldest]
            row = self.table.insert("", 0, values=(value, label, time.strftime("%H:%M:%S")))
        self.rows[row] = payload
        self.table.selection_set(row)
        self.table.see(row)
        self.details()

    def details(self, _event=None):
        selected = self.table.selection()
        if selected:
            report = self.rows[selected[0]]
            self.show_detail(presentation.describe(report))
        self.refresh_actions()

    def refresh_actions(self):
        selected = self.table.selection()
        ready = not self.lookup_busy and self.schedule.clock() >= self.schedule.next_request and self.schedule.requests < 100
        if not selected:
            self.check_selected_button.configure(state='disabled')
            self.submit_button.configure(state='disabled')
            return
        report = self.rows[selected[0]]
        value = report.get("display_indicator", "")
        valid = value.startswith(("https://", "http://")) and report.get("source") != "synthetic_fixture"
        self.check_selected_button.configure(state="normal" if valid and ready else "disabled")
        scan = self.analyses.get(value)
        can_refresh = scan and scan.get('analysis_id')
        self.submit_button.configure(text='Refresh analysis' if can_refresh else 'Submit URL for analysis',
            state='normal' if valid and ready and (can_refresh or (not scan and report.get('status') == 'not_found')) else 'disabled')

    def update_activity(self):
        self.monitor_badge.set('MONITORING' if self.running else 'STOPPED')
        self.start_button.configure(state='disabled' if self.running else 'normal')
        self.stop_button.configure(state='normal' if self.running else 'disabled')
        if not self.running:
            capture = 'Screen reader stopped'
        elif self.ocr_busy:
            capture = 'Reading selected region now…'
        else:
            seconds = max(0, math.ceil(self.next_capture - time.monotonic()))
            capture = f'Next screen read in {seconds}s'
        self.capture_activity.set(f'{capture} · {self.capture_count} reads' +
                                  (f' · Last read {self.last_capture}' if self.last_capture else ''))
        api = f'Request in progress: {self.request_target}' if self.lookup_busy else self.schedule.availability()
        self.request_activity.set(f'{api} · {self.schedule.requests}/100 requests · {len(self.schedule.pending)} queued')
        self.refresh_actions()

    def submit_selected(self):
        selected = self.table.selection()
        if not selected or self.lookup_busy:
            self.status.set('Wait for the current request to finish')
            return
        report = self.rows[selected[0]]
        url = report.get('display_indicator', '')
        scan = self.analyses.get(url)
        if report.get('source') == 'synthetic_fixture' or not url.startswith(('http://', 'https://')):
            return
        identifier = scan.get('analysis_id') if scan else None
        if not identifier and (scan or report.get('status') != 'not_found'):
            return
        key = self.key.get()
        if not key.strip():
            self.status.set('Enter your API key under API settings')
            return
        if self.schedule.clock() < self.schedule.next_request or self.schedule.requests >= 100:
            self.status.set(self.schedule.availability())
            return
        if not identifier and not messagebox.askokcancel('Submit this URL for analysis?',
                'Check that OCR read the exact URL correctly:\n\n' + url +
                '\n\nThis requests a new VirusTotal analysis. The URL may be visited and included in its community dataset. '
                'Do not submit private links, access tokens, or confidential content. Continue?', parent=self.root):
            return
        if not self.schedule.reserve():
            return
        self.lookup_busy = True
        self.request_target = 'analysis progress' if identifier else 'URL submission'
        self.analyses[url] = scan or {'status': 'submitting'}
        self.details()
        self.status.set('Checking analysis progress…' if identifier else 'Submitting URL for analysis…')
        def work():
            try:
                result = analysis_api.refresh(identifier, key) if identifier else analysis_api.submit(url, key)
                self.events.put(('analysis_result', url, result))
            except Exception as exc:
                message = str(exc) if isinstance(exc, vtcheck.LookupError) else 'Request failed'
                if not identifier:
                    message += ' Submission was not confirmed; it may have reached VirusTotal. No automatic retry was made.'
                self.events.put(('analysis_error', url, {'error': message}))
        threading.Thread(target=work, daemon=True).start()

    def check_selected(self):
        selected = self.table.selection()
        if not selected:
            return
        report = self.rows[selected[0]]
        value = report.get("display_indicator", "")
        if report.get("source") == "synthetic_fixture" or not value.startswith(("https://", "http://")):
            return
        if not monitor.automatic_eligible(value):
            if not messagebox.askokcancel("Review URL before sending",
                    "This link may contain private information. Checking it sends the full URL to VirusTotal. Continue?", parent=self.root):
                return
        self.lookup("url", value)

    def browse(self):
        selected = filedialog.askopenfilename(parent=self.root)
        if selected:
            self.kind.set("Local file")
            self.value.set(selected)

    def change_auto(self):
        if self.running:
            self.stop()
            self.status.set("Monitoring stopped · Press Start to apply the changed disclosure setting")

    def select_region(self):
        self.stop()
        overlay = tk.Toplevel(self.root)
        overlay.attributes("-fullscreen", True)
        overlay.attributes("-topmost", True)
        overlay.attributes("-alpha", 0.35)
        canvas = tk.Canvas(overlay, bg="#142f43", cursor="crosshair", highlightthickness=0)
        canvas.pack(fill="both", expand=True)
        canvas.create_text(30, 30, anchor="nw", text="Drag a rectangle around public link text. Escape cancels.", fill="white", font=("Segoe UI", 18))
        start = []
        rectangle = [None]
        def press(event):
            start[:] = [event.x_root, event.y_root]
            if rectangle[0]:
                canvas.delete(rectangle[0])
            rectangle[0] = canvas.create_rectangle(event.x, event.y, event.x, event.y, outline="white", width=3)
        def drag(event):
            if start:
                canvas.coords(rectangle[0], start[0] - overlay.winfo_rootx(), start[1] - overlay.winfo_rooty(), event.x, event.y)
        def release(event):
            if not start:
                return
            x, y = min(start[0], event.x_root), min(start[1], event.y_root)
            w, h = abs(start[0] - event.x_root), abs(start[1] - event.y_root)
            overlay.destroy()
            if 20 <= w <= 4096 and 20 <= h <= 4096:
                self.region = (x, y, w, h)
                self.region_label.set(f"Region: {x}, {y} · {w} × {h} px")
            else:
                self.status.set("Choose a region between 20 and 4096 pixels per dimension")
        canvas.bind("<ButtonPress-1>", press)
        canvas.bind("<B1-Motion>", drag)
        canvas.bind("<ButtonRelease-1>", release)
        overlay.bind("<Escape>", lambda _: overlay.destroy())
        overlay.grab_set()
        overlay.focus_force()

    def start(self):
        if self.running:
            return
        if not self.region:
            self.status.set("Select a screen region first")
            return
        if self.auto.get() and not self.key.get().strip():
            self.status.set("Enter an API key or turn off automatic lookup to use local detection only")
            return
        if self.auto.get() and not messagebox.askokcancel("Enable automatic URL disclosure?",
                "URLs recognized in your selected region will be sent to VirusTotal. Paths can contain private information. "
                "Select only public content. OCR may misread URLs. Screenshots stay local and are not saved. Continue?", parent=self.root):
            return
        self.running = True
        self.stable_reads = monitor.StableReads()
        self.schedule.seen.clear()
        self.generation += 1
        self.scan_status.set("Waiting for the next screen read (up to 5 seconds)…")
        self.status.set("Monitoring started · Leave the selected area visible")
        self.activity_bar.start(40)
        self.update_activity()

    def stop(self):
        self.running = False
        self.generation += 1
        self.schedule.stop()
        self.scan_status.set("Screen reader stopped")
        self.status.set("Stopped · Pending lookups cleared; an already sent request may finish")
        self.activity_bar.stop()
        self.update_activity()

    def capture_tick(self):
        if self.running and not self.ocr_busy:
            self.ocr_busy = True
            generation, region = self.generation, self.region
            def work():
                try:
                    urls, diagnostic = monitor.interpret_capture(monitor.capture_region(region))
                    self.events.put(("ocr_status", generation, diagnostic))
                    self.events.put(("ocr", generation, urls))
                except Exception:
                    self.events.put(("ocr_error", generation, "Screen recognition failed. Check Windows OCR language support."))
            threading.Thread(target=work, daemon=True).start()
        self.next_capture = time.monotonic() + 5
        self.root.after(5000, self.capture_tick)

    def manual(self):
        command = {"URL": "url", "SHA-256": "hash", "Local file": "file"}[self.kind.get()]
        self.lookup(command, self.value.get().strip())

    def lookup(self, command, value):
        if self.lookup_busy:
            self.status.set("A lookup is already running")
            return
        key = self.key.get()
        if not key.strip():
            self.status.set("Enter an API key for live reports, or load the offline demo")
            return
        try:
            if command != "file":
                {"url": vtcheck.url_id, "hash": vtcheck.validate_hash}[command](value)
        except vtcheck.LookupError as exc:
            self.status.set(str(exc))
            return
        if not self.schedule.reserve():
            self.status.set(self.schedule.availability())
            return
        self.lookup_busy = True
        self.request_target = "existing report"
        self.add_row(value, "Checking existing report…")
        self.status.set("Looking up existing report…")
        def work():
            try:
                identifier = {"url": vtcheck.url_id, "hash": vtcheck.validate_hash, "file": vtcheck.hash_file}[command](value)
                kind = "url" if command == "url" else "file"
                result = vtcheck.summarize(vtcheck.fetch_report(kind, identifier, key), kind, identifier)
                self.events.put(("report", value, result))
            except (vtcheck.LookupError, OSError) as exc:
                self.events.put(("lookup_error", value, str(exc) if isinstance(exc, vtcheck.LookupError) else "Unable to read the file"))
            except Exception:
                self.events.put(("lookup_error", value, "Unexpected lookup failure"))
        threading.Thread(target=work, daemon=True).start()

    def tick(self):
        while not self.events.empty():
            event, subject, data = self.events.get_nowait()
            if event.startswith("ocr"):
                if event == "ocr_status":
                    if self.running and subject == self.generation:
                        self.scan_status.set(data)
                    continue
                self.ocr_busy = False
                if not self.running or subject != self.generation:
                    continue
                if event == "ocr_error":
                    self.stop()
                    self.status.set(data)
                    continue
                self.capture_count += 1
                self.last_capture = time.strftime("%H:%M:%S")
                stable = self.stable_reads.observe(data)
                for url in data:
                    if url not in stable and not any(row.get("display_indicator") == url for row in self.rows.values()):
                        self.add_row(url, "Confirming URL · Read 1 of 2")
                if data and not stable:
                    self.scan_status.set("Link detected · Waiting for a second matching screen read before lookup")
                if stable and all(url in self.schedule.seen for url in stable):
                    self.scan_status.set("Same link still visible · Already processed this session · Watching for a different link")
                for url, eligible in self.schedule.add(stable):
                    self.add_row(url, presentation.detected_state(self.auto.get(), eligible, url in self.schedule.pending))
                if not self.auto.get():
                    self.schedule.stop()
            else:
                self.lookup_busy = False
                if event == 'analysis_result':
                    self.analyses[subject] = data
                    self.add_row(subject, presentation.result_label(data), data)
                    self.status.set(presentation.result_status(data))
                elif event == 'analysis_error':
                    self.add_row(subject, 'Analysis request failed', data)
                    self.stop()
                    self.status.set('Analysis request failed · See details; no automatic retry')
                elif event == "lookup_error":
                    self.add_row(subject, "Lookup error", {"error": data})
                    self.stop()
                    self.status.set(data + " · Automatic monitoring stopped")
                else:
                    self.add_row(subject, presentation.result_label(data), data)
                    self.status.set(presentation.result_status(data) + (" · Monitoring remains active" if self.running else " · Monitoring off"))
        if (self.running and self.auto.get() and self.schedule.pending and not self.lookup_busy
                and self.schedule.clock() >= self.schedule.next_request and self.schedule.requests < 100):
            self.lookup("url", self.schedule.pending.popleft())
        self.update_activity()
        self.root.after(150, self.tick)

    def demo(self):
        self.stop()
        for name in ("flagged", "zero-detections", "incomplete"):
            payload = json.loads((Path(__file__).parent / "fixtures" / f"{name}.json").read_text())
            result = vtcheck.summarize(payload, "url", vtcheck.url_id("https://example.com/"))
            result["source"] = "synthetic_fixture"
            result.pop("report_url", None)
            self.add_row(f"SYNTHETIC / {name}", result["assessment"], result)
        self.status.set("Offline demo · Synthetic evidence · No network requests")

    def close(self):
        self.stop()
        self.key.set("")
        self.root.destroy()


def main():
    if os.name == "nt":
        ctypes.windll.user32.SetProcessDPIAware()
    root = tk.Tk()
    LinkScope(root)
    root.mainloop()


if __name__ == "__main__":
    main()
