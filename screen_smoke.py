"""Windows-only capture/OCR/integration check using a controlled sample window.

Displays public example.com strings; never reads unrelated windows or calls VirusTotal.
Run from the project folder: python screen_smoke.py
"""
import ctypes
import json
import time
import tkinter as tk
from unittest.mock import patch
import monitor
import vtcheck
from app import LinkScope


def main():
    ctypes.windll.user32.SetProcessDPIAware()
    root = tk.Tk()
    app = LinkScope(root)
    sample = tk.Toplevel(root)
    sample.title('LinkScope controlled OCR sample')
    sample.geometry('900x70+20+20')
    sample.attributes('-topmost', True)
    label = tk.Label(sample, anchor='w', padx=12, pady=8)
    label.pack(fill='both', expand=True)
    observations = []
    try:
        cases = [
            (8, 'white', 'black', 'https://example.com/guides/test-page'),
            (9, 'white', 'black', 'https://example.com/guides/test-page'),
            (10, '#202124', '#e8eaed', 'https://example.com/guides/test-page'),
            (12, '#2563eb', 'white', 'https://example.com/'),
            (10, 'white', 'black', 'https://example.com/?token=synthetic'),
        ]
        for size, background, foreground, url in cases:
            label.configure(text=url, font=('Segoe UI', size), bg=background, fg=foreground)
            root.update()
            region = (label.winfo_rootx(), label.winfo_rooty(), label.winfo_width(), label.winfo_height())
            urls, diagnostic = monitor.interpret_capture(monitor.capture_region(region))
            observations.append({'font_points': size, 'background': background, 'expected': url,
                                 'recognized': urls, 'exact': urls == [url], 'diagnostic': diagnostic})
            # Recognition depends on display rendering; an uncertain read must not silently change a URL.
            assert not urls or urls == [url], 'OCR produced an incorrect accepted URL'
        label.configure(text='https://example.com/', font=('Segoe UI', 12), bg='white', fg='black')
        root.update()
        app.region = region
        app.auto.set(True)
        app.key.set('synthetic-key-not-a-real-credential')
        with patch('app.messagebox.askokcancel', return_value=True), patch('app.vtcheck.fetch_report', return_value=None) as fetch:
            app.start()
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline and not fetch.called:
                root.update()
                time.sleep(0.02)
            assert fetch.called, 'No automatic lookup after stable screen captures'
            assert fetch.call_args.args == ('url', vtcheck.url_id('https://example.com/'), 'synthetic-key-not-a-real-credential')
            first_sent = time.monotonic()
            label.configure(text='https://example.org/second-link')
            root.update()
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline and fetch.call_count < 2:
                root.update()
                time.sleep(0.02)
            assert fetch.call_count == 2, 'Second visible link was not automatically checked'
            assert fetch.call_args.args[1] == vtcheck.url_id('https://example.org/second-link')
            assert time.monotonic() - first_sent >= 15, 'API pacing was not maintained'
            assert app.running and app.monitor_badge.get() == 'MONITORING'
            assert app.capture_count >= 4
            app.stop()
            assert not app.schedule.pending
            assert app.monitor_badge.get() == 'STOPPED'
        print(json.dumps({'synthetic': True, 'capture_cases': observations,
                          'automatic_capture_to_mock_lookup': 'passed for two successive URLs with real request pacing', 'live_api_called': False}, indent=2))
    finally:
        app.close()


if __name__ == '__main__':
    main()
