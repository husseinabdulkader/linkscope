"""Local screen recognition and bounded reputation scheduling. No GUI dependencies."""
from collections import deque
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import time
import math
from urllib.parse import urlsplit
import vtcheck


def extract_urls(text):
    """Only explicit HTTP(S) text; do not guess schemes or repair OCR output."""
    found = []
    for value in re.findall(r'https?://[^\s<>"\x00-\x1f]+', text, flags=re.IGNORECASE):
        value = value.rstrip(".,;!)]}'")
        try:
            vtcheck.url_id(value)
        except vtcheck.LookupError:
            continue
        if value not in found:
            found.append(value)
    return found[:20]


def automatic_eligible(url):
    """Conservative auto-send policy; not a complete confidentiality detector."""
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        return False
    if "." not in host or host.lower().endswith((".local", ".internal", ".localhost", ".lan")):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return True


def recognition_status(text, urls):
    """Explain empty detections without retaining or exposing captured text."""
    if urls:
        return f"Screen read complete: {len(urls)} URL(s) recognized"
    if not text.strip():
        return "Screen read complete: no text recognized. Enlarge the text and check the region."
    return ("Text recognized, but no full HTTP(S) URL found. In the browser press Ctrl+L "
            "to reveal the full address, or display the full URL in Notepad.")


class Schedule:
    """Deduplicate for this session and space API requests across manual/auto work."""
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.next_request = 0.0
        self.seen = set()
        self.pending = deque()
        self.requests = 0

    def add(self, urls):
        added = []
        for url in urls:
            if url not in self.seen and len(self.seen) < 500:
                self.seen.add(url)
                allowed = automatic_eligible(url)
                added.append((url, allowed))
                if allowed and len(self.pending) < 50:
                    self.pending.append(url)
        return added

    def reserve(self):
        if self.clock() < self.next_request or self.requests >= 100:
            return False
        self.next_request = self.clock() + 16
        self.requests += 1
        return True

    def availability(self):
        if self.requests >= 100:
            return 'Session limit reached (100 requests)'
        seconds = max(0, math.ceil(self.next_request - self.clock()))
        return f'Next API request in {seconds}s' if seconds else 'API ready'

    def stop(self):
        self.pending.clear()


class StableReads:
    """Require a URL in two consecutive observations before automatic submission."""
    def __init__(self):
        self.previous = set()

    def observe(self, urls):
        current = set(urls)
        stable = [url for url in urls if url in self.previous]
        self.previous = current
        return stable


def interpret_capture(payload):
    passes = payload.get('passes', [])
    if len(passes) != 2:
        return [], 'Recognition could not be verified. Check the link manually.'
    if any(item.get('edge') for item in passes):
        return [], 'Text touches the selection edge. Reselect with space around the entire address.'
    for item in passes:
        for line in item.get('text', '').splitlines():
            match = re.search(r'https?://', line, re.IGNORECASE)
            # Address-bar icons may be recognized as words before the URL. Ignore that
            # prefix only; never remove spaces from the URL/path itself.
            if match and len(line[match.start():].split()) > 1:
                return [], 'URL text contains gaps or surrounding words. Select one complete address or paste it for a manual check.'
    candidates = [extract_urls(item.get('text', '')) for item in passes]
    if set(candidates[0]) != set(candidates[1]):
        return [], 'OCR readings disagree. Enlarge the address text or paste the full URL for a manual check.'
    urls = candidates[0]
    if urls:
        return urls, f'{len(urls)} URL(s) read consistently at two sizes.'
    return [], recognition_status(passes[-1].get('text', ''), [])


def capture_region(region):
    x, y, width, height = region
    if not all(type(n) is int for n in region) or not (20 <= width <= 4096 and 20 <= height <= 4096):
        raise vtcheck.LookupError("Select a region between 20 and 4096 pixels per dimension.")
    script = Path(__file__).with_name("screen_ocr.ps1")
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script),
             "-X", str(x), "-Y", str(y), "-Width", str(width), "-Height", str(height)],
            capture_output=True, timeout=25, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if completed.returncode:
            raise vtcheck.LookupError("Screen recognition unavailable. Check Windows OCR language support and region size.")
        return json.loads(completed.stdout.decode("utf-8-sig"))
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError):
        raise vtcheck.LookupError("Screen recognition failed or timed out; monitoring stopped.") from None


def read_region(region):
    """Raw best-scale text for local diagnostic tests; auto checks use interpret_capture."""
    return capture_region(region)['text']
