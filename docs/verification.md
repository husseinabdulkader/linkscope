# Verification record

Verified locally on Windows with Python 3.14.2 on 2026-11-10:

- 25 unittest tests passed, with no skipped tests.
- Offline demo completed all four synthetic scenarios.
- CLI help rendered successfully.
- Missing-key and invalid-input paths are covered without network requests.

Tests mock the HTTP transport. They check the actual generated GET request, target URL, authentication header, absence of a request body, timeout configuration, error behavior and redirect handler. These tests do not establish live API compatibility or simulate every possible transport failure.

No `VT_API_KEY` was configured in the execution environment, so no live VirusTotal requests were performed. No files or URLs were submitted for scanning. At this initial verification milestone, GitHub Actions had not run. Ubuntu and other Python versions have not been locally verified.

For a live smoke test, configure your own key following the README, then look up a public URL you are authorized to disclose. Record the actual command, time, HTTP outcome and returned schema in a private note; do not commit the key or sensitive indicators. A 404 confirms an absent report, not a clean verdict. Do not replace synthetic fixtures with live evidence without labeling the source accurately.

## Screen-reader diagnostics update — 2026-11-17

39 automated tests passed. GUI smoke verification passed for startup, synthetic demo, start/stop, stale capture rejection and automatic lookup with a mocked API. Added regression cases for hidden URL schemes, blank captures and diagnostics that do not expose captured text. The user-reported browser capture has not been observed directly; a hidden scheme is a supported explanation, not a confirmed diagnosis of their screen. No live API result was verified during this update.

## Desktop usability update — 2026-11-17

45 automated tests passed. Desktop smoke checks passed, including selected-link dispatch with a mock and same-indicator row replacement. The detection-only layout was visually inspected at 1000 × 780 pixels. No live VirusTotal response was verified.

## Recognition reliability update — 2026-11-17

- 52 automated tests passed; GUI smoke passed.
- Controlled screen capture and real Windows OCR recognized all five final samples exactly: 8- and 9-point light text, 10-point dark-theme text, 12-point selected text, and a URL with a synthetic query token. The query example is for recognition testing; the automatic privacy filter holds query strings.
- Actual capture → enlarged OCR → agreement check → two consecutive matching reads → automatic request scheduling passed with a mocked API. Verified that the exact expected URL identifier reached the mocked transport and Stop cleared pending work.
- Earlier controlled 8- and 9-point samples were misread by the original OCR path. The revised reader recognized those exact samples correctly. A 6-point sample remained unreadable and was held. These are small controlled observations, not a general OCR accuracy percentage.
- No real VirusTotal API request was made during this update: the execution environment did not contain VT_API_KEY. A key entered into a different running GUI session was not extracted. Authentication, account quota and current live reports remain unverified.

The capture helper follows Windows OCR's documented [maximum image dimension](https://learn.microsoft.com/en-us/uwp/api/windows.media.ocr.ocrengine.maximagedimension) and uses recognized word bounds to detect text near the crop edge. Border checks cannot reliably detect every cropped or visually abbreviated URL. Manual paste remains the most exact input method.

## Explicit URL analysis — 2026-11-17

63 unit tests passed. Added coverage for form-encoded POST submission, accepted versus completed states, URL validation, escaped analysis IDs, GET refresh, queued/in-progress handling, completed counts, response identity mismatch, 404, timeout, quota and no retry. Desktop smoke tests cover cancelling confirmation, submission, and refreshing without another POST. All network calls were mocked; no live URL was submitted in this update. Missing reports now use “Lookup complete · No report found”.

## Continuous monitoring and activity feedback — 2026-11-17

65 unit tests passed and GUI smoke checks passed. A controlled test used real screen capture/OCR, changed from one visible public example URL to a second, and verified both exact identifiers reached the mocked API with the real request interval preserved. The monitoring badge remained active and changed to stopped on Stop. Five image cases still matched exactly.

The user-supplied screenshot was used locally to reproduce the address-bar failure: one OCR pass included icon text before the URL. After the targeted fix both passes produced the exact visible URL. The screenshot was not copied into the repository or sent to VirusTotal. Added regression coverage with a generic URL for that icon-prefix case, plus distinct cooldown/limit messages. Live API results remain unverified by the automated tests.
