# Synthetic reputation triage

All evidence in this exercise is invented. No URL was visited or submitted, and no file was downloaded.

At a fixed reference time of 2026-11-10 00:00 UTC, the offline demo processes four scenarios:

| Scenario | Evidence | Decision |
| --- | --- | --- |
| Flagged | 3 malicious, 1 suspicious, 66 undetected | Prioritize review; do not open the link based on the majority count |
| Zero detections | 0 malicious, 0 suspicious, 70 undetected | Insufficient evidence to establish safety |
| Incomplete | Empty statistics | Unknown; collect more evidence |
| Not found | No report returned | Unknown; no automatic scan |

The first three fixtures carry a fixed last-analysis timestamp, displayed by the demo. There is no observed endpoint or email timeline. Plausible explanations for a flagged result include a harmful resource, a false positive, or a historical verdict that no longer describes the content. Missing evidence includes sender identity, delivery context, redirect destinations, downloaded-file hash and endpoint activity.

An analyst should correlate the indicator with the reported message or alert, inspect report recency, and follow an authorized incident-response process if exposure occurred. A reputation count alone cannot establish execution, account compromise or organizational impact. Severity depends on those facts; this standalone exercise cannot assign an incident severity.

The key lesson is that lookup success, zero detections and safety are different claims. API errors must also remain separate from an absent or inconclusive report.
