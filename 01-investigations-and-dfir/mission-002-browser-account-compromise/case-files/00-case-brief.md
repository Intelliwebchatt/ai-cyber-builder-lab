# Case brief

**Case ID:** M002-2026  
**Status:** Owner-approved case-file draft for synthetic training scenario; mission not yet marked completed  
**Classification:** Synthetic educational data  
**Analyst:** Shane Lockhart  
**Disposition (owner-approved):** Suspected account compromise — not confirmed

## Initial report

At `2026-08-12T16:02:40Z`, fictional employee `jordan.lee@example.test` reported an unexpected account-verification page and a later password-change confirmation (ticket `HD-2026-0812-017`, event **RPT-001**). In-scope systems for this synthetic case are asserted host `WS-217`, Chromium-like profile label `WS-217-chromium-synthetic`, and the attributed identity `jordan.lee@example.test` / `EXAMPLE\jordan.lee` per the fixture manifest (**E-005**).

Questions answered in case files 01–08 use only repository-authored synthetic sources (**E-001** through **E-007**) and Shane-approved investigative judgments. Analyzer rules **M002-R001** through **M002-R005** are investigation leads, not conclusions.

## Questions to answer

1. What happened, in chronological order?
2. Which observations are suspicious, and which remain ambiguous?
3. What additional evidence is required?
4. What immediate containment would be proportionate?
5. What controls could prevent or detect a similar event?

Answers are recorded in the evidence/hash log, browser inventory, combined timeline, identity correlation, hypotheses, ATT&CK hypothesis map, containment plan, and executive report. Case file 09 (owner reflection and AI disclosure) remains deferred.

## Known limitations

- No real browser profile, cookies, passwords, or session tokens are present.
- No email message artifact is supplied for the password-change notice or any delivery of a link.
- Documentation-range IP addresses (for example `198.51.100.77`) are safety markers, not reputation evidence.
- The browser History database does not authenticate who was at the keyboard; user attribution is lab-asserted in the manifest.
- Analyzer rules are leads, not conclusions.
- Download metadata includes byte counts with `payload_included=false`; no PDF bytes are in evidence, and malice, opening, or execution are not established.
- **Lab timestamp limitation:** `2026-07-19` timestamps in the evidence/hash log record the laboratory validation session only. They are **not** forensic acquisition times. Repository-authored synthetic scenario events are dated **`2026-08-12`**.

## Owner notes

Owner-approved judgments applied to case files 00–08:

1. Disposition: suspected account compromise — not confirmed.
2. Primary hypothesis: user interacted with a lookalike verification page; nearby MFA and password-change activity may be related, but causation is unconfirmed.
3. Priority/confidence: high investigation priority; moderate confidence in the suspicious correlation; business impact unknown.
4. Alternate explanation: authorized SSO/training page plus legitimate new-device enrollment or password-reset activity could produce the same sequence and must be verified.
5. Immediate response recommendations recorded in the containment plan (contact via trusted channel, revoke sessions, secure/reset account, review MFA/devices/sessions, preserve logs, temporarily block `accounts-example.test` pending verification, inspect PDF path via authorized endpoint telemetry without opening the file, check IT change-window/training/branding-test records).
