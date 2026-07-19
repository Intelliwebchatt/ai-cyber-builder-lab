# Containment and remediation plan

All containment and remediation items below are **recommended actions for the synthetic scenario** unless explicitly recorded as lab actions performed in this repository. Lab actions actually performed are limited to local fixture build, unit tests, analyzer generation, hashing, and case-file drafting recorded in the evidence log (**E-001**–**E-007**).

Owner disposition guiding proportionate response: **suspected account compromise — not confirmed.** High investigation priority; do not declare confirmed compromise, credential theft, session theft, malware, or attribution from the current dataset.

## Immediate containment

Owner-approved immediate response recommendations:

1. Contact the user (`jordan.lee@example.test`) through a **trusted channel** (not through any unverified page or the non-allowlisted host).
2. Revoke active sessions for the attributed account.
3. Secure / reset the account using approved identity procedures.
4. Review MFA factors, enrolled devices, and identity sessions for anomalies relative to known-good inventory.
5. Preserve relevant identity, endpoint, mail, DNS/proxy, and help-desk logs for the scenario window on **2026-08-12**.
6. Temporarily block `accounts-example.test` pending verification whether the host is authorized (training/branding) or not.
7. Inspect the PDF path `C:\Users\jordan.lee\Downloads\account-security-notice.pdf` using **authorized endpoint telemetry without opening the file**. Do not assume malice, opening, or execution from download metadata alone (`payload_included=false`).
8. Check IT change-window, training, and branding-test records that could explain an authorized SSO/demo host and legitimate new-device or password-reset activity.

## Evidence preservation

1. Preserve IdP authentication, MFA, device enrollment, password-change, and session records for `jordan.lee@example.test` around ID-001–ID-003.
2. Preserve browser-related endpoint telemetry for `WS-217` consistent with asserted profile attribution in **E-005**, without collecting real cookies, passwords, or tokens in this lab.
3. Preserve help-desk ticket `HD-2026-0812-017` (**RPT-001**) as narrative context.
4. Preserve DNS/proxy/web-filter logs for inert host strings `accounts.example.test` and `accounts-example.test` if available in an authorized environment.
5. Maintain hash-verified copies of lab artifacts **E-001**–**E-007**; keep generated SQLite and generated Markdown ignored and untracked.

## Eradication and recovery

1. After evidence preservation, restore normal access only when session revocation, account securing, and device/MFA review support an informed risk decision.
2. If `accounts-example.test` is confirmed unauthorized, keep blocking/detection controls and hunt for related activity; if confirmed as authorized training/branding, document that finding and adjust user guidance.
3. Do not treat blocking documentation-range IP `198.51.100.77` as meaningful threat remediation.
4. Do not wipe or reimage solely from analyzer leads; escalate only if authorized follow-up evidence justifies it.

## Prevention and detection improvements

1. Exact-host allowlisting / lookalike detection for identity portals (string and visual similarity monitoring in authorized tooling).
2. Detection of MFA success on new devices near unusual browser or portal hosts.
3. Alerts for self-service password changes shortly after new-device MFA from unfamiliar context.
4. User reporting paths that prefer trusted-channel contact when unexpected verification or password prompts appear.
5. Playbooks that separate download **metadata** preservation from file opening; authorize controlled malware analysis only when payload collection is approved.

## Validation steps

| Recommendation | Owner | Priority | Validation test | Success evidence |
|---|---|---|---|---|
| Trusted-channel user contact | Help desk / IR | Immediate | Tabletop: contact path does not use the suspect host | Ticket notes show trusted channel; no coaching to revisit non-allowlisted URL |
| Session revocation | Identity | Immediate | Synthetic account exercise: revoke sessions | IdP logs show revocation; subsequent use requires re-authentication |
| Account secure/reset | Identity | Immediate | Approved reset procedure on test account | Password/MFA state updated; old sessions invalid |
| MFA / device / session review | Identity | Immediate | Compare test enrollment set to known-good inventory | Documented review outcome; unknown devices flagged or cleared |
| Temporary block of `accounts-example.test` | Network / web security | Immediate | Deploy block in lab policy for the inert hostname string | Block/hit logs for test requests; exception process documented |
| PDF path telemetry without opening | Endpoint / DFIR | Immediate | Query EDR/file inventory for path/hash/open events on a test host | Telemetry returned; analyst does not open the file during triage |
| IT branding/training verification | IT / IAM | Immediate | Search change-window and training records for the host/theme | Either authorizing record found and cited, or absence documented as gap |
