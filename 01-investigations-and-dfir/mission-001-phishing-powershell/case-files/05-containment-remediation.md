# Containment and remediation plan

All containment and remediation items below are **recommended actions for the synthetic scenario**. They were **not** executed against a real system in this lab. Lab actions actually performed are limited to evidence hashing, unit tests, and local analyzer generation recorded in the evidence log (E-001, E-002).

## Immediate containment

Prioritize actions that preserve evidence and reduce risk without assuming facts not yet proven.

1. Isolate `WS-104` using a reversible control while preserving evidence.
2. Restrict the affected account and invalidate active sessions as appropriate.
3. Quarantine the message and search authorized mail telemetry for other copies.
4. Preserve and collect endpoint, email, identity, DNS, proxy, and firewall telemetry.
5. Do not wipe or reimage the host before required evidence is preserved.

## Evidence preservation

1. Preserve mail-gateway and mailbox copies of the invoice message, including headers and attachment metadata when available.
2. Collect endpoint telemetry for `WS-104` covering process tree, PowerShell logs, EDR alerts, and persistence checks around EVT-002 through EVT-004.
3. Preserve authentication and identity-provider records for `EXAMPLE\alex.morgan`, including successful and failed logons, MFA, and session history around EVT-005 through EVT-007.
4. Preserve DNS, proxy, firewall, and network-flow records for the event window, including activity involving `203.0.113.50` and `198.51.100.24` as synthetic correlation points only.
5. Maintain hash-verified copies of lab artifacts E-001 and E-002; keep `reports/generated-analysis.md` as an ignored local lead, not as committed proof.

## Eradication and recovery

1. After evidence preservation, remove or neutralize the quarantined message and any related unauthorized artifacts identified by authorized follow-up collection.
2. Restore or re-enable `WS-104` and the affected account only after investigative gaps are addressed enough to support a risk decision.
3. Reset or recover account access using approved identity procedures if investigation confirms credential risk; do not assume compromise from the current dataset alone.
4. Do not treat blocking the documentation-range IPs (`203.0.113.50`, `198.51.100.24`) as meaningful threat remediation.

## Prevention and detection improvements

Prioritize:

1. Reversible containment and evidence-preservation playbooks for similar workstation alerts.
2. Email filtering and attachment controls for unexpected invoice/spreadsheet lures.
3. PowerShell logging, appropriate execution controls, and detection of office-to-script-engine process relationships.
4. MFA, session controls, identity monitoring, and detection of repeated failed logons.
5. User reporting and awareness reinforcement for unexpected attachments.

## Validation plan

For each recommendation, define the evidence that would show the control is working. Validation tests below are safe synthetic checks only.

| Recommendation | Owner | Priority | Validation test | Success evidence |
|---|---|---|---|---|
| Reversible isolation of `WS-104` with evidence preserved | Incident response | Immediate | In a lab or authorized test host, apply and reverse the isolation control while confirming forensic artifacts remain readable | Isolation state change is logged; evidence hashes/collection remain intact; restore path works |
| Account restriction and session invalidation | Identity / IR | Immediate | Synthetic account exercise: disable or restrict test account and revoke sessions | Directory/IdP logs show restriction and session revocation; new interactive use blocked until re-enabled |
| Quarantine message and search for copies | Messaging security | Immediate | Inject a synthetic invoice/attachment test message; quarantine and mailbox search | Quarantine record exists; search returns expected synthetic copies; originals preserved for analysis |
| Email filtering and attachment controls | Email security | Short-term | Send authorized synthetic invoice-with-spreadsheet test messages through the filter policy | Policy logs show block/quarantine/sandbox outcomes for the test set; false-positive review documented |
| Detect office-to-script-engine process relationships | Detection engineering | Short-term | Replay or simulate parent-child telemetry equivalent to EVT-002 in a detection test harness | Alert/detection fires with supporting event IDs; analyst runbook references process-tree follow-up |
| PowerShell logging and execution controls | Endpoint security | Short-term | Execute an authorized benign PowerShell test command under policy | Script-block / constrained-language / allow-list controls produce expected logs or blocks |
| MFA, session controls, and failed-logon detection | Identity security | Short-term | Generate synthetic repeated failed logons similar to EVT-005–EVT-007 | Detection alert fires; MFA/session controls enforce challenge or lockout per policy |
| User reporting reinforcement | Security awareness / SOC | Strategic | Tabletop or phishing-simulation report path for unexpected attachment | Report reaches helpdesk/SOC with timestamped ticket comparable to EVT-008 workflow |
