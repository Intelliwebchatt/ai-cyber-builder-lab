# Executive incident report

**Status:** Complete for synthetic training scenario  
**Audience:** Business and security leadership  
**Case ID:** M001-2026  
**Analyst:** Shane Lockhart

## Executive summary

A fictional employee reported opening an unexpected invoice attachment. The supplied synthetic telemetry shows a suspicious sequence: invoice email delivery (EVT-001), user report of opening the attachment (EVT-008), spreadsheet application launching PowerShell (EVT-002), matching PowerShell script-block logging (EVT-003), and a PowerShell outbound connection seconds later (EVT-004). Three failed network logons also appear shortly afterward (EVT-005 through EVT-007); any link to the email activity is unconfirmed.

Compromise is **not confirmed**. The evidence requires proportionate containment and further investigation, not a declaration of system compromise, credential theft, data loss, or financial loss.

Recommended decision: treat this as a suspicious workstation and account investigation, apply reversible containment and evidence preservation for `WS-104` and the affected account, collect the missing mail/endpoint/identity/network/user context, and avoid irreversible reimaging until required evidence is preserved.

## Business impact

**Confirmed impact**

- Suspicious workstation and account activity requiring investigation and proportionate containment (EVT-001 through EVT-008; E-001, E-002).

**Potential impact only (unconfirmed)**

- System compromise
- Credential loss
- Data exposure
- Operational disruption
- Financial loss

## Actions taken

### Performed in this repository lab

1. Confirmed authorized base commit and clean working tree.
2. Ran Mission 001 unit tests (5 passed).
3. Generated ignored analyzer output from the synthetic dataset (E-002 from E-001).
4. Calculated and rechecked SHA-256 hashes for E-001 and E-002 during the Phase A collection session at `2026-07-18T13:08:41Z`.
5. Completed case files using owner-approved investigative judgments.
6. Independently supervising review reproduced tests, hashes, analyzer output, chronology, elapsed times, and rule mappings (recorded in Issue #6 checkpoints).

### Recommended for the synthetic scenario (not executed against a real system)

1. Isolate `WS-104` with a reversible control while preserving evidence.
2. Restrict the affected account and invalidate active sessions as appropriate.
3. Quarantine the message and search authorized mail telemetry for other copies.
4. Preserve and collect endpoint, email, identity, DNS, proxy, and firewall telemetry.
5. Do not wipe or reimage the host before required evidence is preserved.

## Key findings

1. Strongest suspicious relationship: EVT-001 → EVT-008 → EVT-002 → EVT-003 → EVT-004 (invoice email, reported attachment open, spreadsheet-launched PowerShell, script-block log, outbound connection). Supported as leads by E-002 rules R-001 and R-002.
2. PowerShell activity is observed with higher confidence that it ran (EVT-002, EVT-003), but the logged command is explicitly simulated and malicious purpose is unconfirmed.
3. Destination `203.0.113.50` and failed-logon source `198.51.100.24` are documentation-range examples and are not real threat intelligence.
4. Failed logons EVT-005 through EVT-007 support only a low-confidence brute-force possibility (R-003). Relation to the email/PowerShell sequence is unconfirmed.
5. The dataset does not establish causation, malicious payload execution, command and control, compromise, attribution, credential theft, data loss, or financial loss.

## Recommendations

**Immediate**

- Reversible isolation of `WS-104`, account/session restriction, message quarantine, and evidence preservation as listed above.

**Short-term**

- Email filtering and attachment controls.
- PowerShell logging, appropriate execution controls, and detection of office-to-script-engine process relationships.
- MFA, session controls, identity monitoring, and detection of repeated failed logons.

**Strategic**

- User reporting and awareness reinforcement.
- Safe synthetic validation tests demonstrating that each proposed control produces observable success evidence.
- Do not treat blocking documentation-range IPs as meaningful threat remediation.

## Limitations

- Synthetic educational dataset only; no live targets or real credentials.
- Missing email headers/attachment, full process tree/EDR/persistence context, identity/MFA/session detail, and DNS/proxy/firewall/flow telemetry.
- Analyzer output (E-002) is an investigative lead, not a conclusion.
- ATT&CK mappings are behavioral candidates with stated confidence limits; they do not prove attacker identity or successful compromise.
- Alternate explanations remain open, including unexpected but non-malicious software behavior, unrelated authentication noise, and coincidental timing between the email/PowerShell sequence and the failed logons.

## Personal reflection

The hardest part was maintaining vigilance in the work environment while ensuring every action remained compliant with security and evidence-handling procedures.

The evidence that most influenced my assessment was the spreadsheet launching PowerShell and PowerShell making an outbound connection seconds later. That sequence was unusual enough to require immediate investigation, but it did not prove the computer was compromised.

Next, I would collect the complete email, endpoint, identity, network, and user-context evidence needed to confirm or disprove the working theory.

I need to strengthen my ability to correlate email, endpoint, identity, and network logs while separating facts from assumptions.

## AI assistance disclosure

AI assisted with the repository scaffold, question structure, hypotheses, organization, technical editing, and code/review support. Shane Lockhart made the final investigative choices. Cursor executed Phase A deterministic evidence collection. The supervising reviewer independently reproduced the tests, hashes, analyzer output, event chronology, elapsed times, and rule mappings. AI output was treated as a lead and checked against the synthetic dataset. Cursor implemented Phase C case-file content only from those owner-approved judgments and did not invent or strengthen conclusions.
