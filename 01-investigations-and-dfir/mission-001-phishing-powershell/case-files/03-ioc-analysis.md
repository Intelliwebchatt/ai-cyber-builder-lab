# Indicator analysis

| Indicator | Type | Supporting events | Context | Assessment | Confidence |
|---|---|---|---|---|---|
| Unexpected invoice email with spreadsheet attachment (`Updated invoice 1048` / `billing@vendor.example`) | Email / delivery observable | EVT-001, EVT-008 | User later reported the message as unexpected and stated the attachment was opened. Headers, attachment bytes, and authentication results are not in the dataset. | Suspicious delivery and reported interaction. Not proof the attachment was malicious. | Medium that delivery and user report occurred; low that the file was malicious |
| `spreadsheet.exe` → `powershell.exe` parent-child relationship | Process relationship | EVT-002 | Matches analyzer lead R-001. Command line is explicitly `Write-Output 'SIMULATED_TEST_EVENT'`. | Suspicious office-to-script-engine behavior requiring investigation. Does not establish malware execution or compromise. | High that the process relationship occurred; low that purpose was malicious |
| PowerShell script block `Write-Output 'SIMULATED_TEST_EVENT'` | Script execution observable | EVT-003 | Logged 2 seconds after EVT-002 on WS-104 for the same account. | Corroborates PowerShell ran. Logged command is simulated; malicious intent unconfirmed. | High that PowerShell script-block logging occurred; low for malicious purpose |
| Outbound connection from `powershell.exe` to `203.0.113.50:443` | Network destination (documentation-range IP) | EVT-004 | Occurs 19 seconds after PowerShell process creation. Matches R-002. | Suspicious timing relative to PowerShell. Documentation-range IP cannot establish real threat reputation, C2, or exfiltration. | Medium that the synthetic connection was logged; none for real-world reputation |
| Failed network logons from `198.51.100.24` (logon type 3), three events | Authentication failure cluster | EVT-005, EVT-006, EVT-007 | Same host, account, and source IP within 18 seconds. Matches R-003. | Ambiguous. Possible brute-force lead only. Relationship to the email/PowerShell sequence is unconfirmed. Documentation-range source IP. | Low for brute force; none for successful credential access or confirmed relation to EVT-001–EVT-004 |
| Account `EXAMPLE\alex.morgan` / user `alex.morgan` | Identity context | EVT-001 through EVT-008 | Appears across mail, endpoint, failed logons, and the helpdesk report. | Relevant investigative pivot. Not evidence of account compromise. | High as an observed identity string; none for compromise |
| Host `WS-104` | Endpoint context | EVT-002 through EVT-007 | Host of process, PowerShell, network, and failed-logon telemetry. | Primary workstation of interest for proportionate containment and evidence preservation. Compromise not confirmed. | High as observed host; none for confirmed compromise |

## Required distinctions

- An observable is not automatically malicious.
- A documentation-range IP is fictional and cannot establish real threat reputation.
- A suspicious process relationship requires context and corroboration.
- Failed logons require identity and network correlation before attribution.
- Analyzer rules R-001, R-002, and R-003 are investigation leads from E-002, not conclusions.
- The supplied evidence does not establish causation, malicious payload execution, command and control, compromise, attribution, credential theft, data loss, or financial loss.

## Additional evidence requests

Request next (authorized lab / synthetic-scenario collection only):

1. Complete email headers, authentication results, attachment name/hash/metadata, and mail trace.
2. Full endpoint process tree, command-line context, EDR telemetry, persistence checks, and relevant PowerShell logs.
3. Successful and failed authentication records, account/session history, MFA activity, and identity-provider risk events.
4. DNS, proxy, firewall, and network-flow records around the event window.
5. Authorized user interview covering the message, attachment interaction, expected activity, and observed symptoms.
6. Any telemetry needed to confirm or disprove a connection between EVT-001 through EVT-004 and EVT-005 through EVT-007.
