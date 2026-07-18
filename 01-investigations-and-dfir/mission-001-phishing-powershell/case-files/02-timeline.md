# Investigative timeline

Complete this table from the source evidence. Add interpretation only in the final column.

| UTC timestamp | Event UID | Host or system | Observed fact | Interpretation and confidence |
|---|---|---|---|---|
| 2026-07-15T14:02:11Z | EVT-001 | mail.example.test | Mail gateway delivered message subject `Updated invoice 1048` with a spreadsheet attachment from `billing@vendor.example` to user `alex.morgan`. | Unexpected invoice-themed delivery begins the suspicious sequence. Attachment content, headers, and sender authentication are unavailable. Confidence that delivery occurred: high (directly logged). Confidence that the message is malicious: low / unconfirmed. |
| 2026-07-15T14:07:43Z | EVT-002 | WS-104 | Windows Security 4688: `spreadsheet.exe` created `powershell.exe` for `EXAMPLE\alex.morgan`. Command line logged as `powershell.exe -NoProfile -Command "Write-Output 'SIMULATED_TEST_EVENT'"`. | Office-like parent launching PowerShell is suspicious and supports analyzer lead R-001. Elapsed time from EVT-001: 5 minutes 32 seconds. Command text is explicitly simulated; malicious purpose is unconfirmed. Confidence of process creation: high. Confidence of compromise: none. |
| 2026-07-15T14:07:45Z | EVT-003 | WS-104 | PowerShell 4104 script-block log recorded `Write-Output 'SIMULATED_TEST_EVENT'` for the same user and host. | Corroborates PowerShell execution on WS-104 2 seconds after EVT-002. Supports observed PowerShell behavior; does not prove attacker intent. |
| 2026-07-15T14:08:02Z | EVT-004 | WS-104 | Sysmon network connection: `powershell.exe` connected to `203.0.113.50:443`. | Outbound connection seconds after PowerShell start is suspicious and supports R-002. Elapsed time from EVT-002: 19 seconds. Destination is a documentation-range IP and cannot establish real threat reputation. Causation, C2, and data transfer are unconfirmed. |
| 2026-07-15T14:12:09Z | EVT-005 | WS-104 | Windows Security 4625 failed network logon (type 3) for `EXAMPLE\alex.morgan` from `198.51.100.24`. | First of three failed logons. Relationship to EVT-001–EVT-004 is unconfirmed without identity and network correlation. Source IP is documentation-range. |
| 2026-07-15T14:12:18Z | EVT-006 | WS-104 | Second failed network logon (type 3) for the same account from the same source IP. | Continues the failed-logon cluster 9 seconds after EVT-005. Supports R-003 as a lead only. |
| 2026-07-15T14:12:27Z | EVT-007 | WS-104 | Third failed network logon (type 3) for the same account from the same source IP. | Completes three failed logons in 18 seconds. Possible brute-force behavior at low confidence; password guessing and relation to the email activity are not proven. |
| 2026-07-15T14:19:30Z | EVT-008 | helpdesk.example.test | User report: unexpected invoice message; user states the attachment was opened. | Links user interaction to EVT-001. Elapsed time from email delivery: 17 minutes 19 seconds; from final failed logon: 7 minutes 3 seconds. Supports candidate user-execution mapping at low confidence because the file is unavailable and not proven malicious. |

## Correlation questions

- How much time elapsed between email delivery, process execution, network activity, failed logons, and the user report?
  - Email (EVT-001) → PowerShell process (EVT-002): **5 minutes 32 seconds**
  - PowerShell process (EVT-002) → script block (EVT-003): **2 seconds**
  - PowerShell process (EVT-002) → outbound connection (EVT-004): **19 seconds**
  - Outbound connection (EVT-004) → first failed logon (EVT-005): **4 minutes 7 seconds**
  - Failed logons EVT-005 → EVT-007 span: **18 seconds**
  - Final failed logon (EVT-007) → user report (EVT-008): **7 minutes 3 seconds**
  - Email (EVT-001) → user report (EVT-008): **17 minutes 19 seconds**
- Which events share a host, account, process, or source address?
  - Host `WS-104` and account `EXAMPLE\alex.morgan`: EVT-002 through EVT-007
  - Process `powershell.exe`: EVT-002, EVT-003, EVT-004
  - Mail/user identity `alex.morgan`: EVT-001 and EVT-008
  - Failed-logon source IP `198.51.100.24`: EVT-005 through EVT-007
  - Destination IP `203.0.113.50`: EVT-004 only
- What telemetry would confirm or disprove a causal connection?
  - Complete email headers/auth results, attachment hash/metadata, full process tree and EDR context, authentication/MFA/session history, DNS/proxy/firewall/flow records, and authorized user interview — plus any evidence needed to confirm or disprove a link between EVT-001–EVT-004 and EVT-005–EVT-007.
