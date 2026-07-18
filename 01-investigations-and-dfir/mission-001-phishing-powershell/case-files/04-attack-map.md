# MITRE ATT&CK mapping

Map only behavior directly supported by evidence. A mapping describes observed technique-like behavior or a candidate hypothesis; it does not prove attacker identity or successful compromise.

Official MITRE ATT&CK definitions:

- [T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [T1204.002 User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/)

| Possible technique | Evidence | Why it may apply | Missing confirmation | Confidence |
|---|---|---|---|---|
| T1566.001 Spearphishing Attachment — **candidate hypothesis only** (not an observed or confirmed adversary technique) | EVT-001, EVT-008 | Unexpected invoice-themed email with spreadsheet attachment was delivered; user later reported opening that attachment. | Email headers, attachment content, sender authentication, and proof the file was malicious. Targeting and malicious attachment content are not established. | Limited / low-to-medium candidate hypothesis |
| T1204.002 User Execution: Malicious File — **candidate hypothesis only** (not an observed or confirmed adversary technique) | EVT-008 (with EVT-001 context) | User reports the attachment was opened. | The file itself is unavailable and is not proven malicious. | Low candidate hypothesis |
| T1059.001 PowerShell | EVT-002, EVT-003 | Spreadsheet application launched PowerShell and matching script-block telemetry was logged. PowerShell execution is directly observed; adversarial abuse is unconfirmed. | Malicious purpose of the PowerShell activity; logged command is explicitly simulated. | Higher that PowerShell ran; adversarial abuse unconfirmed |
| T1110 Brute Force — **candidate hypothesis only** (not an observed or confirmed adversary technique) | EVT-005, EVT-006, EVT-007 | Three failed network logons for the same account from the same source IP in a short window. | Proof of iterative password guessing; identity/network correlation; relation to the email activity. Three failures alone do not establish iterative password guessing. | Low candidate hypothesis |

## Explicit non-mappings

Do **not** map from this dataset:

- Command and control
- Exfiltration
- Credential theft
- Persistence
- Lateral movement
- Successful account compromise

ATT&CK is used here as a behavioral map and hypothesis aid, not as proof of compromise. T1566.001, T1204.002, and T1110 remain candidate hypotheses only. PowerShell execution (T1059.001) is directly observed in telemetry, while adversarial abuse of PowerShell remains unconfirmed.

## Coverage gaps

Data sources that would improve confidence:

- Complete mail telemetry (headers, auth results, attachment hash/metadata, mail trace)
- Full endpoint process tree, EDR, persistence checks, and richer PowerShell logging context
- Identity-provider authentication, MFA, and session risk events
- DNS, proxy, firewall, and network-flow records around the event window
- Authorized user interview and expected-activity baseline

Incident stages that cannot be assessed from the supplied evidence:

- Whether a malicious payload executed
- Whether outbound activity was command and control or data transfer
- Whether any credential was successfully used
- Whether persistence or lateral movement occurred
- Attribution and business loss
