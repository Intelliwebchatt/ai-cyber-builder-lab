# MITRE ATT&CK mapping

Map only behavior directly supported by evidence. A mapping describes a candidate hypothesis; it does not prove adversary identity or successful compromise. The analyzer does not emit ATT&CK conclusions.

Official MITRE ATT&CK techniques to evaluate (hypothesis aids only):

- [T1566.002 Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/)

| Possible technique | Evidence | Why it may apply | Missing confirmation | Confidence |
|---|---|---|---|---|
| T1566.002 Spearphishing Link — candidate hypothesis only | BRW-001 → BRW-002 (LINK), BRW-003 tab/referrer metadata, RPT-001 narrative about an unexpected verify page | If a malicious link were delivered and followed, the non-allowlisted verification-themed visit could fit a phishing-link pattern under the primary hypothesis | T1566.002 requires evidence of an electronically delivered malicious link; this scaffold has **no message artifact**. Host lookalike is interpretation beyond exact allowlist mismatch. | Low — hypothesis only |
| T1078 Valid Accounts — candidate hypothesis only | ID-001, ID-002 (MFA challenge/success on attributed account); proximity to BRW-002 | If an adversary abused valid credentials or a session, successful MFA on a flagged new device could be consistent with use of a valid account | T1078 requires adversary abuse of valid credentials; an MFA success does **not** prove that. Legitimate new-device enrollment remains open. | Low — hypothesis only |
| T1098 Account Manipulation — candidate hypothesis only | ID-003 self-service password change after ID-002; RPT-001 password-change confirmation narrative | If an adversary with sufficient access changed the password, ID-003 could represent account manipulation | T1098 requires adversary account manipulation with sufficient access; a self-service password change does **not** prove that. User-initiated or help-desk-directed reset remains open. | Low — hypothesis only |

## Explicit non-mappings

Do **not** map from this dataset without additional evidence:

- Credential dumping or cookie theft
- Command and control
- Exfiltration
- Persistence
- Lateral movement
- Confirmed account compromise

Owner disposition remains **suspected account compromise — not confirmed**. ATT&CK rows above are hypothesis aids aligned to that open investigation posture; they do not upgrade confidence to confirmed technique use.
