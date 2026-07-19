# MITRE ATT&CK mapping

Map only behavior directly supported by evidence. A mapping describes a candidate hypothesis; it does not prove adversary identity or successful compromise.

Official MITRE ATT&CK techniques to evaluate (hypothesis aids only):

- [T1566.002 Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/)

| Possible technique | Evidence | Why it may apply | Missing confirmation | Confidence |
|---|---|---|---|---|
| T1566.002 Spearphishing Link — candidate hypothesis only |  |  | T1566.002 requires evidence of an electronically delivered malicious link; this scaffold has no message artifact. |  |
| T1078 Valid Accounts — candidate hypothesis only |  |  | T1078 requires adversary abuse of valid credentials; an MFA success does not prove that. |  |
| T1098 Account Manipulation — candidate hypothesis only |  |  | T1098 requires adversary account manipulation with sufficient access; a self-service password change does not prove that. |  |

## Explicit non-mappings

Do **not** map from this dataset without additional evidence:

- Credential dumping or cookie theft
- Command and control
- Exfiltration
- Persistence
- Lateral movement
- Confirmed account compromise

The analyzer does not emit ATT&CK conclusions. Owner mappings remain hypothesis-only until evidence justifies them.
