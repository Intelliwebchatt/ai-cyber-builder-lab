# Executive incident report

**Status:** Complete for synthetic training scenario  
**Audience:** Business and security leadership  
**Case ID:** M002-2026  
**Analyst:** Shane Lockhart  
**Disposition:** Suspected account compromise — not confirmed

## Executive summary

A fictional employee at Example Civic Services (`jordan.lee@example.test`) later reported an unexpected account-verification page and a password-change confirmation (ticket `HD-2026-0812-017` on **2026-08-12**). Synthetic browser and identity telemetry for asserted host `WS-217` shows, in order:

- Allowlisted corporate sign-in visit (**BRW-001**)
- Non-allowlisted verification-themed visit on host `accounts-example.test` (**BRW-002**)
- PDF download metadata from that same non-allowlisted host, without file payload (**BRW-003**)
- MFA challenge and success on a device flagged as new (**ID-001**, **ID-002**)
- Successful self-service password change (**ID-003**)
- Later allowlisted security-settings visit (**BRW-004**)
- User help-desk report (**RPT-001**)

**Owner-approved primary hypothesis:** the user interacted with a lookalike verification page; nearby MFA and password-change activity may be related, but **causation is unconfirmed**.

Compromise is **not confirmed**. Investigation priority is **high**; confidence in the suspicious correlation is **moderate**; business impact is **unknown**. An authorized SSO/training page combined with legitimate new-device enrollment or password-reset activity could produce the same sequence and must be verified.

Recommended decision: treat this as a suspected account-compromise investigation (not a confirmed breach), apply the owner-approved immediate response actions, preserve evidence, and close or escalate only after the missing identity, mail, endpoint, and IT-authorization checks are complete.

## Business impact

**Confirmed impact**

- No business impact is confirmed from the supplied synthetic evidence.

**Potential impact only (unconfirmed)**

- Account takeover
- Credential or session abuse
- Unauthorized access to Example Civic Services systems or data
- Malicious file execution from the PDF path
- Broader operational or reputational harm

## Actions taken

### Performed in this repository lab

1. Confirmed authorized base commit `16f290fa966c5160d347a9dd53667a3c12d6c286` and clean working tree.
2. Built ignored synthetic History database (**E-006**) and ran Mission 002 unit tests.
3. Generated ignored analyzer lead report (**E-007**) with rules **M002-R001**–**M002-R005**.
4. Calculated and rechecked two-pass SHA-256 hashes for **E-001**–**E-007** during the lab validation session on **2026-07-19** (not forensic acquisition time; scenario events are **2026-08-12**).
5. Drafted case files 00–08 using Shane-approved judgments only, then recorded the owner reflection and AI-assistance disclosure in case file 09.

### Recommended for the synthetic scenario (not executed against a real system)

1. Contact the user through a trusted channel.
2. Revoke active sessions; secure/reset the account.
3. Review MFA factors, enrolled devices, and identity sessions.
4. Preserve relevant logs.
5. Temporarily block `accounts-example.test` pending verification.
6. Inspect the PDF path with authorized endpoint telemetry **without opening the file**.
7. Check IT change-window, training, and branding-test records.

## Key findings

1. Strongest suspicious browser relationship: allowlisted sign-in (**BRW-001**) followed 83 seconds later by non-allowlisted verification-themed visit (**BRW-002**), with download metadata (**BRW-003**) 33 seconds after BRW-002. Supported as leads by **M002-R001** and **M002-R002**.
2. Identity cluster (**ID-001**–**ID-003**) occurs within minutes of BRW-002 and may be related; owner judgment keeps **causation unconfirmed**. Supported as leads by **M002-R003** and **M002-R004**.
3. User report (**RPT-001**) matches verification / password-change themes by targeted phrase screening (**M002-R005**) and is narrative context only.
4. Documentation-range IP `198.51.100.77` is a safety marker, not reputation evidence.
5. The dataset does not establish confirmed compromise, credential theft, session theft, malware, PDF malice/opening/execution, or threat-actor attribution.

## Recommendations

**Immediate**

- Execute the owner-approved response list in case file 07 (trusted-channel contact, session revocation, account securing, MFA/device/session review, log preservation, temporary block of `accounts-example.test`, PDF-path telemetry without opening, IT authorization checks).

**Short-term**

- Portal lookalike detection and exact-host controls for identity properties.
- Detections for new-device MFA success and password changes near unusual portal hosts.
- Strengthen user guidance to verify unexpected account prompts through trusted channels.

**Strategic**

- Tabletop validation of the suspected account-compromise playbook using synthetic evidence.
- Do not treat blocking documentation-range IPs as meaningful threat remediation.

## Limitations

- Synthetic educational dataset only; no live targets, real credentials, cookies, tokens, or payloads.
- `2026-07-19` evidence-log times are lab validation-session timestamps, not forensic acquisition times; scenario events are dated `2026-08-12`.
- Missing mail/message artifact, DNS/proxy telemetry, endpoint file open/execute proof, and IT branding-test source records.
- Analyzer output (**E-007**) is an investigative lead set, not a conclusion.
- ATT&CK mappings are hypothesis-only with low confidence and stated missing confirmations.
- Mission status is **Completed**, with owner reflection and AI-assistance disclosure recorded in case file 09.
