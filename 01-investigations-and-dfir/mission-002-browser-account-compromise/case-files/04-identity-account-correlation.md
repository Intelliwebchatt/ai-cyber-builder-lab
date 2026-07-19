# Identity and account correlation

Lab-asserted attribution from **E-005** links browser artifacts on `WS-217` to `jordan.lee@example.test`. The browser History database itself does not authenticate the human at the keyboard.

| Pivot | Supporting event IDs | What it shows | What it does not show |
|---|---|---|---|
| Attributed user | BRW-001–BRW-004 (lab attribution), ID-001–ID-003, RPT-001 | Same attributed identity appears across browser, IdP, and help-desk narrative sources | Browser DB does not prove keyboard user; does not prove a single human operator controlled every event |
| New-device MFA success | ID-001, ID-002; proximity lead **M002-R003** with BRW-002 | MFA challenge then success with `new_device=true` for WebPortal from `198.51.100.77` | Attacker control, session theft, or that BRW-002 caused the MFA events |
| Password change | ID-003; proximity lead **M002-R004** with BRW-002, ID-002 | Successful self-service password change shortly after MFA success | Account takeover or that the change was attacker-driven |
| Source IP | ID-001, ID-002, ID-003 | Shared synthetic source address across the IdP cluster | Reputation, geolocation, or proof the IP is malicious (documentation-range safety marker only) |
| Non-allowlisted host near identity activity | BRW-002, BRW-003 with ID-001–ID-003 | Temporal correlation within configured windows | Causal link between browser activity and identity events |

## Additional evidence requests

Authorized follow-up sources that would raise or lower confidence:

1. IdP known-good device inventory and risk scores for `jordan.lee@example.test`
2. Active session inventory and revocation capability results
3. Mail notice for password change (headers / authentication results) — not present in this scaffold
4. DNS / proxy / web-filter logs for inert host strings `accounts.example.test` and `accounts-example.test`
5. Endpoint file telemetry for `C:\Users\jordan.lee\Downloads\account-security-notice.pdf` (existence, hash, open/execute indicators) **without opening the file**
6. IT change-window, training, and branding-test records that could explain an authorized lookalike or demo host
7. Authorized user interview through a trusted channel

## Alternate explanations

Owner-approved alternate explanation that remains open and must be verified:

- An authorized SSO/training or branding-test page combined with legitimate new-device enrollment or password-reset activity could produce the same browser + MFA + password-change sequence, including a later confused user report (**RPT-001**).

Other still-plausible benign framings consistent with the dataset:

- User-initiated hardening after a suspicious-looking but non-malicious page
- Help-desk-directed reset (not recorded as a separate source event here)
- VPN or travel-related new-device flag without adversary involvement
