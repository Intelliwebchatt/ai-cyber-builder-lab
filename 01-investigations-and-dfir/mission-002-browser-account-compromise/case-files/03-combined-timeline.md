# Combined timeline

Complete this table from the source evidence. Add interpretation only in the final column. Scenario event dates are **2026-08-12**. Lab validation-session timestamps on **2026-07-19** (evidence log) are not forensic acquisition times.

| UTC timestamp | Event UID | Host or system | Observed fact | Interpretation and confidence |
|---|---|---|---|---|
| 2026-08-12T15:41:08Z | BRW-001 | `WS-217` / `accounts.example.test` | Allowlisted sign-in page visited; TYPED transition | Baseline corporate portal visit. Fact only at this row. |
| 2026-08-12T15:42:31Z | BRW-002 | `WS-217` / `accounts-example.test` | Non-allowlisted verification-themed page visited via LINK from BRW-001; title “Verify your account” | **Owner primary hypothesis (moderate confidence):** lookalike verification page interaction. Host string differs from allowlist; malice and credential entry unproven. Supports lead **M002-R001** with BRW-001. |
| 2026-08-12T15:43:04Z | BRW-003 | `WS-217` / download metadata | PDF download metadata from same non-allowlisted host; payload not included | Suspicious proximity to BRW-002 (**M002-R002**). Does **not** prove file content, opening, or execution. |
| 2026-08-12T15:44:19Z | ID-001 | Identity provider / `198.51.100.77` | MFA challenge required for `jordan.lee@example.test` on WebPortal; `new_device=true` | Temporal neighbor to browser cluster. IP is documentation-range safety marker only. |
| 2026-08-12T15:44:47Z | ID-002 | Identity provider / `198.51.100.77` | MFA success; `new_device=true`; same user/IP/app | May relate to non-allowlisted browse (**M002-R003** with BRW-002, ID-001). **Causation unconfirmed** (owner judgment). Does not prove attacker control. |
| 2026-08-12T15:45:12Z | ID-003 | Identity provider / `198.51.100.77` | Self-service password change succeeded | May relate to prior browse + MFA (**M002-R004** with BRW-002, ID-002). Attacker-driven change **not** established. |
| 2026-08-12T15:46:05Z | BRW-004 | `WS-217` / `accounts.example.test` | Allowlisted security-settings page via LINK from BRW-002 | Compatible with user checking security after prompts; also compatible with other explanations. Not proof of compromise or recovery success. |
| 2026-08-12T16:02:40Z | RPT-001 | Help desk / user report | Ticket `HD-2026-0812-017`: unexpected verify page and password-change confirmation; user states prompts were completed because the page looked official | Narrative context (**M002-R005** phrase screen with BRW-002, BRW-003, ID-003). Not forensic proof of compromise. |

## Correlation questions

### Elapsed times (scenario clock)

| From → To | Elapsed |
|---|---|
| BRW-001 → BRW-002 | 1m 23s (83s) |
| BRW-002 → BRW-003 | 33s |
| BRW-003 → ID-001 | 1m 15s (75s) |
| ID-001 → ID-002 | 28s |
| ID-002 → ID-003 | 25s |
| BRW-002 → ID-002 | 2m 16s (136s) |
| BRW-002 → ID-003 | 2m 41s (161s) |
| BRW-002 → BRW-004 | 3m 34s (214s) |
| ID-003 → RPT-001 | 17m 28s (1048s) |
| BRW-001 → RPT-001 | 21m 32s (1292s) |

### Shared pivots

- Attributed user `jordan.lee@example.test`: BRW-* (lab attribution), ID-001–ID-003, RPT-001.
- Non-allowlisted host `accounts-example.test`: BRW-002, BRW-003 (`tab_url`).
- Source IP `198.51.100.77`: ID-001, ID-002, ID-003 (correlation point only; not reputation evidence).

### What would confirm or disprove causation

Mail/message delivery artifact, DNS/proxy logs, IdP device inventory and risk context, session inventory, endpoint file telemetry for the PDF path (without opening the file), IT change-window/training/branding-test records, and an authorized user interview.
