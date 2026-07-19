# Browser artifact inventory

Inventory only artifacts present in the synthetic fixture. Do not access a real browser profile. Official-host allowlist (exact match from **E-005**): `accounts.example.test`.

| Event UID | SQLite IDs | UTC timestamp | Host | URL / path (inert string) | Title or filename | Notes |
|---|---|---|---|---|---|---|
| BRW-001 | url_id=1, visit_id=1 | 2026-08-12T15:41:08Z | `accounts.example.test` | `https://accounts.example.test/signin` | Example Civic Services Sign-In | Allowlisted. Transition `1` (TYPED); `from_visit=0`; `typed_count=1`. |
| BRW-002 | url_id=2, visit_id=2 | 2026-08-12T15:42:31Z | `accounts-example.test` | `https://accounts-example.test/account/verify` | Verify your account | **Not** allowlisted (exact host string differs). Transition `0` (LINK); `from_visit=1`; `typed_count=0`. |
| BRW-003 | download_id=1 | 2026-08-12T15:43:04Z | `accounts-example.test` (from `tab_url`) | Path: `C:\Users\jordan.lee\Downloads\account-security-notice.pdf`; `tab_url`: `https://accounts-example.test/account/verify`; referrer: `https://accounts.example.test/signin` | `account-security-notice.pdf` | MIME `application/pdf`; `total_bytes=received_bytes=24576`; `danger_type=0`; `interrupt_reason=0`; **`payload_included=false`**. Metadata only. |
| BRW-004 | url_id=3, visit_id=3 | 2026-08-12T15:46:05Z | `accounts.example.test` | `https://accounts.example.test/security` | Security settings | Allowlisted. Transition `0` (LINK); `from_visit=2`; `typed_count=0`. |

## Required distinctions

- A URL and title are observed facts.
- Calling host `accounts-example.test` a “lookalike” relative to allowlisted `accounts.example.test` is an **interpretation** used in the owner-approved primary hypothesis; the recorded fact is exact-string non-membership in the allowlist.
- Use the manifest official-host allowlist for exact host comparison.
- Download metadata byte counts are not file content. `payload_included` remains false. The dataset does not establish that the PDF was malicious, opened, or executed.
- The browser database does not authenticate the human user at the keyboard. Correlation uses lab-asserted attribution from **E-005** (`jordan.lee@example.test` on `WS-217`).

## Out of scope for this mission

- Cookies
- Saved passwords / login data
- Autofill
- Cache payloads
- Cookie decryption, DPAPI, or Keychain access
