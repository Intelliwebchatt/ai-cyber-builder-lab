# Browser artifact inventory

Inventory only artifacts present in the synthetic fixture. Do not access a real browser profile.

| Event UID | SQLite IDs | UTC timestamp | Host | URL / path (inert string) | Title or filename | Notes |
|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |

## Required distinctions

- A URL and title are observed facts.
- Calling a host a “lookalike” is an interpretation unless independently justified.
- Use the manifest official-host allowlist for exact host comparison.
- Download metadata byte counts are not file content. `payload_included` must remain false.
- The browser database does not authenticate the human user at the keyboard.

## Out of scope for this mission

- Cookies
- Saved passwords / login data
- Autofill
- Cache payloads
- Cookie decryption, DPAPI, or Keychain access
