# Mission 002: Browser artifacts and suspected account compromise

**Status:** Scaffolded, not yet completed  
**Type:** Defensive investigation using synthetic evidence  
**Primary roles:** Digital-forensics analyst, SOC / IR triage, identity investigator  
**Analyst:** Shane Lockhart (owner judgments deferred to later phases)

## Scenario

A fictional employee at Example Civic Services reports an unexpected account-verification page and a later password-change confirmation. Synthetic Chromium-like browser artifacts and identity-provider events are supplied for local correlation practice.

All evidence is repository-authored and synthetic. The scenario contains no real browser profile, cookies, passwords, session tokens, payload bytes, live accounts, or reachable hosts.

Prior track context only: [Mission 001](../mission-001-phishing-powershell/) is a completed phishing and PowerShell investigation in the same track. Do not carry facts, findings, or conclusions between cases.

## Objectives

1. Preserve and inventory the supplied synthetic evidence with integrity hashes.
2. Parse Chromium-like visit and download metadata locally, including WebKit timestamp conversion.
3. Build a combined browser and identity timeline.
4. Separate observed facts from interpretations and alternate explanations.
5. Map only supported hypotheses to MITRE ATT&CK with confidence limits.
6. Recommend proportionate containment and remediation for the synthetic scenario.
7. Communicate findings to technical and nontechnical audiences after owner review.

## Repository contents

```text
case-files/   Empty investigation worksheets for later owner-guided work
data/source/  Reviewable synthetic text sources and immutable manifest
data/generated/  Locally built SQLite History DB (ignored; not tracked)
reports/      Generated-tool output (ignored generated Markdown)
src/          Standard-library fixture builder and analyzer
tests/        Automated tests, including a benign negative fixture
```

## Build the synthetic History database

From this mission directory:

```bash
python3 src/build_browser_fixture.py \
  --history-source data/source/browser_history.json \
  --downloads-source data/source/browser_downloads.json \
  --manifest data/source/fixture-manifest.json \
  --output data/generated/History.sqlite \
  --overwrite
```

ISO-8601 UTC timestamps in the JSON sources are canonical. The builder calculates WebKit/Chromium microseconds with integer day/second/microsecond arithmetic, validates source rows one-to-one against the manifest, and enforces `expected_counts`. Record the printed Python and SQLite versions with evidence hashes; database bytes are not guaranteed identical across SQLite versions.

Chromium visit `transition` values follow core page-transition types: `0` = LINK, `1` = TYPED. Linked navigations (`from_visit != 0`, `typed_count = 0`) must use LINK.

## Run the starter analyzer

```bash
python3 src/analyze_browser_identity.py \
  --history data/generated/History.sqlite \
  --identity data/source/identity-events.jsonl \
  --report data/source/user-report.json \
  --manifest data/source/fixture-manifest.json \
  --output reports/generated-analysis.md
```

Run the tests:

```bash
python3 -m unittest discover -s tests -v
```

The tool output is a lead set, not a conclusion. Validate every finding against the source records. The browser database does not authenticate who was at the keyboard; correlation uses lab-asserted attribution from the manifest.

## Correlation windows

Named constants used by the analyzer:

| Constant | Minutes |
|---|---:|
| `WINDOW_CORPORATE_TO_NON_ALLOWLISTED` | 15 |
| `WINDOW_DOWNLOAD_NEAR_VISIT` | 15 |
| `WINDOW_IDENTITY_NEAR_BROWSER` | 20 |
| `WINDOW_PASSWORD_AFTER_MFA` | 15 |
| `WINDOW_PASSWORD_AFTER_BROWSER` | 20 |
| `WINDOW_USER_REPORT` | 120 |

Official hosts are compared by exact normalized hostname against the manifest allowlist. `accounts-example.test` is described as non-allowlisted and verification-themed, not as a proven lookalike.

## Investigation workflow

1. Read the [case brief](case-files/00-case-brief.md).
2. Build the fixture, run tests, and complete the [evidence and hash log](case-files/01-evidence-hash-log.md).
3. Inventory browser artifacts in [02-browser-artifact-inventory.md](case-files/02-browser-artifact-inventory.md).
4. Complete the [combined timeline](case-files/03-combined-timeline.md).
5. Complete [identity and account correlation](case-files/04-identity-account-correlation.md).
6. Record [hypotheses and alternate explanations](case-files/05-hypotheses-and-alternate-explanations.md).
7. Complete the [ATT&CK map](case-files/06-attack-map.md) with confidence limits only.
8. Write the [containment and remediation plan](case-files/07-containment-remediation.md).
9. Write the [executive report](case-files/08-executive-report.md).
10. Add a personal reflection and AI-assistance disclosure in [09-owner-reflection-and-ai-disclosure.md](case-files/09-owner-reflection-and-ai-disclosure.md).

Steps 3–10 remain for owner-guided Phase C/D work. This foundation does not pre-fill owner judgments.

## Completion standard

This mission may be marked completed only when:

- evidence provenance and two-pass hashes are recorded
- browser and identity artifacts are faithfully parsed
- the combined timeline is reproducible
- every finding cites supporting evidence or event IDs
- observed facts, interpretations, uncertainty, and alternate explanations are separated
- no conclusion exceeds what the synthetic evidence supports
- remediation is prioritized and has validation steps
- mission tests and root SignalTrace tests/build pass
- relative links and secret/private-file scans pass
- generated reports and generated SQLite remain ignored and untracked
- SignalTrace and Mission 001 remain untouched
- Shane's reflection is in his own words
- AI assistance is disclosed accurately

## Safety limits

- Do not read or copy a real browser profile, History, cookies, login data, or password database.
- Do not add credential recovery, cookie decryption, DPAPI/Keychain access, session replay, or account-takeover functionality.
- Do not visit URLs, resolve domains, query reputation services, geolocate IPs, or call external services.
- Do not treat documentation-range IP addresses as malicious reputation evidence.
- Analyzer rules are investigation leads, not conclusions.
