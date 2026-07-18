# Evidence log

Record hashes using a locally available SHA-256 tool. Do not copy a hash from AI output.

| Evidence ID | Item | Source and provenance | Collected UTC | SHA-256 | Transformations | Analyst notes |
|---|---|---|---|---|---|---|
| E-001 | `data/synthetic-events.jsonl` | Repository-provided synthetic fixture under `01-investigations-and-dfir/mission-001-phishing-powershell/`. Provenance is the Mission 001 lab dataset on branch `feature/mission-001-completion` at base commit `dfa22574b2caa07daabd07c8150593500d657fc7`. | 2026-07-18T13:08:41Z | `3b8343f5144b4ff12237be9acdba865086b94f769f0ccaf27963ce5ab178fa07` | None | Original evidence copy. Eight JSON Lines events. Hash calculated during the Phase A collection session; value is not an invented file-creation timestamp. |
| E-002 | `reports/generated-analysis.md` | Locally generated from E-001 by `src/analyze_events.py` during the Phase A collection session. | 2026-07-18T13:08:41Z | `34ed6c15c0f8f2c906a777213fcd8e454ce5a754775a963edd4d0e462f26610c` | Parsed and summarized by `src/analyze_events.py` into Markdown investigation leads (R-001, R-002, R-003) | Investigative lead only. Ignored by `.gitignore` rule `**/reports/generated-*.md`. Not treated as a conclusion. |

## Integrity verification

- **Working directory (repository-relative):** `01-investigations-and-dfir/mission-001-phishing-powershell`
- **Collection-session timestamp (UTC):** `2026-07-18T13:08:41Z` — Phase A collection-session timestamp for the hashing and analyzer run; not an exact file-creation timestamp for the repository fixture.
- **Python:** Python 3.12.3
- **SHA-256 tool:** `sha256sum` (GNU coreutils) 9.4 at `/usr/bin/sha256sum`
- **Exact commands executed during collection:**

```bash
python3 -m unittest discover -s tests -v
python3 src/analyze_events.py data/synthetic-events.jsonl \
  --output reports/generated-analysis.md
sha256sum data/synthetic-events.jsonl reports/generated-analysis.md
sha256sum data/synthetic-events.jsonl reports/generated-analysis.md
git check-ignore -v reports/generated-analysis.md
```

- **Unit-test result:** 5 tests passed (`OK`).
- **Analyzer result:** `Wrote reports/generated-analysis.md` — 8 events parsed, 3 hosts observed, 3 findings generated.
- **First hash pass:**
  - E-001: `3b8343f5144b4ff12237be9acdba865086b94f769f0ccaf27963ce5ab178fa07`
  - E-002: `34ed6c15c0f8f2c906a777213fcd8e454ce5a754775a963edd4d0e462f26610c`
- **Recheck (second pass):** identical values for both files — match confirmed.
- **Ignore status:** `reports/generated-analysis.md` matched `.gitignore:45:**/reports/generated-*.md` and remains untracked.

## Lab actions versus scenario recommendations

Performed in this repository lab:

1. Confirmed clean working tree on the authorized base commit.
2. Ran Mission 001 unit tests.
3. Generated the ignored analyzer report from E-001.
4. Calculated and rechecked SHA-256 for E-001 and E-002.

Not performed against any real system: host isolation, account restriction, message quarantine, or live evidence collection. Those remain recommended actions for the synthetic scenario only.
