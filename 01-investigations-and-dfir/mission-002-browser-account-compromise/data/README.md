# Mission 002 synthetic data

## Primary tracked sources

| Path | Role |
|---|---|
| `source/browser_history.json` | Reviewable visit/url rows with canonical ISO-8601 UTC timestamps |
| `source/browser_downloads.json` | Reviewable download metadata; `payload_included=false` |
| `source/identity-events.jsonl` | Synthetic identity-provider events |
| `source/user-report.json` | Synthetic help-desk ticket |
| `source/fixture-manifest.json` | Immutable schema, allowlist, attribution, and SQLite-to-event mappings |

The tracked manifest does not store mutable hashes. Evidence hashes are recorded later in the case-file evidence log.

## Generated derivative evidence

`generated/History.sqlite` is created locally by `src/build_browser_fixture.py` and is gitignored. Rebuild it before analysis:

```bash
python3 src/build_browser_fixture.py \
  --history-source data/source/browser_history.json \
  --downloads-source data/source/browser_downloads.json \
  --output data/generated/History.sqlite \
  --overwrite
```

## Provenance

All source records declare `synthetic: true`. They are repository-authored educational fixtures, not exports from a real browser profile, identity tenant, or help-desk system.
