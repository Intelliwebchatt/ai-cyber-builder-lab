# Identity and account correlation

| Pivot | Supporting event IDs | What it shows | What it does not show |
|---|---|---|---|
| Attributed user |  |  | Browser DB does not prove keyboard user |
| New-device MFA success |  |  | Attacker control |
| Password change |  |  | Account takeover |
| Source IP |  | Correlation point only | Reputation or geolocation conclusion |

## Additional evidence requests

List authorized follow-up sources that would raise or lower confidence. Examples to consider:

- IdP known-good device inventory and risk scores
- Mail notice for password change (headers/auth results)
- DNS/proxy logs for host resolution
- Endpoint file telemetry for the download path
- Authorized user interview

## Alternate explanations

Record benign explanations that remain plausible from the current dataset.
