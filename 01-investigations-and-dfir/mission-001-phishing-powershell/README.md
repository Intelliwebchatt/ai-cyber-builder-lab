# Mission 001: Phishing and PowerShell investigation

**Status:** Scaffolded, not yet completed  
**Type:** Defensive investigation using synthetic evidence  
**Primary roles:** SOC analyst, incident responder, digital-forensics analyst

## Scenario

A fictional employee at Example Manufacturing reports an unexpected invoice email. Shortly afterward, endpoint telemetry records a spreadsheet application launching PowerShell, followed by a connection to a documentation-range IP address. Several failed sign-in events also appear in the same period.

All events are synthetic. The scenario contains no live payload, real credential, real person, or reachable command-and-control system.

## Objectives

1. Preserve and inventory the supplied evidence.
2. Build a defensible event timeline.
3. Identify indicators and suspicious process relationships.
4. Map supported behavior to MITRE ATT&CK without overstating certainty.
5. Recommend containment, eradication, recovery, and prevention actions.
6. Communicate findings to technical and nontechnical audiences.

## Repository contents

```text
case-files/   Investigation worksheets completed by the analyst
data/         Synthetic source events
reports/      Generated-tool output and final reports
src/          Small standard-library analysis tool
tests/        Automated tests for parsing and detection logic
```

## Run the starter analyzer

From this mission directory:

```bash
python3 src/analyze_events.py data/synthetic-events.jsonl \
  --output reports/generated-analysis.md
```

Run the tests:

```bash
python3 -m unittest discover -s tests -v
```

The tool output is a lead, not a conclusion. Validate every finding against the event data and record alternate explanations.

## Investigation workflow

1. Read the [case brief](case-files/00-case-brief.md).
2. Hash the supplied dataset and complete the [evidence log](case-files/01-evidence-log.md).
3. Run and test the analyzer.
4. Complete the [timeline](case-files/02-timeline.md).
5. Analyze potential [indicators](case-files/03-ioc-analysis.md).
6. Complete the [ATT&CK map](case-files/04-attack-map.md).
7. Write the [containment and remediation plan](case-files/05-containment-remediation.md).
8. Write the [executive report](case-files/06-executive-report.md).
9. Add a personal reflection and AI-assistance disclosure.

## Completion standard

This mission is complete only when:

- tests pass
- evidence hashes and provenance are recorded
- every conclusion cites supporting event IDs
- uncertainty and missing telemetry are documented
- remediation is prioritized and testable
- the executive report is written in the repository owner's own words
- README status is changed from `Scaffolded` to `Completed`

## Safety limits

Do not recreate the scenario against a real account, inbox, organization, or public system. Do not replace the synthetic command with executable malicious content.
