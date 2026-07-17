#!/usr/bin/env python3
"""Analyze the synthetic Mission 001 event set.

The rules identify investigation leads. They do not declare compromise.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


OFFICE_LIKE_PARENTS = {"spreadsheet.exe", "winword.exe", "excel.exe"}
SCRIPT_ENGINES = {"powershell.exe", "pwsh.exe"}
DOCUMENTATION_IPS = {"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"}


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}: {exc.msg}") from exc

            for required in ("event_uid", "timestamp", "event_id", "host", "source"):
                if required not in event:
                    raise ValueError(f"Line {line_number} is missing required field: {required}")
            _parse_timestamp(event["timestamp"], line_number)
            events.append(event)

    return sorted(events, key=lambda item: item["timestamp"])


def _parse_timestamp(value: str, line_number: int | None = None) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        where = f" on line {line_number}" if line_number is not None else ""
        raise ValueError(f"Invalid ISO-8601 timestamp{where}: {value}") from exc


def basename(value: str | None) -> str:
    if not value:
        return ""
    return value.replace("/", "\\").rsplit("\\", maxsplit=1)[-1].lower()


def analyze_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    event_list = list(events)
    findings: list[dict[str, Any]] = []

    for event in event_list:
        parent = basename(event.get("parent_process"))
        process = basename(event.get("process"))

        if parent in OFFICE_LIKE_PARENTS and process in SCRIPT_ENGINES:
            findings.append(
                finding(
                    "R-001",
                    "Office-like application launched a script engine",
                    "high",
                    [event["event_uid"]],
                    "Validate whether this parent-child relationship was expected and authorized.",
                )
            )

        if event.get("event_id") == "SYSMON_3" and process in SCRIPT_ENGINES:
            findings.append(
                finding(
                    "R-002",
                    "Script engine made an outbound connection",
                    "medium",
                    [event["event_uid"]],
                    "Correlate the destination with proxy, DNS, firewall, and endpoint telemetry.",
                )
            )

    failures: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    for event in event_list:
        if str(event.get("event_id")) != "4625":
            continue
        key = (
            str(event.get("host", "unknown")),
            str(event.get("user", "unknown")),
            str(event.get("source_ip", "unknown")),
        )
        failures[key].append(event["event_uid"])

    for (host, user, source_ip), evidence in failures.items():
        if len(evidence) >= 3:
            findings.append(
                finding(
                    "R-003",
                    "Repeated failed network logons",
                    "medium",
                    evidence,
                    f"Review authentication telemetry for {user} on {host} from {source_ip}.",
                )
            )

    return findings


def finding(
    rule_id: str,
    title: str,
    severity: str,
    evidence: list[str],
    next_step: str,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "next_step": next_step,
    }


def render_markdown(events: list[dict[str, Any]], findings: list[dict[str, Any]]) -> str:
    event_counts = Counter(str(event["event_id"]) for event in events)
    lines = [
        "# Mission 001 starter analysis",
        "",
        "> Automated rules produce investigation leads, not final conclusions.",
        "",
        "## Dataset summary",
        "",
        f"- Events parsed: {len(events)}",
        f"- Hosts observed: {len({event['host'] for event in events})}",
        f"- Findings generated: {len(findings)}",
        "",
        "### Event counts",
        "",
        "| Event ID | Count |",
        "|---|---:|",
    ]
    lines.extend(f"| {event_id} | {count} |" for event_id, count in sorted(event_counts.items()))

    lines.extend(["", "## Investigation leads", ""])
    if not findings:
        lines.append("No rule-based leads were generated.")
    else:
        for item in findings:
            lines.extend(
                [
                    f"### {item['rule_id']}: {item['title']}",
                    "",
                    f"- Severity: {item['severity']}",
                    f"- Supporting events: {', '.join(item['evidence'])}",
                    f"- Next step: {item['next_step']}",
                    "",
                ]
            )

    lines.extend(
        [
            "## Required analyst validation",
            "",
            "- Confirm timestamps and event provenance.",
            "- Examine the full process tree and command context.",
            "- Correlate endpoint, identity, mail, DNS, proxy, and firewall telemetry.",
            "- Document benign explanations and missing evidence.",
            "- Do not label the host compromised solely from these rules.",
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Path to a JSON Lines event file")
    parser.add_argument("--output", type=Path, help="Optional Markdown output path")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        events = load_events(args.input)
        findings = analyze_events(events)
        report = render_markdown(events, findings)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"error: {exc}") from exc

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
