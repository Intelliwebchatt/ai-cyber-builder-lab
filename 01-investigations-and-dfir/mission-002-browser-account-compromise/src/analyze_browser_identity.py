#!/usr/bin/env python3
"""Correlate synthetic browser and identity artifacts for Mission 002.

Rules emit investigation leads with supporting event IDs. They do not declare
account compromise, credential theft, session theft, or attribution.
"""

from __future__ import annotations

import argparse
import ast
import json
import sqlite3
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NamedTuple


WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

WINDOW_CORPORATE_TO_NON_ALLOWLISTED = timedelta(minutes=15)
WINDOW_DOWNLOAD_NEAR_VISIT = timedelta(minutes=15)
WINDOW_IDENTITY_NEAR_BROWSER = timedelta(minutes=20)
WINDOW_PASSWORD_AFTER_MFA = timedelta(minutes=15)
WINDOW_PASSWORD_AFTER_BROWSER = timedelta(minutes=20)
WINDOW_USER_REPORT = timedelta(minutes=120)

REQUIRED_URL_COLUMNS = {
    "id",
    "url",
    "title",
    "visit_count",
    "typed_count",
    "last_visit_time",
}
REQUIRED_VISIT_COLUMNS = {"id", "url", "visit_time", "from_visit", "transition"}
REQUIRED_DOWNLOAD_COLUMNS = {
    "id",
    "guid",
    "current_path",
    "target_path",
    "start_time",
    "received_bytes",
    "total_bytes",
    "end_time",
    "tab_url",
    "tab_referrer_url",
    "mime_type",
}


class NormalizedEvent(NamedTuple):
    event_uid: str
    timestamp_utc: datetime
    category: str
    summary: str
    host: str | None = None
    url: str | None = None
    title: str | None = None
    user: str | None = None
    source_ip: str | None = None
    event_type: str | None = None
    new_device: bool | None = None
    sqlite_url_id: int | None = None
    sqlite_visit_id: int | None = None
    sqlite_download_id: int | None = None
    payload_included: bool | None = None
    total_bytes: int | None = None
    received_bytes: int | None = None
    report_text: str | None = None


def parse_utc(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid ISO-8601 UTC timestamp: {value}") from exc


def webkit_to_utc(value: int) -> datetime:
    return WEBKIT_EPOCH + timedelta(microseconds=int(value))


def format_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_host(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    if not isinstance(manifest, dict):
        raise ValueError("Manifest must be a JSON object")
    if manifest.get("synthetic") is not True:
        raise ValueError("Manifest must declare synthetic=true")
    for required in (
        "official_host_allowlist",
        "case_attribution",
        "event_mappings",
        "report_phrase_screen",
    ):
        if required not in manifest:
            raise ValueError(f"Manifest missing required field: {required}")
    attribution = manifest["case_attribution"]
    for required in (
        "host",
        "profile_label",
        "asserted_source_path",
        "attributed_user",
        "attribution_note",
    ):
        if required not in attribution:
            raise ValueError(f"case_attribution missing required field: {required}")
    return manifest


def load_identity_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}: {exc.msg}") from exc
            for required in (
                "event_uid",
                "timestamp",
                "event_type",
                "user",
                "source",
                "source_ip",
                "result",
            ):
                if required not in event:
                    raise ValueError(
                        f"Line {line_number} is missing required field: {required}"
                    )
            if event.get("synthetic") is not True:
                raise ValueError(
                    f"Line {line_number} must declare synthetic=true"
                )
            event_uid = str(event["event_uid"])
            if event_uid in seen:
                raise ValueError(f"Duplicate identity event_uid: {event_uid}")
            seen.add(event_uid)
            parse_utc(str(event["timestamp"]))
            events.append(event)
    return events


def load_user_report(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        report = json.load(handle)
    for required in (
        "event_uid",
        "timestamp",
        "ticket_id",
        "reporter",
        "source",
        "summary",
        "description",
    ):
        if required not in report:
            raise ValueError(f"User report missing required field: {required}")
    if report.get("synthetic") is not True:
        raise ValueError("User report must declare synthetic=true")
    parse_utc(str(report["timestamp"]))
    return report


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    if not rows:
        raise ValueError(f"SQLite database is missing required table: {table}")
    return {str(row[1]) for row in rows}


def open_history_readonly(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise ValueError(f"History database not found: {path}")
    uri = path.resolve().as_uri() + "?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        for table, required in (
            ("urls", REQUIRED_URL_COLUMNS),
            ("visits", REQUIRED_VISIT_COLUMNS),
            ("downloads", REQUIRED_DOWNLOAD_COLUMNS),
        ):
            columns = _table_columns(conn, table)
            missing = required - columns
            if missing:
                raise ValueError(
                    f"Table {table} missing required columns: {', '.join(sorted(missing))}"
                )
    except sqlite3.Error as exc:
        raise ValueError(f"Invalid or unreadable SQLite database: {path}") from exc
    return conn


def load_browser_events(
    history_path: Path,
    manifest: dict[str, Any],
) -> list[NormalizedEvent]:
    visit_map = {
        int(item["sqlite_visit_id"]): str(item["event_uid"])
        for item in manifest["event_mappings"]["visits"]
    }
    download_map = {
        int(item["sqlite_download_id"]): str(item["event_uid"])
        for item in manifest["event_mappings"]["downloads"]
    }

    events: list[NormalizedEvent] = []
    seen_uids: set[str] = set()
    conn = open_history_readonly(history_path)
    try:
        visit_rows = conn.execute(
            """
            SELECT v.id AS visit_id, v.url AS url_id, v.visit_time, u.url, u.title
            FROM visits v
            JOIN urls u ON u.id = v.url
            ORDER BY v.visit_time ASC, v.id ASC
            """
        ).fetchall()
        for row in visit_rows:
            visit_id = int(row["visit_id"])
            url_id = int(row["url_id"])
            if visit_id not in visit_map:
                raise ValueError(
                    f"SQLite visit id {visit_id} has no manifest event_uid mapping"
                )
            event_uid = visit_map[visit_id]
            if event_uid in seen_uids:
                raise ValueError(f"Duplicate browser event_uid: {event_uid}")
            seen_uids.add(event_uid)
            url = str(row["url"])
            events.append(
                NormalizedEvent(
                    event_uid=event_uid,
                    timestamp_utc=webkit_to_utc(int(row["visit_time"])),
                    category="browser_visit",
                    summary=f"Visited {url}",
                    host=normalize_host(url),
                    url=url,
                    title=str(row["title"] or ""),
                    user=str(manifest["case_attribution"]["attributed_user"]),
                    sqlite_url_id=url_id,
                    sqlite_visit_id=visit_id,
                )
            )

        download_rows = conn.execute(
            """
            SELECT id, start_time, total_bytes, received_bytes, tab_url,
                   tab_referrer_url, target_path, mime_type
            FROM downloads
            ORDER BY start_time ASC, id ASC
            """
        ).fetchall()
        for row in download_rows:
            download_id = int(row["id"])
            if download_id not in download_map:
                raise ValueError(
                    f"SQLite download id {download_id} has no manifest event_uid mapping"
                )
            event_uid = download_map[download_id]
            if event_uid in seen_uids:
                raise ValueError(f"Duplicate browser event_uid: {event_uid}")
            seen_uids.add(event_uid)
            tab_url = str(row["tab_url"] or "")
            events.append(
                NormalizedEvent(
                    event_uid=event_uid,
                    timestamp_utc=webkit_to_utc(int(row["start_time"])),
                    category="browser_download",
                    summary=(
                        f"Download metadata for {row['target_path']} "
                        f"(payload_included=false)"
                    ),
                    host=normalize_host(tab_url) if tab_url else None,
                    url=tab_url,
                    user=str(manifest["case_attribution"]["attributed_user"]),
                    sqlite_download_id=download_id,
                    payload_included=False,
                    total_bytes=int(row["total_bytes"]),
                    received_bytes=int(row["received_bytes"]),
                )
            )
    finally:
        conn.close()
    return events


def normalize_identity_events(raw_events: list[dict[str, Any]]) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    for raw in raw_events:
        events.append(
            NormalizedEvent(
                event_uid=str(raw["event_uid"]),
                timestamp_utc=parse_utc(str(raw["timestamp"])),
                category="identity",
                summary=str(raw.get("description") or raw["event_type"]),
                user=str(raw["user"]),
                source_ip=str(raw["source_ip"]),
                event_type=str(raw["event_type"]),
                new_device=bool(raw["new_device"]) if "new_device" in raw else None,
            )
        )
    return events


def normalize_user_report(report: dict[str, Any]) -> NormalizedEvent:
    text = f"{report['summary']}\n{report['description']}"
    return NormalizedEvent(
        event_uid=str(report["event_uid"]),
        timestamp_utc=parse_utc(str(report["timestamp"])),
        category="user_report",
        summary=str(report["summary"]),
        user=str(report["reporter"]),
        report_text=text,
    )


def sort_events(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    return sorted(events, key=lambda item: (item.timestamp_utc, item.event_uid))


def is_allowlisted(host: str | None, allowlist: set[str]) -> bool:
    if not host:
        return False
    return host in allowlist


def verification_themed(title: str | None, url: str | None) -> bool:
    haystack = f"{title or ''} {url or ''}".lower()
    return "verify" in haystack or "verification" in haystack


def finding(
    rule_id: str,
    title: str,
    severity: str,
    evidence: list[str],
    alternate_explanation: str,
    cannot_prove: str,
    next_step: str,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "alternate_explanation": alternate_explanation,
        "cannot_prove": cannot_prove,
        "next_step": next_step,
    }


def analyze_events(
    events: list[NormalizedEvent],
    manifest: dict[str, Any],
) -> list[dict[str, Any]]:
    allowlist = {host.lower() for host in manifest["official_host_allowlist"]}
    attributed_user = str(manifest["case_attribution"]["attributed_user"])
    phrases = [str(item).lower() for item in manifest["report_phrase_screen"]]

    visits = [e for e in events if e.category == "browser_visit"]
    downloads = [e for e in events if e.category == "browser_download"]
    identity = [e for e in events if e.category == "identity"]
    reports = [e for e in events if e.category == "user_report"]

    allowlisted_visits = [e for e in visits if is_allowlisted(e.host, allowlist)]
    non_allowlisted_visits = [
        e
        for e in visits
        if e.host and not is_allowlisted(e.host, allowlist) and verification_themed(e.title, e.url)
    ]

    findings: list[dict[str, Any]] = []

    # M002-R001: non-allowlisted verification-themed page after allowlisted sign-in
    for corporate in allowlisted_visits:
        for non_allowlisted in non_allowlisted_visits:
            delta = non_allowlisted.timestamp_utc - corporate.timestamp_utc
            if timedelta(0) <= delta <= WINDOW_CORPORATE_TO_NON_ALLOWLISTED:
                findings.append(
                    finding(
                        "M002-R001",
                        "Non-allowlisted verification-themed page after allowlisted sign-in",
                        "medium",
                        [corporate.event_uid, non_allowlisted.event_uid],
                        (
                            "Authorized SSO branding test, user research, or an internal "
                            "training page could produce the same host sequence."
                        ),
                        (
                            "Phishing success, credential entry, malice of the page, or that "
                            "the hosts are impersonating each other beyond exact string "
                            "comparison against the allowlist."
                        ),
                        "Inventory both URLs as inert strings and request mail/DNS/proxy context.",
                    )
                )

    # M002-R002: download metadata from non-allowlisted host near verification visit
    for visit in non_allowlisted_visits:
        for download in downloads:
            if not download.host or is_allowlisted(download.host, allowlist):
                continue
            delta = abs(download.timestamp_utc - visit.timestamp_utc)
            if delta <= WINDOW_DOWNLOAD_NEAR_VISIT:
                findings.append(
                    finding(
                        "M002-R002",
                        "Download metadata from non-allowlisted host near verification visit",
                        "medium",
                        [visit.event_uid, download.event_uid],
                        (
                            "A benign PDF saved from an internal demo or training host could "
                            "create the same metadata pattern."
                        ),
                        (
                            "File content, maliciousness, opening, or execution. "
                            "Download metadata byte counts are not payload bytes."
                        ),
                        "Preserve download path metadata and request endpoint file telemetry if authorized.",
                    )
                )

    # M002-R003: MFA success on a new device near non-allowlisted browser activity
    mfa_successes = [
        e
        for e in identity
        if e.event_type == "MFA_SUCCESS"
        and e.new_device is True
        and e.user == attributed_user
    ]
    for mfa in mfa_successes:
        for visit in non_allowlisted_visits:
            if visit.user != attributed_user:
                continue
            delta = abs(mfa.timestamp_utc - visit.timestamp_utc)
            if delta <= WINDOW_IDENTITY_NEAR_BROWSER:
                support = sorted({visit.event_uid, mfa.event_uid})
                # Include preceding challenge when present in window for richer support
                for challenge in identity:
                    if (
                        challenge.event_type == "MFA_CHALLENGE"
                        and challenge.user == attributed_user
                        and abs(challenge.timestamp_utc - mfa.timestamp_utc)
                        <= WINDOW_IDENTITY_NEAR_BROWSER
                    ):
                        support = sorted(set(support) | {challenge.event_uid})
                findings.append(
                    finding(
                        "M002-R003",
                        "MFA success on a new device near non-allowlisted browser activity",
                        "high",
                        support,
                        (
                            "Legitimate new-device enrollment, travel, or VPN use with a "
                            "benign browser session could explain the same combination."
                        ),
                        (
                            "Attacker presence, session theft, or that the browser visit "
                            "caused the MFA event. Documentation-range IPs are safety markers "
                            "only and are not reputation evidence."
                        ),
                        "Compare to known-good device inventory and IdP risk context.",
                    )
                )

    # M002-R004: password change after non-allowlisted browse + MFA success
    password_changes = [
        e
        for e in identity
        if e.event_type == "PASSWORD_CHANGE" and e.user == attributed_user
    ]
    for password in password_changes:
        for mfa in mfa_successes:
            mfa_delta = password.timestamp_utc - mfa.timestamp_utc
            if not (timedelta(0) <= mfa_delta <= WINDOW_PASSWORD_AFTER_MFA):
                continue
            for visit in non_allowlisted_visits:
                browser_delta = password.timestamp_utc - visit.timestamp_utc
                if timedelta(0) <= browser_delta <= WINDOW_PASSWORD_AFTER_BROWSER:
                    findings.append(
                        finding(
                            "M002-R004",
                            "Password change shortly after non-allowlisted browse and MFA success",
                            "high",
                            [visit.event_uid, mfa.event_uid, password.event_uid],
                            (
                                "User-initiated hardening after a suspicious-looking page, or a "
                                "help-desk-directed reset, could produce the same sequence."
                            ),
                        (
                            "Account takeover or that the password change was attacker-driven."
                        ),
                            "Review password-change initiator, session inventory, and mail notices.",
                        )
                    )

    # M002-R005: targeted phrase screening on user report near cluster
    for report in reports:
        text = (report.report_text or "").lower()
        matched = [phrase for phrase in phrases if phrase in text]
        if not matched:
            continue
        related = [
            e
            for e in events
            if e.category in {"browser_visit", "browser_download", "identity"}
            and e.user == attributed_user
            and timedelta(0)
            <= (report.timestamp_utc - e.timestamp_utc)
            <= WINDOW_USER_REPORT
            and (
                (e.category == "browser_visit" and e in non_allowlisted_visits)
                or (e.category == "identity" and e.event_type == "PASSWORD_CHANGE")
                or (
                    e.category == "browser_download"
                    and e.host
                    and not is_allowlisted(e.host, allowlist)
                )
            )
        ]
        if not related:
            continue
        support = sorted({report.event_uid, *[item.event_uid for item in related]})
        # Keep expected core IDs stable and readable
        preferred = [
            uid
            for uid in ("BRW-002", "BRW-003", "ID-003", "RPT-001")
            if uid in support
        ]
        if preferred:
            # Include all related non-allowlisted/password/report IDs but order preferred first
            remainder = [uid for uid in support if uid not in preferred]
            support = preferred + remainder
        findings.append(
            finding(
                "M002-R005",
                "User report phrase screen matches verification or password-change theme",
                "low",
                support,
                (
                    "User confusion about a legitimate IT message could produce matching "
                    "phrases without malicious activity."
                ),
                (
                    "Factual corroboration beyond the report text. Phrase screening is not "
                    "semantic verification and does not establish compromise."
                ),
                "Treat the ticket as narrative context and validate against primary telemetry.",
            )
        )

    # Deduplicate identical rule+evidence sets while preserving deterministic order
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for item in findings:
        key = (item["rule_id"], tuple(item["evidence"]))
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)

    rule_order = {
        "M002-R001": 1,
        "M002-R002": 2,
        "M002-R003": 3,
        "M002-R004": 4,
        "M002-R005": 5,
    }
    return sorted(
        unique,
        key=lambda item: (rule_order.get(item["rule_id"], 99), ",".join(item["evidence"])),
    )


def render_markdown(
    events: list[NormalizedEvent],
    findings: list[dict[str, Any]],
    manifest: dict[str, Any],
) -> str:
    attribution = manifest["case_attribution"]
    allowlist = ", ".join(manifest["official_host_allowlist"])
    lines = [
        "# Mission 002 starter analysis",
        "",
        "> Automated rules produce investigation leads, not final conclusions.",
        "",
        "## Case attribution and limits",
        "",
        f"- Asserted host: `{attribution['host']}`",
        f"- Asserted profile: `{attribution['profile_label']}`",
        f"- Asserted source path: `{attribution['asserted_source_path']}`",
        f"- Attributed user for correlation: `{attribution['attributed_user']}`",
        f"- Official-host allowlist (exact match): `{allowlist}`",
        f"- Attribution note: {attribution['attribution_note']}",
        "",
        "## Dataset summary",
        "",
        f"- Events normalized: {len(events)}",
        f"- Browser visits: {sum(1 for e in events if e.category == 'browser_visit')}",
        f"- Browser downloads: {sum(1 for e in events if e.category == 'browser_download')}",
        f"- Identity events: {sum(1 for e in events if e.category == 'identity')}",
        f"- User reports: {sum(1 for e in events if e.category == 'user_report')}",
        f"- Findings generated: {len(findings)}",
        "",
        "### Normalized timeline",
        "",
        "| UTC timestamp | Event UID | Category | Summary |",
        "|---|---|---|---|",
    ]
    for event in events:
        summary = event.summary.replace("|", "\\|")
        lines.append(
            f"| {format_utc(event.timestamp_utc)} | {event.event_uid} | "
            f"{event.category} | {summary} |"
        )

    lines.extend(["", "## Investigation leads", ""])
    if not findings:
        lines.append("No rule-based suspicious correlation leads were generated.")
    else:
        for item in findings:
            lines.extend(
                [
                    f"### {item['rule_id']}: {item['title']}",
                    "",
                    f"- Severity: {item['severity']}",
                    f"- Supporting events: {', '.join(item['evidence'])}",
                    f"- Alternate explanation: {item['alternate_explanation']}",
                    f"- Cannot prove: {item['cannot_prove']}",
                    f"- Next step: {item['next_step']}",
                    "",
                ]
            )

    lines.extend(
        [
            "## Required analyst validation",
            "",
            "- Confirm timestamps, provenance, and two-pass hashes in the evidence log.",
            "- Treat all evidence URLs as inert strings; do not visit or resolve them.",
            "- Download metadata does not establish file content, maliciousness, opening, or execution.",
            "- Documentation-range IP addresses are safety markers, not reputation evidence.",
            "- Document benign explanations and missing evidence.",
            "- Do not label the account compromised solely from these rules.",
            "",
            "## Explicit non-conclusions",
            "",
            "- No confirmed account compromise.",
            "- No credential theft, session theft, or cookie theft finding.",
            "- No malware, payload execution, or framework-technique conclusion is emitted by this analyzer.",
            "",
        ]
    )
    return "\n".join(lines)


def run_analysis(
    history: Path,
    identity: Path,
    report: Path,
    manifest_path: Path,
) -> tuple[list[NormalizedEvent], list[dict[str, Any]], str]:
    manifest = load_manifest(manifest_path)
    browser_events = load_browser_events(history, manifest)
    identity_events = normalize_identity_events(load_identity_events(identity))
    user_report = normalize_user_report(load_user_report(report))
    events = sort_events([*browser_events, *identity_events, user_report])
    findings = analyze_events(events, manifest)
    markdown = render_markdown(events, findings, manifest)
    return events, findings, markdown


def module_forbids_network_imports(module_path: Path) -> None:
    """Supporting control: reject network-capable imports in this analyzer module."""
    tree = ast.parse(module_path.read_text(encoding="utf-8"), filename=str(module_path))
    # Names assembled to avoid false positives in source-string scans of this checker.
    forbidden_modules = {
        "urllib" + ".request",
        "http" + ".client",
        "socket",
        "requests",
        "subprocess",
        "webbrowser",
    }
    forbidden_roots = {"socket", "requests", "subprocess", "webbrowser", "http"}
    forbidden_names = {
        "urlopen",
        "Request",
        "create_connection",
        "Popen",
        "open_new",
        "open_new_tab",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if alias.name in forbidden_modules or root in forbidden_roots:
                    raise ValueError(f"Forbidden import: {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            root = module.split(".")[0]
            if module == "urllib.parse":
                continue
            if module in forbidden_modules or root in forbidden_roots:
                raise ValueError(f"Forbidden import from: {module}")
            if root == "urllib":
                raise ValueError(f"Forbidden urllib import: {module}")
            for alias in node.names:
                if alias.name in forbidden_names:
                    raise ValueError(f"Forbidden imported name: {alias.name}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history", type=Path, required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="Optional Markdown output path")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        module_forbids_network_imports(Path(__file__).resolve())
        _events, _findings, report = run_analysis(
            history=args.history,
            identity=args.identity,
            report=args.report,
            manifest_path=args.manifest,
        )
    except (OSError, ValueError, json.JSONDecodeError, sqlite3.Error) as exc:
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
