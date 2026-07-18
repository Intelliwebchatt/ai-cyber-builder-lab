#!/usr/bin/env python3
"""Build a synthetic Chromium-like History SQLite database from reviewable JSON.

ISO-8601 UTC timestamps in the source JSON are canonical. This builder converts
them to WebKit/Chromium microseconds when writing SQLite rows.

Chromium core transition values used by this fixture:
- 0 = LINK (navigation from a previous page)
- 1 = TYPED (omnibox / typed entry)

See: https://chromium.googlesource.com/chromium/src/+/HEAD/ui/base/page_transition_types.h
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Chromium ui/base/page_transition_types.h core values
TRANSITION_LINK = 0
TRANSITION_TYPED = 1


def parse_utc(value: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Timestamp must be a non-empty string: {value!r}")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid ISO-8601 UTC timestamp: {value}") from exc
    if dt.tzinfo is None:
        raise ValueError(f"Timestamp must be timezone-aware ISO-8601: {value}")
    return dt.astimezone(timezone.utc)


def utc_to_webkit(value: str) -> int:
    dt = parse_utc(value)
    delta = dt - WEBKIT_EPOCH
    # Integer day/second/microsecond arithmetic avoids float rounding.
    return (
        delta.days * 86_400 * 1_000_000
        + delta.seconds * 1_000_000
        + delta.microseconds
    )


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def require_nonblank_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-blank string")
    return value


def require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a JSON boolean")
    return value


def require_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be a JSON integer")
    return value


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    data = require_object(data, str(path))
    if data.get("synthetic") is not True:
        raise ValueError(f"{path} must declare synthetic=true")
    return data


def load_manifest(path: Path) -> dict[str, Any]:
    manifest = load_json(path)
    for required in (
        "official_host_allowlist",
        "case_attribution",
        "event_mappings",
        "expected_counts",
        "correlation_windows_minutes",
        "report_phrase_screen",
    ):
        if required not in manifest:
            raise ValueError(f"Manifest missing required field: {required}")
    require_object(manifest["case_attribution"], "case_attribution")
    require_object(manifest["event_mappings"], "event_mappings")
    require_object(manifest["expected_counts"], "expected_counts")
    require_object(
        manifest["correlation_windows_minutes"], "correlation_windows_minutes"
    )
    if not isinstance(manifest["official_host_allowlist"], list):
        raise ValueError("official_host_allowlist must be a JSON array")
    if not isinstance(manifest["report_phrase_screen"], list):
        raise ValueError("report_phrase_screen must be a JSON array")
    return manifest


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_transition(visit: dict[str, Any]) -> None:
    """Reject Chromium transition metadata inconsistent with from_visit/typed_count."""
    event_uid = require_nonblank_str(visit.get("event_uid"), "Visit event_uid")
    transition = require_int(visit.get("transition"), f"Visit {event_uid} transition")
    from_visit = require_int(visit.get("from_visit"), f"Visit {event_uid} from_visit")
    typed_count = require_int(visit.get("typed_count"), f"Visit {event_uid} typed_count")
    if transition not in {TRANSITION_LINK, TRANSITION_TYPED}:
        raise ValueError(
            f"Visit {event_uid} transition must be 0 (LINK) or 1 (TYPED), got {transition}"
        )
    if from_visit != 0 and typed_count == 0 and transition != TRANSITION_LINK:
        raise ValueError(
            f"Visit {event_uid}: linked navigation (from_visit={from_visit}, "
            f"typed_count=0) must use transition=0 (LINK), not {transition}"
        )
    if from_visit == 0 and typed_count > 0 and transition != TRANSITION_TYPED:
        raise ValueError(
            f"Visit {event_uid}: typed entry (from_visit=0, typed_count={typed_count}) "
            f"must use transition=1 (TYPED), not {transition}"
        )


def validate_sources_against_manifest(
    history: dict[str, Any],
    downloads: dict[str, Any],
    manifest: dict[str, Any],
) -> None:
    mappings = manifest["event_mappings"]
    visit_mappings = mappings.get("visits")
    download_mappings = mappings.get("downloads")
    if not isinstance(visit_mappings, list):
        raise ValueError("event_mappings.visits must be a JSON array")
    if not isinstance(download_mappings, list):
        raise ValueError("event_mappings.downloads must be a JSON array")

    visits = history.get("visits")
    download_rows = downloads.get("downloads")
    if not isinstance(visits, list) or not visits:
        raise ValueError("browser_history.json must include a non-empty visits list")
    if not isinstance(download_rows, list) or not download_rows:
        raise ValueError("browser_downloads.json must include a non-empty downloads list")

    for index, visit in enumerate(visits):
        require_object(visit, f"visits[{index}]")
    for index, download in enumerate(download_rows):
        require_object(download, f"downloads[{index}]")
    for index, item in enumerate(visit_mappings):
        require_object(item, f"event_mappings.visits[{index}]")
    for index, item in enumerate(download_mappings):
        require_object(item, f"event_mappings.downloads[{index}]")

    seen_uids: set[str] = set()
    seen_visit_ids: set[int] = set()
    seen_url_ids: set[int] = set()
    source_visit_keys: dict[str, tuple[int, int]] = {}
    for visit in visits:
        event_uid = require_nonblank_str(visit.get("event_uid"), "Visit event_uid")
        if event_uid in seen_uids:
            raise ValueError(f"Duplicate source event_uid: {event_uid}")
        seen_uids.add(event_uid)
        url_id = require_int(visit.get("sqlite_url_id"), f"{event_uid} sqlite_url_id")
        visit_id = require_int(
            visit.get("sqlite_visit_id"), f"{event_uid} sqlite_visit_id"
        )
        if visit_id in seen_visit_ids:
            raise ValueError(f"Duplicate sqlite_visit_id: {visit_id}")
        seen_visit_ids.add(visit_id)
        seen_url_ids.add(url_id)
        source_visit_keys[event_uid] = (url_id, visit_id)
        validate_transition(visit)

    source_download_keys: dict[str, int] = {}
    seen_download_ids: set[int] = set()
    for download in download_rows:
        event_uid = require_nonblank_str(download.get("event_uid"), "Download event_uid")
        if event_uid in seen_uids:
            raise ValueError(f"Duplicate source event_uid: {event_uid}")
        seen_uids.add(event_uid)
        download_id = require_int(
            download.get("sqlite_download_id"), f"{event_uid} sqlite_download_id"
        )
        if download_id in seen_download_ids:
            raise ValueError(f"Duplicate sqlite_download_id: {download_id}")
        seen_download_ids.add(download_id)
        source_download_keys[event_uid] = download_id

    mapped_visit_uids: set[str] = set()
    mapped_visit_ids: set[int] = set()
    for item in visit_mappings:
        event_uid = require_nonblank_str(
            item.get("event_uid"), "Visit mapping event_uid"
        )
        url_id = require_int(item.get("sqlite_url_id"), f"{event_uid} mapping sqlite_url_id")
        visit_id = require_int(
            item.get("sqlite_visit_id"), f"{event_uid} mapping sqlite_visit_id"
        )
        if event_uid in mapped_visit_uids:
            raise ValueError(f"Duplicate visit mapping event_uid: {event_uid}")
        if visit_id in mapped_visit_ids:
            raise ValueError(f"Duplicate visit mapping sqlite_visit_id: {visit_id}")
        mapped_visit_uids.add(event_uid)
        mapped_visit_ids.add(visit_id)
        if event_uid not in source_visit_keys:
            raise ValueError(f"Manifest visit mapping {event_uid} missing from source")
        if source_visit_keys[event_uid] != (url_id, visit_id):
            raise ValueError(
                f"Manifest visit mapping for {event_uid} does not match source "
                f"sqlite ids {source_visit_keys[event_uid]}"
            )

    if mapped_visit_uids != set(source_visit_keys):
        raise ValueError("Visit source records and manifest mappings are not one-to-one")

    mapped_download_uids: set[str] = set()
    mapped_download_ids: set[int] = set()
    for item in download_mappings:
        event_uid = require_nonblank_str(
            item.get("event_uid"), "Download mapping event_uid"
        )
        download_id = require_int(
            item.get("sqlite_download_id"), f"{event_uid} mapping sqlite_download_id"
        )
        if event_uid in mapped_download_uids:
            raise ValueError(f"Duplicate download mapping event_uid: {event_uid}")
        if download_id in mapped_download_ids:
            raise ValueError(
                f"Duplicate download mapping sqlite_download_id: {download_id}"
            )
        mapped_download_uids.add(event_uid)
        mapped_download_ids.add(download_id)
        if event_uid not in source_download_keys:
            raise ValueError(
                f"Manifest download mapping {event_uid} missing from source"
            )
        if source_download_keys[event_uid] != download_id:
            raise ValueError(
                f"Manifest download mapping for {event_uid} does not match source "
                f"sqlite_download_id {source_download_keys[event_uid]}"
            )

    if mapped_download_uids != set(source_download_keys):
        raise ValueError(
            "Download source records and manifest mappings are not one-to-one"
        )

    counts = manifest["expected_counts"]
    expected_urls = require_int(counts.get("urls"), "expected_counts.urls")
    expected_visits = require_int(counts.get("visits"), "expected_counts.visits")
    expected_downloads = require_int(
        counts.get("downloads"), "expected_counts.downloads"
    )
    if expected_visits != len(visits):
        raise ValueError(
            f"expected_counts.visits={expected_visits} does not match source "
            f"visit count {len(visits)}"
        )
    if expected_downloads != len(download_rows):
        raise ValueError(
            f"expected_counts.downloads={expected_downloads} does not match source "
            f"download count {len(download_rows)}"
        )
    if expected_urls != len(seen_url_ids):
        raise ValueError(
            f"expected_counts.urls={expected_urls} does not match distinct "
            f"source url count {len(seen_url_ids)}"
        )


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 0,
            typed_count INTEGER DEFAULT 0,
            last_visit_time INTEGER NOT NULL,
            hidden INTEGER DEFAULT 0
        );
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY,
            url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL,
            from_visit INTEGER DEFAULT 0,
            transition INTEGER DEFAULT 0,
            segment_id INTEGER DEFAULT 0,
            visit_duration INTEGER DEFAULT 0,
            incremented_omnibox_typed_score INTEGER DEFAULT 0
        );
        CREATE TABLE downloads (
            id INTEGER PRIMARY KEY,
            guid TEXT NOT NULL,
            current_path TEXT NOT NULL,
            target_path TEXT NOT NULL,
            start_time INTEGER NOT NULL,
            received_bytes INTEGER NOT NULL,
            total_bytes INTEGER NOT NULL,
            state INTEGER DEFAULT 1,
            danger_type INTEGER DEFAULT 0,
            interrupt_reason INTEGER DEFAULT 0,
            hash BLOB,
            end_time INTEGER NOT NULL,
            opened INTEGER DEFAULT 0,
            last_access_time INTEGER DEFAULT 0,
            transient INTEGER DEFAULT 0,
            referrer TEXT,
            site_url TEXT,
            tab_url TEXT,
            tab_referrer_url TEXT,
            http_method TEXT DEFAULT 'GET',
            by_ext_id TEXT DEFAULT '',
            by_ext_name TEXT DEFAULT '',
            etag TEXT DEFAULT '',
            last_modified TEXT DEFAULT '',
            mime_type TEXT,
            original_mime_type TEXT
        );
        CREATE TABLE downloads_url_chains (
            id INTEGER NOT NULL,
            chain_index INTEGER NOT NULL,
            url TEXT NOT NULL,
            PRIMARY KEY (id, chain_index)
        );
        """
    )


def build_database(
    history_source: Path,
    downloads_source: Path,
    output: Path,
    overwrite: bool = False,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    if output.exists() and not overwrite:
        raise FileExistsError(
            f"Refusing to overwrite existing database without --overwrite: {output}"
        )

    history = load_json(history_source)
    downloads = load_json(downloads_source)
    visits = history.get("visits")
    download_rows = downloads.get("downloads")
    if not isinstance(visits, list) or not visits:
        raise ValueError("browser_history.json must include a non-empty visits list")
    if not isinstance(download_rows, list) or not download_rows:
        raise ValueError("browser_downloads.json must include a non-empty downloads list")

    if manifest_path is not None:
        manifest = load_manifest(manifest_path)
        validate_sources_against_manifest(history, downloads, manifest)
    else:
        for index, visit in enumerate(visits):
            require_object(visit, f"visits[{index}]")
            validate_transition(visit)
        for index, download in enumerate(download_rows):
            require_object(download, f"downloads[{index}]")

    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()

    conn = sqlite3.connect(output)
    try:
        create_schema(conn)
        urls_written: set[int] = set()
        seen_visit_ids: set[int] = set()
        seen_download_ids: set[int] = set()
        seen_uids: set[str] = set()

        for visit in visits:
            for required in (
                "event_uid",
                "sqlite_url_id",
                "sqlite_visit_id",
                "url",
                "title",
                "visit_time_utc",
                "transition",
                "from_visit",
                "typed_count",
                "visit_count",
            ):
                if required not in visit:
                    raise ValueError(f"Visit missing required field: {required}")
            if visit.get("synthetic") is not True:
                raise ValueError(f"Visit {visit['event_uid']} must declare synthetic=true")

            event_uid = require_nonblank_str(visit["event_uid"], "Visit event_uid")
            if event_uid in seen_uids:
                raise ValueError(f"Duplicate source event_uid: {event_uid}")
            seen_uids.add(event_uid)

            url_id = require_int(visit["sqlite_url_id"], f"{event_uid} sqlite_url_id")
            visit_id = require_int(
                visit["sqlite_visit_id"], f"{event_uid} sqlite_visit_id"
            )
            if visit_id in seen_visit_ids:
                raise ValueError(f"Duplicate sqlite_visit_id: {visit_id}")
            seen_visit_ids.add(visit_id)
            validate_transition(visit)
            require_nonblank_str(visit["url"], f"{event_uid} url")
            require_nonblank_str(visit["title"], f"{event_uid} title")
            webkit_time = utc_to_webkit(str(visit["visit_time_utc"]))

            if url_id not in urls_written:
                conn.execute(
                    """
                    INSERT INTO urls (
                        id, url, title, visit_count, typed_count, last_visit_time, hidden
                    ) VALUES (?, ?, ?, ?, ?, ?, 0)
                    """,
                    (
                        url_id,
                        visit["url"],
                        visit["title"],
                        require_int(visit["visit_count"], f"{event_uid} visit_count"),
                        require_int(visit["typed_count"], f"{event_uid} typed_count"),
                        webkit_time,
                    ),
                )
                urls_written.add(url_id)
            else:
                conn.execute(
                    """
                    UPDATE urls
                    SET title = ?, visit_count = ?, typed_count = ?, last_visit_time = ?
                    WHERE id = ?
                    """,
                    (
                        visit["title"],
                        require_int(visit["visit_count"], f"{event_uid} visit_count"),
                        require_int(visit["typed_count"], f"{event_uid} typed_count"),
                        webkit_time,
                        url_id,
                    ),
                )

            conn.execute(
                """
                INSERT INTO visits (
                    id, url, visit_time, from_visit, transition,
                    segment_id, visit_duration, incremented_omnibox_typed_score
                ) VALUES (?, ?, ?, ?, ?, 0, 0, 0)
                """,
                (
                    visit_id,
                    url_id,
                    webkit_time,
                    require_int(visit["from_visit"], f"{event_uid} from_visit"),
                    require_int(visit["transition"], f"{event_uid} transition"),
                ),
            )

        for download in download_rows:
            for required in (
                "event_uid",
                "sqlite_download_id",
                "guid",
                "current_path",
                "target_path",
                "tab_url",
                "tab_referrer_url",
                "mime_type",
                "original_mime_type",
                "total_bytes",
                "received_bytes",
                "start_time_utc",
                "end_time_utc",
                "danger_type",
                "interrupt_reason",
                "payload_included",
            ):
                if required not in download:
                    raise ValueError(f"Download missing required field: {required}")
            if download.get("synthetic") is not True:
                raise ValueError(
                    f"Download {download['event_uid']} must declare synthetic=true"
                )
            require_bool(
                download.get("payload_included"),
                f"Download {download['event_uid']} payload_included",
            )
            if download.get("payload_included") is not False:
                raise ValueError(
                    f"Download {download['event_uid']} must set payload_included=false"
                )

            event_uid = require_nonblank_str(download["event_uid"], "Download event_uid")
            if event_uid in seen_uids:
                raise ValueError(f"Duplicate source event_uid: {event_uid}")
            seen_uids.add(event_uid)

            download_id = require_int(
                download["sqlite_download_id"], f"{event_uid} sqlite_download_id"
            )
            if download_id in seen_download_ids:
                raise ValueError(f"Duplicate sqlite_download_id: {download_id}")
            seen_download_ids.add(download_id)
            start_webkit = utc_to_webkit(str(download["start_time_utc"]))
            end_webkit = utc_to_webkit(str(download["end_time_utc"]))
            conn.execute(
                """
                INSERT INTO downloads (
                    id, guid, current_path, target_path, start_time, received_bytes,
                    total_bytes, state, danger_type, interrupt_reason, hash, end_time,
                    opened, last_access_time, transient, referrer, site_url, tab_url,
                    tab_referrer_url, http_method, by_ext_id, by_ext_name, etag,
                    last_modified, mime_type, original_mime_type
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, NULL, ?, 0, 0, 0, ?, '', ?, ?,
                    'GET', '', '', '', '', ?, ?
                )
                """,
                (
                    download_id,
                    require_nonblank_str(download["guid"], f"{event_uid} guid"),
                    require_nonblank_str(
                        download["current_path"], f"{event_uid} current_path"
                    ),
                    require_nonblank_str(
                        download["target_path"], f"{event_uid} target_path"
                    ),
                    start_webkit,
                    require_int(
                        download["received_bytes"], f"{event_uid} received_bytes"
                    ),
                    require_int(download["total_bytes"], f"{event_uid} total_bytes"),
                    require_int(download["danger_type"], f"{event_uid} danger_type"),
                    require_int(
                        download["interrupt_reason"], f"{event_uid} interrupt_reason"
                    ),
                    end_webkit,
                    require_nonblank_str(
                        download["tab_referrer_url"], f"{event_uid} tab_referrer_url"
                    ),
                    require_nonblank_str(download["tab_url"], f"{event_uid} tab_url"),
                    require_nonblank_str(
                        download["tab_referrer_url"], f"{event_uid} tab_referrer_url"
                    ),
                    require_nonblank_str(download["mime_type"], f"{event_uid} mime_type"),
                    require_nonblank_str(
                        download["original_mime_type"],
                        f"{event_uid} original_mime_type",
                    ),
                ),
            )
            conn.execute(
                """
                INSERT INTO downloads_url_chains (id, chain_index, url)
                VALUES (?, 0, ?)
                """,
                (download_id, download["tab_url"]),
            )

        conn.commit()
        url_count = conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
        visit_count = conn.execute("SELECT COUNT(*) FROM visits").fetchone()[0]
        download_count = conn.execute("SELECT COUNT(*) FROM downloads").fetchone()[0]
    finally:
        conn.close()

    if manifest_path is not None:
        counts = load_manifest(manifest_path)["expected_counts"]
        if require_int(counts["urls"], "expected_counts.urls") != url_count:
            raise ValueError("Generated urls count does not match expected_counts.urls")
        if require_int(counts["visits"], "expected_counts.visits") != visit_count:
            raise ValueError(
                "Generated visits count does not match expected_counts.visits"
            )
        if require_int(counts["downloads"], "expected_counts.downloads") != download_count:
            raise ValueError(
                "Generated downloads count does not match expected_counts.downloads"
            )

    return {
        "output": str(output),
        "urls": url_count,
        "visits": visit_count,
        "downloads": download_count,
        "sha256": sha256_file(output),
        "python_version": sys.version.split()[0],
        "sqlite_version": sqlite3.sqlite_version,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history-source", type=Path, required=True)
    parser.add_argument("--downloads-source", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow replacing an existing output database",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        result = build_database(
            history_source=args.history_source,
            downloads_source=args.downloads_source,
            output=args.output,
            overwrite=args.overwrite,
            manifest_path=args.manifest,
        )
    except (OSError, ValueError, FileExistsError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc

    print(f"Wrote {result['output']}")
    print(f"urls={result['urls']} visits={result['visits']} downloads={result['downloads']}")
    print(f"sha256={result['sha256']}")
    print(f"python={result['python_version']} sqlite={result['sqlite_version']}")
    print(
        "Note: SQLite bytes are not guaranteed identical across SQLite versions; "
        "record runtime versions with evidence hashes."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
