#!/usr/bin/env python3
"""Build a synthetic Chromium-like History SQLite database from reviewable JSON.

ISO-8601 UTC timestamps in the source JSON are canonical. This builder converts
them to WebKit/Chromium microseconds when writing SQLite rows.
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


def parse_utc(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid ISO-8601 UTC timestamp: {value}") from exc


def utc_to_webkit(value: str) -> int:
    dt = parse_utc(value)
    if dt.tzinfo is None:
        raise ValueError(f"Timestamp must be timezone-aware UTC: {value}")
    delta = dt.astimezone(timezone.utc) - WEBKIT_EPOCH
    return int(delta.total_seconds() * 1_000_000)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    if data.get("synthetic") is not True:
        raise ValueError(f"{path} must declare synthetic=true")
    return data


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


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

    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()

    conn = sqlite3.connect(output)
    try:
        create_schema(conn)
        urls_written: set[int] = set()

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

            url_id = int(visit["sqlite_url_id"])
            visit_id = int(visit["sqlite_visit_id"])
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
                        int(visit["visit_count"]),
                        int(visit["typed_count"]),
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
                        int(visit["visit_count"]),
                        int(visit["typed_count"]),
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
                    int(visit["from_visit"]),
                    int(visit["transition"]),
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
            if download.get("payload_included") is not False:
                raise ValueError(
                    f"Download {download['event_uid']} must set payload_included=false"
                )

            download_id = int(download["sqlite_download_id"])
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
                    download["guid"],
                    download["current_path"],
                    download["target_path"],
                    start_webkit,
                    int(download["received_bytes"]),
                    int(download["total_bytes"]),
                    int(download["danger_type"]),
                    int(download["interrupt_reason"]),
                    end_webkit,
                    download["tab_referrer_url"],
                    download["tab_url"],
                    download["tab_referrer_url"],
                    download["mime_type"],
                    download["original_mime_type"],
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
