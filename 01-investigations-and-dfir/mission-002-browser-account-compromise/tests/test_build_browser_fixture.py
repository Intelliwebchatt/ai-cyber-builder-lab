import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


MISSION_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = MISSION_ROOT / "src" / "build_browser_fixture.py"
SPEC = importlib.util.spec_from_file_location("build_browser_fixture", MODULE_PATH)
assert SPEC and SPEC.loader
BUILDER = importlib.util.module_from_spec(SPEC)
sys.modules["build_browser_fixture"] = BUILDER
SPEC.loader.exec_module(BUILDER)

CASE_SOURCE = MISSION_ROOT / "data" / "source"


class BuildBrowserFixtureTests(unittest.TestCase):
    def test_utc_webkit_round_trip_vectors(self):
        cases = {
            "2026-08-12T15:41:08Z": 13431022868000000,
            "2026-08-12T15:43:04Z": 13431022984000000,
            "2026-08-12T15:41:08.123456Z": 13431022868123456,
        }
        for utc_value, webkit_value in cases.items():
            self.assertEqual(webkit_value, BUILDER.utc_to_webkit(utc_value))
            dt = datetime.fromisoformat(utc_value.replace("Z", "+00:00"))
            self.assertEqual(timezone.utc, dt.tzinfo)

    def test_rejects_naive_timestamp(self):
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            BUILDER.utc_to_webkit("2026-08-12T15:41:08")

    def test_builds_expected_counts_from_case_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "History.sqlite"
            result = BUILDER.build_database(
                history_source=CASE_SOURCE / "browser_history.json",
                downloads_source=CASE_SOURCE / "browser_downloads.json",
                output=output,
                manifest_path=CASE_SOURCE / "fixture-manifest.json",
            )
            self.assertEqual(3, result["urls"])
            self.assertEqual(3, result["visits"])
            self.assertEqual(1, result["downloads"])

            conn = sqlite3.connect(output)
            try:
                visit_time = conn.execute(
                    "SELECT visit_time FROM visits WHERE id = 1"
                ).fetchone()[0]
                self.assertEqual(13431022868000000, visit_time)
                download_start = conn.execute(
                    "SELECT start_time FROM downloads WHERE id = 1"
                ).fetchone()[0]
                self.assertEqual(13431022984000000, download_start)
                total_bytes, received_bytes = conn.execute(
                    "SELECT total_bytes, received_bytes FROM downloads WHERE id = 1"
                ).fetchone()
                self.assertEqual(24576, total_bytes)
                self.assertEqual(24576, received_bytes)
                transitions = {
                    row[0]: row[1]
                    for row in conn.execute(
                        "SELECT id, transition FROM visits ORDER BY id"
                    ).fetchall()
                }
                self.assertEqual({1: 1, 2: 0, 3: 0}, transitions)
            finally:
                conn.close()

            source = json.loads(
                (CASE_SOURCE / "browser_downloads.json").read_text(encoding="utf-8")
            )
            self.assertFalse(source["downloads"][0]["payload_included"])

    def test_refuses_overwrite_without_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "History.sqlite"
            BUILDER.build_database(
                history_source=CASE_SOURCE / "browser_history.json",
                downloads_source=CASE_SOURCE / "browser_downloads.json",
                output=output,
                manifest_path=CASE_SOURCE / "fixture-manifest.json",
            )
            with self.assertRaisesRegex(FileExistsError, "Refusing to overwrite"):
                BUILDER.build_database(
                    history_source=CASE_SOURCE / "browser_history.json",
                    downloads_source=CASE_SOURCE / "browser_downloads.json",
                    output=output,
                    manifest_path=CASE_SOURCE / "fixture-manifest.json",
                )

    def test_rejects_inconsistent_link_transition(self):
        with tempfile.TemporaryDirectory() as directory:
            history = json.loads(
                (CASE_SOURCE / "browser_history.json").read_text(encoding="utf-8")
            )
            history["visits"][1]["transition"] = 1
            history_path = Path(directory) / "browser_history.json"
            history_path.write_text(json.dumps(history), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must use transition=0 \\(LINK\\)"):
                BUILDER.build_database(
                    history_source=history_path,
                    downloads_source=CASE_SOURCE / "browser_downloads.json",
                    output=Path(directory) / "History.sqlite",
                    manifest_path=CASE_SOURCE / "fixture-manifest.json",
                )

    def test_rejects_swapped_manifest_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = json.loads(
                (CASE_SOURCE / "fixture-manifest.json").read_text(encoding="utf-8")
            )
            manifest["event_mappings"]["visits"][0]["event_uid"] = "BRW-002"
            manifest["event_mappings"]["visits"][1]["event_uid"] = "BRW-001"
            manifest_path = Path(directory) / "fixture-manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not match source"):
                BUILDER.build_database(
                    history_source=CASE_SOURCE / "browser_history.json",
                    downloads_source=CASE_SOURCE / "browser_downloads.json",
                    output=Path(directory) / "History.sqlite",
                    manifest_path=manifest_path,
                )

    def test_rejects_expected_count_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = json.loads(
                (CASE_SOURCE / "fixture-manifest.json").read_text(encoding="utf-8")
            )
            manifest["expected_counts"]["visits"] = 99
            manifest_path = Path(directory) / "fixture-manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "expected_counts.visits"):
                BUILDER.build_database(
                    history_source=CASE_SOURCE / "browser_history.json",
                    downloads_source=CASE_SOURCE / "browser_downloads.json",
                    output=Path(directory) / "History.sqlite",
                    manifest_path=manifest_path,
                )

    def test_rejects_non_object_visit_record(self):
        with tempfile.TemporaryDirectory() as directory:
            history = json.loads(
                (CASE_SOURCE / "browser_history.json").read_text(encoding="utf-8")
            )
            history["visits"][0] = ["not", "an", "object"]
            history_path = Path(directory) / "browser_history.json"
            history_path.write_text(json.dumps(history), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must be a JSON object"):
                BUILDER.build_database(
                    history_source=history_path,
                    downloads_source=CASE_SOURCE / "browser_downloads.json",
                    output=Path(directory) / "History.sqlite",
                    manifest_path=CASE_SOURCE / "fixture-manifest.json",
                )


if __name__ == "__main__":
    unittest.main()
