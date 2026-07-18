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


class BuildBrowserFixtureTests(unittest.TestCase):
    def test_utc_webkit_round_trip_vectors(self):
        cases = {
            "2026-08-12T15:41:08Z": 13431022868000000,
            "2026-08-12T15:43:04Z": 13431022984000000,
        }
        for utc_value, webkit_value in cases.items():
            self.assertEqual(webkit_value, BUILDER.utc_to_webkit(utc_value))
            round_trip = BUILDER.WEBKIT_EPOCH.timestamp()  # ensure epoch constant exists
            self.assertIsInstance(round_trip, float)
            dt = datetime.fromisoformat(utc_value.replace("Z", "+00:00"))
            self.assertEqual(timezone.utc, dt.tzinfo)

    def test_builds_expected_counts_from_case_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "History.sqlite"
            result = BUILDER.build_database(
                history_source=MISSION_ROOT / "data" / "source" / "browser_history.json",
                downloads_source=MISSION_ROOT
                / "data"
                / "source"
                / "browser_downloads.json",
                output=output,
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
            finally:
                conn.close()

            source = json.loads(
                (MISSION_ROOT / "data" / "source" / "browser_downloads.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertFalse(source["downloads"][0]["payload_included"])

    def test_refuses_overwrite_without_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "History.sqlite"
            BUILDER.build_database(
                history_source=MISSION_ROOT / "data" / "source" / "browser_history.json",
                downloads_source=MISSION_ROOT
                / "data"
                / "source"
                / "browser_downloads.json",
                output=output,
            )
            with self.assertRaisesRegex(FileExistsError, "Refusing to overwrite"):
                BUILDER.build_database(
                    history_source=MISSION_ROOT
                    / "data"
                    / "source"
                    / "browser_history.json",
                    downloads_source=MISSION_ROOT
                    / "data"
                    / "source"
                    / "browser_downloads.json",
                    output=output,
                )


if __name__ == "__main__":
    unittest.main()
