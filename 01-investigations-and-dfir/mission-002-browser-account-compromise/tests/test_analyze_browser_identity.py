import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


MISSION_ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = MISSION_ROOT / "src" / "build_browser_fixture.py"
ANALYZER_PATH = MISSION_ROOT / "src" / "analyze_browser_identity.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BUILDER = _load_module("build_browser_fixture", BUILDER_PATH)
ANALYZER = _load_module("analyze_browser_identity", ANALYZER_PATH)

CASE_SOURCE = MISSION_ROOT / "data" / "source"
BENIGN = MISSION_ROOT / "tests" / "fixtures" / "benign"


class AnalyzeBrowserIdentityTests(unittest.TestCase):
    def _build(self, history: Path, downloads: Path, output: Path) -> None:
        BUILDER.build_database(
            history_source=history,
            downloads_source=downloads,
            output=output,
            overwrite=True,
        )

    def test_timestamp_conversion_vectors(self):
        self.assertEqual(
            "2026-08-12T15:41:08Z",
            ANALYZER.format_utc(ANALYZER.webkit_to_utc(13431022868000000)),
        )
        self.assertEqual(
            "2026-08-12T15:43:04Z",
            ANALYZER.format_utc(ANALYZER.webkit_to_utc(13431022984000000)),
        )

    def test_sorts_chronologically_with_stable_tiebreak(self):
        with tempfile.TemporaryDirectory() as directory:
            history_db = Path(directory) / "History.sqlite"
            self._build(
                CASE_SOURCE / "browser_history.json",
                CASE_SOURCE / "browser_downloads.json",
                history_db,
            )
            events, _findings, _report = ANALYZER.run_analysis(
                history=history_db,
                identity=CASE_SOURCE / "identity-events.jsonl",
                report=CASE_SOURCE / "user-report.json",
                manifest_path=CASE_SOURCE / "fixture-manifest.json",
            )
            uids = [event.event_uid for event in events]
            self.assertEqual(
                [
                    "BRW-001",
                    "BRW-002",
                    "BRW-003",
                    "ID-001",
                    "ID-002",
                    "ID-003",
                    "BRW-004",
                    "RPT-001",
                ],
                uids,
            )

    def test_generates_expected_leads_with_supporting_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            history_db = Path(directory) / "History.sqlite"
            self._build(
                CASE_SOURCE / "browser_history.json",
                CASE_SOURCE / "browser_downloads.json",
                history_db,
            )
            _events, findings, report = ANALYZER.run_analysis(
                history=history_db,
                identity=CASE_SOURCE / "identity-events.jsonl",
                report=CASE_SOURCE / "user-report.json",
                manifest_path=CASE_SOURCE / "fixture-manifest.json",
            )
            by_rule = {item["rule_id"]: item for item in findings}
            self.assertEqual(
                {"M002-R001", "M002-R002", "M002-R003", "M002-R004", "M002-R005"},
                set(by_rule),
            )
            self.assertEqual(["BRW-001", "BRW-002"], by_rule["M002-R001"]["evidence"])
            self.assertEqual(["BRW-002", "BRW-003"], by_rule["M002-R002"]["evidence"])
            self.assertEqual(
                ["BRW-002", "ID-001", "ID-002"], by_rule["M002-R003"]["evidence"]
            )
            self.assertEqual(
                ["BRW-002", "ID-002", "ID-003"], by_rule["M002-R004"]["evidence"]
            )
            self.assertEqual(
                ["BRW-002", "BRW-003", "ID-003", "RPT-001"],
                by_rule["M002-R005"]["evidence"],
            )
            self.assertIn("investigation leads, not final conclusions", report)
            self.assertIn("does not authenticate the human user", report)
            self.assertIn("payload_included=false", report)
            self.assertNotIn("T1566", report)
            self.assertNotIn("T1078", report)
            self.assertNotIn("T1098", report)

    def test_benign_fixture_produces_no_suspicious_leads(self):
        with tempfile.TemporaryDirectory() as directory:
            history_db = Path(directory) / "History.sqlite"
            self._build(
                BENIGN / "browser_history.json",
                BENIGN / "browser_downloads.json",
                history_db,
            )
            _events, findings, report = ANALYZER.run_analysis(
                history=history_db,
                identity=BENIGN / "identity-events.jsonl",
                report=BENIGN / "user-report.json",
                manifest_path=BENIGN / "fixture-manifest.json",
            )
            self.assertEqual([], findings)
            self.assertIn(
                "No rule-based suspicious correlation leads were generated.", report
            )

    def test_rejects_missing_required_identity_field(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            path.write_text(
                '{"event_uid":"ID-X","timestamp":"2026-08-12T15:44:47Z",'
                '"event_type":"MFA_SUCCESS","user":"jordan.lee@example.test",'
                '"source":"identity_provider","result":"success","synthetic":true}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "missing required field: source_ip"):
                ANALYZER.load_identity_events(path)

    def test_rejects_malformed_identity_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            path.write_text("{not json}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Invalid JSON on line 1"):
                ANALYZER.load_identity_events(path)

    def test_rejects_duplicate_identity_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dup.jsonl"
            line = (
                '{"event_uid":"ID-001","timestamp":"2026-08-12T15:44:19Z",'
                '"event_type":"MFA_CHALLENGE","user":"jordan.lee@example.test",'
                '"source":"identity_provider","source_ip":"198.51.100.77",'
                '"result":"challenge_required","synthetic":true}\n'
            )
            path.write_text(line + line, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Duplicate identity event_uid"):
                ANALYZER.load_identity_events(path)

    def test_rejects_invalid_sqlite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "not-a-db.sqlite"
            path.write_text("not sqlite", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Invalid or unreadable SQLite"):
                ANALYZER.open_history_readonly(path)

    def test_markdown_is_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            history_db = Path(directory) / "History.sqlite"
            self._build(
                CASE_SOURCE / "browser_history.json",
                CASE_SOURCE / "browser_downloads.json",
                history_db,
            )
            first = ANALYZER.run_analysis(
                history=history_db,
                identity=CASE_SOURCE / "identity-events.jsonl",
                report=CASE_SOURCE / "user-report.json",
                manifest_path=CASE_SOURCE / "fixture-manifest.json",
            )[2]
            second = ANALYZER.run_analysis(
                history=history_db,
                identity=CASE_SOURCE / "identity-events.jsonl",
                report=CASE_SOURCE / "user-report.json",
                manifest_path=CASE_SOURCE / "fixture-manifest.json",
            )[2]
            self.assertEqual(first, second)

    def test_module_forbids_network_imports(self):
        ANALYZER.module_forbids_network_imports(ANALYZER_PATH)
        source = ANALYZER_PATH.read_text(encoding="utf-8")
        self.assertIn("import urllib.parse", source)
        self.assertNotRegex(source, r"(?m)^\s*import\s+socket\b")
        self.assertNotRegex(source, r"(?m)^\s*import\s+requests\b")
        self.assertNotRegex(source, r"(?m)^\s*import\s+subprocess\b")
        self.assertNotRegex(source, r"(?m)^\s*import\s+webbrowser\b")
        self.assertNotRegex(source, r"(?m)^\s*from\s+urllib\.request\s+import\b")
        self.assertNotRegex(source, r"(?m)^\s*from\s+http\.client\s+import\b")

    def test_manifest_has_no_mutable_hash_fields(self):
        manifest = json.loads(
            (CASE_SOURCE / "fixture-manifest.json").read_text(encoding="utf-8")
        )
        serialized = json.dumps(manifest)
        self.assertNotIn("sha256", serialized.lower())
        self.assertNotIn("hash_placeholder", serialized.lower())


if __name__ == "__main__":
    unittest.main()
