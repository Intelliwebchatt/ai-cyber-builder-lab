import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
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
    def _build(self, history: Path, downloads: Path, output: Path, manifest: Path) -> None:
        BUILDER.build_database(
            history_source=history,
            downloads_source=downloads,
            output=output,
            overwrite=True,
            manifest_path=manifest,
        )

    def _write_json(self, path: Path, data: object) -> None:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def _case_bundle(self, directory: Path):
        history_db = directory / "History.sqlite"
        self._build(
            CASE_SOURCE / "browser_history.json",
            CASE_SOURCE / "browser_downloads.json",
            history_db,
            CASE_SOURCE / "fixture-manifest.json",
        )
        return history_db

    def test_timestamp_conversion_vectors(self):
        self.assertEqual(
            "2026-08-12T15:41:08Z",
            ANALYZER.format_utc(ANALYZER.webkit_to_utc(13431022868000000)),
        )
        self.assertEqual(
            "2026-08-12T15:43:04Z",
            ANALYZER.format_utc(ANALYZER.webkit_to_utc(13431022984000000)),
        )
        micros = BUILDER.utc_to_webkit("2026-08-12T15:41:08.123456Z")
        self.assertEqual(13431022868123456, micros)
        recovered = ANALYZER.webkit_to_utc(micros)
        self.assertEqual(
            datetime(2026, 8, 12, 15, 41, 8, 123456, tzinfo=timezone.utc),
            recovered,
        )

    def test_sorts_chronologically_with_stable_tiebreak(self):
        with tempfile.TemporaryDirectory() as directory:
            history_db = self._case_bundle(Path(directory))
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
            history_db = self._case_bundle(Path(directory))
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
                BENIGN / "fixture-manifest.json",
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
                '"app":"WebPortal","result":"challenge_required","synthetic":true}\n'
            )
            path.write_text(line + line, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Duplicate identity event_uid"):
                ANALYZER.load_identity_events(path)

    def test_rejects_string_false_new_device(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            path.write_text(
                '{"event_uid":"ID-X","timestamp":"2026-08-12T15:44:47Z",'
                '"event_type":"MFA_SUCCESS","user":"jordan.lee@example.test",'
                '"source":"identity_provider","source_ip":"198.51.100.77",'
                '"app":"WebPortal","result":"success","new_device":"false",'
                '"synthetic":true}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "new_device must be a JSON boolean"):
                ANALYZER.load_identity_events(path)

    def test_rejects_naive_timestamp(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            path.write_text(
                '{"event_uid":"ID-X","timestamp":"2026-08-12T15:44:47",'
                '"event_type":"MFA_SUCCESS","user":"jordan.lee@example.test",'
                '"source":"identity_provider","source_ip":"198.51.100.77",'
                '"app":"WebPortal","result":"success","new_device":true,'
                '"synthetic":true}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "timezone-aware"):
                ANALYZER.load_identity_events(path)

    def test_rejects_non_object_identity_row(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            path.write_text('["not","an","object"]\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must be a JSON object"):
                ANALYZER.load_identity_events(path)

    def test_rejects_cross_source_duplicate_event_uid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            history_db = self._case_bundle(root)
            identity = root / "identity-events.jsonl"
            identity.write_text(
                '{"event_uid":"BRW-001","timestamp":"2026-08-12T15:44:19Z",'
                '"event_type":"MFA_CHALLENGE","user":"jordan.lee@example.test",'
                '"source":"identity_provider","source_ip":"198.51.100.77",'
                '"app":"WebPortal","result":"challenge_required","new_device":true,'
                '"synthetic":true}\n'
                '{"event_uid":"ID-002","timestamp":"2026-08-12T15:44:47Z",'
                '"event_type":"MFA_SUCCESS","user":"jordan.lee@example.test",'
                '"source":"identity_provider","source_ip":"198.51.100.77",'
                '"app":"WebPortal","result":"success","new_device":true,'
                '"synthetic":true}\n'
                '{"event_uid":"ID-003","timestamp":"2026-08-12T15:45:12Z",'
                '"event_type":"PASSWORD_CHANGE","user":"jordan.lee@example.test",'
                '"source":"identity_provider","source_ip":"198.51.100.77",'
                '"app":"WebPortal","result":"success","new_device":true,'
                '"synthetic":true}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "Duplicate event_uid across inputs"):
                ANALYZER.run_analysis(
                    history=history_db,
                    identity=identity,
                    report=CASE_SOURCE / "user-report.json",
                    manifest_path=CASE_SOURCE / "fixture-manifest.json",
                )

    def test_rejects_conflicting_manifest_url_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            history_db = self._case_bundle(root)
            manifest = json.loads(
                (CASE_SOURCE / "fixture-manifest.json").read_text(encoding="utf-8")
            )
            # Point visit 1 at the wrong url id so SQLite and manifest disagree.
            manifest["event_mappings"]["visits"][0]["sqlite_url_id"] = 2
            manifest_path = root / "fixture-manifest.json"
            self._write_json(manifest_path, manifest)
            with self.assertRaisesRegex(ValueError, "conflicts with SQLite"):
                ANALYZER.run_analysis(
                    history=history_db,
                    identity=CASE_SOURCE / "identity-events.jsonl",
                    report=CASE_SOURCE / "user-report.json",
                    manifest_path=manifest_path,
                )

    def test_rejects_duplicate_manifest_mapping(self):
        manifest = json.loads(
            (CASE_SOURCE / "fixture-manifest.json").read_text(encoding="utf-8")
        )
        manifest["event_mappings"]["visits"].append(
            copy.deepcopy(manifest["event_mappings"]["visits"][0])
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture-manifest.json"
            self._write_json(path, manifest)
            with self.assertRaisesRegex(ValueError, "Duplicate mapping"):
                ANALYZER.load_manifest(path)

    def test_rejects_missing_manifest_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            history_db = self._case_bundle(root)
            manifest = json.loads(
                (CASE_SOURCE / "fixture-manifest.json").read_text(encoding="utf-8")
            )
            manifest["event_mappings"]["visits"].pop()
            manifest["expected_counts"]["visits"] = 2
            manifest["expected_counts"]["urls"] = 2
            manifest_path = root / "fixture-manifest.json"
            self._write_json(manifest_path, manifest)
            with self.assertRaisesRegex(ValueError, "not one-to-one"):
                ANALYZER.run_analysis(
                    history=history_db,
                    identity=CASE_SOURCE / "identity-events.jsonl",
                    report=CASE_SOURCE / "user-report.json",
                    manifest_path=manifest_path,
                )

    def test_rejects_correlation_window_mismatch(self):
        manifest = json.loads(
            (CASE_SOURCE / "fixture-manifest.json").read_text(encoding="utf-8")
        )
        manifest["correlation_windows_minutes"]["WINDOW_USER_REPORT"] = 999
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture-manifest.json"
            self._write_json(path, manifest)
            with self.assertRaisesRegex(ValueError, "correlation window WINDOW_USER_REPORT"):
                ANALYZER.load_manifest(path)

    def test_rejects_expected_count_mismatch_for_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            history_db = self._case_bundle(root)
            manifest = json.loads(
                (CASE_SOURCE / "fixture-manifest.json").read_text(encoding="utf-8")
            )
            manifest["expected_counts"]["identity_events"] = 1
            manifest_path = root / "fixture-manifest.json"
            self._write_json(manifest_path, manifest)
            with self.assertRaisesRegex(ValueError, "expected_counts.identity_events"):
                ANALYZER.run_analysis(
                    history=history_db,
                    identity=CASE_SOURCE / "identity-events.jsonl",
                    report=CASE_SOURCE / "user-report.json",
                    manifest_path=manifest_path,
                )

    def test_r001_requires_allowlisted_sign_in_theme(self):
        """Allowlisted /security alone must not satisfy M002-R001."""
        events = [
            ANALYZER.NormalizedEvent(
                event_uid="BRW-SEC",
                timestamp_utc=ANALYZER.parse_utc("2026-08-12T15:41:08Z"),
                category="browser_visit",
                summary="security",
                host="accounts.example.test",
                url="https://accounts.example.test/security",
                title="Security settings",
                user="jordan.lee@example.test",
            ),
            ANALYZER.NormalizedEvent(
                event_uid="BRW-VERIFY",
                timestamp_utc=ANALYZER.parse_utc("2026-08-12T15:42:31Z"),
                category="browser_visit",
                summary="verify",
                host="accounts-example.test",
                url="https://accounts-example.test/account/verify",
                title="Verify your account",
                user="jordan.lee@example.test",
            ),
        ]
        manifest = ANALYZER.load_manifest(CASE_SOURCE / "fixture-manifest.json")
        findings = ANALYZER.analyze_events(events, manifest)
        self.assertEqual([], [item for item in findings if item["rule_id"] == "M002-R001"])

    def test_r002_requires_matching_non_allowlisted_host(self):
        events = [
            ANALYZER.NormalizedEvent(
                event_uid="BRW-VERIFY",
                timestamp_utc=ANALYZER.parse_utc("2026-08-12T15:42:31Z"),
                category="browser_visit",
                summary="verify",
                host="accounts-example.test",
                url="https://accounts-example.test/account/verify",
                title="Verify your account",
                user="jordan.lee@example.test",
            ),
            ANALYZER.NormalizedEvent(
                event_uid="BRW-DL",
                timestamp_utc=ANALYZER.parse_utc("2026-08-12T15:43:04Z"),
                category="browser_download",
                summary="download",
                host="other-example.test",
                url="https://other-example.test/file.pdf",
                user="jordan.lee@example.test",
                payload_included=False,
                total_bytes=100,
                received_bytes=100,
            ),
        ]
        manifest = ANALYZER.load_manifest(CASE_SOURCE / "fixture-manifest.json")
        findings = ANALYZER.analyze_events(events, manifest)
        self.assertEqual([], [item for item in findings if item["rule_id"] == "M002-R002"])

    def test_r003_ignores_future_or_mismatched_challenge(self):
        visit = ANALYZER.NormalizedEvent(
            event_uid="BRW-VERIFY",
            timestamp_utc=ANALYZER.parse_utc("2026-08-12T15:42:31Z"),
            category="browser_visit",
            summary="verify",
            host="accounts-example.test",
            url="https://accounts-example.test/account/verify",
            title="Verify your account",
            user="jordan.lee@example.test",
        )
        mfa = ANALYZER.NormalizedEvent(
            event_uid="ID-MFA",
            timestamp_utc=ANALYZER.parse_utc("2026-08-12T15:44:47Z"),
            category="identity",
            summary="mfa",
            user="jordan.lee@example.test",
            source_ip="198.51.100.77",
            event_type="MFA_SUCCESS",
            new_device=True,
            app="WebPortal",
            result="success",
        )
        future_challenge = ANALYZER.NormalizedEvent(
            event_uid="ID-CH-FUTURE",
            timestamp_utc=ANALYZER.parse_utc("2026-08-12T15:45:00Z"),
            category="identity",
            summary="challenge later",
            user="jordan.lee@example.test",
            source_ip="198.51.100.77",
            event_type="MFA_CHALLENGE",
            new_device=True,
            app="WebPortal",
            result="challenge_required",
        )
        mismatched = ANALYZER.NormalizedEvent(
            event_uid="ID-CH-MISMATCH",
            timestamp_utc=ANALYZER.parse_utc("2026-08-12T15:44:19Z"),
            category="identity",
            summary="challenge other app",
            user="jordan.lee@example.test",
            source_ip="203.0.113.50",
            event_type="MFA_CHALLENGE",
            new_device=True,
            app="OtherApp",
            result="challenge_required",
        )
        manifest = ANALYZER.load_manifest(CASE_SOURCE / "fixture-manifest.json")
        findings = ANALYZER.analyze_events(
            [visit, mfa, future_challenge, mismatched], manifest
        )
        r003 = [item for item in findings if item["rule_id"] == "M002-R003"]
        self.assertEqual(1, len(r003))
        self.assertEqual(["BRW-VERIFY", "ID-MFA"], r003[0]["evidence"])

    def test_r005_orders_evidence_by_chronology_and_stable_id(self):
        """Generic IDs must order by timestamp then event_uid, not hard-coded case IDs."""
        events = [
            ANALYZER.NormalizedEvent(
                event_uid="ZZ-VISIT",
                timestamp_utc=ANALYZER.parse_utc("2026-08-12T15:42:31Z"),
                category="browser_visit",
                summary="verify",
                host="accounts-example.test",
                url="https://accounts-example.test/account/verify",
                title="Verify your account",
                user="jordan.lee@example.test",
            ),
            ANALYZER.NormalizedEvent(
                event_uid="AA-DOWNLOAD",
                timestamp_utc=ANALYZER.parse_utc("2026-08-12T15:43:04Z"),
                category="browser_download",
                summary="download",
                host="accounts-example.test",
                url="https://accounts-example.test/account/verify",
                user="jordan.lee@example.test",
                payload_included=False,
                total_bytes=100,
                received_bytes=100,
            ),
            ANALYZER.NormalizedEvent(
                event_uid="MM-PASSWORD",
                timestamp_utc=ANALYZER.parse_utc("2026-08-12T15:45:12Z"),
                category="identity",
                summary="password",
                user="jordan.lee@example.test",
                source_ip="198.51.100.77",
                event_type="PASSWORD_CHANGE",
                new_device=True,
                app="WebPortal",
                result="success",
            ),
            ANALYZER.NormalizedEvent(
                event_uid="TT-REPORT",
                timestamp_utc=ANALYZER.parse_utc("2026-08-12T16:02:40Z"),
                category="user_report",
                summary="Unexpected verify your account and password-change notice",
                user="jordan.lee@example.test",
                report_text=(
                    "Unexpected verify your account page and password-change confirmation"
                ),
            ),
        ]
        manifest = ANALYZER.load_manifest(CASE_SOURCE / "fixture-manifest.json")
        findings = ANALYZER.analyze_events(events, manifest)
        r005 = [item for item in findings if item["rule_id"] == "M002-R005"]
        self.assertEqual(1, len(r005))
        self.assertEqual(
            ["ZZ-VISIT", "AA-DOWNLOAD", "MM-PASSWORD", "TT-REPORT"],
            r005[0]["evidence"],
        )

    def test_rejects_invalid_sqlite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "not-a-db.sqlite"
            path.write_text("not sqlite", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Invalid or unreadable SQLite"):
                ANALYZER.open_history_readonly(path)

    def test_markdown_is_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            history_db = self._case_bundle(Path(directory))
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

    def test_case_source_transitions_match_chromium_semantics(self):
        history = json.loads(
            (CASE_SOURCE / "browser_history.json").read_text(encoding="utf-8")
        )
        by_uid = {item["event_uid"]: item for item in history["visits"]}
        self.assertEqual(1, by_uid["BRW-001"]["transition"])
        self.assertEqual(0, by_uid["BRW-001"]["from_visit"])
        self.assertEqual(1, by_uid["BRW-001"]["typed_count"])
        self.assertEqual(0, by_uid["BRW-002"]["transition"])
        self.assertEqual(1, by_uid["BRW-002"]["from_visit"])
        self.assertEqual(0, by_uid["BRW-002"]["typed_count"])
        self.assertEqual(0, by_uid["BRW-004"]["transition"])
        self.assertEqual(2, by_uid["BRW-004"]["from_visit"])
        self.assertEqual(0, by_uid["BRW-004"]["typed_count"])


if __name__ == "__main__":
    unittest.main()
