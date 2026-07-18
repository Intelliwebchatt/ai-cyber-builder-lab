import importlib.util
import tempfile
import unittest
from pathlib import Path


MISSION_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = MISSION_ROOT / "src" / "analyze_events.py"
SPEC = importlib.util.spec_from_file_location("analyze_events", MODULE_PATH)
assert SPEC and SPEC.loader
ANALYZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZER)


class AnalyzeEventsTests(unittest.TestCase):
    def test_loads_and_sorts_fixture(self):
        events = ANALYZER.load_events(MISSION_ROOT / "data" / "synthetic-events.jsonl")
        self.assertEqual(8, len(events))
        self.assertEqual("EVT-001", events[0]["event_uid"])
        self.assertEqual("EVT-008", events[-1]["event_uid"])

    def test_generates_expected_investigation_leads(self):
        events = ANALYZER.load_events(MISSION_ROOT / "data" / "synthetic-events.jsonl")
        findings = ANALYZER.analyze_events(events)
        self.assertEqual({"R-001", "R-002", "R-003"}, {item["rule_id"] for item in findings})

        repeated_logons = next(item for item in findings if item["rule_id"] == "R-003")
        self.assertEqual(["EVT-005", "EVT-006", "EVT-007"], repeated_logons["evidence"])

    def test_rejects_invalid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            path.write_text("{not json}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Invalid JSON on line 1"):
                ANALYZER.load_events(path)

    def test_rejects_missing_required_field(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.jsonl"
            path.write_text(
                '{"event_uid":"EVT-X","timestamp":"2026-01-01T00:00:00Z","event_id":"1","host":"H"}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "missing required field: source"):
                ANALYZER.load_events(path)

    def test_markdown_warns_that_rules_are_not_conclusions(self):
        events = ANALYZER.load_events(MISSION_ROOT / "data" / "synthetic-events.jsonl")
        report = ANALYZER.render_markdown(events, ANALYZER.analyze_events(events))
        self.assertIn("investigation leads, not final conclusions", report)
        self.assertIn("R-001", report)


if __name__ == "__main__":
    unittest.main()
