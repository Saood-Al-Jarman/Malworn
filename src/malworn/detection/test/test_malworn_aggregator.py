"""Run: python -m unittest discover -s tests -v"""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from malworn_aggregator import (  # noqa: E402
    AggregationError, aggregate_agent_run, aggregate_results, load_json,
    write_report_json,
)

HASH = "f" * 64


def result(tool="hashes", status="success", data=None, call_id="a-1", **extra):
    value = {"tool": tool, "status": status, "call_id": call_id}
    if data is not None:
        value["data"] = data
    elif status == "success":
        value["data"] = {}
    value.update(extra)
    return value


class AggregatorTests(unittest.TestCase):
    def test_preserves_values_and_nested_fact_provenance(self):
        input_data = {"sections": [{"name": ".text", "entropy": 6.21}]}
        report = aggregate_results([result("sections", data=input_data)], file_info={"sha256": HASH})
        section = report["tool_results"][0]
        self.assertEqual(section["data"], input_data)
        self.assertEqual(section["facts"][0]["source_tool"], "sections")
        self.assertEqual(section["facts"][0]["source_call_id"], "a-1")
        self.assertEqual(section["facts"][0]["field_path"], 'data["sections"][0]["name"]')
        self.assertEqual(section["facts"][1]["value"], 6.21)
        self.assertNotIn("verdict", report)

    def test_not_selected_is_not_failure(self):
        report = aggregate_results(
            [result()], file_info={}, selected_tools=["hashes"],
            available_tools=["hashes", "virustotal"],
        )
        self.assertEqual(report["execution_summary"]["not_selected_tools"], ["virustotal"])
        self.assertEqual(report["execution_summary"]["failed_call_count"], 0)

    def test_failed_tool_is_unavailable_without_fake_facts(self):
        report = aggregate_results([
            result("virustotal", "failure", call_id="v-1", error="API timed out")
        ], file_info={}, selected_tools=["virustotal"])
        r = report["tool_results"][0]
        self.assertEqual(r["display_status"], "not_available")
        self.assertEqual(r["facts"], [])
        self.assertEqual(report["execution_summary"]["failed_call_count"], 1)

    def test_selected_tool_missing_result_is_recorded(self):
        report = aggregate_results(
            [result()], file_info={}, selected_tools=["hashes", "imports"]
        )
        self.assertEqual(report["execution_summary"]["missing_results"], ["imports"])
        self.assertEqual(len(report["tool_results"]), 1)

    def test_multiple_calls_same_tool_are_retained(self):
        report = aggregate_results([
            result("hashes", data={"sha256": HASH}, call_id="a"),
            result("hashes", data={"sha256": HASH}, call_id="b"),
        ], file_info={})
        self.assertEqual(report["execution_summary"]["successful_calls"], 2)
        self.assertEqual(len(report["tool_results"]), 2)

    def test_duplicate_call_id_rejected(self):
        with self.assertRaises(AggregationError):
            aggregate_results([result(), result("imports")], file_info={})

    def test_unselected_result_rejected(self):
        with self.assertRaises(AggregationError):
            aggregate_results([result("virustotal")], file_info={}, selected_tools=["hashes"])

    def test_unknown_status_rejected(self):
        with self.assertRaises(AggregationError):
            aggregate_results([result(status="totally_safe")], file_info={})

    def test_registry_mismatch_rejected(self):
        with self.assertRaises(AggregationError):
            aggregate_results([result()], file_info={}, available_tools=["imports"])

    def test_invalid_sha256_rejected(self):
        with self.assertRaises(AggregationError):
            aggregate_results([result()], file_info={"sha256": "wrong"})

    def test_json_roundtrip_and_mock_fixture(self):
        root = Path(__file__).resolve().parents[1]
        mock = load_json(root / "examples" / "mock_agent_run.json")
        report = aggregate_agent_run(mock)
        self.assertEqual(report["analysis_scope"], "static_only")
        self.assertEqual(report["execution_summary"]["successful_calls"], 7)
        self.assertEqual(report["execution_summary"]["not_selected_tools"], ["packer_signatures"])
        self.assertEqual(report["tool_results"][-1]["data"]["found"], False)
        with tempfile.TemporaryDirectory() as tmp:
            p = write_report_json(report, Path(tmp) / "out" / "report.json")
            output = json.loads(p.read_text(encoding="utf-8"))
        self.assertEqual(output, report)

    def test_failed_tool_with_no_data_field(self):
        report = aggregate_results([result(status="error", error="offline")], file_info={})
        self.assertEqual(report["tool_results"][0]["data"], {})


if __name__ == "__main__":
    unittest.main()
