import unittest
from unittest.mock import patch

import server


class EvidenceIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.original_history = list(server.SCAN_HISTORY)
        server.SCAN_HISTORY.clear()

    def tearDown(self):
        server.SCAN_HISTORY.clear()
        server.SCAN_HISTORY.extend(self.original_history)

    def test_missing_module_is_unavailable_without_synthetic_telemetry(self):
        with patch("server.resolve_script_path", return_value="/definitely/missing/aragos_test_module.py"):
            output, _duration, unavailable = server.execute_module_safe(
                "aragos_test_module.py",
                {"name": "Test Module", "number": "test"},
                "example.com",
            )

        self.assertTrue(unavailable)
        self.assertIn("[UNAVAILABLE]", output)
        self.assertIn("no synthetic telemetry was generated", output.lower())
        self.assertNotIn("ASN / Geo Edge", output)
        self.assertNotIn("OpenSSH", output)

    def test_unavailable_module_does_not_create_findings_or_risk_analysis(self):
        fake_tool = {
            "number": "test-id",
            "name": "Test Module",
            "section": "Network & Infrastructure",
            "script": "aragos_test_module.py",
        }
        with (
            patch("server.tools_mapping", {"test-id": fake_tool}),
            patch("server.execute_module_safe", return_value=(
                "[UNAVAILABLE] Live evidence was not collected.",
                0.01,
                True,
            )),
            patch("server.generate_report"),
            patch("server.ai_engine.analyze_scan_report") as analyze,
        ):
            record = server.run_scan_job(
                server.ScanRequest(
                    target="example.com",
                    module_ids=["test-id"],
                    mode="single",
                    auto_ai_analyze=True,
                )
            )

        self.assertEqual(record["status"], "unavailable")
        self.assertEqual(record["severities"]["Test Module"], "UNAVAILABLE")
        self.assertEqual(record["findings"], [])
        self.assertIsNone(record["ai_analysis"])
        self.assertEqual(record["runtimes"][0]["status"], "unavailable")
        analyze.assert_not_called()

    def test_ai_analysis_rejects_scan_without_live_evidence(self):
        server.SCAN_HISTORY.append({
            "scan_id": "scan-test",
            "status": "unavailable",
            "severities": {"Test Module": "UNAVAILABLE"},
            "outputs": {"Test Module": "[UNAVAILABLE]"},
            "findings": [],
        })

        with self.assertRaises(server.HTTPException) as caught:
            server.api_ai_analyze(server.AIAnalyzeRequest(scan_id="scan-test"))

        self.assertEqual(caught.exception.status_code, 409)


if __name__ == "__main__":
    unittest.main()
