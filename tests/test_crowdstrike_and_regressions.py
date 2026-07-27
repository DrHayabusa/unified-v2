from __future__ import annotations

import csv
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mva_engine.tenable_dashboards import build_adhoc_dashboard, build_monthly_comparison, load_monthly_snapshot
from mva_engine.tenable_normalizer import (
    calculate_patch_priority,
    detect_source,
    is_exploit_available,
    load_findings,
)


CS = ROOT / "samples" / "crowdstrike_100_row"


class PriorityMatrixTests(unittest.TestCase):
    def test_exact_priority_matrix(self) -> None:
        expected = {
            ("Critical", True): "P1",
            ("High", True): "P1",
            ("Medium", True): "P2",
            ("Low", True): "P2",
            ("Critical", False): "P2",
            ("High", False): "P2",
            ("Medium", False): "P3",
            ("Low", False): "P4",
        }
        for inputs, priority in expected.items():
            with self.subTest(inputs=inputs):
                self.assertEqual(calculate_patch_priority(*inputs), priority)

    def test_exploit_signal_variants(self) -> None:
        positives = ["Yes", "Available", "Exploit available", "Actively exploited", "Confirmed", "Weaponized", "PoC", "1", "3"]
        negatives = ["No", "0", "False", "No known exploit", "Unavailable", "", "None"]
        for value in positives:
            with self.subTest(value=value):
                self.assertTrue(is_exploit_available(value))
        for value in negatives:
            with self.subTest(value=value):
                self.assertFalse(is_exploit_available(value))


class CrowdStrikeDetectionTests(unittest.TestCase):
    def test_detailed_export_detection(self) -> None:
        headers = read_headers(CS / "crowdstrike_vulnerabilities_july_2026_100plus.csv")
        self.assertEqual(detect_source(headers), "crowdstrike_vulnerabilities")
        self.assertIn("Vulnerability ID", headers)
        self.assertIn("Exploit status label", headers)
        self.assertIn("Is CISA KEV", headers)
        self.assertIn("Internet exposure", headers)

    def test_remediation_asset_export_detection(self) -> None:
        headers = read_headers(CS / "crowdstrike_remediation_per_assets_july_2026_100plus.csv")
        self.assertEqual(detect_source(headers), "crowdstrike_remediation_assets")
        self.assertIn("RecommendedRemediation", headers)
        self.assertIn("RemediationDetail", headers)
        self.assertIn("Count", headers)
        self.assertIn("ExPRT Critical", headers)

    def test_per_asset_export_uses_detailed_mapping(self) -> None:
        headers = read_headers(CS / "crowdstrike_vulnerability_per_asset_july_2026_100plus.csv")
        self.assertEqual(detect_source(headers), "crowdstrike_vulnerabilities")


class CrowdStrikeNormalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.detailed = load_findings(CS / "crowdstrike_vulnerabilities_july_2026_100plus.csv")
        cls.aggregated = load_findings(CS / "crowdstrike_remediation_per_assets_july_2026_100plus.csv")

    def test_closed_rows_are_excluded(self) -> None:
        self.assertEqual(len(self.detailed), 120)
        self.assertTrue(all(finding.status == "Open" for finding in self.detailed))

    def test_detailed_core_mapping(self) -> None:
        finding = self.detailed[0]
        self.assertEqual(finding.source_tool, "crowdstrike_vulnerabilities")
        self.assertTrue(finding.ip_address.startswith("10.40."))
        self.assertTrue(finding.dns_name.endswith(".corp.example"))
        self.assertTrue(finding.source_vulnerability_id.startswith("CS-VULN-"))
        self.assertTrue(finding.vulnerability_name)
        self.assertTrue(finding.cve.startswith("CVE-"))
        self.assertIn(finding.severity, {"Critical", "High", "Medium", "Low"})
        self.assertIn(finding.patch_priority, {"P1", "P2", "P3", "P4"})
        self.assertGreaterEqual(finding.asset_exposure, 0)
        self.assertLessEqual(finding.asset_exposure, 1000)
        self.assertTrue(finding.remediation)
        self.assertTrue(finding.kb_links.startswith("http"))
        self.assertTrue(finding.first_discovered)
        self.assertEqual(finding.last_observed, "2026-07-31")
        self.assertEqual(finding.record_count, 1)
        self.assertEqual(finding.export_type, "Vulnerabilities / Vulnerability per asset")

    def test_exploit_and_kev_mapping(self) -> None:
        exploitable = [finding for finding in self.detailed if finding.exploit_available]
        kev = [finding for finding in self.detailed if finding.cisa_kev]
        internet = [finding for finding in self.detailed if finding.internet_exposed]
        self.assertEqual(len(exploitable), 47)
        self.assertEqual(len(kev), 11)
        self.assertEqual(len(internet), 24)
        self.assertTrue(all(finding.patch_priority in {"P1", "P2"} for finding in exploitable))

    def test_aggregate_count_is_preserved(self) -> None:
        self.assertEqual(len(self.aggregated), 100)
        self.assertTrue(all(finding.record_count >= 2 for finding in self.aggregated))
        self.assertEqual(sum(finding.record_count for finding in self.aggregated), 542)
        self.assertTrue(all(finding.export_type == "Remediation per assets" for finding in self.aggregated))

    def test_aggregate_adhoc_dashboard_is_weighted(self) -> None:
        dashboard = build_adhoc_dashboard(self.aggregated)
        self.assertEqual(dashboard["total_vulnerabilities"], 542)
        self.assertEqual(dashboard["distinct_assets"], 45)
        self.assertEqual(sum(dashboard["severity_counts"].values()), 542)
        self.assertEqual(sum(dashboard["patch_priority_counts"].values()), 542)
        self.assertEqual(dashboard["detected_export_types"], ["Remediation per assets"])
        self.assertEqual(len(dashboard["top_10_affected_assets"]), 10)
        self.assertEqual(len(dashboard["top_products"]), 8)
        self.assertGreater(dashboard["exploit_available"], 0)
        self.assertGreater(dashboard["internet_exposed"], 0)


class MonthlyDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.snapshots = [
            load_monthly_snapshot(CS / "crowdstrike_vulnerabilities_april_2026_100plus.csv", "April 2026"),
            load_monthly_snapshot(CS / "crowdstrike_vulnerabilities_may_2026_100plus.csv", "May 2026"),
            load_monthly_snapshot(CS / "crowdstrike_vulnerabilities_june_2026_100plus.csv", "June 2026"),
            load_monthly_snapshot(CS / "crowdstrike_vulnerabilities_july_2026_100plus.csv", "July 2026"),
        ]
        cls.dashboard = build_monthly_comparison(cls.snapshots)

    def test_required_trends(self) -> None:
        self.assertEqual([row["discovered_count"] for row in self.dashboard["trend_discovered_last_3_months"]], [30, 25, 20])
        self.assertEqual([row["remediated_count"] for row in self.dashboard["trend_remediated_last_3_months"]], [20, 20, 25])
        self.assertEqual([row["month"] for row in self.dashboard["trend_discovered_last_3_months"]], ["May 2026", "June 2026", "July 2026"])

    def test_total_open_formula(self) -> None:
        open_counts = self.dashboard["total_open_vulnerabilities"]
        self.assertEqual(open_counts["total_open"], 120)
        self.assertEqual(open_counts["new_vulnerabilities"], 20)
        self.assertEqual(open_counts["not_closed_from_previous_months"], 100)
        self.assertEqual(open_counts["new_vulnerabilities"] + open_counts["not_closed_from_previous_months"], open_counts["total_open"])

    def test_priority_distribution(self) -> None:
        priorities = self.dashboard["total_open_by_patch_priority"]
        self.assertEqual(priorities, {"P1": 24, "P2": 59, "P3": 18, "P4": 19})
        self.assertEqual(sum(priorities.values()), 120)

    def test_age_priority_matrix(self) -> None:
        matrix = self.dashboard["total_open_by_age_and_patch_priority"]
        self.assertEqual(set(matrix), {"P1", "P2", "P3", "P4"})
        for priority in matrix:
            self.assertGreaterEqual(matrix[priority][">7 days"], matrix[priority][">30 days"])
            self.assertGreaterEqual(matrix[priority][">30 days"], matrix[priority][">60 days"])
            self.assertGreaterEqual(matrix[priority][">60 days"], matrix[priority][">180 days (6+ months)"])

    def test_patched_formula(self) -> None:
        patched = self.dashboard["total_vulnerabilities_patched_last_month"]
        self.assertEqual(patched["previous_month_open"], 125)
        self.assertEqual(patched["new_vulnerabilities_identified_this_month"], 20)
        self.assertEqual(patched["current_month_open"], 120)
        self.assertEqual(patched["patched_count"], 25)
        self.assertEqual(patched["patched_count_by_key_diff"], 25)
        self.assertEqual(125 + 20 - 120, patched["patched_count"])

    def test_crowdstrike_insights(self) -> None:
        insights = self.dashboard["crowdstrike_insights"]
        self.assertEqual(insights["exploit_available"], 47)
        self.assertEqual(insights["cisa_kev"], 11)
        self.assertEqual(insights["internet_exposed"], 24)
        self.assertEqual(insights["critical_assets"], 12)
        self.assertEqual(len(insights["top_products"]), 8)
        self.assertEqual(len(insights["top_assets"]), 10)


class ExistingSourceRegressionTests(unittest.TestCase):
    def test_tenable_sc_still_loads(self) -> None:
        findings = load_findings(ROOT / "samples" / "tenable_100_row" / "tenable_sc_july_2026_100plus.csv")
        self.assertGreaterEqual(len(findings), 100)
        self.assertEqual(findings[0].source_tool, "tenable_sc")
        self.assertTrue(findings[0].finding_key)

    def test_tenable_io_still_uses_vulnerability_age(self) -> None:
        findings = load_findings(ROOT / "samples" / "tenable_100_row" / "tenable_io_july_2026_100plus.csv")
        self.assertGreaterEqual(len(findings), 100)
        self.assertEqual(findings[0].source_tool, "tenable_io")
        self.assertIsNotNone(findings[0].vulnerability_age_days)

    def test_qualys_monthly_still_loads(self) -> None:
        findings = load_findings(ROOT / "samples" / "qualys_100_row" / "qualys_monthly_july_2026_100plus.csv")
        self.assertGreaterEqual(len(findings), 100)
        self.assertEqual(findings[0].source_tool, "qualys_monthly")
        self.assertIn(findings[0].patch_priority, {"P1", "P2", "P3", "P4"})


def read_headers(path: Path) -> list[str]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return next(csv.reader(handle))


if __name__ == "__main__":
    unittest.main()
