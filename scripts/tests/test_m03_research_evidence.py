from __future__ import annotations

import csv
import hashlib
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "docs" / "evidence"


def load_json(name: str) -> dict[str, object]:
    return json.loads((EVIDENCE / name).read_text(encoding="utf-8"))


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class M03ResearchEvidenceTests(unittest.TestCase):
    def test_npm_pilot_freezes_abstentions_without_a_clean_claim(self) -> None:
        evidence = load_json("npm-cli-m0.3-pilot-2026-08-30.json")
        self.assertEqual(
            evidence["target"]["revision"],
            "b888cc9a9ff34a8b023ff47b784692396635397b",
        )
        self.assertEqual(evidence["frozen_budget"]["full_graph_runs_max"], 0)
        self.assertEqual(evidence["frozen_budget"]["model_calls_max"], 0)
        self.assertEqual(evidence["frozen_budget"]["remote_requests_max"], 0)
        observation = evidence["historical_observation"]
        self.assertEqual(observation["engine_candidates"], 0)
        self.assertEqual(observation["engine_abstentions"], 3)
        self.assertEqual(observation["validated_vulnerabilities"], 0)
        self.assertFalse(observation["clean_verdict"])
        states = evidence["triage_state_counts"]
        self.assertEqual(sum(states.values()), 3)
        self.assertEqual(states["abstained_after_source_review"], 3)
        self.assertEqual(len(evidence["triage"]), 3)
        self.assertTrue(
            all(
                lead["state"] == "abstained-after-source-review"
                and lead["missing_gates"]
                for lead in evidence["triage"]
            )
        )

    def test_mitiquete_inventory_is_not_promoted_to_exposure_or_vulnerability(self) -> None:
        evidence = load_json("mitiquete-offline-web-m0.3-2026-08-30.json")
        self.assertEqual(
            evidence["target"]["revision"],
            "0dfb307902ea6f20c9a2755c8af4d338536b99fd",
        )
        self.assertEqual(evidence["authorization"]["network_requests"], 0)
        self.assertFalse(evidence["authorization"]["target_code_executed"])
        inventory = evidence["offline_pipeline"]["inventory"]
        self.assertEqual(
            inventory["routes_total"],
            inventory["api_routes"]
            + inventory["page_routes"]
            + inventory["server_actions"]
            + inventory["middleware_records"],
        )
        self.assertFalse(inventory["truncated"])
        self.assertEqual(inventory["issues"], 0)
        inference = evidence["offline_pipeline"]["inference"]
        self.assertEqual(
            inference["candidates_total"],
            inference["locally_correlated_http_endpoints"]
            + inference["dynamic_client_call_abstentions"]
            + inference["trpc_candidates_needing_human_review"],
        )
        boundary = evidence["security_decision_boundary"]
        self.assertEqual(
            boundary["not_assessed_candidates"], inference["candidates_total"]
        )
        self.assertEqual(boundary["human_validated_vulnerabilities"], 0)
        self.assertEqual(boundary["production_exposure_observations"], 0)
        self.assertFalse(boundary["clean_verdict"])
        self.assertFalse(boundary["inventory_is_exposure_evidence"])
        self.assertFalse(boundary["inference_is_vulnerability_evidence"])
        staging = evidence["passive_staging_plan"]
        self.assertEqual(staging["state"], "blocked")
        self.assertFalse(staging["production_allowed"])

    def test_human_comparison_remains_blocked_and_claim_safe(self) -> None:
        evidence = load_json("m0.3-human-comparison-readiness-2026-08-30.json")
        design = evidence["minimum_design"]
        self.assertGreaterEqual(design["opaque_holdout_cases"], 20)
        self.assertGreaterEqual(design["vulnerable_cases_min"], 10)
        self.assertGreaterEqual(design["safe_controls_min"], 10)
        self.assertGreaterEqual(design["participants_per_lane_min"], 3)
        self.assertGreaterEqual(design["independent_primary_adjudicators"], 2)
        self.assertTrue(all(not value for value in evidence["blocking_gates"].values()))
        claims = evidence["claims"]
        self.assertEqual(claims["task_bounded_comparison_status"], "not-established")
        self.assertFalse(claims["global_superiority_claim_allowed"])
        self.assertFalse(claims["human_replacement_claim_allowed"])
        self.assertFalse(claims["production_safety_claim_allowed"])

    def test_catalog_measurements_match_csv_and_pass_declared_gates(self) -> None:
        evidence = load_json("catalog-quality-gate-2026-08-30.json")
        csv_path = EVIDENCE / "catalog-quality-gate-2026-08-30.csv"
        source_path = (
            ROOT
            / "crates"
            / "secureflow-knowledge"
            / "examples"
            / "catalog_bench.rs"
        )
        self.assertEqual(evidence["measurement_csv_sha256"], sha256(csv_path))
        self.assertEqual(
            evidence["implementation"]["benchmark_source_sha256"],
            sha256(source_path),
        )
        with csv_path.open(encoding="utf-8", newline="") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual([int(row["source_records"]) for row in rows], [50_000, 100_000])
        measurements = {
            item["source_records"]: item for item in evidence["measurements"]
        }
        self.assertEqual(set(measurements), {50_000, 100_000})
        for row in rows:
            count = int(row["source_records"])
            measurement = measurements[count]
            canonical = int(row["canonical_vulnerabilities"])
            expected = int(row["expected_canonical_vulnerabilities"])
            self.assertEqual(canonical, expected)
            self.assertEqual(int(row["exact_alias_reduction"]), count - canonical)
            self.assertEqual(row["dedup_gate_passed"], "true")
            self.assertEqual(row["quick_check"], "ok")
            self.assertEqual(int(row["foreign_key_violations"]), 0)
            self.assertEqual(row["search_index_status"], "ready")
            self.assertEqual(row["integrity_gate_passed"], "true")
            self.assertEqual(measurement["canonical_vulnerabilities"], canonical)
            self.assertTrue(measurement["dedup_gate_passed"])
            self.assertTrue(measurement["integrity_gate_passed"])
        gates = evidence["gates"]
        at_100k = measurements[100_000]
        self.assertLessEqual(
            at_100k["database_bytes"], gates["database_bytes_at_100k_max"]
        )
        self.assertLessEqual(
            at_100k["total_ingest_ms"], gates["total_ingest_ms_at_100k_max"]
        )
        self.assertGreaterEqual(
            at_100k["records_per_second"], gates["records_per_second_at_100k_min"]
        )
        self.assertLessEqual(
            at_100k["exact_identifier_median_us"],
            gates["exact_identifier_median_us_at_100k_max"],
        )
        self.assertLessEqual(
            at_100k["exact_package_median_us"],
            gates["exact_package_median_us_at_100k_max"],
        )
        self.assertLessEqual(
            at_100k["worst_case_fts_median_us"],
            gates["worst_case_fts_median_us_at_100k_max"],
        )
        self.assertEqual(evidence["gate_result"], "passed")
        self.assertFalse(evidence["real_source_reference_lane"]["rerun_as_part_of_this_gate"])
        self.assertFalse(evidence["real_source_reference_lane"]["latency_result_inherited"])
        self.assertIn(
            "warm",
            " ".join(evidence["limitations"]).lower(),
        )


if __name__ == "__main__":
    unittest.main()
