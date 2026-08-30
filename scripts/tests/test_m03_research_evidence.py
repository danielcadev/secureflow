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

    def test_fresh_npm_evidence_is_exact_and_preserves_the_baseline(self) -> None:
        evidence = load_json("npm-cli-m0.3-fresh-scan-2026-08-30.json")
        self.assertEqual(
            evidence["evidence_version"],
            "secureflow-npm-cli-m0.3-fresh-scan-v2",
        )
        self.assertEqual(
            evidence["supersedes_for_current_engine_observation"],
            "npm-cli-m0.3-pilot-2026-08-30.json",
        )
        self.assertTrue(evidence["preserves_historical_baseline"])
        self.assertEqual(
            evidence["target"]["revision"],
            "b888cc9a9ff34a8b023ff47b784692396635397b",
        )
        self.assertEqual(
            evidence["engine"]["source_commit"],
            "0959cc6d9fe06fb92369497caab78af31cbf98d5",
        )
        self.assertEqual(
            evidence["engine"]["binary_sha256"],
            "14ddca249a22a324ef6fa206268cf7089216cc400d3617c9fb750f40ccc2de3c",
        )
        self.assertEqual(evidence["engine"]["rules_evaluated"], 13)
        self.assertEqual(
            evidence["engine"]["rule_ids"],
            [f"SE{number}" for number in range(1001, 1014)],
        )
        self.assertEqual(
            evidence["report"]["raw_report_sha256"],
            "2557f2ba0a0705e4cf9ee18a00c6201bb35fa82e8d40cb0db9017fe4c2a36e7d",
        )
        self.assertEqual(
            evidence["report"]["semantic_fingerprint"],
            "91b75fdacd4caecb2610d86afdcd855cc9dc5446060ec61aea9ae33fd3159a89",
        )
        self.assertEqual(evidence["report"]["bytes"], 2_508_213)
        self.assertFalse(evidence["report"]["raw_report_published"])

        accounting = evidence["exact_accounting"]
        self.assertEqual(
            accounting,
            {
                "candidate_files": 4859,
                "files_scanned": 4847,
                "normalized_facts_total": 57748,
                "facts_retained": 14,
                "conceptual_graph_nodes_total": 208157,
                "conceptual_graph_edges_total": 368627,
                "graph_nodes_retained": 7,
                "graph_edges_retained": 4,
                "candidate_paths": 3,
                "findings": 0,
                "explicit_abstentions": 3,
                "parser_diagnostics": 0,
                "scan_errors": 0,
                "truncated": False,
                "scan_completed": True,
            },
        )
        resources = evidence["resource_observation"]
        self.assertEqual(resources["wall_seconds"], 19.17)
        self.assertEqual(resources["peak_rss_kib"], 737_564)
        self.assertFalse(resources["performance_claim_allowed"])

        expected_dispositions = [
            (
                "SE1004",
                "lib/utils/oidc.js",
                "actor-authority-equivalence",
                "205c3897d837142dfe549136eed2bbd56949281dbd043cd84be157851f154fcb",
            ),
            (
                "SE1013",
                "workspaces/arborist/lib/arborist/rebuild.js",
                "independent-policy-bypass",
                "a2bc3c16683c14906dee2c4ba9a8ad7d0d35068c8f23b0e62964bedf319ef162",
            ),
            (
                "SE1001",
                "workspaces/libnpmpack/test/index.js",
                "test-context-reachability-unresolved",
                "cb1c16a4983ce6a423371cf0e82f0ab2fadb299ec71cc6a172f6488703b41314",
            ),
        ]
        actual_dispositions = [
            (
                item["rule_id"],
                item["path"],
                item["engine_reason"],
                item["engine_fingerprint"],
            )
            for item in evidence["dispositions"]
        ]
        self.assertEqual(actual_dispositions, expected_dispositions)
        self.assertTrue(
            all(
                item["engine_disposition"] == "explicit-abstention"
                and item["human_disposition"] == "abstained-after-source-review"
                and item["unresolved_gates"]
                for item in evidence["dispositions"]
            )
        )
        self.assertEqual(
            evidence["disposition_counts"],
            {
                "validated_vulnerabilities": 0,
                "abstained_after_source_review": 3,
                "clean_verdict": False,
            },
        )

        protocol = (ROOT / "docs" / "pilots" / "npm-cli-m0.3-pilot.md").read_text(
            encoding="utf-8"
        )
        index = (ROOT / "docs" / "m0.3-research-phases-3-6.md").read_text(
            encoding="utf-8"
        )
        for document in (protocol, index):
            self.assertIn("npm-cli-m0.3-pilot-2026-08-30.json", document)
            self.assertIn("npm-cli-m0.3-fresh-scan-2026-08-30.json", document)

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
