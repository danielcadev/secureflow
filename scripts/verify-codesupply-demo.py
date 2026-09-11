#!/usr/bin/env python3
"""Check the synthetic demo's retained links; never produce a human verdict."""
import hashlib
import json
from pathlib import Path
import sys


def verify(repository, artifacts):
    def load(name):
        return json.loads((artifacts / name).read_text())

    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def require(condition, message):
        if not condition:
            raise ValueError(message)

    inputs = load('fixture-inputs.json')
    actual_inputs = {
        p.relative_to(repository).as_posix(): digest(p)
        for directory in ('codesupply-ready', 'osv-source')
        for p in (repository / 'tests/fixtures' / directory).rglob('*') if p.is_file()
    }
    require(inputs == actual_inputs, 'fixture inputs changed')
    run = load('run.json')
    correlation = load('correlation.json')
    plan = load('orchestration.json')
    bundle = load('catalog.core.manifest.json')
    verification = load('bundle-verification.json')
    snapshot = load('snapshot/manifest.json')
    manifest_hash = digest(artifacts / 'run.json')
    require(run['engine']['report_sha256'] == digest(artifacts / 'engine-report.json'), 'report hash mismatch')
    require(run['engine']['binary_sha256'] == digest(repository / 'tests/fixtures/codesupply-ready/engine.sh'), 'engine hash mismatch')
    require((artifacts / 'engine-report.json').read_bytes() == (repository / 'tests/fixtures/codesupply-ready/engine-report.json').read_bytes(), 'unexpected engine output')
    require(len(run['findings']) == 1, 'expected one synthetic candidate')
    finding = run['findings'][0]
    require(finding['finding_id'] == 'sf_finding_' + hashlib.sha256(b'codesupply-synthetic-candidate-v1').hexdigest(), 'finding identity mismatch')
    require(finding['human_review'] == {'decision': 'pending'}, 'unexpected human decision')
    require(finding['ai_validation']['status'] == 'not_requested' and run['summary']['ai_calls'] == 0, 'unexpected AI activity')
    require(run['summary']['validated_count'] == 0, 'unexpected validation')
    require(run['target']['authorization']['status'] == 'authorized', 'missing authorization')
    require(run['engine']['sandbox_name'] == 'bubblewrap', 'required sandbox missing')
    require(load('installed-check.json') == {'quick_check': 'ok', 'foreign_key_violations': 0, 'search_index_status': 'ready'}, 'installed catalog integrity failed')
    require(run['target']['revision'] == {'kind': 'snapshot', 'value': 'codesupply-synthetic-v1'}, 'revision mismatch')
    require(correlation['linked_run'] == {
        'run_id': run['run_id'], 'manifest_sha256': manifest_hash,
        'finding_id': finding['finding_id'], 'human_decision': 'pending',
    }, 'correlation/run link mismatch')
    require(correlation['package_context'] == {
        'assertion': 'operator-supplied-exact-package-context',
        'ecosystem': 'crates.io', 'name': 'secureflow-fixture', 'version': '1.0.0',
    }, 'package context mismatch')
    semantics = correlation['semantics']
    require(semantics['validation_authority'] == 'human-only', 'authority mismatch')
    for key in ('causal_relationship_asserted', 'changes_human_decision', 'version_result_validates_vulnerability'):
        require(semantics[key] is False, f'unsupported claim: {key}')
    require(correlation['version_summary'] == {'affected': 1, 'not_affected': 0, 'unknown': 0, 'not_evaluated': 0}, 'unexpected advisory assessment')
    require(correlation['catalog'] == bundle['origin']['provenance'], 'restored catalog provenance mismatch')
    require(bundle['payload']['provenance']['complete_snapshot_ids'] == [], 'core projection unexpectedly retains history')
    require(correlation['catalog']['complete_snapshot_ids'] == [snapshot['snapshot_id']], 'snapshot link mismatch')
    require(snapshot['artifact']['sha256'] == digest(artifacts / 'synthetic-osv.zip'), 'archive hash mismatch')
    require(bundle['profile'] == verification['profile'] == 'core', 'profile substitution')
    require(bundle['compressed_sha256'] == digest(artifacts / 'catalog.core.sqlite3.zst'), 'compressed hash mismatch')
    require(bundle['payload']['database_sha256'] == digest(artifacts / 'installed.core.sqlite3'), 'installed database hash mismatch')
    require(verification['manifest_sha256'] == digest(artifacts / 'catalog.core.manifest.json') == (artifacts / 'expected-manifest-sha256.txt').read_text().strip(), 'manifest hash mismatch')
    require(verification['integrity'] == 'verified', 'bundle verification failed')
    require(verification['authenticity'] == 'manifest-sha256-pinned', 'manifest hash was not pinned')
    require(snapshot['accounting']['accepted_records'] == 1 and snapshot['accounting']['quarantined_records'] == 1, 'snapshot accounting mismatch')
    sources = bundle['payload']['composition']['sources']
    require(len(sources) == 1 and sources[0]['license_expression'] == 'CC-BY-4.0', 'license expression mismatch')
    require(len(correlation['advisories']) == 1 and correlation['advisories'][0]['source_record_id'] == 'GHSA-aaaa-bbbb-cccc' and correlation['advisories'][0]['source_name'] == sources[0]['name'], 'advisory source mismatch')
    require(sources[0]['license_evidence_sha256'] == digest(repository / 'tests/fixtures/osv-source/LICENSE'), 'license evidence mismatch')
    require(plan['manifest_sha256'] == manifest_hash and plan['linked_run_id'] == run['run_id'] and plan['target_sha256'] == run['target']['root_sha256'], 'orchestration/run link mismatch')
    require(plan['evidence'] == [{'kind': 'advisory-correlation', 'sha256': digest(artifacts / 'correlation.json')}], 'orchestration evidence mismatch')
    require(plan['next_action'] == 'human-review-or-abstain', 'unexpected next action')
    require(plan['claim_status'] == 'candidates-require-human-review', 'unexpected claim')
    require(plan['state']['pending_human_reviews'] == 1 and plan['state']['terminal_human_reviews'] == 0, 'unexpected review state')
    print('CodeSupply artifact links verified; human review remains pending.')


if __name__ == '__main__':
    verify(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
