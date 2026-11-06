import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import crypto from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createCompanyResearch, openCompanyResearch } from '../../plugins/secureflow/scripts/company-research-core.mjs';

const sha = (value) => createHash('sha256').update(value).digest('hex');
const id = (kind, value) => `sf_asset_${sha(`${kind}\n${value}`)}`;
const encode = (value) => `${JSON.stringify(value)}\n`;
const source = (name = 'official', extra = {}) => ({ id: name, kind: 'official-site', reference_url: 'https://example.com/', content_sha256: sha('declared content'), ...extra });
const asset = (kind = 'domain', value = 'example.com', sourceIds = ['official'], extra = {}) => ({ kind, value, source_ids: sourceIds, relations: [], limitations: ['Partial external evidence; ownership remains unverified.'], ...extra });
const bundle = (assets = [asset()], sources = [source()]) => ({ contract_version: 'secureflow-company-discovery-v1', sources, assets });
function fixture(t, seed = { kind: 'company', value: 'Example Company' }) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secureflow-company-test-')); fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const session = createCompanyResearch({ workspaceRoot: root, seed });
  const directory = path.join(root, session.id);
  const reopen = () => openCompanyResearch({ workspaceRoot: root, workspaceId: session.id });
  const names = () => fs.readdirSync(directory).sort();
  return { root, session, directory, reopen, names };
}
function unchanged(f, operation, code) {
  const before = f.names(); const original = fs.writeFileSync; let writes = 0;
  fs.writeFileSync = (...args) => { writes++; return original(...args); };
  try { assert.throws(operation, { code }); } finally { fs.writeFileSync = original; }
  assert.equal(writes, 0); assert.deepEqual(f.names(), before);
}
function withFsFault(fault, operation) {
  const original = fs.fsyncSync;
  fs.fsyncSync = (fd) => { if (fault(fd)) throw Object.assign(new Error('untrusted filesystem detail'), { code: 'EIO' }); return original(fd); };
  try { operation(); } finally { fs.fsyncSync = original; }
}

test('company intake is unresolved, private, durable, closed and incapable of testing', (t) => {
  const f = fixture(t, { kind: 'company', value: '  Example   Company  ' });
  assert.deepEqual(f.names(), ['request.json', 'request.sha256']);
  const description = f.session.describe();
  assert.equal(description.executor_mode, 'unavailable');
  assert.equal(description.request.seed.value, 'Example Company');
  assert.deepEqual(description.request.capabilities, { discovery: 'external-host-evidence-import', active_testing: 'disabled', repo_analysis: 'requires-separate-authorization', human_decisions: 'human-only' });
  assert.deepEqual(description.request.limits, { max_batches: 64, max_sources: 128, max_assets: 512, max_batch_bytes: 65536 });
  assert.deepEqual(Object.keys(description.request), ['contract_version', 'workspace_id', 'seed', 'created_at', 'capabilities', 'limits']);
  assert.equal(description.request_sha256, sha(fs.readFileSync(path.join(f.directory, 'request.json'))));
  assert.equal(f.session.summary().identity_status, 'company-identity-unresolved');
  assert.equal(f.session.summary().coverage.asset_count, 0);
  assert.equal(fs.statSync(f.directory).mode & 0o777, 0o700);
  for (const name of f.names()) assert.equal(fs.statSync(path.join(f.directory, name)).mode & 0o777, 0o600);
  assert.equal('execute' in f.session, false); assert.equal('approve' in f.session, false);
  description.request.capabilities.active_testing = 'enabled';
  assert.equal(f.session.describe().request.capabilities.active_testing, 'disabled');
  assert.deepEqual(f.reopen().summary(), f.session.summary());
});

test('URL, GitHub and domain canonicalization produces stable identities without inferred assets', (t) => {
  const f = fixture(t, { kind: 'url', value: 'https://EXAMPLE.COM:443/a/../service' });
  assert.equal(f.session.describe().request.seed.value, 'https://example.com/service');
  assert.equal(f.session.summary().coverage.asset_count, 0);
  f.session.registerDiscovery(bundle([
    asset('domain', 'EXAMPLE.COM'), asset('origin', 'https://EXAMPLE.COM:443'),
    asset('repository', 'https://GitHub.com/ExampleOrg/ExampleRepo'), asset('endpoint', 'https://EXAMPLE.COM:443/a/../service'),
  ]));
  const result = f.session.exportPlan().inventory;
  assert.ok(result.assets.find((a) => a.id === id('domain', 'example.com')));
  assert.ok(result.assets.find((a) => a.value === 'https://github.com/exampleorg/examplerepo'));
  assert.ok(result.assets.find((a) => a.value === 'https://example.com/'));
  const org = createCompanyResearch({ workspaceRoot: f.root, seed: { kind: 'github-org', value: 'Example-Org' } });
  assert.equal(org.describe().request.seed.value, 'example-org');
  assert.equal(org.summary().coverage.asset_count, 0);
});

test('ambiguous company names remain plain intake and invalid seeds fail before mutation', (t) => {
  const f = fixture(t, { kind: 'company', value: 'Acme (the unrelated company)' });
  assert.equal(f.session.summary().identity_status, 'company-identity-unresolved');
  const before = fs.readdirSync(f.root);
  for (const seed of [
    { kind: 'company', value: '<script>alert(1)</script>' }, { kind: 'company', value: 'a\nsecret' },
    { kind: 'company', value: 'x'.repeat(129) }, { kind: 'company', value: '   ' },
    { kind: 'company', value: 'Name', ownership: true }, { kind: 'github-org', value: 'owner/repo' },
    { kind: 'github-org', value: '-owner' }, { kind: 'github-org', value: 'a'.repeat(40) },
    { kind: 'url', value: 'https://user:secret@example.com' }, { kind: 'url', value: 'file:///etc/passwd' },
  ]) assert.throws(() => createCompanyResearch({ workspaceRoot: f.root, seed }), { code: 'invalid_seed' });
  assert.deepEqual(fs.readdirSync(f.root), before);
});

test('closed discovery objects reject unknown authority, raw bodies and secret URL components', (t) => {
  const f = fixture(t);
  const changes = [
    (b) => { b.authorization = true; }, (b) => { b.sources[0].raw_body = 'secret'; },
    (b) => { b.sources[0].headers = { Authorization: 'secret' }; }, (b) => { b.assets[0].execution_allowed = true; },
    (b) => { b.assets[0].ownership = 'verified'; }, (b) => { b.assets[0].relations = [{ kind: 'references', target_id: id('domain', 'example.com'), approval: true }]; },
    (b) => { b.sources[0].reference_url = 'https://example.com/?token=secret'; },
    (b) => { b.sources[0].reference_url = 'https://user:secret@example.com/'; },
    (b) => { b.sources[0].reference_url = 'https://example.com/#secret'; },
    (b) => { b.sources[0].content_sha256 = 'A'.repeat(64); },
    (b) => { b.assets[0].limitations = ['<script>act</script>']; },
    (b) => { b.sources.push(source()); }, (b) => { b.sources = []; },
  ];
  for (const change of changes) { const value = bundle(); change(value); unchanged(f, () => f.session.registerDiscovery(value), 'invalid_discovery'); }
});

test('domain, repository and URL boundary rejects ambiguous host suffixes and credentials', (t) => {
  const f = fixture(t);
  for (const [kind, value] of [
    ['domain', 'localhost'], ['domain', 'app.localhost'], ['domain', '127.0.0.1'], ['domain', '1.2.3.999'],
    ['domain', 'example.com.'], ['domain', 'bad..example.com'], ['domain', '-bad.example.com'], ['domain', 'éxample.com'],
    ['domain', 'example.com/evil'], ['domain', 'example%2ecom'], ['domain', 'example.com\n'],
    ['repository', 'https://github.com.evil.example/owner/repo'], ['repository', 'https://github.com/owner/repo.git'],
    ['repository', 'https://github.com/owner/repo/'], ['repository', 'https://github.com/owner/repo/tree/main'],
    ['repository', 'https://github.com:444/owner/repo'], ['repository', 'https://github.com/owner/repo?secret=1'],
    ['repository', 'https://github.com/owner/repo#fragment'], ['repository', 'https://owner@github.com/owner/repo'],
    ['origin', 'https://example.com/api'], ['origin', 'https://example.com/./'], ['origin', 'https://example.com//'],
    ['endpoint', 'javascript:alert(1)'], ['endpoint', 'file:///etc/passwd'], ['endpoint', 'https://example.com\\@evil.example/'],
    ['endpoint', 'https://%65xample.com/'], ['endpoint', 'https://127.1/'], ['endpoint', 'http://localhost:1024/'],
    ['endpoint', 'http://127.0.0.1:80/'], ['endpoint', 'http://127.0.0.1:1023/'], ['endpoint', 'http://127.0.0.2:1024/'],
    ['endpoint', 'http://127.0.0.1.evil.example:1024/'], ['endpoint', 'https://example.com/%0aheader'],
  ]) unchanged(f, () => f.session.registerDiscovery(bundle([asset(kind, value)])), 'invalid_discovery');
  f.session.registerDiscovery(bundle([asset('endpoint', 'http://127.0.0.1:1024/test'), asset('origin', 'https://10.0.0.1/')]));
  assert.ok(f.session.exportPlan().inventory.assets.every((a) => a.execution_allowed === false));
});

test('raw repository dot segments reject before append while normal URL paths and dotted names canonicalize', (t) => {
  const f = fixture(t); f.session.registerDiscovery(bundle());
  for (const value of [
    'https://github.com/owner/fake/../repo', 'https://github.com/owner/fake/%2e%2e/repo',
    'https://github.com/owner/./repo', 'https://github.com/owner/%2E/repo',
    'https://github.com/owner/fake/.%2e/repo', 'https://github.com/owner/fake/%2e./repo',
  ]) unchanged(f, () => f.session.registerDiscovery(bundle([asset('repository', value)])), 'invalid_discovery');
  assert.equal(f.reopen().summary().coverage.batch_count, 1);
  f.session.registerDiscovery(bundle([
    asset('repository', 'https://GitHub.com:443/Owner/Repo.v1'),
    asset('endpoint', 'https://example.com/fake/../status'),
  ]));
  const inventory = f.session.exportPlan().inventory;
  assert.ok(inventory.assets.some((item) => item.value === 'https://github.com/owner/repo.v1'));
  assert.ok(inventory.assets.some((item) => item.value === 'https://example.com/status'));
});

test('cross-batch sources, asset merges and graph relations retain declarations and limitations', (t) => {
  const f = fixture(t);
  f.session.registerDiscovery(bundle());
  const next = bundle([
    asset('domain', 'EXAMPLE.COM', ['second', 'official'], { limitations: ['Evidence remains incomplete.'] }),
    asset('domain', 'api.example.com', ['official'], { relations: [{ kind: 'candidate-subdomain', target_id: id('domain', 'example.com') }] }),
    asset('repository', 'https://github.com/owner/repo', ['second'], { relations: [{ kind: 'deployed-on', target_id: id('domain', 'api.example.com') }] }),
  ], [source('second', { kind: 'agent-search' })]);
  f.session.registerDiscovery(next);
  f.session.registerDiscovery(bundle([asset('domain', 'example.com')], [source()]));
  const value = f.session.exportPlan().inventory;
  assert.equal(value.assets.length, 3); assert.equal(value.sources.length, 2);
  const merged = value.assets.find((a) => a.value === 'example.com');
  assert.deepEqual(merged.source_ids, ['official', 'second']); assert.equal(merged.limitations.length, 2);
  assert.ok(value.assets.every((a) => a.ownership === 'unverified' && a.scope_status === 'unapproved' && a.execution_allowed === false));
  assert.deepEqual(f.reopen().exportPlan().inventory, value);
  const files = f.names().filter((n) => /^batch-\d{3}\.json$/.test(n));
  let previous = null;
  for (const name of files) {
    const bytes = fs.readFileSync(path.join(f.directory, name)); const entry = JSON.parse(bytes);
    assert.equal(entry.previous_batch_sha256, previous); assert.equal(entry.request_sha256, value.request_sha256);
    assert.equal(entry.workspace_id, f.session.id); assert.equal(new Date(entry.recorded_at).toISOString(), entry.recorded_at);
    assert.deepEqual(Object.keys(entry), ['contract_version', 'workspace_id', 'request_sha256', 'batch_number', 'previous_batch_sha256', 'recorded_at', 'bundle']);
    previous = sha(bytes);
  }
});

test('conflicting source reuse, missing references and false subdomain boundaries never append', (t) => {
  const f = fixture(t); f.session.registerDiscovery(bundle());
  unchanged(f, () => f.session.registerDiscovery(bundle([], [source('official', { content_sha256: sha('conflict') })])), 'source_conflict');
  unchanged(f, () => f.session.registerDiscovery(bundle([asset('domain', 'a.example.com', ['absent'])])), 'unknown_source');
  unchanged(f, () => f.session.registerDiscovery(bundle([asset('domain', 'a.example.com', ['official'], { relations: [{ kind: 'references', target_id: id('domain', 'absent.example.com') }] })])), 'unknown_asset');
  for (const candidate of ['evilexample.com', 'example.com.evil.example', 'example.com']) {
    unchanged(f, () => f.session.registerDiscovery(bundle([asset('domain', candidate, ['official'], { relations: [{ kind: 'candidate-subdomain', target_id: id('domain', 'example.com') }] })])), 'invalid_relation');
  }
  unchanged(f, () => f.session.registerDiscovery(bundle([asset('origin', 'https://api.example.com/', ['official'], { relations: [{ kind: 'candidate-subdomain', target_id: id('domain', 'example.com') }] })])), 'invalid_relation');
  assert.equal(f.reopen().summary().coverage.batch_count, 1);
});

test('all references are validated before writes, including later assets in same batch', (t) => {
  const f = fixture(t);
  f.session.registerDiscovery(bundle([
    asset('domain', 'api.example.com', ['official'], { relations: [{ kind: 'candidate-subdomain', target_id: id('domain', 'example.com') }] }), asset(),
  ]));
  const before = f.names(); let writes = 0; const original = fs.writeFileSync;
  fs.writeFileSync = (...args) => { writes++; return original(...args); };
  try {
    assert.throws(() => f.session.registerDiscovery(bundle([asset('domain', 'valid.example.com'), asset('domain', 'bad.example.com', ['missing'])])), { code: 'unknown_source' });
  } finally { fs.writeFileSync = original; }
  assert.equal(writes, 0); assert.deepEqual(f.names(), before);
});

test('source quota of 128 is preflighted with no mutation and identical reuse remains allowed', (t) => {
  const f = fixture(t);
  for (let n = 0; n < 4; n++) f.session.registerDiscovery(bundle([], Array.from({ length: 32 }, (_, i) => source(`source_${n * 32 + i}`))));
  assert.equal(f.session.summary().coverage.source_count, 128);
  unchanged(f, () => f.session.registerDiscovery(bundle([], [source('new_source')])), 'capacity_exceeded');
  f.session.registerDiscovery(bundle([], [source('source_0')]));
  assert.equal(f.reopen().summary().coverage.source_count, 128);
});

test('asset quota of 512 is preflighted and failed large batch leaves a reopenable journal', (t) => {
  const f = fixture(t);
  for (let n = 0; n < 6; n++) {
    const count = n === 5 ? 12 : 100;
    f.session.registerDiscovery(bundle(Array.from({ length: count }, (_, i) => asset('domain', `a${n * 100 + i}.example.com`))));
  }
  assert.equal(f.session.summary().coverage.asset_count, 512);
  assert.ok(JSON.stringify(f.session.summary()).length < 2000);
  unchanged(f, () => f.session.registerDiscovery(bundle([asset('domain', 'overflow.example.com')])), 'capacity_exceeded');
  assert.equal(f.reopen().summary().coverage.asset_count, 512);
});

test('64-batch quota, per-batch byte capacity and generated journal overhead are preflighted', (t) => {
  const f = fixture(t);
  for (let n = 0; n < 64; n++) f.session.registerDiscovery(bundle([], [source()]));
  assert.equal(f.reopen().summary().coverage.batch_count, 64);
  unchanged(f, () => f.session.registerDiscovery(bundle([], [source()])), 'capacity_exceeded');
  const other = createCompanyResearch({ workspaceRoot: f.root, seed: { kind: 'company', value: 'Other' } });
  const dir = path.join(f.root, other.id); const before = fs.readdirSync(dir);
  const tooLarge = bundle(Array.from({ length: 100 }, (_, i) => asset('domain', `a${i}.example.com`, ['official'], { limitations: Array.from({ length: 20 }, (_, j) => `${j} ${'x'.repeat(250)}`) })));
  assert.throws(() => other.registerDiscovery(tooLarge), { code: 'capacity_exceeded' }); assert.deepEqual(fs.readdirSync(dir), before);
  assert.equal(openCompanyResearch({ workspaceRoot: f.root, workspaceId: other.id }).summary().coverage.batch_count, 0);
  const envelope = bundle(Array.from({ length: 100 }, (_, i) => asset('domain', `b${i}.example.com`, ['official'], { limitations: ['x'.repeat(256), 'y', 'z'] })));
  for (const item of envelope.assets) {
    for (const index of [1, 2]) {
      const remaining = 65500 - Buffer.byteLength(encode(envelope));
      item.limitations[index] += item.limitations[index].repeat(Math.min(255, Math.max(0, remaining)));
    }
  }
  assert.equal(Buffer.byteLength(encode(envelope)), 65500);
  assert.throws(() => other.registerDiscovery(envelope), { code: 'capacity_exceeded' });
  assert.deepEqual(fs.readdirSync(dir), before);
  assert.equal(openCompanyResearch({ workspaceRoot: f.root, workspaceId: other.id }).summary().coverage.batch_count, 0);
});

test('pagination, inspection and merged provenance are bounded and immutable', (t) => {
  const f = fixture(t);
  const sources = Array.from({ length: 32 }, (_, i) => source(`s${i}`));
  const targets = Array.from({ length: 25 }, (_, i) => asset('domain', `target${i}.example.com`, ['s0']));
  f.session.registerDiscovery(bundle([asset('domain', 'main.example.com', sources.map((s) => s.id), { limitations: [] }), ...targets], sources));
  for (let n = 0; n < 2; n++) f.session.registerDiscovery(bundle([asset('domain', 'main.example.com', ['s0'], {
    relations: targets.slice(n * 20, n * 20 + 20).map((a) => ({ kind: 'references', target_id: id(a.kind, a.value) })),
    limitations: Array.from({ length: 20 }, (_, i) => `Bounded note ${n * 20 + i}`),
  })], [sources[0]]));
  const first = f.session.listAssets({ kind: null, query: '', offset: 0, limit: 20 });
  const second = f.session.listAssets({ kind: null, query: '', offset: 20, limit: 20 });
  assert.equal(first.total, 26); assert.equal(first.assets.length, 20); assert.equal(second.assets.length, 6);
  assert.equal(new Set([...first.assets, ...second.assets].map((a) => a.id)).size, 26);
  assert.equal(f.session.listAssets({ kind: 'domain', query: 'MAIN', offset: 0, limit: 20 }).total, 1);
  const detail = f.session.inspectAsset(id('domain', 'main.example.com'));
  assert.equal(detail.source_count, 32); assert.equal(detail.sources.length, 20);
  assert.equal(detail.relation_count, 25); assert.equal(detail.relations.length, 20);
  assert.equal(detail.limitations_count, 40); assert.equal(detail.limitations.length, 20);
  assert.equal('source_ids' in detail.asset, false); assert.equal('relations' in detail.asset, false);
  detail.sources[0].kind = 'scope-policy'; assert.equal(f.session.inspectAsset(detail.asset.id).sources[0].kind, 'official-site');
  for (const args of [{ kind: null, query: '', offset: 0, limit: 21 }, { kind: 'bad', query: '', offset: 0, limit: 1 }, { kind: null, query: '', offset: -1, limit: 1 }]) assert.throws(() => f.session.listAssets(args), { code: 'invalid_query' });
  assert.throws(() => f.session.inspectAsset('../request.json'), { code: 'invalid_asset_id' });
  assert.throws(() => f.session.inspectAsset(id('domain', 'missing.example.com')), { code: 'asset_not_found' });
});

test('exports have fresh numbered paths, exact closed envelope, synced hashes and no authority', (t) => {
  const f = fixture(t); f.session.registerDiscovery(bundle());
  const first = f.session.exportPlan(); const second = f.session.exportPlan();
  assert.notEqual(first.inventory_path, second.inventory_path); assert.equal(first.inventory_sha256, second.inventory_sha256);
  assert.equal(first.inventory_sha256, sha(fs.readFileSync(first.inventory_path)));
  assert.equal(fs.statSync(first.inventory_path).ino, fs.statSync(first.inventory_path.replace('.json', '.provisional.json')).ino);
  assert.deepEqual(Object.keys(first.inventory), ['contract_version', 'workspace_id', 'request_sha256', 'seed', 'sources', 'assets', 'coverage', 'next_step']);
  assert.deepEqual(Object.keys(first.inventory.assets[0]), ['id', 'kind', 'value', 'source_ids', 'relations', 'limitations', 'ownership', 'scope_status', 'execution_allowed']);
  assert.deepEqual(first.inventory.coverage, { discovery: 'external-host-evidence-only', asset_count: 1, source_count: 1, batch_count: 1, active_tests: 0, repo_scans: 0, vulnerabilities_validated: 0, human_decisions: 0, broker_provider_calls: 0, host_model_usage: 'not-measured' });
  assert.equal(first.inventory.next_step, 'approve-exact-scope-and-qualified-executor');
  assert.equal(JSON.stringify(first.inventory).includes('verdict'), false);
  assert.equal(first.inventory.sources[0].content_sha256, source().content_sha256);
  f.session.registerDiscovery(bundle([asset('domain', 'new.example.com')]));
  assert.equal(f.reopen().exportPlan().inventory.coverage.batch_count, 2);
  for (const name of f.names()) assert.equal(fs.statSync(path.join(f.directory, name)).mode & 0o777, 0o600);
});

test('UUID collision cannot overwrite or resume an existing workspace', (t) => {
  const f = fixture(t); const original = crypto.randomUUID; const before = fs.readFileSync(path.join(f.directory, 'request.json'));
  crypto.randomUUID = () => f.session.id; syncBuiltinESMExports();
  try {
    assert.throws(() => createCompanyResearch({ workspaceRoot: f.root, seed: { kind: 'company', value: 'Overwrite attempt' } }), { code: 'evidence_write_failed' });
  } finally { crypto.randomUUID = original; syncBuiltinESMExports(); }
  assert.deepEqual(fs.readFileSync(path.join(f.directory, 'request.json')), before);
  assert.deepEqual(f.names(), ['request.json', 'request.sha256']); assert.equal(f.reopen().summary().coverage.batch_count, 0);
});

test('request, hashes, journal chain, export and directory drift are rejected on reopen and live operations', (t) => {
  const scenarios = [
    (f) => { fs.appendFileSync(path.join(f.directory, 'request.json'), ' '); },
    (f) => { fs.writeFileSync(path.join(f.directory, 'request.sha256'), `${'0'.repeat(64)}\n`); },
    (f) => { const p = path.join(f.directory, 'batch-001.json'); const b = JSON.parse(fs.readFileSync(p)); b.request_sha256 = '0'.repeat(64); fs.writeFileSync(p, encode(b)); },
    (f) => { const p = path.join(f.directory, 'batch-001.json'); const b = JSON.parse(fs.readFileSync(p)); b.previous_batch_sha256 = '0'.repeat(64); fs.writeFileSync(p, encode(b)); },
    (f) => { fs.renameSync(path.join(f.directory, 'batch-001.json'), path.join(f.directory, 'batch-002.json')); },
    (f) => { const e = f.session.exportPlan(); const b = JSON.parse(fs.readFileSync(e.inventory_path)); b.assets[0].ownership = 'verified'; fs.writeFileSync(e.inventory_path, encode(b)); },
    (f) => { fs.writeFileSync(path.join(f.directory, 'summary.json'), '{}', { mode: 0o600 }); },
    (f) => { fs.chmodSync(path.join(f.directory, 'batch-001.json'), 0o644); },
  ];
  for (const mutate of scenarios) {
    const f = fixture(t); f.session.registerDiscovery(bundle()); mutate(f);
    assert.throws(f.reopen, { code: 'corrupt_workspace' });
    assert.throws(() => f.session.summary(), { code: 'corrupt_workspace' });
    assert.throws(() => f.session.registerDiscovery(bundle()), { code: 'corrupt_workspace' });
  }
});

test('cross-workspace journal transplant is rejected; evidence and quotas are isolated', (t) => {
  const a = fixture(t); const b = fixture(t); a.session.registerDiscovery(bundle());
  assert.equal(b.session.summary().coverage.asset_count, 0);
  b.session.registerDiscovery(bundle([asset('domain', 'other.example.com')], [source('official', { content_sha256: sha('different independent declaration') })]));
  assert.equal(a.session.inspectAsset(id('domain', 'example.com')).sources[0].content_sha256, source().content_sha256);
  fs.copyFileSync(path.join(a.directory, 'batch-001.json'), path.join(b.directory, 'batch-001.json'));
  fs.copyFileSync(path.join(a.directory, 'batch-001.provisional.json'), path.join(b.directory, 'batch-001.provisional.json'));
  assert.throws(b.reopen, { code: 'corrupt_workspace' }); assert.equal(a.reopen().summary().coverage.batch_count, 1);
});

test('workspace UUID and explicit private existing roots resist traversal and symlinks', (t) => {
  const f = fixture(t);
  for (const workspaceId of ['../outside', f.session.id.toUpperCase(), `${f.session.id}/../other`, '', 'not-uuid']) assert.throws(() => openCompanyResearch({ workspaceRoot: f.root, workspaceId }), { code: 'invalid_workspace_id' });
  for (const workspaceRoot of ['relative', path.join(f.root, 'missing'), '/', `${f.root}/../${path.basename(f.root)}`]) assert.throws(() => createCompanyResearch({ workspaceRoot, seed: { kind: 'company', value: 'Name' } }), { code: 'invalid_workspace_root' });
  fs.chmodSync(f.root, 0o755);
  assert.throws(() => createCompanyResearch({ workspaceRoot: f.root, seed: { kind: 'company', value: 'Name' } }), { code: 'invalid_workspace_root' }); fs.chmodSync(f.root, 0o700);
  const link = path.join(f.root, 'link'); fs.symlinkSync(f.directory, link);
  assert.throws(() => createCompanyResearch({ workspaceRoot: link, seed: { kind: 'company', value: 'Name' } }), { code: 'invalid_workspace_root' });
  const moved = path.join(f.root, 'old'); fs.renameSync(f.directory, moved); fs.symlinkSync(moved, f.directory);
  assert.throws(f.reopen, { code: 'corrupt_workspace' }); assert.throws(() => f.session.summary(), { code: 'workspace_changed' });
});

test('journal reads refuse symlink, FIFO, oversized and nonprivate files without blocking', (t) => {
  for (const mode of ['symlink', 'fifo', 'oversized', 'permissions']) {
    const f = fixture(t); const p = path.join(f.directory, 'request.json'); const original = fs.readFileSync(p); fs.unlinkSync(p);
    if (mode === 'symlink') { const external = path.join(f.root, 'external'); fs.writeFileSync(external, original, { mode: 0o600 }); fs.symlinkSync(external, p); }
    if (mode === 'fifo') execFileSync('mkfifo', ['-m', '600', p]);
    if (mode === 'oversized') fs.writeFileSync(p, 'x'.repeat(4097), { mode: 0o600 });
    if (mode === 'permissions') fs.writeFileSync(p, original, { mode: 0o644 });
    const start = Date.now(); assert.throws(f.reopen, { code: 'corrupt_workspace' }); assert.ok(Date.now() - start < 1000);
  }
});

test('dangling batch provisionals cannot be resumed; valid incomplete export is explicitly nonfinal', (t) => {
  const f = fixture(t); f.session.registerDiscovery(bundle());
  fs.copyFileSync(path.join(f.directory, 'batch-001.json'), path.join(f.directory, 'batch-002.provisional.json'));
  assert.throws(f.reopen, { code: 'corrupt_workspace' });
  const other = fixture(t); const output = other.session.exportPlan(); fs.unlinkSync(output.inventory_path);
  assert.equal(other.reopen().summary().coverage.batch_count, 0);
  const next = other.reopen().exportPlan(); assert.ok(next.inventory_path.endsWith('inventory-002.json'));
});

test('file fsync failure leaves no final journal append or final export and fixed errors', (t) => {
  const f = fixture(t);
  withFsFault((fd) => fs.fstatSync(fd).isFile(), () => assert.throws(() => f.session.registerDiscovery(bundle()), { code: 'evidence_write_failed', message: 'evidence_write_failed' }));
  assert.equal(fs.existsSync(path.join(f.directory, 'batch-001.json')), false);
  assert.throws(f.reopen, { code: 'corrupt_workspace' });
  const other = fixture(t);
  withFsFault((fd) => fs.fstatSync(fd).isFile(), () => assert.throws(() => other.session.exportPlan(), { code: 'evidence_write_failed' }));
  assert.equal(fs.existsSync(path.join(other.directory, 'inventory-001.json')), false);
});

test('directory fsync failure after publication quarantines final journal and export names', (t) => {
  for (const kind of ['batch', 'inventory']) {
    const f = fixture(t); let directoryCalls = 0;
    withFsFault((fd) => fs.fstatSync(fd).isDirectory() && ++directoryCalls === 2,
      () => assert.throws(() => kind === 'batch' ? f.session.registerDiscovery(bundle()) : f.session.exportPlan(), { code: 'evidence_write_failed' }));
    assert.equal(fs.existsSync(path.join(f.directory, `${kind}-001.json`)), false);
    assert.equal(fs.existsSync(path.join(f.directory, `${kind}-001.unpublished.json`)), true);
    if (kind === 'batch') assert.throws(f.reopen, { code: 'corrupt_workspace' });
    else assert.equal(f.reopen().summary().coverage.batch_count, 0);
  }
});

test('root and startup directory fsync failures are fixed, never falsely successful', (t) => {
  const f = fixture(t); const before = fs.readdirSync(f.root);
  withFsFault((fd) => fs.fstatSync(fd).isDirectory(), () => assert.throws(() => createCompanyResearch({ workspaceRoot: f.root, seed: { kind: 'company', value: 'Failure' } }), { code: 'evidence_write_failed', message: 'evidence_write_failed' }));
  const added = fs.readdirSync(f.root).filter((name) => !before.includes(name)); assert.equal(added.length, 1);
  assert.throws(() => openCompanyResearch({ workspaceRoot: f.root, workspaceId: added[0] }), { code: 'corrupt_workspace' });
});

test('intake uses only local filesystem, path and crypto imports and stores no human verdict', (t) => {
  const f = fixture(t); f.session.registerDiscovery(bundle([], [source('scope', { kind: 'scope-policy' })]));
  const modulePath = fileURLToPath(new URL('../../plugins/secureflow/scripts/company-research-core.mjs', import.meta.url));
  const text = fs.readFileSync(modulePath, 'utf8');
  assert.deepEqual([...text.matchAll(/from '(node:[^']+)'/g)].map((m) => m[1]).sort(), ['node:crypto', 'node:fs', 'node:path']);
  assert.equal(/\b(?:fetch|spawn|execFile|createConnection|request)\s*\(/.test(text), false);
  const value = f.session.exportPlan().inventory;
  assert.equal(value.coverage.active_tests, 0); assert.equal(value.coverage.repo_scans, 0); assert.equal(value.coverage.broker_provider_calls, 0);
  assert.equal(value.coverage.vulnerabilities_validated, 0); assert.equal(value.coverage.human_decisions, 0);
  assert.equal(value.assets.length, 0);
});
