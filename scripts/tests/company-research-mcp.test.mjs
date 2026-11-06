import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createCompanyMcpClient } from '../demo-company-research-local.mjs';

const runner = fileURLToPath(new URL('../../plugins/secureflow/scripts/run-company-research.mjs', import.meta.url));
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const id = (kind, value) => `sf_asset_${sha(`${kind}\n${value}`)}`;
const toolNames = ['prepare_company_research', 'register_company_discovery', 'summarize_company_research', 'list_company_assets', 'inspect_company_asset', 'export_company_research_plan'];
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secureflow-company-mcp-test-')); fs.chmodSync(root, 0o700);
  const workspaceRoot = path.join(root, 'workspaces'); fs.mkdirSync(workspaceRoot, { mode: 0o700 });
  const clients = [];
  t.after(async () => { for (const client of clients) await client.close(); fs.rmSync(root, { recursive: true, force: true }); });
  return { root, workspaceRoot,
    client() { const client = createCompanyMcpClient(workspaceRoot); clients.push(client); return client; },
    cli(args) { return spawnSync(process.execPath, [runner, '--workspace-root', workspaceRoot, ...args], { encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024 }); },
  };
}
function discovery(extraDomains = 0) {
  const source = { id: 'host_fixture', kind: 'agent-search', reference_url: 'https://example.test/synthetic-metadata', content_sha256: sha('host-declared synthetic graph') };
  const asset = (kind, value, relations = []) => ({ kind, value, source_ids: [source.id], relations,
    limitations: ['Host-declared synthetic evidence; no remote fetch or ownership verification.'] });
  return { contract_version: 'secureflow-company-discovery-v1', sources: [source], assets: [
    asset('domain', 'example.test'),
    asset('domain', 'api.example.test', [{ kind: 'candidate-subdomain', target_id: id('domain', 'example.test') }]),
    asset('repository', 'https://github.com/example/research-fixture', [{ kind: 'deployed-on', target_id: id('origin', 'https://api.example.test/') }]),
    asset('origin', 'https://api.example.test/', [{ kind: 'contains', target_id: id('endpoint', 'https://api.example.test/status') }]),
    asset('endpoint', 'https://api.example.test/status'),
    ...Array.from({ length: extraDomains }, (_, i) => asset('domain', `candidate${i}.example.test`)),
  ] };
}
const resultValue = (message) => { assert.equal(message.result.isError, false); return JSON.parse(message.result.content[0].text); };
const toolFailure = (message, code) => { assert.equal(message.result.isError, true); assert.deepEqual(message.result.content, [{ type: 'text', text: code }]); };
const cliValue = (result) => { assert.equal(result.status, 0, result.stderr); assert.equal(result.stderr, ''); return JSON.parse(result.stdout); };
async function prepare(client, seed = { kind: 'company', value: 'Example Research' }) {
  return client.tool('prepare_company_research', { seed });
}

test('real stdio initialization gates tools and exposes exactly six closed tools', async (t) => {
  const f = fixture(t); const client = f.client();
  assert.deepEqual((await client.request('tools/list')).error, { code: -32000, message: 'Initialization required' });
  assert.equal((await client.request('initialize', { protocolVersion: 'bad' })).error.code, -32602);
  const initialization = await client.initialize(); assert.equal(initialization.serverInfo.name, 'secureflow-company-research');
  const listed = (await client.request('tools/list')).result.tools;
  assert.deepEqual(listed.map((tool) => tool.name), toolNames);
  assert.ok(listed.every((tool) => tool.inputSchema.additionalProperties === false));
  const schema = JSON.parse(fs.readFileSync(new URL('../../schemas/secureflow-company-discovery-v1.schema.json', import.meta.url)));
  const { $schema, $id, description, ...structural } = schema;
  assert.deepEqual(listed.find((tool) => tool.name === 'register_company_discovery').inputSchema.properties.bundle, structural);
  assert.equal((await client.request('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } })).error.code, -32602);
  assert.deepEqual((await client.request('ping')).result, {});
  assert.equal((await client.request('not-a-method')).error.code, -32601);
  assert.equal((await client.close()).code, 0); assert.equal(client.stderr(), '');
  assert.deepEqual(fs.readdirSync(f.workspaceRoot), []);
});

test('company, URL and org preparation imports a graph with compact paginated identities and inspect evidence', async (t) => {
  const f = fixture(t); const client = f.client(); await client.initialize();
  const company = await prepare(client); const url = await prepare(client, { kind: 'url', value: 'https://EXAMPLE.TEST:443/a/../status' });
  const org = await prepare(client, { kind: 'github-org', value: 'Example-Org' });
  assert.equal(company.executor_mode, 'unavailable'); assert.equal(url.request.seed.value, 'https://example.test/status');
  assert.equal(org.request.seed.value, 'example-org');
  for (const request of [company, url, org]) {
    const summary = await client.tool('summarize_company_research', { workspace_id: request.request.workspace_id });
    assert.equal(summary.coverage.asset_count, 0); assert.equal(summary.scope_status, 'unapproved'); assert.equal(summary.executor_mode, 'unavailable');
  }
  const workspaceId = company.request.workspace_id;
  const imported = await client.tool('register_company_discovery', { workspace_id: workspaceId, bundle: discovery(22) });
  assert.equal(imported.coverage.asset_count, 27); assert.equal(imported.coverage.batch_count, 1);
  const page = await client.tool('list_company_assets', { workspace_id: workspaceId, kind: null, query: '', offset: 0, limit: 20 });
  const tail = await client.tool('list_company_assets', { workspace_id: workspaceId, kind: null, query: '', offset: 20, limit: 20 });
  assert.equal(page.total, 27); assert.equal(page.assets.length, 20); assert.equal(tail.assets.length, 7);
  assert.equal(new Set([...page.assets, ...tail.assets].map((a) => a.id)).size, 27);
  assert.ok(page.assets.every((a) => !('relations' in a) && !('source_ids' in a) && !('limitations' in a) && a.execution_allowed === false));
  const filtered = await client.tool('list_company_assets', { workspace_id: workspaceId, kind: 'repository', query: 'RESEARCH', offset: 0, limit: 20 });
  assert.equal(filtered.total, 1);
  const detail = await client.tool('inspect_company_asset', { workspace_id: workspaceId, asset_id: id('domain', 'api.example.test') });
  assert.equal(detail.asset.ownership, 'unverified'); assert.equal(detail.asset.execution_allowed, false);
  assert.deepEqual(detail.relations, [{ kind: 'candidate-subdomain', target_id: id('domain', 'example.test') }]);
  assert.equal(detail.sources[0].content_sha256, discovery().sources[0].content_sha256);
  assert.equal(detail.source_count, 1); assert.equal(detail.relation_count, 1);
  assert.equal((await client.tool('summarize_company_research', { workspace_id: url.request.workspace_id })).coverage.asset_count, 0);
  assert.equal((await client.close()).code, 0); assert.equal(client.stderr(), '');
});

test('hash export is a nonexecutable inventory and a new stdio process validates persisted replay', async (t) => {
  const f = fixture(t); const first = f.client(); await first.initialize();
  const prepared = await prepare(first); const workspaceId = prepared.request.workspace_id;
  await first.tool('register_company_discovery', { workspace_id: workspaceId, bundle: discovery() });
  const exported = await first.tool('export_company_research_plan', { workspace_id: workspaceId });
  assert.equal(exported.is_executable_authorization, false); assert.equal(exported.coverage.broker_provider_calls, 0);
  assert.equal(exported.coverage.repo_scans, 0); assert.equal(exported.coverage.active_tests, 0); assert.equal(exported.coverage.human_decisions, 0);
  const bytes = fs.readFileSync(exported.inventory_path); assert.equal(sha(bytes), exported.inventory_sha256);
  const inventory = JSON.parse(bytes); assert.equal(inventory.request_sha256, prepared.request_sha256);
  assert.ok(inventory.assets.every((a) => a.ownership === 'unverified' && a.scope_status === 'unapproved' && !a.execution_allowed));
  const summary = await first.tool('summarize_company_research', { workspace_id: workspaceId }); await first.close();
  const second = f.client(); await second.initialize();
  assert.deepEqual(await second.tool('summarize_company_research', { workspace_id: workspaceId }), summary);
  const again = await second.tool('export_company_research_plan', { workspace_id: workspaceId });
  assert.notEqual(again.inventory_path, exported.inventory_path); assert.equal(again.inventory_sha256, exported.inventory_sha256);
  await second.close();
  const cliSummary = cliValue(f.cli(['--workspace', workspaceId, '--summary'])); assert.deepEqual(cliSummary, summary);
});

test('closed MCP arguments, secret URL and traversal failures reflect only fixed codes and never authorize', async (t) => {
  const f = fixture(t); const client = f.client(); await client.initialize();
  assert.equal((await client.call('prepare_company_research', { seed: { kind: 'company', value: 'Name' }, authorization: true })).error.code, -32602);
  assert.equal((await client.call('execute_company_research', {})).error.code, -32602);
  toolFailure(await client.call('prepare_company_research', { seed: { kind: 'url', value: 'https://user:secret-canary@example.test/' } }), 'invalid_seed');
  const prepared = await prepare(client); const workspaceId = prepared.request.workspace_id;
  const directory = path.join(f.workspaceRoot, workspaceId); const before = fs.readdirSync(directory);
  const bad = discovery(); bad.sources[0].reference_url = 'https://example.test/?token=secret-canary';
  toolFailure(await client.call('register_company_discovery', { workspace_id: workspaceId, bundle: bad }), 'invalid_discovery');
  assert.deepEqual(fs.readdirSync(directory), before);
  assert.equal((await client.call('export_company_research_plan', { workspace_id: workspaceId, output_path: '/tmp/secret-canary' })).error.code, -32602);
  toolFailure(await client.call('summarize_company_research', { workspace_id: '../secret-canary' }), 'invalid_workspace_id');
  toolFailure(await client.call('inspect_company_asset', { workspace_id: workspaceId, asset_id: '../secret-canary' }), 'invalid_asset_id');
  assert.equal(JSON.stringify(client.messages).includes('secret-canary'), false);
  assert.equal((await client.tool('summarize_company_research', { workspace_id: workspaceId })).coverage.batch_count, 0);
});

test('oversized fragmented stdio message drains through its newline and preserves the following request', async (t) => {
  const f = fixture(t); const client = f.client(); await client.initialize();
  const oversized = JSON.stringify({ jsonrpc: '2.0', id: 900, method: 'tools/call', params: { name: 'prepare_company_research', arguments: { seed: { kind: 'company', value: 'x'.repeat(70000) } } } });
  await client.writeRaw(oversized.slice(0, 32000)); await client.writeRaw(oversized.slice(32000)); await client.writeRaw('\n');
  const rejected = await client.waitMessage((message) => message.id === null && message.error?.message === 'Message too large');
  assert.equal(rejected.error.code, -32700); assert.deepEqual((await client.request('ping')).result, {});
  assert.equal(client.messages.filter((message) => message.error?.message === 'Message too large').length, 1);
  assert.deepEqual(fs.readdirSync(f.workspaceRoot), []); assert.equal(client.stderr(), '');
});

test('pinned CLI import mismatch leaves no batch, and matching import, summary and export work in separate processes', (t) => {
  const f = fixture(t);
  const prepared = cliValue(f.cli(['--seed-kind', 'company', '--seed-value', 'Example CLI Research']));
  const workspaceId = prepared.request.workspace_id; const directory = path.join(f.workspaceRoot, workspaceId);
  const bytes = Buffer.from(`${JSON.stringify(discovery())}\n`); const input = path.join(f.root, 'host-discovery.json'); fs.writeFileSync(input, bytes, { mode: 0o600 });
  const before = fs.readdirSync(directory);
  const mismatch = f.cli(['--workspace', workspaceId, '--import', input, '--import-sha256', '0'.repeat(64)]);
  assert.equal(mismatch.status, 1); assert.equal(mismatch.stdout, ''); assert.equal(mismatch.stderr, 'import_hash_mismatch\n');
  assert.deepEqual(fs.readdirSync(directory), before);
  const imported = cliValue(f.cli(['--workspace', workspaceId, '--import', input, '--import-sha256', sha(bytes)]));
  assert.equal(imported.coverage.asset_count, 5); assert.equal(imported.coverage.batch_count, 1);
  const summary = cliValue(f.cli(['--workspace', workspaceId, '--summary'])); assert.equal(summary.executor_mode, 'unavailable');
  const exported = cliValue(f.cli(['--workspace', workspaceId, '--export']));
  assert.equal(sha(fs.readFileSync(exported.inventory_path)), exported.inventory_sha256); assert.equal(exported.inventory.coverage.active_tests, 0);
});

test('CLI rejects missing pins, symlink import, traversal and conflicting modes with fixed errors', (t) => {
  const f = fixture(t);
  const prepared = cliValue(f.cli(['--seed-kind', 'github-org', '--seed-value', 'Example'])); const workspaceId = prepared.request.workspace_id;
  const input = path.join(f.root, 'host.json'); const bytes = `${JSON.stringify(discovery())}\n`; fs.writeFileSync(input, bytes, { mode: 0o600 });
  const link = path.join(f.root, 'host-link.json'); fs.symlinkSync(input, link);
  const cases = [
    [['--workspace', workspaceId, '--import', input], 'invalid_startup_arguments'],
    [['--workspace', workspaceId, '--import', link, '--import-sha256', sha(bytes)], 'invalid_import_file'],
    [['--workspace', '../secret-canary', '--summary'], 'invalid_workspace_id'],
    [['--workspace', workspaceId, '--summary', '--export'], 'invalid_startup_arguments'],
    [['--seed-kind', 'url', '--seed-value', 'https://example.test/?token=secret-canary'], 'invalid_seed'],
  ];
  for (const [args, code] of cases) { const result = f.cli(args); assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.equal(result.stderr, `${code}\n`); }
  assert.equal(cliValue(f.cli(['--workspace', workspaceId, '--summary'])).coverage.batch_count, 0);
  assert.equal(fs.readdirSync(f.workspaceRoot).length, 1);
});
