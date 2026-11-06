#!/usr/bin/env node
// Synthetic local intake qualification. No discovery provider or target traffic.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const repository = fileURLToPath(new URL('../', import.meta.url));
const runner = path.join(repository, 'plugins/secureflow/scripts/run-company-research.mjs');
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const assetId = (kind, value) => `sf_asset_${sha(`${kind}\n${value}`)}`;
const error = (code) => Object.assign(new Error(code), { code });

// Shared by the integration tests; importing this file never starts a demo.
export function createCompanyMcpClient(workspaceRoot) {
  const child = spawn(process.execPath, [runner, '--workspace-root', workspaceRoot, '--mcp'], { cwd: repository, stdio: ['pipe', 'pipe', 'pipe'] });
  let nextId = 0; let stderr = ''; let bytes = 0; let ended = false; let failure = null;
  const pending = new Map(); const listeners = new Set(); const messages = [];
  const rejectPending = (cause) => {
    failure = cause;
    for (const value of pending.values()) { clearTimeout(value.timer); value.reject(cause); }
    pending.clear();
    for (const listener of listeners) listener(null, cause);
  };
  const lines = readline.createInterface({ input: child.stdout });
  lines.on('line', (line) => {
    try {
      bytes += Buffer.byteLength(line) + 1;
      if (bytes > 1024 * 1024 || messages.length >= 128) throw error('unexpected_protocol_volume');
      const message = JSON.parse(line); messages.push(message);
      const waiter = pending.get(message.id);
      if (waiter) { clearTimeout(waiter.timer); pending.delete(message.id); waiter.resolve(message); }
      for (const listener of listeners) listener(message, null);
    } catch { rejectPending(error('invalid_protocol_output')); child.kill(); }
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(0, 16384); });
  child.stdin.on('error', (cause) => rejectPending(error(cause.code === 'EPIPE' ? 'broker_input_closed' : 'broker_input_failed')));
  const exited = new Promise((resolve, reject) => {
    child.once('error', () => { ended = true; rejectPending(error('broker_start_failed')); reject(error('broker_start_failed')); });
    child.once('close', (code, signal) => { ended = true; lines.close(); rejectPending(error('broker_exited')); resolve({ code, signal }); });
  });
  exited.catch(() => {});
  const writeRaw = (value) => new Promise((resolve, reject) => {
    if (ended || failure) { reject(failure ?? error('broker_exited')); return; }
    child.stdin.write(value, (cause) => cause ? reject(error('broker_input_failed')) : resolve());
  });
  const request = (method, params) => {
    const id = ++nextId;
    return new Promise((resolve, reject) => {
      if (ended || failure) { reject(failure ?? error('broker_exited')); return; }
      const timer = setTimeout(() => { pending.delete(id); reject(error('broker_response_timeout')); }, 5000);
      pending.set(id, { resolve, reject, timer });
      writeRaw(`${JSON.stringify({ jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) })}\n`).catch((cause) => { clearTimeout(timer); pending.delete(id); reject(cause); });
    });
  };
  const waitMessage = (predicate) => {
    const existing = messages.find(predicate); if (existing) return Promise.resolve(existing);
    return new Promise((resolve, reject) => {
      const finish = (message, cause) => {
        if (!cause && !predicate(message)) return;
        clearTimeout(timer); listeners.delete(finish); cause ? reject(cause) : resolve(message);
      };
      const timer = setTimeout(() => { listeners.delete(finish); reject(error('broker_response_timeout')); }, 5000);
      listeners.add(finish);
      if (ended || failure) finish(null, failure ?? error('broker_exited'));
    });
  };
  return {
    child, exited, messages, request, writeRaw, waitMessage,
    async initialize() {
      const result = await request('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'secureflow-company-local-qualification', version: '1' } });
      assert.equal(result.result.protocolVersion, '2025-11-25');
      await writeRaw(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
      return result.result;
    },
    call(name, args) { return request('tools/call', { name, arguments: args }); },
    async tool(name, args) {
      const message = await request('tools/call', { name, arguments: args });
      if (message.error || message.result?.isError !== false) throw error('demo_tool_failed');
      return JSON.parse(message.result.content[0].text);
    },
    async close() { if (!ended) child.stdin.end(); return exited; },
    stderr() { return stderr; },
  };
}

function syncDirectory(directory) {
  const fd = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function writeNew(file, bytes) {
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  syncDirectory(path.dirname(file));
}
function demoRoot(args) {
  const external = (root) => {
    const canonical = path.join(fs.realpathSync(path.dirname(root)), path.basename(root));
    const relative = path.relative(fs.realpathSync(repository), canonical);
    if (!relative || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative))) throw error('demo_output_must_be_external');
    return canonical;
  };
  if (!args.length) {
    const prefix = external(path.join(os.tmpdir(), 'secureflow-company-demo-'));
    const root = fs.mkdtempSync(prefix); fs.chmodSync(root, 0o700); return root;
  }
  if (args.length !== 2 || args[0] !== '--output-dir' || !path.isAbsolute(args[1]) || path.resolve(args[1]) !== args[1]
      || /[\x00-\x1f\x7f]/.test(args[1])) throw error('invalid_demo_arguments');
  const root = external(args[1]);
  fs.mkdirSync(root, { mode: 0o700 }); return root;
}
async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') {
    process.stdout.write('Usage: node scripts/demo-company-research-local.mjs [--output-dir FRESH_EXTERNAL_DIR]\nSynthetic passive evidence intake through stdio MCP. Artifacts are retained; no target or provider requests.\n'); return;
  }
  const root = demoRoot(args); let client;
  try {
    const workspaceRoot = path.join(root, 'workspaces'); const sourcesRoot = path.join(root, 'sources');
    fs.mkdirSync(workspaceRoot, { mode: 0o700 }); fs.mkdirSync(sourcesRoot, { mode: 0o700 }); syncDirectory(root);
    const fixtures = [
      { id: 'synthetic_site', kind: 'official-site', reference_url: 'https://example.test/', file: 'official-site.txt', text: 'HOST-DECLARED SYNTHETIC FIXTURE: Example Research; example.test; api.example.test. No fetched content or ownership proof.\n' },
      { id: 'synthetic_github', kind: 'github-metadata', reference_url: 'https://github.com/example/research-fixture', file: 'github-metadata.txt', text: 'HOST-DECLARED SYNTHETIC FIXTURE: repository example/research-fixture and deployment reference https://api.example.test/. No GitHub API call or repository analysis.\n' },
      { id: 'synthetic_ct', kind: 'certificate-transparency', reference_url: 'https://example.test/synthetic-ct', file: 'certificate-transparency.txt', text: 'HOST-DECLARED SYNTHETIC FIXTURE: candidate DNS name api.example.test. This is not a certificate-transparency query or evidence of ownership.\n' },
    ];
    for (const fixture of fixtures) writeNew(path.join(sourcesRoot, fixture.file), fixture.text);
    const sources = fixtures.map(({ id, kind, reference_url, text }) => ({ id, kind, reference_url, content_sha256: sha(text) }));
    const asset = (kind, value, source_ids, relations = []) => ({ kind, value, source_ids, relations,
      limitations: ['Host-declared synthetic evidence only; ownership and exact scope are unverified.'] });
    const bundle = { contract_version: 'secureflow-company-discovery-v1', sources, assets: [
      asset('domain', 'example.test', ['synthetic_site'], [{ kind: 'references', target_id: assetId('repository', 'https://github.com/example/research-fixture') }]),
      asset('domain', 'api.example.test', ['synthetic_site', 'synthetic_ct'], [{ kind: 'candidate-subdomain', target_id: assetId('domain', 'example.test') }]),
      asset('repository', 'https://github.com/example/research-fixture', ['synthetic_github'], [{ kind: 'deployed-on', target_id: assetId('origin', 'https://api.example.test/') }]),
      asset('origin', 'https://api.example.test/', ['synthetic_github'], [{ kind: 'contains', target_id: assetId('endpoint', 'https://api.example.test/status') }]),
      asset('endpoint', 'https://api.example.test/status', ['synthetic_site'], [{ kind: 'references', target_id: assetId('domain', 'api.example.test') }]),
    ] };
    writeNew(path.join(root, 'synthetic-discovery.json'), `${JSON.stringify(bundle, null, 2)}\n`);
    client = createCompanyMcpClient(workspaceRoot); const initialization = await client.initialize();
    const tools = (await client.request('tools/list')).result.tools; assert.equal(tools.length, 6);
    const prepared = await client.tool('prepare_company_research', { seed: { kind: 'company', value: 'Example Research' } });
    const workspaceId = prepared.request.workspace_id;
    const imported = await client.tool('register_company_discovery', { workspace_id: workspaceId, bundle });
    const page = await client.tool('list_company_assets', { workspace_id: workspaceId, kind: null, query: '', offset: 0, limit: 20 });
    const inspected = await client.tool('inspect_company_asset', { workspace_id: workspaceId, asset_id: assetId('domain', 'api.example.test') });
    const exported = await client.tool('export_company_research_plan', { workspace_id: workspaceId });
    const summary = await client.tool('summarize_company_research', { workspace_id: workspaceId });
    const firstExit = await client.close(); assert.equal(firstExit.code, 0); assert.equal(client.stderr(), '');
    client = createCompanyMcpClient(workspaceRoot); await client.initialize();
    const replayed = await client.tool('summarize_company_research', { workspace_id: workspaceId });
    assert.deepEqual(replayed, summary); assert.equal((await client.close()).code, 0); assert.equal(client.stderr(), '');
    const inventoryBytes = fs.readFileSync(exported.inventory_path); assert.equal(sha(inventoryBytes), exported.inventory_sha256);
    const inventory = JSON.parse(inventoryBytes); assert.equal(page.total, 5); assert.equal(imported.coverage.source_count, 3);
    assert.equal(inspected.asset.execution_allowed, false);
    assert.ok(inventory.assets.every((item) => item.ownership === 'unverified' && item.scope_status === 'unapproved' && item.execution_allowed === false));
    assert.ok(inventory.sources.every((item) => fixtures.some((fixture) => fixture.id === item.id && sha(fs.readFileSync(path.join(sourcesRoot, fixture.file))) === item.content_sha256)));
    const receipt = { contract_version: 'secureflow-company-demo-receipt-v1', fixture_status: 'host-declared-synthetic', protocol_version: initialization.protocolVersion,
      tool_count: tools.length, workspace_id: workspaceId, request_sha256: prepared.request_sha256, inventory_path: exported.inventory_path,
      inventory_sha256: exported.inventory_sha256, ownership: 'unverified', scope_status: 'unapproved', execution_allowed: false,
      executor_mode: 'unavailable', is_executable_authorization: false, replay_in_fresh_process: true, network_calls: 0,
      coverage: summary.coverage, fixture_sources: fixtures.map(({ id, file, text }) => ({ id, file: `sources/${file}`, content_sha256: sha(text) })) };
    writeNew(path.join(root, 'demo-receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`);
    const files = fs.readdirSync(root, { recursive: true }).filter((name) => fs.lstatSync(path.join(root, name)).isFile()).sort();
    writeNew(path.join(root, 'SHA256SUMS'), files.map((name) => `${sha(fs.readFileSync(path.join(root, name)))}  ${name}`).join('\n') + '\n');
    process.stdout.write(`${JSON.stringify({ workspace_id: workspaceId, asset_count: summary.coverage.asset_count, source_count: summary.coverage.source_count,
      batch_count: summary.coverage.batch_count, ownership: 'unverified', execution_allowed: false, network_calls: 0,
      active_tests: 0, repo_scans: 0, vulnerabilities_validated: 0, human_decisions: 0, broker_provider_calls: 0, replay_in_fresh_process: true })}\n`);
    process.stdout.write(`company demo artifacts retained at: ${root}\n`);
  } catch {
    process.stderr.write(`company demo artifacts retained at: ${root}\n`); throw error('company_demo_failed');
  } finally { if (client && client.child.exitCode === null) await client.close(); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((cause) => { process.stderr.write(`${/^[a-z_]{1,64}$/.test(cause?.code ?? '') ? cause.code : 'company_demo_failed'}\n`); process.exitCode = 1; });
}
