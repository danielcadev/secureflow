#!/usr/bin/env node
// Synthetic transport qualification, not a model-driven security investigation.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import readline from 'node:readline';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const repository = fileURLToPath(new URL('../', import.meta.url));
const broker = path.join(repository, 'plugins/secureflow/scripts/run-dynamic-review.mjs');
const writeNew = (name, data) => fs.writeFileSync(name, data, { flag: 'wx', mode: 0o600 });

async function main() {
  if (process.argv.length !== 2) {
    if (process.argv.length === 3 && process.argv[2] === '--help') {
      process.stdout.write('Usage: node scripts/demo-dynamic-local.mjs\nOwned synthetic loopback fixture and MCP subprocess; no model or remote target.\n');
      return;
    }
    throw new Error('invalid_demo_arguments');
  }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secureflow-dynamic-demo-'));
  fs.chmodSync(root, 0o700);
  const tokens = [randomBytes(32).toString('hex'), randomBytes(32).toString('hex')];
  const identity = Buffer.from(randomBytes(32).toString('hex'));
  const canary = 'synthetic-private-body-' + randomBytes(16).toString('hex');
  const requests = [];
  const server = http.createServer((req, res) => {
    const principal = req.headers.authorization === 'Bearer ' + tokens[0] ? 'userA'
      : req.headers.authorization === 'Bearer ' + tokens[1] ? 'userB' : 'anonymous';
    requests.push({ path: req.url, principal, method: req.method });
    if (req.method !== 'GET') { res.writeHead(405); res.end(); return; }
    if (req.url === '/__secureflow_identity') {
      res.writeHead(200); res.end(identity); return;
    }
    if (req.url === '/api/invoices/a') {
      if (principal === 'anonymous') { res.writeHead(401); res.end('denied'); return; }
      if (principal !== 'userA') { res.writeHead(403); res.end('denied'); return; }
      res.writeHead(200); res.end(canary); return;
    }
    if (req.url === '/api/broken/invoices/a' && principal !== 'anonymous') {
      // Deliberately broken fixture: missing ownership guard.
      res.writeHead(200); res.end(canary); return;
    }
    if (req.url === '/api/corrected/invoices/a') {
      res.writeHead(principal === 'userA' ? 200 : 403);
      res.end(principal === 'userA' ? canary : 'denied'); return;
    }
    res.writeHead(404); res.end('not-found');
  });
  let child;
  let lines;
  const pending = new Map();
  let stderr = '';
  let protocol = '';
  let failure = null;
  const rejectPending = (cause) => {
    for (const value of pending.values()) { clearTimeout(value.timer); value.reject(cause); }
    pending.clear();
  };
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const plan = {
      contract_version: 'secureflow-dynamic-plan-v1',
      authorization: {
        operator: 'owned-synthetic-demo',
        reference: 'Local fixture transport qualification only',
        issued_at: new Date(Date.now() - 1000).toISOString(),
        expires_at: new Date(Date.now() + 60000).toISOString(),
        owned_local_service: true,
      },
      target: { host: '127.0.0.1', port: server.address().port,
        identity_path: '/__secureflow_identity', identity_sha256: sha256(identity) },
      budgets: { max_requests: 10, timeout_ms: 1000, total_budget_ms: 10000,
        max_response_bytes: 4096, min_interval_ms: 20 },
      principals: [
        { id: 'userA', token_env: 'SECUREFLOW_DYNAMIC_DEMO_USER_A' },
        { id: 'userB', token_env: 'SECUREFLOW_DYNAMIC_DEMO_USER_B' },
        { id: 'anonymous', token_env: null },
      ],
      actions: [
        { id: 'owner_baseline', principal_id: 'userA', path: '/api/invoices/a', expected_status: 200 },
        { id: 'cross_user_control', principal_id: 'userB', path: '/api/invoices/a', expected_status: 403 },
        { id: 'anonymous_control', principal_id: 'anonymous', path: '/api/invoices/a', expected_status: 401 },
        { id: 'broken_guard', principal_id: 'userB', path: '/api/broken/invoices/a', expected_status: 403 },
        { id: 'corrected_control', principal_id: 'userB', path: '/api/corrected/invoices/a', expected_status: 403 },
      ],
      output_directory: path.join(root, 'run'),
    };
    const bytes = Buffer.from(JSON.stringify(plan, null, 2) + '\n');
    const planPath = path.join(root, 'approved-plan.json');
    const planHash = sha256(bytes);
    writeNew(planPath, bytes);
    child = spawn(process.execPath, [broker, '--plan', planPath, '--plan-sha256', planHash, '--mcp'], {
      cwd: repository, env: { ...process.env,
        SECUREFLOW_DYNAMIC_DEMO_USER_A: tokens[0], SECUREFLOW_DYNAMIC_DEMO_USER_B: tokens[1] },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const exited = new Promise((resolve, reject) => {
      child.once('error', (cause) => { rejectPending(cause); reject(cause); });
      child.once('exit', (code, signal) => {
        rejectPending(new Error('broker_exited'));
        resolve({ code, signal });
      });
    });
    exited.catch(() => {});
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    lines = readline.createInterface({ input: child.stdout });
    lines.on('line', (line) => {
      try {
        protocol += line + '\n';
        assert.ok(protocol.length < 65536, 'unexpected_protocol_volume');
        const message = JSON.parse(line);
        assert.equal(message.jsonrpc, '2.0');
        const item = pending.get(message.id);
        assert.ok(item, 'unexpected_rpc_response');
        pending.delete(message.id);
        clearTimeout(item.timer);
        if (message.error) item.reject(new Error('rpc_error'));
        else item.resolve(message.result);
      } catch (cause) { failure = cause; rejectPending(cause); }
    });
    let id = 0;
    const rpc = (method, params) => new Promise((resolve, reject) => {
      const requestId = ++id;
      const timer = setTimeout(() => {
        pending.delete(requestId); reject(new Error('demo_rpc_timeout'));
      }, 5000);
      pending.set(requestId, { resolve, reject, timer });
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: requestId, method, params }) + '\n');
    });
    const call = async (name, args = {}) => {
      const response = await rpc('tools/call', { name, arguments: args });
      assert.equal(response.isError, false, 'broker_tool_failed');
      return JSON.parse(response.content[0].text);
    };
    const initialize = await rpc('initialize', {
      protocolVersion: '2025-11-25', capabilities: {},
      clientInfo: { name: 'secureflow-synthetic-qualification', version: '0.1.0' },
    });
    assert.equal(initialize.protocolVersion, '2025-11-25');
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
    assert.equal((await rpc('tools/list', {})).tools.length, 4);
    assert.equal((await call('describe_authorized_dynamic_plan')).plan_sha256, planHash);
    for (const action of plan.actions) await call('execute_authorized_dynamic_action', { action_id: action.id });
    assert.equal((await call('dynamic_run_status')).status, 'running');
    const result = await call('finish_dynamic_run');
    assert.equal(result.status, 'completed');
    assert.equal(result.requests_used, 10);
    assert.equal(result.actions_completed, 5);
    assert.equal(result.human_decisions, 0);
    assert.equal(result.provider_calls, 0);
    assert.deepEqual(result.observations.map((item) => item.outcome), [
      'status-matched', 'status-matched', 'status-matched', 'status-mismatched', 'status-matched',
    ]);
    assert.deepEqual(result.observations.map((item) => item.status_code), [200, 403, 401, 200, 403]);
    child.stdin.end();
    assert.deepEqual(await exited, { code: 0, signal: null });
    assert.equal(stderr, '');
    assert.equal(failure, null);
    assert.equal(requests.length, 10);
    for (let i = 0; i < plan.actions.length; i++) {
      assert.deepEqual(requests[2 * i], { path: plan.target.identity_path, principal: 'anonymous', method: 'GET' });
      assert.deepEqual(requests[2 * i + 1], { path: plan.actions[i].path, principal: plan.actions[i].principal_id, method: 'GET' });
    }
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(plan.output_directory, 'result.json'))), result);
    assert.equal(sha256(fs.readFileSync(path.join(plan.output_directory, 'plan.json'))), planHash);
    assert.equal(fs.readFileSync(path.join(plan.output_directory, 'plan.sha256'), 'utf8').trim(), planHash);
    const runFiles = fs.readdirSync(plan.output_directory);
    assert.equal(runFiles.filter((name) => name.endsWith('-reservation.json')).length, 10);
    assert.equal(runFiles.filter((name) => name.endsWith('-receipt.json')).length, 10);
    const data = protocol + stderr + runFiles.map((name) => fs.readFileSync(path.join(plan.output_directory, name), 'utf8')).join('');
    for (const secret of [...tokens, canary]) assert.equal(data.includes(secret), false, 'secret_or_raw_body_leaked');
    writeNew(path.join(root, 'qualification.json'), JSON.stringify({
      fixture: 'synthetic-owned-local-service',
      reasoning: 'scripted-mcp-client-no-model',
      runtime: process.version,
      plan_sha256: planHash,
      requests_verified: 10,
      observations_verified: 5,
      status_mismatches: 1,
      human_decisions: 0,
      broker_provider_calls: 0,
      claims: 'transport-and-control-qualification-not-real-world-vulnerability-discovery',
    }, null, 2) + '\n');
    const retained = ['approved-plan.json', 'qualification.json',
      ...runFiles.map((name) => 'run/' + name)].sort();
    writeNew(path.join(root, 'SHA256SUMS'), retained.map((name) =>
      sha256(fs.readFileSync(path.join(root, name))) + '  ' + name + '\n').join(''));
    process.stdout.write('Dynamic local MCP demo passed: 5 observations, 10 requests, 0 human decisions.\n');
    process.stdout.write('dynamic demo artifacts retained at: ' + root + '\n');
  } finally {
    lines?.close();
    rejectPending(new Error('demo_closed'));
    if (child && child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}
main().catch(() => {
  process.stderr.write('dynamic_demo_failed\n');
  process.exitCode = 1;
});
