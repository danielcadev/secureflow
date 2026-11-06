import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createDynamicSession } from '../../plugins/secureflow/scripts/dynamic-review-core.mjs';

const runner = fileURLToPath(new URL('../../plugins/secureflow/scripts/run-dynamic-review.mjs', import.meta.url));
const sha = (value) => createHash('sha256').update(value).digest('hex');
const identity = 'owned-local-service-test-identity';
const tokenA = 'alice.secret-credential';
const tokenB = 'bob.secret-credential';
const envA = 'SECUREFLOW_DYNAMIC_TEST_ALICE';
const envB = 'SECUREFLOW_DYNAMIC_TEST_BOB';
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function fixture(t, handler = (_req, res) => res.end('response')) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secureflow-dynamic-test-'));
  fs.chmodSync(root, 0o700);
  const requests = [];
  const sockets = new Set();
  const server = http.createServer((req, res) => {
    requests.push({ path: req.url, authorization: req.headers.authorization ?? null });
    if (req.url === '/identity') res.end(identity);
    else handler(req, res);
  });
  server.on('connection', (socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const oldA = process.env[envA];
  const oldB = process.env[envB];
  process.env[envA] = tokenA;
  process.env[envB] = tokenB;
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
    for (const [key, value] of [[envA, oldA], [envB, oldB]]) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    fs.rmSync(root, { recursive: true, force: true });
  });
  const plan = {
    contract_version: 'secureflow-dynamic-plan-v1',
    authorization: { operator: 'test-operator', reference: 'test-grant', issued_at: new Date(Date.now() - 1000).toISOString(), expires_at: new Date(Date.now() + 60000).toISOString(), owned_local_service: true },
    target: { host: '127.0.0.1', port: server.address().port, identity_path: '/identity', identity_sha256: sha(identity) },
    budgets: { max_requests: 8, timeout_ms: 500, total_budget_ms: 10000, max_response_bytes: 1024, min_interval_ms: 20 },
    principals: [{ id: 'alice', token_env: envA }],
    actions: [{ id: 'read', principal_id: 'alice', path: '/resource', expected_status: 200 }],
    output_directory: path.join(root, 'evidence'),
  };
  const planPath = path.join(root, 'plan.json');
  const save = (value = plan, bytes = JSON.stringify(value)) => {
    fs.writeFileSync(planPath, bytes, { mode: 0o600 });
    return { planPath, planSha256: sha(bytes) };
  };
  const evidence = () => fs.readdirSync(plan.output_directory).map((file) => fs.readFileSync(path.join(plan.output_directory, file), 'utf8')).join('\n');
  return { root, plan, planPath, server, requests, save, evidence };
}

function assertStartupRejected(f, modify, code = 'invalid_plan') {
  const value = structuredClone(f.plan);
  modify(value);
  assert.throws(() => createDynamicSession(f.save(value)), { code });
  assert.equal(f.requests.length, 0);
  assert.equal(fs.existsSync(f.plan.output_directory), false);
}

async function child(f, mcp = true) {
  const args = f.save();
  const processChild = spawn(process.execPath, [runner, '--plan', args.planPath, '--plan-sha256', args.planSha256, ...(mcp ? ['--mcp'] : [])], { env: process.env, stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  const messages = [];
  let partial = '';
  processChild.stdout.on('data', (chunk) => {
    stdout += chunk;
    partial += chunk;
    let boundary;
    while ((boundary = partial.indexOf('\n')) !== -1) {
      const line = partial.slice(0, boundary);
      partial = partial.slice(boundary + 1);
      messages.push(JSON.parse(line));
    }
  });
  processChild.stderr.on('data', (chunk) => { stderr += chunk; });
  const exited = new Promise((resolve, reject) => {
    processChild.on('error', reject);
    processChild.on('close', (code, signal) => resolve({ code, signal }));
  });
  const send = (message) => processChild.stdin.write(`${JSON.stringify(message)}\n`);
  const wait = async (id) => {
    const end = Date.now() + 5000;
    while (Date.now() < end) {
      const message = messages.find((value) => value.id === id);
      if (message) return message;
      await delay(5);
    }
    assert.fail(`No subprocess response for ${id}; stderr=${stderr}`);
  };
  return { process: processChild, messages, exited, send, wait, output: () => ({ stdout, stderr }) };
}
const rpc = (id, method, params) => ({ jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) });
const initialize = { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'regression-test', version: '1' } };
async function initializeChild(c) {
  c.send(rpc(1, 'initialize', initialize));
  assert.equal((await c.wait(1)).result.protocolVersion, '2025-11-25');
  c.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
}
const tool = (id, name, args = {}) => rpc(id, 'tools/call', { name, arguments: args });

test('matched evidence, hashes, private files, anonymous identity and no secrets', async (t) => {
  const f = await fixture(t, (_req, res) => { res.setHeader('X-Secret', tokenB); res.end(tokenB); });
  const session = createDynamicSession(f.save());
  assert.equal(session.status().status, 'running');
  const observation = await session.execute('read');
  assert.equal(observation.outcome, 'status-matched');
  assert.equal(observation.body_sha256, sha(tokenB));
  const result = await session.finish();
  assert.equal(result.status, 'completed');
  assert.equal(result.requests_used, 2);
  assert.equal(result.actions_attempted, 1);
  assert.equal(result.actions_completed, 1);
  assert.deepEqual(f.requests, [{ path: '/identity', authorization: null }, { path: '/resource', authorization: `Bearer ${tokenA}` }]);
  assert.equal(result.provider_calls, 0);
  assert.equal(result.human_decisions, 0);
  assert.equal(result.ai_reasoning, 'external-client-not-measured');
  assert.equal(result.final_authority, 'human-only');
  assert.equal(fs.statSync(path.join(f.plan.output_directory, 'result.json')).ino,
    fs.statSync(path.join(f.plan.output_directory, 'result.provisional.json')).ino);
  assert.equal(fs.statSync(f.plan.output_directory).mode & 0o777, 0o700);
  for (const name of fs.readdirSync(f.plan.output_directory)) assert.equal(fs.statSync(path.join(f.plan.output_directory, name)).mode & 0o777, 0o600);
  assert.equal(f.evidence().includes(tokenA), false);
  assert.equal(f.evidence().includes(tokenB), false);
  assert.ok(fs.existsSync(path.join(f.plan.output_directory, 'action-001.json')));
  assert.ok(fs.existsSync(path.join(f.plan.output_directory, 'request-001-reservation.json')));
  assert.equal(JSON.stringify(session.describe()).includes(tokenA), false);
  assert.deepEqual(await session.finish(), result);
  await assert.rejects(session.execute('read'), { code: 'run_closed' });
});

test('multiple principals, anonymous actions, mismatches and server-error observations', async (t) => {
  const f = await fixture(t, (req, res) => { res.statusCode = req.url === '/server_error' ? 500 : req.headers.authorization ? 403 : 200; res.end('bounded'); });
  f.plan.principals.push({ id: 'bob', token_env: envB }, { id: 'anonymous', token_env: null });
  f.plan.actions.push({ id: 'bob_read', principal_id: 'bob', path: '/resource', expected_status: 403 }, { id: 'anonymous_read', principal_id: 'anonymous', path: '/server_error', expected_status: 200 });
  const session = createDynamicSession(f.save());
  const results = await Promise.all(f.plan.actions.map((action) => session.execute(action.id)));
  assert.deepEqual(results.map((result) => result.outcome), ['status-mismatched', 'status-matched', 'inconclusive']);
  assert.deepEqual(f.requests.map((request) => request.authorization), [null, `Bearer ${tokenA}`, null, `Bearer ${tokenB}`, null, null]);
  assert.equal((await session.finish()).requests_used, 6);
});

test('reservations precede every request, cadence is enforced and returned plan is immutable', async (t) => {
  const f = await fixture(t);
  const arrivals = [];
  const reserved = [];
  f.server.on('request', () => {
    arrivals.push(performance.now());
    reserved.push(fs.existsSync(path.join(f.plan.output_directory, `request-${String(arrivals.length).padStart(3, '0')}-reservation.json`))
      && fs.existsSync(path.join(f.plan.output_directory, 'action-001.json')));
  });
  f.plan.budgets.min_interval_ms = 60;
  const session = createDynamicSession(f.save());
  session.describe().plan.target.host = 'outside.invalid';
  session.describe().plan.actions[0].path = '/changed';
  await session.execute('read');
  assert.deepEqual(reserved, [true, true]);
  assert.ok(arrivals[1] - arrivals[0] >= 50, 'cadence must separate the two GETs');
  assert.equal(f.requests[1].path, '/resource');
  const snapshot = session.status();
  snapshot.observations[0].path = '/changed';
  assert.equal(session.status().observations[0].path, '/resource');
  await session.finish();
});

test('identity is rechecked before every action and mismatch stops later traffic', async (t) => {
  const f = await fixture(t);
  f.plan.actions.push({ id: 'second', principal_id: 'alice', path: '/second', expected_status: 200 });
  const session = createDynamicSession(f.save());
  await session.execute('read');
  f.server.removeAllListeners('request');
  f.server.on('request', (req, res) => { f.requests.push({ path: req.url, authorization: req.headers.authorization ?? null }); res.end('different-service'); });
  await assert.rejects(session.execute('second'), { code: 'identity_mismatch' });
  assert.equal(session.status().status, 'failed');
  assert.equal(session.status().requests_used, 3);
  assert.equal(session.status().actions_completed, 1);
  await assert.rejects(session.execute('read'), { code: 'run_closed' });
  assert.equal(f.requests.length, 3);
});

test('strict plan shape, grant, identifiers, budgets, principal and action allowlists reject before mutation', async (t) => {
  const f = await fixture(t);
  const invalid = [
    (p) => { p.extra = true; }, (p) => { p.authorization.extra = true; }, (p) => { p.target.extra = true; },
    (p) => { p.budgets.extra = true; }, (p) => { p.principals[0].extra = true; }, (p) => { p.actions[0].extra = true; },
    (p) => { p.contract_version = 'other'; }, (p) => { p.authorization.owned_local_service = false; },
    (p) => { p.authorization.issued_at = '2026-02-30T00:00:00Z'; }, (p) => { p.authorization.issued_at = '2026-01-01'; },
    (p) => { p.authorization.expires_at = '2026-01-01T25:00:00Z'; }, (p) => { p.authorization.expires_at = '2026-01-01T00:00:00+24:00'; },
    (p) => { p.authorization.operator = 'x\n'; }, (p) => { p.principals = []; },
    (p) => { p.principals = Array.from({ length: 9 }, (_, i) => ({ id: `person${i}`, token_env: null })); },
    (p) => { p.principals.push(p.principals[0]); }, (p) => { p.principals[0].id = 'bad id'; },
    (p) => { p.actions = []; }, (p) => { p.actions.push(p.actions[0]); }, (p) => { p.actions[0].principal_id = 'unknown'; },
    (p) => { p.actions[0].id = 'bad/id'; }, (p) => { p.actions[0].expected_status = 500; },
    (p) => { p.actions = Array.from({ length: 33 }, (_, i) => ({ ...p.actions[0], id: `action${i}` })); },
    (p) => { p.budgets.max_requests = 1; }, (p) => { p.budgets.max_requests = 65; },
    (p) => { p.actions.push({ ...p.actions[0], id: 'second' }); p.budgets.max_requests = 3; },
    ...[['timeout_ms', 0], ['timeout_ms', 5001], ['total_budget_ms', 0], ['total_budget_ms', 120001], ['max_response_bytes', 0], ['max_response_bytes', 65537], ['min_interval_ms', 19], ['min_interval_ms', 1001], ['min_interval_ms', 20.5]].map(([key, value]) => (p) => { p.budgets[key] = value; }),
  ];
  for (const modify of invalid) assertStartupRejected(f, modify);
  for (const modify of [
    (p) => { p.authorization.expires_at = new Date(Date.now() - 1).toISOString(); },
    (p) => { p.authorization.issued_at = new Date(Date.now() + 10000).toISOString(); },
    (p) => { p.authorization.expires_at = new Date(Date.now() + 86400000).toISOString(); },
  ]) assertStartupRejected(f, modify, 'invalid_authorization');
});

test('literal IPv4 and canonical paths only', async (t) => {
  const f = await fixture(t);
  for (const host of ['localhost', '127.1', '127.0.0.2', '::1', '2130706433', 'example.invalid', '127.0.0.1\n']) assertStartupRejected(f, (p) => { p.target.host = host; });
  for (const port of [0, 80, 1023, 65536, '8080', 8080.5]) assertStartupRejected(f, (p) => { p.target.port = port; });
  for (const route of ['relative', '//double', '/a//b', '/a/../b', '/a.b', '/a%2fb', '/a?b', '/a#b', '/a\\b', '/é', '/a\n']) {
    assertStartupRejected(f, (p) => { p.actions[0].path = route; });
    assertStartupRejected(f, (p) => { p.target.identity_path = route; });
  }
});

test('bounded exact-byte plan hash and startup arguments', async (t) => {
  const f = await fixture(t);
  const args = f.save();
  for (const value of [undefined, null, {}, { ...args, extra: true }, { ...args, planSha256: 'A'.repeat(64) }]) assert.throws(() => createDynamicSession(value), { code: 'invalid_startup_arguments' });
  assert.throws(() => createDynamicSession({ ...args, planSha256: '0'.repeat(64) }), { code: 'plan_hash_mismatch' });
  assert.throws(() => createDynamicSession(f.save(f.plan, '{')), { code: 'invalid_plan' });
  assert.throws(() => createDynamicSession(f.save(f.plan, ' '.repeat(65537))), { code: 'invalid_plan_file' });
  const exact = `${JSON.stringify(f.plan)}\n`;
  f.save(f.plan, exact);
  assert.throws(() => createDynamicSession({ planPath: f.planPath, planSha256: sha(exact.trim()) }), { code: 'plan_hash_mismatch' });
  fs.unlinkSync(f.planPath);
  fs.symlinkSync(path.join(f.root, 'missing'), f.planPath);
  assert.throws(() => createDynamicSession(args), { code: 'invalid_plan_file' });
  assert.equal(f.requests.length, 0);
  assert.equal(fs.existsSync(f.plan.output_directory), false);
});

test('exact 64 KiB plan and maximum approved static budgets are accepted', async (t) => {
  const f = await fixture(t);
  f.plan.budgets = { max_requests: 64, timeout_ms: 5000, total_budget_ms: 120000, max_response_bytes: 65536, min_interval_ms: 1000 };
  f.plan.principals = Array.from({ length: 8 }, (_, index) => ({ id: `person${index}`, token_env: null }));
  f.plan.actions = Array.from({ length: 32 }, (_, index) => ({ id: `action${index}`, principal_id: `person${index % 8}`, path: '/resource', expected_status: 200 }));
  const json = JSON.stringify(f.plan);
  const bytes = json + ' '.repeat(65536 - Buffer.byteLength(json));
  const session = createDynamicSession(f.save(f.plan, bytes));
  assert.equal(session.describe().plan.actions.length, 32);
  assert.equal((await session.finish()).status, 'incomplete');
  assert.equal(f.requests.length, 0);
});

test('credentials are environment-only, bounded, grammar checked and cannot appear escaped in plan', async (t) => {
  const f = await fixture(t);
  for (const value of ['', 'a b', 'a\nb', 'a\rb', 'é', 'a'.repeat(513), 'a=b=c']) {
    process.env[envA] = value;
    assertStartupRejected(f, () => {}, 'invalid_credential');
  }
  delete process.env[envA];
  assertStartupRejected(f, () => {}, 'invalid_credential');
  process.env[envA] = tokenA;
  for (const name of ['TOKEN', 'SECUREFLOW_DYNAMIC_lower', 'SECUREFLOW_DYNAMIC_', 'SECUREFLOW_DYNAMIC_A\n']) assertStartupRejected(f, (p) => { p.principals[0].token_env = name; });
  assertStartupRejected(f, (p) => { p.authorization.reference = tokenA; }, 'credential_in_plan');
  const value = structuredClone(f.plan);
  value.authorization.reference = tokenA;
  const escaped = JSON.stringify(value).replace(tokenA, [...tokenA].map((char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`).join(''));
  assert.throws(() => createDynamicSession(f.save(value, escaped)), { code: 'credential_in_plan' });
  assert.equal(f.requests.length, 0);
});

test('unsafe output, existing evidence and symlinks are rejected without overwrite', async (t) => {
  const f = await fixture(t);
  for (const directory of ['relative', '/', `${f.root}/../escape`, `${f.root}/bad\n`]) assertStartupRejected(f, (p) => { p.output_directory = directory; }, 'invalid_output_directory');
  fs.chmodSync(f.root, 0o755);
  assertStartupRejected(f, () => {}, 'unsafe_output_parent');
  fs.chmodSync(f.root, 0o700);
  const link = path.join(f.root, 'linked_parent');
  fs.symlinkSync(f.root, link);
  assertStartupRejected(f, (p) => { p.output_directory = path.join(link, 'evidence'); }, 'unsafe_output_parent');
  fs.mkdirSync(f.plan.output_directory, { mode: 0o700 });
  const sentinel = path.join(f.plan.output_directory, 'sentinel');
  fs.writeFileSync(sentinel, 'preserved');
  assert.throws(() => createDynamicSession(f.save()), { code: 'output_exists' });
  assert.equal(fs.readFileSync(sentinel, 'utf8'), 'preserved');
  fs.rmSync(f.plan.output_directory, { recursive: true });
  fs.symlinkSync(f.root, f.plan.output_directory);
  assert.throws(() => createDynamicSession(f.save()), { code: 'output_exists' });
  assert.equal(f.requests.length, 0);
});

test('proxy variables cannot redirect the explicit loopback connection', async (t) => {
  const f = await fixture(t);
  const names = ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'NO_PROXY'];
  const previous = new Map(names.map((key) => [key, process.env[key]]));
  t.after(() => { for (const [key, value] of previous) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } });
  for (const key of names) process.env[key] = 'http://unreachable.invalid:1';
  const session = createDynamicSession(f.save());
  await session.execute('read');
  assert.equal((await session.finish()).status, 'completed');
  assert.equal(f.requests.length, 2);
});

test('redirects fail once and do not follow Location or leak headers', async (t) => {
  const f = await fixture(t, (_req, res) => { res.writeHead(302, { Location: '/followup', 'X-Secret': tokenA }); res.end(tokenA); });
  const session = createDynamicSession(f.save());
  await assert.rejects(session.execute('read'), { code: 'redirect_refused' });
  assert.equal(session.status().failure.code, 'redirect_refused');
  assert.equal(f.requests.length, 2);
  assert.equal(f.evidence().includes(tokenA), false);
  assert.equal(f.requests.some((request) => request.path === '/followup'), false);
});

test('response and response-header limits stop traffic and sanitize failures', async (t) => {
  for (const [name, handler, code] of [
    ['body', (_req, res) => res.end('x'.repeat(2048)), 'response_too_large'],
    ['headers', (_req, res) => { res.setHeader('X-Large', tokenA.repeat(1000)); res.end(); }, 'transport_failed'],
  ]) await t.test(name, async (st) => {
    const f = await fixture(st, handler);
    const session = createDynamicSession(f.save());
    await assert.rejects(session.execute('read'), { code });
    assert.equal(session.status().status, 'failed');
    assert.equal(f.requests.length, 2);
    assert.equal(f.evidence().includes(tokenA), false);
    assert.equal(session.status().observations.length, 0);
  });
});

test('request timeout, monotonic total budget and grant expiry are fatal', async (t) => {
  await t.test('request timeout', async (st) => {
    const f = await fixture(st, () => {});
    f.plan.budgets.timeout_ms = 30;
    const session = createDynamicSession(f.save());
    await assert.rejects(session.execute('read'), { code: 'request_timeout' });
    assert.equal(f.requests.length, 2);
    await assert.rejects(session.execute('read'), { code: 'run_closed' });
  });
  await t.test('total budget includes cadence and is not retried', async (st) => {
    const f = await fixture(st);
    f.plan.budgets.total_budget_ms = 80;
    f.plan.budgets.min_interval_ms = 100;
    const session = createDynamicSession(f.save());
    await assert.rejects(session.execute('read'), { code: 'run_budget_exhausted' });
    assert.equal(session.status().requests_used, 1);
    assert.equal(f.requests.length, 1);
  });
  await t.test('expiry checked again at execution', async (st) => {
    const f = await fixture(st);
    f.plan.authorization.expires_at = new Date(Date.now() + 40).toISOString();
    const session = createDynamicSession(f.save());
    await delay(60);
    await assert.rejects(session.execute('read'), { code: 'authorization_expired' });
    assert.equal(f.requests.length, 0);
  });
  await t.test('total budget interrupts an active response', async (st) => {
    const f = await fixture(st, () => {});
    f.plan.budgets.total_budget_ms = 100;
    const session = createDynamicSession(f.save());
    await assert.rejects(session.execute('read'), { code: 'run_budget_exhausted' });
    assert.equal(session.status().requests_used, 2);
    assert.equal(f.requests.length, 2);
  });
});

test('actions are serialized and reserved once; partial finish is incomplete', async (t) => {
  const f = await fixture(t);
  f.plan.actions.push({ ...f.plan.actions[0], id: 'second', path: '/second' });
  const session = createDynamicSession(f.save());
  await assert.rejects(session.execute('unknown'), { code: 'unknown_action' });
  assert.equal(session.status().actions_attempted, 0);
  const [first, replay] = await Promise.allSettled([session.execute('read'), session.execute('read')]);
  assert.equal(first.status, 'fulfilled');
  assert.equal(replay.reason.code, 'action_already_attempted');
  assert.equal(f.requests.length, 2);
  const result = await session.finish();
  assert.equal(result.status, 'incomplete');
  assert.equal(result.actions_completed, 1);
  await assert.rejects(session.execute('second'), { code: 'run_closed' });
  assert.equal(fs.readdirSync(f.plan.output_directory).filter((name) => name.startsWith('action-')).length, 1);
});

test('early finish sends no request and directory replacement fails before network', async (t) => {
  await t.test('early finish', async (st) => {
    const f = await fixture(st);
    const session = createDynamicSession(f.save());
    assert.equal((await session.finish()).status, 'incomplete');
    assert.equal(f.requests.length, 0);
  });
  await t.test('replaced evidence directory', async (st) => {
    const f = await fixture(st);
    const session = createDynamicSession(f.save());
    fs.renameSync(f.plan.output_directory, path.join(f.root, 'original-evidence'));
    fs.symlinkSync(path.join(f.root, 'original-evidence'), f.plan.output_directory);
    await assert.rejects(session.execute('read'), { code: 'evidence_write_failed' });
    assert.equal(session.status().status, 'failed');
    assert.equal(f.requests.length, 0);
  });
});

test('final-result fsync failures cannot publish a misleading completed result in exercised faults', async (t) => {
  for (const phase of ['provisional-file', 'provisional-directory', 'published-directory']) {
    await t.test(phase, async (st) => {
      const f = await fixture(st);
      const session = createDynamicSession(f.save());
      await session.execute('read');
      assert.equal(f.requests.length, 2);
      const originalSync = fs.fsyncSync;
      let directorySyncs = 0;
      let syncCalls = 0;
      fs.fsyncSync = (fd) => {
        syncCalls += 1;
        const info = fs.fstatSync(fd);
        if (info.isDirectory()) directorySyncs += 1;
        if ((phase === 'provisional-file' && info.isFile())
            || (phase === 'provisional-directory' && info.isDirectory())
            || (phase === 'published-directory' && info.isDirectory() && directorySyncs >= 2)) {
          throw Object.assign(new Error('injected private filesystem detail'), { code: 'EIO' });
        }
        return originalSync(fd);
      };
      try {
        await assert.rejects(session.finish(), { code: 'evidence_write_failed' });
        const result = session.status();
        assert.equal(result.status, 'failed');
        assert.deepEqual(result.failure, { code: 'evidence_write_failed', action_id: null });
        assert.equal(result.actions_completed, 1);
        assert.equal(result.requests_used, 2);
        assert.equal(fs.existsSync(path.join(f.plan.output_directory, 'result.json')), false);
        assert.equal(fs.existsSync(path.join(f.plan.output_directory, 'result.provisional.json')), true);
        assert.equal(fs.existsSync(path.join(f.plan.output_directory, 'result.unpublished.json')), phase === 'published-directory');
        if (phase === 'published-directory') {
          assert.equal(fs.statSync(path.join(f.plan.output_directory, 'result.provisional.json')).ino,
            fs.statSync(path.join(f.plan.output_directory, 'result.unpublished.json')).ino);
        }
        const names = fs.readdirSync(f.plan.output_directory);
        const callsAtFailure = syncCalls;
        await assert.rejects(session.execute('read'), { code: 'run_closed' });
        assert.deepEqual(await session.finish(), result);
        assert.equal(syncCalls, callsAtFailure, 'a failed run must not retry publication');
        assert.deepEqual(fs.readdirSync(f.plan.output_directory), names);
        assert.equal(f.requests.length, 2);
        assert.equal(JSON.stringify(result).includes('private filesystem detail'), false);
      } finally { fs.fsyncSync = originalSync; }
    });
  }
});

test('deterministic CLI executes all approved actions and closes completed evidence', async (t) => {
  const f = await fixture(t);
  f.plan.actions.push({ ...f.plan.actions[0], id: 'second', path: '/second' });
  const c = await child(f, false);
  c.process.stdin.end();
  assert.equal((await c.exited).code, 0);
  assert.equal(c.messages[0].status, 'completed');
  assert.equal(c.messages[0].requests_used, 4);
  assert.equal(c.output().stderr, '');
});

test('real MCP lifecycle lists four closed tools and executes only valid calls serially', async (t) => {
  const f = await fixture(t);
  const c = await child(f);
  c.send(rpc(0, 'tools/list', {}));
  assert.equal((await c.wait(0)).error.code, -32000);
  await initializeChild(c);
  c.send(rpc(2, 'tools/list', {}));
  const listed = (await c.wait(2)).result.tools;
  assert.equal(listed.length, 4);
  assert.ok(listed.every((entry) => entry.inputSchema.additionalProperties === false));
  c.send(tool(3, 'execute_authorized_dynamic_action', { action_id: 'read' }));
  c.send(tool(4, 'execute_authorized_dynamic_action', { action_id: 'read' }));
  c.send(tool(5, 'dynamic_run_status'));
  assert.equal((await c.wait(3)).result.isError, false);
  assert.equal((await c.wait(4)).result.content[0].text, 'action_already_attempted');
  assert.equal(JSON.parse((await c.wait(5)).result.content[0].text).actions_completed, 1);
  c.send(tool(6, 'finish_dynamic_run'));
  assert.equal(JSON.parse((await c.wait(6)).result.content[0].text).status, 'completed');
  c.process.stdin.end();
  assert.equal((await c.exited).code, 0);
  assert.equal(f.requests.length, 2);
  assert.equal(c.output().stdout.includes(tokenA), false);
});

test('MCP stdout backpressure pauses serial dispatch until the client resumes reading', async (t) => {
  const f = await fixture(t);
  f.plan.budgets.max_requests = 64;
  f.plan.actions = Array.from({ length: 32 }, (_, index) => ({ id: `action${index}`, principal_id: 'alice', path: `/${'a'.repeat(1023)}`, expected_status: 200 }));
  const c = await child(f);
  t.after(() => { c.process.stdout.resume(); c.process.kill(); });
  await initializeChild(c);
  c.process.stdout.pause();
  // Eight bounded ~38 KiB descriptions exceed the local pipe/stream buffers;
  // the following action must remain behind the pending response.
  for (let id = 2; id <= 9; id++) c.send(tool(id, 'describe_authorized_dynamic_plan'));
  c.send(tool(10, 'execute_authorized_dynamic_action', { action_id: 'action0' }));
  await delay(60);
  assert.equal(f.requests.length, 0);
  c.process.stdout.resume();
  assert.equal((await c.wait(10)).result.isError, false);
  assert.deepEqual(c.messages.map((message) => message.id), Array.from({ length: 10 }, (_, index) => index + 1));
  c.send(tool(11, 'finish_dynamic_run'));
  assert.equal(JSON.parse((await c.wait(11)).result.content[0].text).status, 'incomplete');
  c.process.stdin.end();
  assert.equal((await c.exited).code, 0);
  assert.equal(f.requests.length, 2);
  assert.equal(c.output().stderr, '');
});

test('MCP invalid message and tool arguments never reflect secrets or cause network', async (t) => {
  const f = await fixture(t);
  const c = await child(f);
  c.send(rpc(0, 'initialize', { ...initialize, extra: tokenA }));
  assert.equal((await c.wait(0)).error.code, -32602);
  await initializeChild(c);
  const invalid = [
    rpc(2, 'initialize', initialize), rpc(3, 'tools/list', { cursor: tokenA }),
    tool(4, 'dynamic_run_status', { token: tokenA }), tool(5, 'execute_authorized_dynamic_action', { action_id: 'read', token: tokenA }),
    tool(6, 'execute_authorized_dynamic_action', { action_id: 1 }), tool(7, tokenA),
    rpc(8, 'tools/call', { name: 'dynamic_run_status', arguments: {}, extra: tokenA }),
  ];
  for (const message of invalid) { c.send(message); assert.equal((await c.wait(message.id)).error.code, -32602); }
  c.send(tool(9, 'execute_authorized_dynamic_action', { action_id: tokenA }));
  assert.equal((await c.wait(9)).result.content[0].text, 'unknown_action');
  c.process.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: null, method: 'tools/list' })}\n`);
  c.process.stdin.write('{malformed-json\n');
  c.process.stdin.end();
  assert.equal((await c.exited).code, 0);
  assert.equal(f.requests.length, 0);
  assert.equal(c.output().stdout.includes(tokenA), false);
  assert.equal(JSON.parse(fs.readFileSync(path.join(f.plan.output_directory, 'result.json'))).status, 'incomplete');
  assert.ok(c.messages.some((message) => message.error?.code === -32600));
  assert.ok(c.messages.some((message) => message.error?.code === -32700));
});

test('MCP message bound handles split oversize lines and EOF closes incomplete', async (t) => {
  const f = await fixture(t);
  const c = await child(f);
  await initializeChild(c);
  c.process.stdin.write('x'.repeat(40000));
  c.process.stdin.write('x'.repeat(30000));
  c.process.stdin.write('\n');
  c.send(rpc(2, 'ping', {}));
  assert.deepEqual((await c.wait(2)).result, {});
  c.process.stdin.end('x'.repeat(65537));
  assert.equal((await c.exited).code, 0);
  assert.equal(c.messages.filter((message) => message.error?.message === 'Message too large').length, 2);
  assert.equal(f.requests.length, 0);
  assert.equal(JSON.parse(fs.readFileSync(path.join(f.plan.output_directory, 'result.json'))).status, 'incomplete');
});

test('CLI startup rejection is sanitized and performs no network or evidence mutation', async (t) => {
  const f = await fixture(t);
  const args = f.save();
  const processChild = spawn(process.execPath, [runner, '--plan', args.planPath, '--plan-sha256', '0'.repeat(64)], { env: process.env, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  processChild.stdout.on('data', (chunk) => { stdout += chunk; });
  processChild.stderr.on('data', (chunk) => { stderr += chunk; });
  const code = await new Promise((resolve, reject) => { processChild.on('error', reject); processChild.on('close', resolve); });
  assert.equal(code, 1);
  assert.equal(stdout, '');
  assert.equal(stderr, 'plan_hash_mismatch\n');
  assert.equal(f.requests.length, 0);
  assert.equal(fs.existsSync(f.plan.output_directory), false);
});
