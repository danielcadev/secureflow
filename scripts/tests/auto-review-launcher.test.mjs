import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync, truncateSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const script = fileURLToPath(new URL('../../plugins/secureflow/scripts/run-auto-review.mjs', import.meta.url));
const hash = 'a'.repeat(64);

function fixture(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'secureflow-launcher-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, 'bin'); mkdirSync(bin);
  const log = path.join(root, 'argv.json');
  writeFileSync(path.join(bin, 'secureflow'), `#!${process.execPath}
const fs = require('node:fs');
fs.writeFileSync(process.env.SF_LAUNCHER_ARGV, JSON.stringify(process.argv.slice(2)));
process.stdout.write(process.env.SF_LAUNCHER_REPLY);
process.exit(Number(process.env.SF_LAUNCHER_EXIT || 0));
`, { mode: 0o700 });
  const reply = {
    contract_version: 'secureflow-auto-review-result-v1', plan_sha256: hash,
    status: 'ready-for-review', ready_for_review: true, human_decisions: 0,
    components_completed: 1, components_requested: 1,
    components: [{ case_path: path.join(root, 'case with spaces.json') }],
  };
  const casePath = reply.components[0].case_path;
  writeFileSync(casePath, '{}');
  const app = path.join(root, 'app');
  mkdirSync(path.join(app, 'dist', 'server'), { recursive: true });
  writeFileSync(path.join(app, 'package.json'), '{}');
  writeFileSync(path.join(app, 'dist', 'server', 'wrangler.json'), '{}');
  const runtimeLog = path.join(root, 'runtime-started');
  writeFileSync(path.join(bin, 'npm'), `#!${process.execPath}
require('node:fs').writeFileSync(process.env.SF_LAUNCHER_RUNTIME, 'started');
process.exit(0);
`, { mode: 0o700 });
  function run(args, changes = {}, code = 0) {
    return spawnSync(process.execPath, [script, ...args], {
      encoding: 'utf8', env: { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`,
        SF_LAUNCHER_ARGV: log, SF_LAUNCHER_REPLY: JSON.stringify({ ...reply, ...changes }), SF_LAUNCHER_EXIT: String(code), SF_LAUNCHER_RUNTIME: runtimeLog },
      timeout: 15_000,
    });
  }
  return { root, bin, log, run, app, runtimeLog, casePath };
}

async function occupiedPort(t) {
  const server = createServer(socket => socket.destroy());
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return server.address().port;
}

test('help describes the installed entry point without invoking the CLI or runtime', (t) => {
  const f = fixture(t);
  for (const flag of ['--help', '-h']) {
    const result = f.run([flag]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /usage: secureflow-review/);
    assert.match(result.stdout, /--plan-sha256/);
    assert.equal(existsSync(f.log), false);
    assert.equal(existsSync(f.runtimeLog), false);
  }
});

test('execute and reopen preserve literal paths and return the verified bundle', (t) => {
  const f = fixture(t);
  for (const option of ['--plan', '--directory']) {
    const input = path.join(f.root, 'path with spaces;not-a-shell');
    const result = f.run([option, input, '--plan-sha256', hash, '--no-serve']);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).status, 'ready-for-review');
    assert.deepEqual(JSON.parse(readFileSync(f.log)), [option === '--plan' ? 'review-execute' : 'review-status', option, input, '--plan-sha256', hash]);
  }
});

test('invalid capabilities or ambiguous options do not invoke the CLI', (t) => {
  const f = fixture(t);
  for (const args of [
    ['--plan', '/tmp/example', '--plan-sha256', 'wrong'],
    ['--plan', '/tmp/a', '--directory', '/tmp/b', '--plan-sha256', hash],
    ['--plan', '/tmp/a', '--plan', '/tmp/b', '--plan-sha256', hash],
    ['--plan', '/tmp/a', '--plan-sha256', hash, '--system-browser'],
  ]) {
    assert.notEqual(f.run(args).status, 0);
    assert.equal(existsSync(f.log), false);
  }
});

test('failure, incomplete coverage, hash substitution, and malformed paths cannot open the panel', (t) => {
  const f = fixture(t);
  const args = ['--directory', path.join(f.root, 'run'), '--plan-sha256', hash, '--no-serve'];
  for (const change of [
    { status: 'failed', ready_for_review: false },
    { components_requested: 2 },
    { components: [] },
    { plan_sha256: 'b'.repeat(64) },
    { human_decisions: 1 },
    { components: [{ case_path: '../outside.json' }] },
    { components: [{ case_path: '/tmp/control\ncharacter.json' }] },
  ]) assert.notEqual(f.run(args, change).status, 0);
  assert.notEqual(f.run(args, {}, 1).status, 0);
});

test('a session port collision fails before starting the UI or announcing its URL', async (t) => {
  const f = fixture(t);
  const port = await occupiedPort(t);
  const result = f.run(['--directory', path.join(f.root, 'run'), '--plan-sha256', hash,
    '--app-dir', f.app, '--port', String(port + 1), '--session-port', String(port)]);
  assert.notEqual(result.status, 0, result.stderr);
  assert.equal(existsSync(f.runtimeLog), false);
  assert.doesNotMatch(result.stderr, /SecureFlow Review Room: http/);
});

test('aggregate presentation limits stop serving but preserve headless verification', (t) => {
  const f = fixture(t);
  const components = Array.from({ length: 16 }, (_, index) => {
    const casePath = path.join(f.root, `case-${index}.json`);
    writeFileSync(casePath, '{}');
    // Mock CLI has accepted these files; sparse files exercise byte limits without
    // inventing a real Security Case or allocating a large synthetic document.
    truncateSync(casePath, 9 * 1024 * 1024);
    return { case_path: casePath };
  });
  const changes = { components, components_completed: 16, components_requested: 16 };
  const args = ['--directory', path.join(f.root, 'run'), '--plan-sha256', hash];
  assert.equal(f.run([...args, '--no-serve'], changes).status, 0);
  const result = f.run([...args, '--app-dir', f.app, '--port', '43151', '--session-port', '43152'], changes);
  assert.notEqual(result.status, 0, result.stderr);
  assert.equal(existsSync(f.runtimeLog), false);
  assert.doesNotMatch(result.stderr, /SecureFlow Review Room: http/);
  assert.match(result.stderr, /128 MiB/);
});

test('the serving path announces cases only after the loader is listening', async (t) => {
  const f = fixture(t);
  const reserved = createServer();
  await new Promise(resolve => reserved.listen(0, '127.0.0.1', resolve));
  const port = reserved.address().port;
  await new Promise(resolve => reserved.close(resolve));
  const result = f.run(['--directory', path.join(f.root, 'run'), '--plan-sha256', hash,
    '--app-dir', f.app, '--port', String(port + 1), '--session-port', String(port)]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(existsSync(f.runtimeLog), true);
  const ready = result.stderr.indexOf('SecureFlow review session ready');
  const announced = result.stderr.indexOf('SecureFlow Review Room: http');
  assert.ok(ready >= 0 && announced > ready, result.stderr);
});

test('unexpected loader shutdown terminates the owned runtime and returns failure', (t) => {
  const f = fixture(t);
  const helper = path.join(f.root, 'run-review-session.mjs');
  writeFileSync(helper, readFileSync(new URL('../../plugins/secureflow/scripts/run-review-session.mjs', import.meta.url)));
  writeFileSync(path.join(f.root, 'review-session-server.mjs'), `
process.send({type:'secureflow-review-session-ready'});
setTimeout(() => process.exit(17), 500);
`);
  writeFileSync(path.join(f.bin, 'npm'), `#!${process.execPath}
require('node:fs').writeFileSync(process.env.SF_LAUNCHER_RUNTIME, String(process.pid));
setInterval(() => {}, 1000);
`, { mode: 0o700 });
  const result = spawnSync(process.execPath, [helper, '--app-dir', f.app,
    '--port', '43151', '--session-port', '43152', '--case', f.casePath], {
    encoding: 'utf8', timeout: 5000,
    env: { ...process.env, PATH: `${f.bin}${path.delimiter}${process.env.PATH}`, SF_LAUNCHER_RUNTIME: f.runtimeLog },
  });
  assert.equal(result.status, 17, result.stderr);
  assert.match(result.stderr, /case loader stopped/);
  const runtimePid = Number(readFileSync(f.runtimeLog, 'utf8'));
  assert.throws(() => process.kill(runtimePid, 0), { code: 'ESRCH' });
});

test('a UI runtime failure keeps its exit status and closes the session loader', async (t) => {
  const f = fixture(t);
  const reserved = createServer();
  await new Promise(resolve => reserved.listen(0, '127.0.0.1', resolve));
  const port = reserved.address().port;
  await new Promise(resolve => reserved.close(resolve));
  writeFileSync(path.join(f.bin, 'npm'), `#!${process.execPath}
process.exit(23);
`, { mode: 0o700 });
  const result = f.run(['--directory', path.join(f.root, 'run'), '--plan-sha256', hash,
    '--app-dir', f.app, '--port', String(port + 1), '--session-port', String(port)]);
  assert.equal(result.status, 23, result.stderr);
  // A successful rebind proves the helper did not leave its loader listening.
  const rebound = createServer();
  await new Promise((resolve, reject) => {
    rebound.once('error', reject);
    rebound.listen(port, '127.0.0.1', resolve);
  });
  await new Promise(resolve => rebound.close(resolve));
});

test('cleanup reaches a SIGTERM-ignoring descendant after its runtime leader exits', { skip: process.platform !== 'linux' }, (t) => {
  const f = fixture(t);
  const helper = path.join(f.root, 'run-review-session.mjs');
  writeFileSync(helper, readFileSync(new URL('../../plugins/secureflow/scripts/run-review-session.mjs', import.meta.url)));
  writeFileSync(path.join(f.root, 'review-session-server.mjs'), `
process.send({type:'secureflow-review-session-ready'});
setInterval(() => {}, 1000);
`);
  const descendantLog = path.join(f.root, 'descendant.pid');
  t.after(() => {
    if (existsSync(descendantLog)) {
      try { process.kill(Number(readFileSync(descendantLog, 'utf8')), 'SIGKILL'); } catch { /* Already stopped. */ }
    }
  });
  writeFileSync(path.join(f.bin, 'npm'), `#!${process.execPath}
const {spawn} = require('node:child_process');
const code = ${JSON.stringify("require('node:fs').writeFileSync(process.env.SF_DESCENDANT_LOG,String(process.pid)); process.on('SIGTERM',()=>{}); process.send({ready:true}); setInterval(()=>{},1000);")};
const child = spawn(process.execPath, ['-e',code], {stdio:['ignore','ignore','ignore','ipc']});
child.on('message', () => process.exit(0));
`, { mode: 0o700 });
  const result = spawnSync(process.execPath, [helper, '--app-dir', f.app,
    '--port', '43151', '--session-port', '43152', '--case', f.casePath], {
    encoding: 'utf8', timeout: 8000,
    env: { ...process.env, PATH: `${f.bin}${path.delimiter}${process.env.PATH}`, SF_DESCENDANT_LOG: descendantLog },
  });
  assert.equal(result.error, undefined, result.stderr);
  assert.ok([0, 1].includes(result.status), result.stderr);
  const descendantPid = Number(readFileSync(descendantLog, 'utf8'));
  // Orphans may remain as zombies until the host's init reaps them; they must
  // never remain running. An unconfirmed group cleanup must return failure.
  try {
    const stat = readFileSync(`/proc/${descendantPid}/stat`, 'utf8');
    assert.equal(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[0], 'Z');
    assert.equal(result.status, 1);
    assert.match(result.stderr, /cleanup could not be confirmed/);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
});
