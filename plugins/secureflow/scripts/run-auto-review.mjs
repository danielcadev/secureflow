#!/usr/bin/env node
// Run or reopen a hash-pinned bundle, then reuse the existing local Review Room.
import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function fail(message) {
  process.stderr.write(`secureflow: ${message}\n`);
  process.exit(2);
}

const usage = 'usage: secureflow-review (--plan PATH | --directory PATH) --plan-sha256 SHA256 [--app-dir PATH] [--port PORT] [--session-port PORT] [--no-serve]';
if (process.argv.length === 3 && ['--help', '-h'].includes(process.argv[2])) {
  process.stdout.write(`${usage}\nExecute an authorized pinned plan, or reopen its verified cases without rescanning.\nThe host opens the printed local session URL; no external browser is launched.\n`);
  process.exit(0);
}

const options = new Map();
const values = new Set(['--plan', '--directory', '--plan-sha256', '--app-dir', '--port', '--session-port']);
const flags = new Set(['--no-serve']);
const args = process.argv.slice(2);
for (let index = 0; index < args.length; index += 1) {
  const key = args[index];
  if (options.has(key)) fail(`duplicate option: ${key}`);
  if (flags.has(key)) options.set(key, true);
  else if (values.has(key) && typeof args[index + 1] === 'string' && !args[index + 1].startsWith('--')) options.set(key, args[++index]);
  else fail(usage);
}
if (options.has('--plan') === options.has('--directory')) fail('select exactly one of --plan or --directory');
const hash = options.get('--plan-sha256');
if (typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash)) fail('an exact plan SHA-256 is required');

// The CLI is operator-selected via PATH, not via case data or tool arguments.
const command = options.has('--plan')
  ? ['review-execute', '--plan', options.get('--plan'), '--plan-sha256', hash]
  : ['review-status', '--directory', options.get('--directory'), '--plan-sha256', hash];
const result = spawnSync('secureflow', command, {
  encoding: 'utf8', maxBuffer: 2 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'],
});
if (result.error || result.status !== 0) {
  process.stderr.write(result.stderr ?? '');
  fail(result.error?.message ?? 'automatic review failed; retained partial evidence must be inspected, not presented as complete');
}
let summary;
try { summary = JSON.parse(result.stdout); } catch { fail('CLI did not return a valid review summary'); }
if (summary.contract_version !== 'secureflow-auto-review-result-v1' || summary.plan_sha256 !== hash
    || summary.status !== 'ready-for-review' || summary.ready_for_review !== true
    || summary.human_decisions !== 0 || summary.components_completed !== summary.components_requested
    || !Array.isArray(summary.components) || summary.components.length === 0 || summary.components.length > 16
    || summary.components.length !== summary.components_completed) fail('review is not complete and verified');
const casePaths = summary.components.map((component) => component.case_path);
if (casePaths.some((value) => typeof value !== 'string' || !path.isAbsolute(value) || /[\x00-\x1f\x7f]/.test(value))) fail('invalid case paths');
process.stdout.write(`${JSON.stringify(summary)}\n`);
if (options.has('--no-serve')) process.exit(0);

const launcher = path.join(path.dirname(fileURLToPath(import.meta.url)), 'open-review-room.sh');
const launchArgs = [launcher];
for (const name of ['--app-dir', '--port', '--session-port']) {
  if (options.has(name)) launchArgs.push(name, options.get(name));
}
for (const casePath of casePaths) launchArgs.push('--case', casePath);
// No system-browser flag: the host opens the printed loopback URL in its panel.
const child = spawn('bash', launchArgs, {
  stdio: 'inherit', env: { ...process.env, WRANGLER_SEND_METRICS: 'false' },
});
child.on('error', (error) => fail(error.message));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
child.on('exit', (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
