#!/usr/bin/env node
// Start the UI only after its own case loader has passed limits and bound its port.
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const options = new Map();
const cases = [];
const args = process.argv.slice(2);
function fail(message) {
  process.stderr.write(`secureflow: ${message}\n`);
  process.exit(2);
}
for (let index = 0; index < args.length; index += 1) {
  const name = args[index];
  if (name === '--system-browser' && !options.has(name)) options.set(name, true);
  else if (['--app-dir', '--port', '--session-port', '--case'].includes(name)
    && typeof args[index + 1] === 'string') {
    const value = args[++index];
    if (name === '--case') cases.push(value);
    else if (!options.has(name)) options.set(name, value);
    else fail(`duplicate option: ${name}`);
  } else fail('invalid review-session arguments');
}
const appDir = options.get('--app-dir');
const port = Number(options.get('--port'));
const sessionPort = Number(options.get('--session-port'));
if (typeof appDir !== 'string' || !cases.length
  || ![port, sessionPort].every(value => Number.isInteger(value) && value > 0 && value <= 65535)
  || port === sessionPort) fail('invalid review-session configuration');

const token = randomBytes(32).toString('hex');
const origin = `http://127.0.0.1:${port}`;
const url = `${origin}/?session_port=${sessionPort}&session_token=${token}`;
const loader = spawn(process.execPath, [
  fileURLToPath(new URL('./review-session-server.mjs', import.meta.url)),
  '--port', String(sessionPort), '--origin', origin, '--token', token, ...cases,
], { stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
let runtime;
let loaderClosed = false;
let runtimeClosed = false;
let started = false;
let stopping = false;
let exitCode = 1;
let forceTimer;
let cleanupTimer;
let cleanupDeadline;
let browserTimer;

function signalRuntime(signal) {
  if (!runtime || !Number.isInteger(runtime.pid)) return;
  try {
    // npm starts descendants; terminate the owned runtime group on POSIX hosts.
    if (process.platform !== 'win32') process.kill(-runtime.pid, signal);
    else runtime.kill(signal);
  } catch { /* The runtime may already have exited. */ }
}
function runtimeGroupAlive() {
  if (!runtime || !Number.isInteger(runtime.pid)) return false;
  if (process.platform === 'win32') return !runtimeClosed;
  try {
    process.kill(-runtime.pid, 0);
    return true;
  } catch (error) {
    return error.code !== 'ESRCH';
  }
}
function finish() {
  if (stopping && loaderClosed && (!runtime || runtimeClosed) && !runtimeGroupAlive()) {
    clearTimeout(forceTimer);
    clearTimeout(cleanupDeadline);
    clearInterval(cleanupTimer);
    process.exit(exitCode);
  }
}
function stop(code) {
  if (stopping) return;
  stopping = true;
  exitCode = code;
  clearTimeout(readyTimer);
  clearTimeout(browserTimer);
  signalRuntime('SIGTERM');
  if (!loaderClosed) loader.kill('SIGTERM');
  forceTimer = setTimeout(() => {
    signalRuntime('SIGKILL');
    if (!loaderClosed) loader.kill('SIGKILL');
  }, 2000);
  cleanupTimer = setInterval(finish, 50);
  cleanupDeadline = setTimeout(() => {
    process.stderr.write('secureflow: owned runtime cleanup could not be confirmed after termination\n');
    process.exit(exitCode || 1);
  }, 4000);
  finish();
}
const readyTimer = setTimeout(() => {
  process.stderr.write('secureflow: case loader did not become ready within 10 seconds\n');
  stop(1);
}, 10_000);

loader.on('error', error => {
  process.stderr.write(`secureflow: cannot start case loader: ${error.message}\n`);
  stop(1);
});
loader.on('close', code => {
  loaderClosed = true;
  if (!stopping) {
    process.stderr.write('secureflow: case loader stopped; Review Room session is unavailable\n');
    stop(code || 1);
  }
  finish();
});
loader.on('message', message => {
  if (stopping || started || message?.type !== 'secureflow-review-session-ready') return;
  started = true;
  clearTimeout(readyTimer);
  runtime = spawn('npm', ['start', '--', '--local', '--ip', '127.0.0.1', '--port', String(port)], {
    cwd: appDir, stdio: 'inherit', detached: process.platform !== 'win32',
    env: { ...process.env, WRANGLER_SEND_METRICS: 'false' },
  });
  runtime.on('error', error => {
    process.stderr.write(`secureflow: cannot start Review Room: ${error.message}\n`);
    stop(1);
  });
  runtime.on('close', code => {
    runtimeClosed = true;
    stop(code ?? 1);
    finish();
  });
  runtime.on('spawn', () => {
    if (stopping) return;
    process.stderr.write(`SecureFlow Review Room: ${url}\n`);
    if (options.has('--system-browser')) {
      browserTimer = setTimeout(() => {
        function open(command, fallback) {
          const child = spawn(command, [url], { stdio: 'ignore' });
          child.on('error', () => {
            if (fallback) open(fallback);
            else process.stderr.write('secureflow: open the printed URL in your browser\n');
          });
          child.unref();
        }
        open('xdg-open', 'open');
      }, 2000);
    }
  });
});
for (const [signal, code] of [['SIGINT', 130], ['SIGTERM', 143]]) {
  process.on(signal, () => stop(code));
}
