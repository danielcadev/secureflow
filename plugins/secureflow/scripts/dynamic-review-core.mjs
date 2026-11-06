import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { validateApprovedTarget, requestApprovedHttps } from './approved-https-transport.mjs';

const HASH = /^[a-f0-9]{64}$/;
const ID = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const PLAN_LIMIT = 64 * 1024;
const error = (code) => Object.assign(new Error(code), { code });
const reject = (code) => { throw error(code); };
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const object = (value, keys) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) reject('invalid_plan');
};
const integer = (value, min, max) => { if (!Number.isInteger(value) || value < min || value > max) reject('invalid_plan'); };
const text = (value, max) => { if (typeof value !== 'string' || !value.length || value.length > max || /[\x00-\x1f\x7f]/.test(value)) reject('invalid_plan'); };
const route = (value) => {
  if (typeof value !== 'string' || value.length > 1024 || !/^\/[A-Za-z0-9/_-]*$/.test(value) || value.includes('//')) reject('invalid_plan');
};
const timestamp = (value) => {
  const match = typeof value === 'string' && /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match) reject('invalid_plan');
  const [, year, month, day, hour, minute, second, zone] = match;
  const days = new Date(Date.UTC(Number(year), Number(month), 0)).getUTCDate();
  if (+year < 1970 || +month < 1 || +month > 12 || +day < 1 || +day > days || +hour > 23 || +minute > 59 || +second > 59
      || (zone !== 'Z' && (+zone.slice(1, 3) > 23 || +zone.slice(4, 6) > 59))) reject('invalid_plan');
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) reject('invalid_plan');
  return parsed;
};

function validate(plan, bytes) {
  object(plan, ['contract_version', 'authorization', 'target', 'budgets', 'principals', 'actions', 'output_directory']);
  const remote = plan.contract_version === 'secureflow-dynamic-plan-v2';
  if (!remote && plan.contract_version !== 'secureflow-dynamic-plan-v1') reject('invalid_plan');
  const grantKey = remote ? 'authorized_remote_service' : 'owned_local_service';
  object(plan.authorization, ['operator', 'reference', 'issued_at', 'expires_at', grantKey]);
  text(plan.authorization.operator, 512);
  text(plan.authorization.reference, 512);
  if (plan.authorization[grantKey] !== true) reject('invalid_plan');
  const issued = timestamp(plan.authorization.issued_at);
  const expires = timestamp(plan.authorization.expires_at);
  if (issued > Date.now() || expires <= Date.now() || expires <= issued || expires - issued > 86400000) reject('invalid_authorization');
  if (remote) validateApprovedTarget(plan.target);
  else {
  object(plan.target, ['host', 'port', 'identity_path', 'identity_sha256']);
  if (plan.target.host !== '127.0.0.1') reject('invalid_plan');
  integer(plan.target.port, 1024, 65535);
  route(plan.target.identity_path);
  if (typeof plan.target.identity_sha256 !== 'string' || !HASH.test(plan.target.identity_sha256)) reject('invalid_plan');
  }
  object(plan.budgets, ['max_requests', 'timeout_ms', 'total_budget_ms', 'max_response_bytes', 'min_interval_ms']);
  integer(plan.budgets.max_requests, remote ? 1 : 2, 64);
  integer(plan.budgets.timeout_ms, 1, 5000);
  integer(plan.budgets.total_budget_ms, 1, 120000);
  integer(plan.budgets.max_response_bytes, 1, 65536);
  integer(plan.budgets.min_interval_ms, 20, 1000);
  if (!Array.isArray(plan.principals) || plan.principals.length < 1 || plan.principals.length > 8) reject('invalid_plan');
  const principals = new Map();
  const credentials = new Map();
  for (const principal of plan.principals) {
    object(principal, ['id', 'token_env']);
    if (typeof principal.id !== 'string' || !ID.test(principal.id) || principals.has(principal.id)) reject('invalid_plan');
    if (principal.token_env !== null && (typeof principal.token_env !== 'string' || !/^SECUREFLOW_DYNAMIC_[A-Z0-9_]+$/.test(principal.token_env))) reject('invalid_plan');
    principals.set(principal.id, principal);
    if (principal.token_env !== null) {
      const value = process.env[principal.token_env];
      if (typeof value !== 'string' || value.length < 1 || value.length > 512 || !/^[A-Za-z0-9._~+/-]+=*$/.test(value)) reject('invalid_credential');
      if (bytes.includes(Buffer.from(value))) reject('credential_in_plan');
      credentials.set(principal.id, value);
    }
  }
  if (!Array.isArray(plan.actions) || plan.actions.length < 1 || plan.actions.length > 32 || plan.budgets.max_requests < plan.actions.length * (remote ? 1 : 2)) reject('invalid_plan');
  const ids = new Set();
  for (const action of plan.actions) {
    object(action, ['id', 'principal_id', 'path', 'expected_status']);
    if (typeof action.id !== 'string' || !ID.test(action.id) || ids.has(action.id) || !principals.has(action.principal_id)) reject('invalid_plan');
    ids.add(action.id);
    route(action.path);
    integer(action.expected_status, 200, 499);
  }
  // JSON escapes must not turn an otherwise harmless-looking plan into a
  // credential disclosure through describe() or the persisted plan bytes.
  const strings = (value) => typeof value === 'string' ? [value]
    : Array.isArray(value) ? value.flatMap(strings)
      : value && typeof value === 'object' ? Object.values(value).flatMap(strings) : [];
  const planStrings = strings(plan);
  for (const credential of credentials.values()) {
    if (planStrings.some((value) => value.includes(credential))) reject('credential_in_plan');
  }
  if (typeof plan.output_directory !== 'string' || !path.isAbsolute(plan.output_directory)
      || path.resolve(plan.output_directory) !== plan.output_directory || plan.output_directory === path.parse(plan.output_directory).root
      || /[\x00-\x1f\x7f]/.test(plan.output_directory)) reject('invalid_output_directory');
  const parent = path.dirname(plan.output_directory);
  let info;
  try { info = fs.lstatSync(parent); } catch { reject('unsafe_output_parent'); }
  if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid() || (info.mode & 0o077) !== 0) reject('unsafe_output_parent');
  return { credentials, expires, parent, parentInfo: info };
}

// Trusted ancestors and other processes running as the same account are outside
// this filesystem boundary. The immediate parent must be private and owned.
export function createDynamicSession(args = {}) {
  const started = performance.now();
  if (!args || typeof args !== 'object' || Array.isArray(args)
      || Object.keys(args).length !== 2 || !Object.hasOwn(args, 'planPath') || !Object.hasOwn(args, 'planSha256')) reject('invalid_startup_arguments');
  const { planPath, planSha256 } = args;
  if (typeof planPath !== 'string' || typeof planSha256 !== 'string' || !HASH.test(planSha256)) reject('invalid_startup_arguments');
  let bytes;
  let fd;
  try {
    // Opening a FIFO must not block before the regular-file check can run.
    fd = fs.openSync(planPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const info = fs.fstatSync(fd);
    if (!info.isFile() || info.size > PLAN_LIMIT) reject('invalid_plan_file');
    const buffer = Buffer.alloc(PLAN_LIMIT + 1);
    let count = 0;
    while (count < buffer.length) {
      const read = fs.readSync(fd, buffer, count, buffer.length - count, null);
      if (read === 0) break;
      count += read;
    }
    bytes = buffer.subarray(0, count);
  } catch (failure) {
    if (failure.code === 'invalid_plan_file') throw failure;
    reject('invalid_plan_file');
  } finally { if (fd !== undefined) fs.closeSync(fd); }
  if (bytes.length > PLAN_LIMIT) reject('invalid_plan_file');
  if (digest(bytes) !== planSha256) reject('plan_hash_mismatch');
  let plan;
  try { plan = JSON.parse(bytes.toString('utf8')); } catch { reject('invalid_plan'); }
  const { credentials, expires, parent, parentInfo } = validate(plan, bytes);
  const remote = plan.contract_version === 'secureflow-dynamic-plan-v2';
  const directory = plan.output_directory;
  let directoryInfo;
  const ensureDirectory = () => {
    const currentParent = fs.lstatSync(parent);
    const current = fs.lstatSync(directory);
    if (!currentParent.isDirectory() || currentParent.isSymbolicLink() || currentParent.ino !== parentInfo.ino || currentParent.dev !== parentInfo.dev
        || currentParent.uid !== process.getuid() || (currentParent.mode & 0o077) !== 0
        || !current.isDirectory() || current.isSymbolicLink() || current.ino !== directoryInfo.ino || current.dev !== directoryInfo.dev
        || current.uid !== process.getuid() || (current.mode & 0o077) !== 0) reject('evidence_directory_changed');
  };
  const syncDirectory = () => {
    const handle = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try { fs.fsyncSync(handle); } finally { fs.closeSync(handle); }
  };
  const writeNew = (name, value) => {
    ensureDirectory();
    const handle = fs.openSync(path.join(directory, name), fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    try { fs.writeFileSync(handle, value); fs.fsyncSync(handle); } finally { fs.closeSync(handle); }
    syncDirectory();
  };
  try {
    fs.mkdirSync(directory, { mode: 0o700 });
    directoryInfo = fs.lstatSync(directory);
    const parentHandle = fs.openSync(parent, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try { fs.fsyncSync(parentHandle); } finally { fs.closeSync(parentHandle); }
    writeNew('plan.json', bytes);
    writeNew('plan.sha256', `${planSha256}\n`);
  } catch (failure) { reject(failure.code === 'EEXIST' ? 'output_exists' : 'evidence_write_failed'); }

  const deadline = started + plan.budgets.total_budget_ms;
  const attempted = new Set();
  const observations = [];
  let requests = 0;
  let lastRequest = -Infinity;
  let state = 'running';
  let failure = null;
  let queue = Promise.resolve();
  const snapshot = () => ({
    contract_version: remote ? 'secureflow-dynamic-result-v2' : 'secureflow-dynamic-result-v1', status: state, plan_sha256: planSha256,
    actions_approved: plan.actions.length, actions_attempted: attempted.size, actions_completed: observations.length,
    requests_used: requests, observations: structuredClone(observations), failure: failure ? { ...failure } : null,
    human_decisions: 0, provider_calls: 0, ai_reasoning: 'external-client-not-measured', final_authority: 'human-only',
  });
  const checkTime = () => {
    if (Date.now() >= expires) reject('authorization_expired');
    if (performance.now() >= deadline) reject('run_budget_exhausted');
  };
  const publish = () => {
    const provisional = path.join(directory, 'result.provisional.json');
    const final = path.join(directory, 'result.json');
    let published = false;
    try {
      // Keep the fully synced source inode under an explicitly nonfinal name.
      // link() publishes atomically and fails rather than replacing a final file.
      writeNew('result.provisional.json', `${JSON.stringify(snapshot(), null, 2)}\n`);
      ensureDirectory();
      fs.linkSync(provisional, final);
      published = true;
      syncDirectory();
    } catch {
      failure = { code: 'evidence_write_failed', action_id: failure?.action_id ?? null };
      state = 'failed';
      if (published) {
        // Best effort only: preserve the inode under nonfinal names before
        // removing its final name. Arbitrary filesystem failures can also
        // prevent this quarantine or its directory synchronization.
        try {
          ensureDirectory();
          fs.linkSync(final, path.join(directory, 'result.unpublished.json'));
          fs.unlinkSync(final);
          syncDirectory();
        } catch { /* The run stays failed even if quarantine is unavailable. */ }
      }
      reject('evidence_write_failed');
    }
  };
  const serial = (operation) => {
    const next = queue.then(operation);
    queue = next.catch(() => {});
    return next;
  };
  const request = async (action, phase) => {
    checkTime();
    const pause = lastRequest + plan.budgets.min_interval_ms - performance.now();
    if (pause > 0) {
      const remaining = Math.min(deadline - performance.now(), expires - Date.now());
      if (pause >= remaining) reject(expires - Date.now() <= remaining ? 'authorization_expired' : 'run_budget_exhausted');
      await new Promise((resolve) => setTimeout(resolve, pause));
    }
    checkTime();
    if (requests >= plan.budgets.max_requests) reject('request_budget_exhausted');
    const number = ++requests;
    const pathname = phase === 'identity' ? plan.target.identity_path : action.path;
    const base = { request_number: number, action_id: action.id, phase, principal_id: phase === 'identity' ? null : action.principal_id, path: pathname };
    writeNew(`request-${String(number).padStart(3, '0')}-reservation.json`, `${JSON.stringify(base)}\n`);
    checkTime();
    lastRequest = performance.now();
    let receipt;
    try {
      if (remote) {
        const remaining = Math.min(plan.budgets.timeout_ms, deadline - performance.now(), expires - Date.now());
        const timeoutCode = remaining < plan.budgets.timeout_ms
          ? (expires - Date.now() <= deadline - performance.now() ? 'authorization_expired' : 'run_budget_exhausted') : 'request_timeout';
        receipt = await requestApprovedHttps({ target: plan.target, path: pathname, token: credentials.get(action.principal_id) ?? null,
          maxResponseBytes: plan.budgets.max_response_bytes, timeoutMs: remaining, timeoutCode });
        checkTime();
      } else receipt = await new Promise((resolve, rejectRequest) => {
        let settled = false;
        let response;
        let size = 0;
        const hash = createHash('sha256');
        const remaining = Math.min(plan.budgets.timeout_ms, deadline - performance.now(), expires - Date.now());
        const timeoutCode = remaining < plan.budgets.timeout_ms
          ? (expires - Date.now() <= deadline - performance.now() ? 'authorization_expired' : 'run_budget_exhausted') : 'request_timeout';
        let timer;
        const settle = (cause, result) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          if (cause) { response?.destroy(); req.destroy(); rejectRequest(error(cause)); }
          else resolve(result);
        };
        const headers = { Accept: '*/*', Connection: 'close' };
        if (phase === 'action' && credentials.has(action.principal_id)) headers.Authorization = `Bearer ${credentials.get(action.principal_id)}`;
        const agent = new http.Agent({ keepAlive: false });
        agent.createConnection = () => net.createConnection({ host: '127.0.0.1', port: plan.target.port, family: 4 });
        const req = http.request({
          host: '127.0.0.1', port: plan.target.port, method: 'GET', path: pathname, headers, agent,
          maxHeaderSize: 16384,
        }, (res) => {
          response = res;
          if (res.statusCode >= 300 && res.statusCode < 400) { settle('redirect_refused'); return; }
          res.on('data', (chunk) => {
            if (settled) return;
            size += chunk.length;
            if (size > plan.budgets.max_response_bytes) { settle('response_too_large'); return; }
            hash.update(chunk);
          });
          res.on('aborted', () => settle('transport_failed'));
          res.on('error', () => settle('transport_failed'));
          res.on('end', () => {
            if (settled) return;
            try { checkTime(); } catch (cause) { settle(cause.code); return; }
            settle(null, { status_code: res.statusCode, body_bytes: size, body_sha256: hash.digest('hex') });
          });
        });
        req.on('error', () => settle('transport_failed'));
        timer = setTimeout(() => settle(timeoutCode), Math.max(1, remaining));
        req.end();
      });
      writeNew(`request-${String(number).padStart(3, '0')}-receipt.json`, `${JSON.stringify({ ...base, ...receipt, error_code: null })}\n`);
      return receipt;
    } catch (cause) {
      const code = ['authorization_expired', 'run_budget_exhausted', 'request_timeout', 'redirect_refused', 'response_too_large', 'transport_failed', ...(remote ? ['dns_resolution_failed', 'dns_scope_mismatch'] : [])].includes(cause.code) ? cause.code : 'evidence_write_failed';
      try { writeNew(`request-${String(number).padStart(3, '0')}-receipt.json`, `${JSON.stringify({ ...base, status_code: null, body_bytes: null, body_sha256: null, error_code: code })}\n`); } catch { reject('evidence_write_failed'); }
      reject(code);
    }
  };
  const execute = (actionId) => serial(async () => {
    if (typeof actionId !== 'string' || !plan.actions.some((action) => action.id === actionId)) reject('unknown_action');
    if (state !== 'running') reject('run_closed');
    if (attempted.has(actionId)) reject('action_already_attempted');
    const action = plan.actions.find((candidate) => candidate.id === actionId);
    try {
      checkTime();
      writeNew(`action-${String(attempted.size + 1).padStart(3, '0')}.json`, `${JSON.stringify({ action_id: actionId, principal_id: action.principal_id })}\n`);
      attempted.add(actionId);
      if (!remote) {
        const identity = await request(action, 'identity');
        if (identity.status_code !== 200 || identity.body_sha256 !== plan.target.identity_sha256) reject('identity_mismatch');
      }
      const actual = await request(action, 'action');
      const observation = { action_id: actionId, principal_id: action.principal_id, path: action.path, ...actual,
        expected_status: action.expected_status, outcome: actual.status_code >= 500 ? 'inconclusive' : actual.status_code === action.expected_status ? 'status-matched' : 'status-mismatched' };
      writeNew(`observation-${String(observations.length + 1).padStart(3, '0')}.json`, `${JSON.stringify(observation)}\n`);
      observations.push(observation);
      return structuredClone(observation);
    } catch (cause) {
      const allowed = ['authorization_expired', 'run_budget_exhausted', 'request_budget_exhausted', 'identity_mismatch', 'request_timeout', 'redirect_refused', 'response_too_large', 'transport_failed'];
      if (remote) allowed.push('dns_resolution_failed', 'dns_scope_mismatch');
      failure = { code: allowed.includes(cause.code) ? cause.code : 'evidence_write_failed', action_id: actionId };
      state = 'failed';
      publish();
      reject(failure.code);
    }
  });
  const finish = () => serial(async () => {
    if (state !== 'running') return snapshot();
    try { checkTime(); }
    catch (cause) { state = 'failed'; failure = { code: cause.code, action_id: null }; }
    if (state === 'running') state = observations.length === plan.actions.length ? 'completed' : 'incomplete';
    publish();
    return snapshot();
  });
  return Object.freeze({ describe: () => ({ plan: structuredClone(plan), plan_sha256: planSha256 }), execute, status: snapshot, finish });
}
