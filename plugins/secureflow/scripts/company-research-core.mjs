import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

// This module performs local intake only. References and hashes are declarations
// supplied by the external host, never proof of ownership or permission to test.
const VERSION = 'secureflow-company-';
const HASH = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const ID = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const ASSET_ID = /^sf_asset_[a-f0-9]{64}$/;
const LIMITS = Object.freeze({ max_batches: 64, max_sources: 128, max_assets: 512, max_batch_bytes: 65536 });
const CAPABILITIES = Object.freeze({ discovery: 'external-host-evidence-import', active_testing: 'disabled', repo_analysis: 'requires-separate-authorization', human_decisions: 'human-only' });
const SOURCE_KINDS = ['official-site', 'scope-policy', 'github-metadata', 'certificate-transparency', 'dns-record', 'agent-search'];
const RELATION_KINDS = ['references', 'deployed-on', 'contains', 'candidate-subdomain'];
const ASSET_KINDS = ['domain', 'origin', 'repository', 'endpoint'];
const NEXT = 'approve-exact-scope-and-qualified-executor';
const fail = (code) => { throw Object.assign(new Error(code), { code }); };
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const encode = (value) => Buffer.from(`${JSON.stringify(value)}\n`);
const copy = (value) => structuredClone(value);
const sort = (values) => [...new Set(values)].sort();
const exact = (value, keys, code = 'invalid_discovery') => {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Object.keys(value).length !== keys.length
      || keys.some((key) => !Object.hasOwn(value, key) || !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'))) fail(code);
};
const plain = (value, max, code = 'invalid_discovery') => {
  if (typeof value !== 'string' || !value.length || value.length > max || /[\x00-\x1f\x7f<>]/.test(value)) fail(code);
  return value;
};
const array = (value, min, max) => { if (!Array.isArray(value) || value.length < min || value.length > max) fail('invalid_discovery'); };
const ipv4 = (value) => /^\d+\.\d+\.\d+\.\d+$/.test(value);
function domain(value) {
  plain(value, 253);
  const result = value.toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(result) || !result.includes('.') || result.endsWith('.') || ipv4(result)
      || result === 'localhost' || result.endsWith('.localhost')
      || result.split('.').some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) fail('invalid_discovery');
  return result;
}
function url(value, rootOnly = false) {
  plain(value, 2048);
  if (/[\s\\]/.test(value)) fail('invalid_discovery');
  const raw = /^(https?):\/\/([^/?#]+)(\/[^?#]*)?$/i.exec(value);
  if (!raw || /[@%]/.test(raw[2])) fail('invalid_discovery');
  let parsed;
  try { parsed = new URL(value); } catch { fail('invalid_discovery'); }
  if (parsed.username || parsed.password || parsed.search || parsed.hash || !parsed.hostname) fail('invalid_discovery');
  // Reject alternative IPv4 notation (WHATWG otherwise silently rewrites it).
  const rawHost = raw[2].startsWith('[') ? raw[2].slice(0, raw[2].indexOf(']') + 1) : raw[2].split(':')[0];
  if (rawHost.toLowerCase() !== parsed.hostname.toLowerCase()) fail('invalid_discovery');
  if (parsed.hostname.startsWith('[')) {
    if (!/^\[[a-f0-9:]+\]$/i.test(parsed.hostname)) fail('invalid_discovery');
  } else if (ipv4(parsed.hostname)) {
    if (parsed.hostname.split('.').some((part) => !/^(0|[1-9]\d{0,2})$/.test(part) || +part > 255)) fail('invalid_discovery');
  } else domain(parsed.hostname);
  if (parsed.protocol === 'http:' && (rawHost !== '127.0.0.1' || !parsed.port || +parsed.port < 1024)) fail('invalid_discovery');
  if (rootOnly && (parsed.pathname !== '/' || (raw[3] && raw[3] !== '/'))) fail('invalid_discovery');
  // URL credentials, query/fragment delimiters, and escaped controls cannot be
  // smuggled into a stored path. Ordinary percent-encoded path data is retained.
  if (/%(?:0[0-9a-f]|1[0-9a-f]|7f)/i.test(parsed.pathname)) fail('invalid_discovery');
  if (parsed.href.length > 2048) fail('invalid_discovery');
  return parsed.href;
}
function assetValue(kind, value) {
  if (kind === 'domain') return domain(value);
  if (kind === 'origin') return url(value, true);
  if (kind === 'endpoint') return url(value);
  if (kind !== 'repository') fail('invalid_discovery');
  plain(value, 2048);
  const repositoryPath = /^\/[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9_.-]{1,100}$/;
  const rawPath = /^https?:\/\/[^/?#]+(\/[^?#]*)?$/i.exec(value)?.[1];
  // Repository identity requires exactly two raw segments. URL normalization
  // must not turn literal or escaped traversal into an accepted repository.
  if (!rawPath || !repositoryPath.test(rawPath)) fail('invalid_discovery');
  const result = url(value);
  const parsed = new URL(result);
  if (parsed.protocol !== 'https:' || parsed.host !== 'github.com'
      || !repositoryPath.test(parsed.pathname)
      || /(?:\.git|\.)$/i.test(parsed.pathname) || parsed.pathname.endsWith('/..')) fail('invalid_discovery');
  return result.toLowerCase();
}
const assetId = (kind, value) => `sf_asset_${sha(`${kind}\n${value}`)}`;
function seedValue(seed) {
  exact(seed, ['kind', 'value'], 'invalid_seed');
  try {
    if (seed.kind === 'company') return { kind: seed.kind, value: plain(seed.value, 128).trim().replace(/ +/g, ' ') || fail('invalid_seed') };
    if (seed.kind === 'url') return { kind: seed.kind, value: url(seed.value) };
    if (seed.kind === 'github-org' && typeof seed.value === 'string'
        && /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(seed.value)) return { kind: seed.kind, value: seed.value.toLowerCase() };
  } catch { fail('invalid_seed'); }
  fail('invalid_seed');
}
function requestValue(request) {
  exact(request, ['contract_version', 'workspace_id', 'seed', 'created_at', 'capabilities', 'limits'], 'corrupt_workspace');
  if (request.contract_version !== `${VERSION}request-v1` || !UUID.test(request.workspace_id)
      || typeof request.created_at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(request.created_at)
      || !Number.isFinite(Date.parse(request.created_at)) || new Date(request.created_at).toISOString() !== request.created_at) fail('corrupt_workspace');
  const canonicalSeed = seedValue(request.seed);
  exact(request.capabilities, Object.keys(CAPABILITIES), 'corrupt_workspace');
  exact(request.limits, Object.keys(LIMITS), 'corrupt_workspace');
  if (JSON.stringify(request.seed) !== JSON.stringify(canonicalSeed)
      || Object.entries(CAPABILITIES).some(([key, value]) => request.capabilities[key] !== value)
      || Object.entries(LIMITS).some(([key, value]) => request.limits[key] !== value)) fail('corrupt_workspace');
  return { contract_version: `${VERSION}request-v1`, workspace_id: request.workspace_id, seed: canonicalSeed,
    created_at: request.created_at, capabilities: { ...CAPABILITIES }, limits: { ...LIMITS } };
}
function normalizeBundle(bundle) {
  exact(bundle, ['contract_version', 'sources', 'assets']);
  if (bundle.contract_version !== `${VERSION}discovery-v1`) fail('invalid_discovery');
  array(bundle.sources, 1, 32); array(bundle.assets, 0, 100);
  const sourceIds = new Set();
  const sources = bundle.sources.map((source) => {
    exact(source, ['id', 'kind', 'reference_url', 'content_sha256']);
    if (typeof source.id !== 'string' || !ID.test(source.id) || sourceIds.has(source.id)
        || !SOURCE_KINDS.includes(source.kind) || typeof source.content_sha256 !== 'string' || !HASH.test(source.content_sha256)) fail('invalid_discovery');
    sourceIds.add(source.id);
    return { id: source.id, kind: source.kind, reference_url: url(source.reference_url), content_sha256: source.content_sha256 };
  }).sort((a, b) => a.id.localeCompare(b.id, 'en'));
  const assets = bundle.assets.map((asset) => {
    exact(asset, ['kind', 'value', 'source_ids', 'relations', 'limitations']);
    if (!ASSET_KINDS.includes(asset.kind)) fail('invalid_discovery');
    array(asset.source_ids, 1, 128); array(asset.relations, 0, 20); array(asset.limitations, 0, 20);
    if (asset.source_ids.some((id) => typeof id !== 'string' || !ID.test(id))) fail('invalid_discovery');
    const relations = asset.relations.map((relation) => {
      exact(relation, ['kind', 'target_id']);
      if (!RELATION_KINDS.includes(relation.kind) || typeof relation.target_id !== 'string' || !ASSET_ID.test(relation.target_id)) fail('invalid_discovery');
      return { kind: relation.kind, target_id: relation.target_id };
    });
    return { kind: asset.kind, value: assetValue(asset.kind, asset.value), source_ids: sort(asset.source_ids),
      relations: uniqueRelations(relations), limitations: sort(asset.limitations.map((limit) => plain(limit, 256))) };
  }).sort((a, b) => assetId(a.kind, a.value).localeCompare(assetId(b.kind, b.value), 'en'));
  const normalized = { contract_version: `${VERSION}discovery-v1`, sources, assets };
  if (encode(normalized).length > LIMITS.max_batch_bytes) fail('capacity_exceeded');
  return normalized;
}
function uniqueRelations(relations) {
  return [...new Map(relations.map((relation) => [`${relation.kind}\n${relation.target_id}`, relation])).values()]
    .sort((a, b) => `${a.kind}\n${a.target_id}`.localeCompare(`${b.kind}\n${b.target_id}`, 'en'));
}
function applyBundle(state, bundle) {
  const sources = new Map(state.sources); const assets = new Map([...state.assets].map(([id, asset]) => [id, copy(asset)]));
  for (const source of bundle.sources) {
    const previous = sources.get(source.id);
    if (previous && JSON.stringify(previous) !== JSON.stringify(source)) fail('source_conflict');
    sources.set(source.id, source);
  }
  for (const candidate of bundle.assets) {
    if (candidate.source_ids.some((id) => !sources.has(id))) fail('unknown_source');
    const id = assetId(candidate.kind, candidate.value);
    const previous = assets.get(id);
    assets.set(id, { id, kind: candidate.kind, value: candidate.value,
      source_ids: sort([...(previous?.source_ids ?? []), ...candidate.source_ids]),
      relations: uniqueRelations([...(previous?.relations ?? []), ...candidate.relations]),
      limitations: sort([...(previous?.limitations ?? []), ...candidate.limitations]),
      ownership: 'unverified', scope_status: 'unapproved', execution_allowed: false });
  }
  for (const asset of assets.values()) {
    if (asset.source_ids.length > 128 || asset.relations.length > 512 || asset.limitations.length > 128) fail('capacity_exceeded');
    for (const relation of asset.relations) {
      const target = assets.get(relation.target_id);
      if (!target) fail('unknown_asset');
      if (relation.kind === 'candidate-subdomain' && (asset.kind !== 'domain' || target.kind !== 'domain'
          || asset.value === target.value || !asset.value.endsWith(`.${target.value}`))) fail('invalid_relation');
    }
  }
  if (sources.size > LIMITS.max_sources || assets.size > LIMITS.max_assets || state.batch_count >= LIMITS.max_batches) fail('capacity_exceeded');
  return { sources, assets, batch_count: state.batch_count + 1, last_hash: state.last_hash };
}
const coverage = (state) => ({ discovery: 'external-host-evidence-only', asset_count: state.assets.size, source_count: state.sources.size,
  batch_count: state.batch_count, active_tests: 0, repo_scans: 0, vulnerabilities_validated: 0, human_decisions: 0,
  broker_provider_calls: 0, host_model_usage: 'not-measured' });
const inventory = (request, requestHash, state) => ({ contract_version: `${VERSION}inventory-v1`, workspace_id: request.workspace_id,
  request_sha256: requestHash, seed: copy(request.seed), sources: [...state.sources.values()].sort((a, b) => a.id.localeCompare(b.id, 'en')).map(copy),
  assets: [...state.assets.values()].sort((a, b) => a.id.localeCompare(b.id, 'en')).map(copy), coverage: coverage(state), next_step: NEXT });
function privateDirectory(directory, code) {
  try {
    const info = fs.lstatSync(directory);
    if (!info.isDirectory() || info.isSymbolicLink() || typeof process.getuid !== 'function'
        || info.uid !== process.getuid() || (info.mode & 0o777) !== 0o700) fail(code);
    return info;
  } catch { fail(code); }
}
function rootValue(root) {
  if (typeof root !== 'string' || !path.isAbsolute(root) || path.resolve(root) !== root || root === path.parse(root).root) fail('invalid_workspace_root');
  return privateDirectory(root, 'invalid_workspace_root');
}
function storage(root, id, rootInfo) {
  const directory = path.join(root, id);
  const directoryInfo = privateDirectory(directory, 'corrupt_workspace');
  const ensure = () => {
    const parent = privateDirectory(root, 'workspace_changed'); const current = privateDirectory(directory, 'workspace_changed');
    if (parent.ino !== rootInfo.ino || parent.dev !== rootInfo.dev || current.ino !== directoryInfo.ino || current.dev !== directoryInfo.dev) fail('workspace_changed');
  };
  const sync = (dir = directory) => {
    ensure();
    const fd = fs.openSync(dir, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  };
  const read = (name, max) => {
    ensure(); let fd;
    try {
      fd = fs.openSync(path.join(directory, name), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
      const info = fs.fstatSync(fd);
      if (!info.isFile() || info.uid !== process.getuid() || (info.mode & 0o777) !== 0o600 || info.size > max) fail('corrupt_workspace');
      const buffer = Buffer.alloc(max + 1); let count = 0;
      while (count < buffer.length) { const n = fs.readSync(fd, buffer, count, buffer.length - count, null); if (!n) break; count += n; }
      if (count > max) fail('corrupt_workspace');
      return buffer.subarray(0, count);
    } catch { fail('corrupt_workspace'); } finally { if (fd !== undefined) fs.closeSync(fd); }
  };
  const write = (name, bytes) => {
    ensure(); let fd;
    try {
      fd = fs.openSync(path.join(directory, name), fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
      fs.writeFileSync(fd, bytes); fs.fsyncSync(fd);
    } finally { if (fd !== undefined) fs.closeSync(fd); }
    sync();
  };
  const publish = (stem, bytes) => {
    const provisional = `${stem}.provisional.json`; const final = `${stem}.json`; let linked = false;
    try {
      write(provisional, bytes); ensure();
      fs.linkSync(path.join(directory, provisional), path.join(directory, final)); linked = true; sync();
    } catch {
      if (linked) {
        try { ensure(); fs.linkSync(path.join(directory, final), path.join(directory, `${stem}.unpublished.json`)); fs.unlinkSync(path.join(directory, final)); sync(); } catch { /* best effort quarantine; never report success */ }
      }
      fail('evidence_write_failed');
    }
    return path.join(directory, final);
  };
  return { directory, ensure, sync, read, write, publish };
}
function parse(bytes) { try { return JSON.parse(bytes.toString('utf8')); } catch { fail('corrupt_workspace'); } }
function load(store, expectedId, expectedHash = null) {
  store.ensure();
  let names;
  try { names = fs.readdirSync(store.directory).sort(); } catch { fail('corrupt_workspace'); }
  if (names.length > 390 || names.some((name) => !/^(?:request\.(?:json|sha256)|batch-\d{3}(?:\.provisional|\.unpublished)?\.json|inventory-\d{3}(?:\.provisional|\.unpublished)?\.json)$/.test(name))) fail('corrupt_workspace');
  const requestBytes = store.read('request.json', 4096); const request = requestValue(parse(requestBytes)); const requestHash = sha(requestBytes);
  if (!requestBytes.equals(encode(request)) || request.workspace_id !== expectedId
      || store.read('request.sha256', 65).toString('utf8') !== `${requestHash}\n` || (expectedHash && requestHash !== expectedHash)) fail('corrupt_workspace');
  let state = { sources: new Map(), assets: new Map(), batch_count: 0, last_hash: null };
  // Historical exports need integrity checks, not retained copies of every
  // historical graph. Keep only the digest for each bounded journal prefix.
  const inventoryHashes = new Map([[0, sha(encode(inventory(request, requestHash, state)))]]); let totalBytes = 0;
  const batchNames = names.filter((name) => /^batch-\d{3}\.json$/.test(name));
  if (batchNames.length > LIMITS.max_batches) fail('corrupt_workspace');
  for (let i = 0; i < batchNames.length; i++) {
    const stem = `batch-${String(i + 1).padStart(3, '0')}`;
    if (batchNames[i] !== `${stem}.json`) fail('corrupt_workspace');
    const bytes = store.read(batchNames[i], LIMITS.max_batch_bytes); totalBytes += bytes.length;
    const entry = parse(bytes);
    exact(entry, ['contract_version', 'workspace_id', 'request_sha256', 'batch_number', 'previous_batch_sha256', 'recorded_at', 'bundle'], 'corrupt_workspace');
    if (entry.contract_version !== `${VERSION}batch-v1` || entry.workspace_id !== expectedId || entry.request_sha256 !== requestHash
        || entry.batch_number !== i + 1 || entry.previous_batch_sha256 !== state.last_hash
        || typeof entry.recorded_at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(entry.recorded_at)
        || !Number.isFinite(Date.parse(entry.recorded_at)) || new Date(entry.recorded_at).toISOString() !== entry.recorded_at) fail('corrupt_workspace');
    let normalized;
    try { normalized = normalizeBundle(entry.bundle); state = applyBundle(state, normalized); } catch { fail('corrupt_workspace'); }
    if (JSON.stringify(entry.bundle) !== JSON.stringify(normalized) || !bytes.equals(encode(entry))) fail('corrupt_workspace');
    state.last_hash = sha(bytes);
    const inventoryBytes = encode(inventory(request, requestHash, state));
    if (inventoryBytes.length > 4 * 1024 * 1024) fail('corrupt_workspace');
    inventoryHashes.set(state.batch_count, sha(inventoryBytes));
    if (names.includes(`${stem}.provisional.json`) && !store.read(`${stem}.provisional.json`, LIMITS.max_batch_bytes).equals(bytes)) fail('corrupt_workspace');
  }
  if (totalBytes > LIMITS.max_batches * LIMITS.max_batch_bytes) fail('corrupt_workspace');
  // An unfinished journal append cannot be resumed or skipped. It never grants
  // authority, and a caller must create a fresh workspace after a failed append.
  if (names.some((name) => /^batch-\d{3}\.(?:provisional|unpublished)\.json$/.test(name)
      && !names.includes(name.replace(/\.(?:provisional|unpublished)/, '')))) fail('corrupt_workspace');
  if (names.some((name) => /^batch-\d{3}\.unpublished\.json$/.test(name))) fail('corrupt_workspace');
  const exportNumbers = new Set();
  for (const name of names.filter((item) => /^inventory-/.test(item))) {
    const number = Number(name.slice(10, 13));
    if (number < 1 || number > 64) fail('corrupt_workspace');
    exportNumbers.add(number);
    const bytes = store.read(name, 4 * 1024 * 1024); const value = parse(bytes);
    const count = value?.coverage?.batch_count;
    if (!Number.isInteger(count) || count < 0 || count > state.batch_count
        || sha(bytes) !== inventoryHashes.get(count)) fail('corrupt_workspace');
    const finalName = `inventory-${String(number).padStart(3, '0')}.json`;
    if (name !== finalName && names.includes(finalName) && !store.read(finalName, 4 * 1024 * 1024).equals(bytes)) fail('corrupt_workspace');
  }
  return { request, requestHash, state, exportNumbers };
}
function session(store, id, initial) {
  const expectedHash = initial.requestHash;
  const current = () => load(store, id, expectedHash);
  const summarize = ({ request, state }) => ({ workspace_id: id, seed: copy(request.seed),
    identity_status: request.seed.kind === 'company' ? 'company-identity-unresolved' : 'seed-only-unverified',
    ownership: 'unverified', scope_status: 'unapproved', executor_mode: 'unavailable', coverage: coverage(state), next_step: NEXT });
  return Object.freeze({
    id,
    describe() { const value = current(); return { request: copy(value.request), request_sha256: value.requestHash, workspace_path: store.directory, executor_mode: 'unavailable' }; },
    summary() { return summarize(current()); },
    registerDiscovery(bundle) {
      const normalized = normalizeBundle(bundle); const value = current(); const next = applyBundle(value.state, normalized);
      const entry = { contract_version: `${VERSION}batch-v1`, workspace_id: id, request_sha256: expectedHash,
        batch_number: next.batch_count, previous_batch_sha256: value.state.last_hash, recorded_at: new Date().toISOString(), bundle: normalized };
      const bytes = encode(entry);
      if (bytes.length > LIMITS.max_batch_bytes || encode(inventory(value.request, expectedHash, next)).length > 4 * 1024 * 1024) fail('capacity_exceeded');
      store.publish(`batch-${String(next.batch_count).padStart(3, '0')}`, bytes);
      return { ...summarize({ request: value.request, state: next }), batch_sha256: sha(bytes) };
    },
    listAssets(args) {
      exact(args, ['kind', 'query', 'offset', 'limit'], 'invalid_query');
      if ((args.kind !== null && !ASSET_KINDS.includes(args.kind)) || typeof args.query !== 'string' || args.query.length > 128
          || /[\x00-\x1f\x7f]/.test(args.query) || !Number.isInteger(args.offset) || args.offset < 0 || args.offset > 512
          || !Number.isInteger(args.limit) || args.limit < 1 || args.limit > 20) fail('invalid_query');
      const { state } = current(); const query = args.query.toLowerCase();
      const matching = [...state.assets.values()].filter((asset) => (!args.kind || asset.kind === args.kind) && asset.value.toLowerCase().includes(query))
        .sort((a, b) => a.id.localeCompare(b.id, 'en'));
      // Detailed arrays are available through bounded inspect, never pagination.
      const assets = matching.slice(args.offset, args.offset + args.limit).map((asset) => ({ id: asset.id, kind: asset.kind, value: asset.value,
        source_count: asset.source_ids.length, relation_count: asset.relations.length, limitations_count: asset.limitations.length,
        ownership: asset.ownership, scope_status: asset.scope_status, execution_allowed: asset.execution_allowed }));
      return { workspace_id: id, total: matching.length, offset: args.offset, limit: args.limit, assets };
    },
    inspectAsset(idValue) {
      if (typeof idValue !== 'string' || !ASSET_ID.test(idValue)) fail('invalid_asset_id');
      const { state } = current(); const asset = state.assets.get(idValue); if (!asset) fail('asset_not_found');
      return { workspace_id: id, asset: { id: asset.id, kind: asset.kind, value: asset.value, ownership: 'unverified', scope_status: 'unapproved', execution_allowed: false },
        sources: asset.source_ids.slice(0, 20).map((sourceId) => copy(state.sources.get(sourceId))), source_count: asset.source_ids.length,
        relations: asset.relations.slice(0, 20).map(copy), relation_count: asset.relations.length,
        limitations: asset.limitations.slice(0, 20), limitations_count: asset.limitations.length };
    },
    exportPlan() {
      const value = current(); const number = Math.max(0, ...value.exportNumbers) + 1;
      if (number > 64) fail('capacity_exceeded');
      const result = inventory(value.request, value.requestHash, value.state); const bytes = encode(result);
      if (bytes.length > 4 * 1024 * 1024) fail('capacity_exceeded');
      const outputPath = store.publish(`inventory-${String(number).padStart(3, '0')}`, bytes);
      return { inventory: result, inventory_path: outputPath, inventory_sha256: sha(bytes) };
    },
  });
}
export function createCompanyResearch(args) {
  exact(args, ['workspaceRoot', 'seed'], 'invalid_startup_arguments');
  const seed = seedValue(args.seed); const rootInfo = rootValue(args.workspaceRoot); const id = randomUUID();
  const request = { contract_version: `${VERSION}request-v1`, workspace_id: id, seed, created_at: new Date().toISOString(),
    capabilities: { ...CAPABILITIES }, limits: { ...LIMITS } };
  const bytes = encode(request); let store;
  try {
    fs.mkdirSync(path.join(args.workspaceRoot, id), { mode: 0o700 }); store = storage(args.workspaceRoot, id, rootInfo); store.sync(args.workspaceRoot);
    store.write('request.json', bytes); store.write('request.sha256', `${sha(bytes)}\n`);
  } catch { fail('evidence_write_failed'); }
  return session(store, id, load(store, id));
}
export function openCompanyResearch(args) {
  exact(args, ['workspaceRoot', 'workspaceId'], 'invalid_startup_arguments');
  if (typeof args.workspaceId !== 'string' || !UUID.test(args.workspaceId)) fail('invalid_workspace_id');
  const rootInfo = rootValue(args.workspaceRoot); const store = storage(args.workspaceRoot, args.workspaceId, rootInfo);
  return session(store, args.workspaceId, load(store, args.workspaceId));
}
