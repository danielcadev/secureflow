#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createCompanyResearch, openCompanyResearch } from './company-research-core.mjs';

const HELP = 'Usage: node run-company-research.mjs --workspace-root PRIVATE_DIR [--mcp | --seed-kind company|url|github-org --seed-value VALUE | --workspace UUID --summary|--export|--import FILE --import-sha256 SHA256]\nSource-only company research preparation. No provider calls, target traffic, ownership validation or active testing.\n';
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));
const fail = (code) => { throw Object.assign(new Error(code), { code }); };
const safeCode = (cause) => /^[a-z_]{1,64}$/.test(cause?.code ?? '') ? cause.code : 'company_request_failed';
// Keep this advertised contract aligned with the standalone discovery schema.
const discoverySchema = {"type":"object","additionalProperties":false,"required":["contract_version","sources","assets"],"properties":{"contract_version":{"const":"secureflow-company-discovery-v1"},"sources":{"type":"array","minItems":1,"maxItems":32,"items":{"type":"object","additionalProperties":false,"required":["id","kind","reference_url","content_sha256"],"properties":{"id":{"type":"string","minLength":1,"maxLength":64,"pattern":"^[A-Za-z][A-Za-z0-9_-]{0,63}$"},"kind":{"enum":["official-site","scope-policy","github-metadata","certificate-transparency","dns-record","agent-search"]},"reference_url":{"type":"string","minLength":1,"maxLength":2048,"format":"uri"},"content_sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"}}}},"assets":{"type":"array","minItems":0,"maxItems":100,"items":{"type":"object","additionalProperties":false,"required":["kind","value","source_ids","relations","limitations"],"properties":{"kind":{"enum":["domain","origin","repository","endpoint"]},"value":{"type":"string","minLength":1,"maxLength":2048},"source_ids":{"type":"array","minItems":1,"maxItems":128,"items":{"type":"string","minLength":1,"maxLength":64,"pattern":"^[A-Za-z][A-Za-z0-9_-]{0,63}$"}},"relations":{"type":"array","minItems":0,"maxItems":20,"items":{"type":"object","additionalProperties":false,"required":["kind","target_id"],"properties":{"kind":{"enum":["references","deployed-on","contains","candidate-subdomain"]},"target_id":{"type":"string","pattern":"^sf_asset_[a-f0-9]{64}$"}}}},"limitations":{"type":"array","minItems":0,"maxItems":20,"items":{"type":"string","minLength":1,"maxLength":256}}}}}}};
const tools = [
  { name: 'prepare_company_research', description: 'Prepare a company, URL or GitHub-organization workspace. This does not discover assets or authorize target traffic.',
    inputSchema: { type: 'object', additionalProperties: false, required: ['seed'],
      properties: { seed: { type: 'object', additionalProperties: false, required: ['kind', 'value'],
        properties: { kind: { enum: ['company', 'url', 'github-org'] }, value: { type: 'string', maxLength: 2048 } } } } } },
  { name: 'register_company_discovery', description: 'Import bounded host-declared evidence and asset relationships; all ownership and testing authority remain unverified.',
    inputSchema: { type: 'object', additionalProperties: false, required: ['workspace_id', 'bundle'],
      properties: { workspace_id: { type: 'string', format: 'uuid' }, bundle: discoverySchema } } },
  { name: 'summarize_company_research', description: 'Read compact asset and coverage counts. Zero active tests is not a security result.',
    inputSchema: { type: 'object', additionalProperties: false, required: ['workspace_id'], properties: { workspace_id: { type: 'string' } } } },
  { name: 'list_company_assets', description: 'Read a filtered page of at most 20 asset identities. Evidence does not transfer approval between assets.',
    inputSchema: { type: 'object', additionalProperties: false, required: ['workspace_id', 'kind', 'query', 'offset', 'limit'],
      properties: { workspace_id: { type: 'string' }, kind: { enum: [null, 'domain', 'origin', 'repository', 'endpoint'] },
        query: { type: 'string', maxLength: 128 }, offset: { type: 'integer', minimum: 0, maximum: 512 },
        limit: { type: 'integer', minimum: 1, maximum: 20 } } } },
  { name: 'inspect_company_asset', description: 'Read bounded evidence and relationships for one asset. It remains unverified and unapproved.',
    inputSchema: { type: 'object', additionalProperties: false, required: ['workspace_id', 'asset_id'],
      properties: { workspace_id: { type: 'string' }, asset_id: { type: 'string' } } } },
  { name: 'export_company_research_plan', description: 'Export an evidence inventory for scope selection; not an executable scan authorization.',
    inputSchema: { type: 'object', additionalProperties: false, required: ['workspace_id'], properties: { workspace_id: { type: 'string' } } } },
];

function validateRoot(root) {
  if (typeof root !== 'string' || !path.isAbsolute(root) || path.resolve(root) !== root || /[\x00-\x1f\x7f]/.test(root)) fail('invalid_workspace_root');
  let info;
  try { info = fs.lstatSync(root); } catch { fail('invalid_workspace_root'); }
  if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid() || (info.mode & 0o077) !== 0) fail('invalid_workspace_root');
}
function readPinned(file, hash) {
  if (typeof file !== 'string' || typeof hash !== 'string' || !/^[a-f0-9]{64}$/.test(hash)) fail('invalid_import_arguments');
  let fd;
  let bytes;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const info = fs.fstatSync(fd);
    if (!info.isFile() || info.size > 65536) fail('invalid_import_file');
    const buffer = Buffer.alloc(65537);
    let size = 0;
    while (size < buffer.length) {
      const count = fs.readSync(fd, buffer, size, buffer.length - size, null);
      if (!count) break;
      size += count;
    }
    bytes = buffer.subarray(0, size);
    if (size > 65536) fail('invalid_import_file');
  } catch (cause) {
    if (cause.code === 'invalid_import_file') throw cause;
    fail('invalid_import_file');
  } finally { if (fd !== undefined) fs.closeSync(fd); }
  if (createHash('sha256').update(bytes).digest('hex') !== hash) fail('import_hash_mismatch');
  try { return JSON.parse(bytes.toString('utf8')); } catch { fail('invalid_discovery'); }
}

async function serve(root) {
  let initialized = false;
  let notified = false;
  let outputClosed = false;
  let rejectOutput = null;
  const closeOutput = () => { outputClosed = true; rejectOutput?.(); };
  process.stdout.on('error', closeOutput);
  process.stdout.on('close', closeOutput);
  const send = (message) => new Promise((resolve, reject) => {
    const broken = () => Object.assign(new Error('mcp_output_failed'), { code: 'mcp_output_failed' });
    if (outputClosed) { reject(broken()); return; }
    rejectOutput = () => { rejectOutput = null; reject(broken()); };
    try {
      process.stdout.write(JSON.stringify(message) + '\n', (cause) => {
        if (cause) { closeOutput(); return; }
        rejectOutput = null; resolve();
      });
    } catch { closeOutput(); }
  });
  const error = (id, code, message) => send({ jsonrpc: '2.0', id, error: { code, message } });
  const get = (id) => openCompanyResearch({ workspaceRoot: root, workspaceId: id });
  let creations = 0;
  async function dispatch(line) {
    let request;
    try { request = JSON.parse(line.toString('utf8')); } catch { return error(null, -32700, 'Parse error'); }
    if (!request || typeof request !== 'object' || Array.isArray(request) || request.jsonrpc !== '2.0'
        || typeof request.method !== 'string' || Object.keys(request).some((key) => !['jsonrpc', 'id', 'method', 'params'].includes(key))
        || (Object.hasOwn(request, 'id') && !(typeof request.id === 'string' || Number.isSafeInteger(request.id)))) return error(null, -32600, 'Invalid request');
    const { id, method, params } = request;
    if (!Object.hasOwn(request, 'id')) {
      if (method === 'notifications/initialized' && initialized && (params === undefined || exact(params, []))) notified = true;
      return;
    }
    if (method === 'initialize') {
      if (initialized || !exact(params, ['protocolVersion', 'capabilities', 'clientInfo'])
          || !['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25'].includes(params.protocolVersion)
          || !params.capabilities || typeof params.capabilities !== 'object' || Array.isArray(params.capabilities)
          || !exact(params.clientInfo, ['name', 'version']) || typeof params.clientInfo.name !== 'string'
          || typeof params.clientInfo.version !== 'string') return error(id, -32602, 'Invalid initialize parameters');
      initialized = true;
      return send({ jsonrpc: '2.0', id, result: { protocolVersion: params.protocolVersion,
        capabilities: { tools: {} }, serverInfo: { name: 'secureflow-company-research', version: '0.1.0' } } });
    }
    if (!initialized || !notified) return error(id, -32000, 'Initialization required');
    if (method === 'ping') {
      if (params !== undefined && !exact(params, [])) return error(id, -32602, 'Invalid parameters');
      return send({ jsonrpc: '2.0', id, result: {} });
    }
    if (method === 'tools/list') {
      if (params !== undefined && !exact(params, [])) return error(id, -32602, 'Invalid parameters');
      return send({ jsonrpc: '2.0', id, result: { tools } });
    }
    if (method !== 'tools/call') return error(id, -32601, 'Method not found');
    if (!exact(params, ['name', 'arguments']) || !tools.some((tool) => tool.name === params.name)) return error(id, -32602, 'Invalid tool arguments');
    const args = params.arguments;
    const fields = {
      prepare_company_research: ['seed'], register_company_discovery: ['workspace_id', 'bundle'],
      summarize_company_research: ['workspace_id'], list_company_assets: ['workspace_id', 'kind', 'query', 'offset', 'limit'],
      inspect_company_asset: ['workspace_id', 'asset_id'], export_company_research_plan: ['workspace_id'],
    };
    if (!exact(args, fields[params.name])) return error(id, -32602, 'Invalid tool arguments');
    try {
      let result;
      switch (params.name) {
        case 'prepare_company_research':
          if (creations >= 32) fail('workspace_creation_budget_exhausted');
          result = createCompanyResearch({ workspaceRoot: root, seed: args.seed }).describe();
          creations += 1;
          break;
        case 'register_company_discovery': result = get(args.workspace_id).registerDiscovery(args.bundle); break;
        case 'summarize_company_research': result = get(args.workspace_id).summary(); break;
        case 'list_company_assets': result = get(args.workspace_id).listAssets({ kind: args.kind, query: args.query, offset: args.offset, limit: args.limit }); break;
        case 'inspect_company_asset': result = get(args.workspace_id).inspectAsset(args.asset_id); break;
        case 'export_company_research_plan': {
          const exported = get(args.workspace_id).exportPlan();
          result = { workspace_id: args.workspace_id, inventory_path: exported.inventory_path,
            inventory_sha256: exported.inventory_sha256, coverage: exported.inventory.coverage,
            next_step: exported.inventory.next_step, is_executable_authorization: false };
          break;
        }
      }
      await send({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(result) }], isError: false } });
    } catch (cause) {
      if (cause.code === 'mcp_output_failed') throw cause;
      await send({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: safeCode(cause) }], isError: true } });
    }
  }
  let pending = Buffer.alloc(0);
  let oversized = false;
  for await (const chunk of process.stdin) {
    let start = 0;
    while (start < chunk.length) {
      const newline = chunk.indexOf(10, start);
      const end = newline < 0 ? chunk.length : newline;
      const part = chunk.subarray(start, end);
      if (!oversized) {
        if (pending.length + part.length > 65536) { oversized = true; pending = Buffer.alloc(0); }
        else pending = Buffer.concat([pending, part]);
      }
      if (newline >= 0) {
        if (oversized) await error(null, -32700, 'Message too large');
        else if (pending.length) await dispatch(pending);
        pending = Buffer.alloc(0); oversized = false;
      }
      start = newline < 0 ? chunk.length : newline + 1;
    }
  }
  if (oversized) await error(null, -32700, 'Message too large');
  else if (pending.length) await dispatch(pending);
}
async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && ['--help', '-h'].includes(args[0])) { process.stdout.write(HELP); return; }
  const options = {};
  const switches = ['--mcp', '--summary', '--export'];
  const pairs = ['--workspace-root', '--seed-kind', '--seed-value', '--workspace', '--import', '--import-sha256'];
  for (let i = 0; i < args.length; i++) {
    const key = args[i];
    if (Object.hasOwn(options, key)) fail('invalid_startup_arguments');
    if (switches.includes(key)) options[key] = true;
    else if (pairs.includes(key) && i + 1 < args.length && !args[i + 1].startsWith('--')) options[key] = args[++i];
    else fail('invalid_startup_arguments');
  }
  validateRoot(options['--workspace-root']);
  if (options['--mcp']) {
    if (Object.keys(options).length !== 2) fail('invalid_startup_arguments');
    await serve(options['--workspace-root']); return;
  }
  let result;
  if (Object.hasOwn(options, '--seed-kind') || Object.hasOwn(options, '--seed-value')) {
    if (Object.keys(options).length !== 3) fail('invalid_startup_arguments');
    result = createCompanyResearch({ workspaceRoot: options['--workspace-root'],
      seed: { kind: options['--seed-kind'], value: options['--seed-value'] } }).describe();
  } else {
    const id = options['--workspace'];
    if (options['--summary'] && Object.keys(options).length === 3) result = openCompanyResearch({ workspaceRoot: options['--workspace-root'], workspaceId: id }).summary();
    else if (options['--export'] && Object.keys(options).length === 3) result = openCompanyResearch({ workspaceRoot: options['--workspace-root'], workspaceId: id }).exportPlan();
    else if (options['--import'] && Object.keys(options).length === 4 && Object.hasOwn(options, '--import-sha256')) {
      const bundle = readPinned(options['--import'], options['--import-sha256']);
      result = openCompanyResearch({ workspaceRoot: options['--workspace-root'], workspaceId: id }).registerDiscovery(bundle);
    } else fail('invalid_startup_arguments');
  }
  process.stdout.write(JSON.stringify(result) + '\n');
}
main().catch((cause) => { process.stderr.write(safeCode(cause) + '\n'); process.exitCode = 1; });
