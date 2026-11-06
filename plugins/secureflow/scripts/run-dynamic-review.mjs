#!/usr/bin/env node
import { createDynamicSession } from './dynamic-review-core.mjs';

const HELP = 'Usage: node run-dynamic-review.mjs --plan PATH --plan-sha256 SHA256 [--mcp]\nExplicit approved GET plans: v1 owned loopback; v2 experimental HTTPS. Final authority remains human.\n';
const ownObject = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const empty = (value) => ownObject(value, []);
const tools = [
  ['describe_authorized_dynamic_plan', 'Describe the immutable operator-approved plan and its transport version.', {}],
  ['execute_authorized_dynamic_action', 'Execute one approved GET action once within the exact startup grant.', { action_id: { type: 'string' } }],
  ['dynamic_run_status', 'Read bounded status-only evidence; this is not a vulnerability verdict.', {}],
  ['finish_dynamic_run', 'Close the run; unattempted approved actions make it incomplete.', {}],
].map(([name, description, properties]) => ({ name, description, inputSchema: {
  type: 'object', properties, required: Object.keys(properties), additionalProperties: false,
} }));

async function serve(session) {
  let initialized = false;
  let notified = false;
  let outputClosed = false;
  let rejectPendingOutput = null;
  const outputFailure = () => Object.assign(new Error('mcp_output_failed'), { code: 'mcp_output_failed' });
  const closeOutput = () => { outputClosed = true; rejectPendingOutput?.(); };
  process.stdout.on('error', closeOutput);
  process.stdout.on('close', closeOutput);
  const send = (payload) => new Promise((resolve, reject) => {
    if (outputClosed) { reject(outputFailure()); return; }
    rejectPendingOutput = () => { rejectPendingOutput = null; reject(outputFailure()); };
    try {
      // Await the write callback even when write() returns true. It runs only
      // after this frame flushes, so serial dispatch never queues more frames
      // behind a client that has stopped reading stdout.
      process.stdout.write(`${JSON.stringify(payload)}\n`, (cause) => {
        if (cause) { closeOutput(); return; }
        rejectPendingOutput = null;
        resolve();
      });
    } catch { closeOutput(); }
  });
  const rpcError = (id, code, message) => send({ jsonrpc: '2.0', id, error: { code, message } });
  async function dispatch(line) {
    let message;
    try { message = JSON.parse(line.toString('utf8')); }
    catch { return rpcError(null, -32700, 'Parse error'); }
    if (!message || typeof message !== 'object' || Array.isArray(message) || message.jsonrpc !== '2.0'
        || typeof message.method !== 'string' || Object.keys(message).some((key) => !['jsonrpc', 'id', 'method', 'params'].includes(key))
        || (Object.hasOwn(message, 'id') && !(typeof message.id === 'string' || (Number.isSafeInteger(message.id))))) {
      return rpcError(null, -32600, 'Invalid request');
    }
    const hasId = Object.hasOwn(message, 'id');
    if (!hasId) {
      if (message.method === 'notifications/initialized' && initialized && (message.params === undefined || empty(message.params))) notified = true;
      return;
    }
    const { id, method, params } = message;
    if (method === 'initialize') {
      if (initialized || !ownObject(params, ['protocolVersion', 'capabilities', 'clientInfo'])
          || typeof params.protocolVersion !== 'string' || params.protocolVersion.length > 64
          || !params.capabilities || typeof params.capabilities !== 'object' || Array.isArray(params.capabilities)
          || !ownObject(params.clientInfo, ['name', 'version']) || typeof params.clientInfo.name !== 'string'
          || typeof params.clientInfo.version !== 'string') { return rpcError(id, -32602, 'Invalid initialize parameters'); }
      if (!['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25'].includes(params.protocolVersion)) { return rpcError(id, -32602, 'Unsupported protocol version'); }
      initialized = true;
      return send({ jsonrpc: '2.0', id, result: { protocolVersion: params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: 'secureflow-dynamic-review', version: '0.1.0' } } });
    }
    if (!initialized || !notified) { return rpcError(id, -32000, 'Initialization required'); }
    if (method === 'ping') {
      if (params !== undefined && !empty(params)) { return rpcError(id, -32602, 'Invalid parameters'); }
      return send({ jsonrpc: '2.0', id, result: {} });
    }
    if (method === 'tools/list') {
      if (params !== undefined && !empty(params)) { return rpcError(id, -32602, 'Invalid parameters'); }
      return send({ jsonrpc: '2.0', id, result: { tools } });
    }
    if (method !== 'tools/call') { return rpcError(id, -32601, 'Method not found'); }
    if (!ownObject(params, ['name', 'arguments']) || typeof params.name !== 'string'
        || !tools.some((tool) => tool.name === params.name)
        || (params.name === 'execute_authorized_dynamic_action'
          ? !ownObject(params.arguments, ['action_id']) || typeof params.arguments.action_id !== 'string'
          : !empty(params.arguments))) { return rpcError(id, -32602, 'Invalid tool arguments'); }
    try {
      let result;
      switch (params.name) {
        case 'describe_authorized_dynamic_plan': result = session.describe(); break;
        case 'execute_authorized_dynamic_action': result = await session.execute(params.arguments.action_id); break;
        case 'dynamic_run_status': result = session.status(); break;
        case 'finish_dynamic_run': result = await session.finish(); break;
      }
      await send({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(result) }], isError: false } });
    } catch (cause) {
      if (cause.code === 'mcp_output_failed') throw cause;
      // Core errors are fixed codes. Do not stringify a native error or its cause.
      await send({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: cause.code ?? 'dynamic_run_failed' }], isError: true } });
    }
  }
  let pending = Buffer.alloc(0);
  let oversized = false;
  for await (const chunk of process.stdin) {
    let start = 0;
    while (start < chunk.length) {
      const newline = chunk.indexOf(10, start);
      const end = newline === -1 ? chunk.length : newline;
      const segment = chunk.subarray(start, end);
      if (!oversized) {
        if (pending.length + segment.length > 65536) { oversized = true; pending = Buffer.alloc(0); }
        else pending = Buffer.concat([pending, segment]);
      }
      if (newline !== -1) {
        if (oversized) await rpcError(null, -32700, 'Message too large');
        else if (pending.length) await dispatch(pending);
        pending = Buffer.alloc(0);
        oversized = false;
      }
      start = newline === -1 ? chunk.length : newline + 1;
    }
  }
  if (oversized) await rpcError(null, -32700, 'Message too large');
  else if (pending.length) await dispatch(pending);
  await session.finish();
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && (args[0] === '--help' || args[0] === '-h')) { process.stdout.write(HELP); return; }
  const options = {};
  for (let i = 0; i < args.length; i++) {
    const key = args[i];
    if (key === '--mcp' && !options.mcp) options.mcp = true;
    else if (['--plan', '--plan-sha256'].includes(key) && !Object.hasOwn(options, key) && i + 1 < args.length && !args[i + 1].startsWith('--')) options[key] = args[++i];
    else throw Object.assign(new Error('invalid_startup_arguments'), { code: 'invalid_startup_arguments' });
  }
  const session = createDynamicSession({ planPath: options['--plan'], planSha256: options['--plan-sha256'] });
  if (options.mcp) {
    try { await serve(session); }
    finally { await session.finish(); }
    return;
  }
  for (const action of session.describe().plan.actions) {
    try { await session.execute(action.id); } catch { break; }
  }
  const result = await session.finish();
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (result.status !== 'completed') process.exitCode = 1;
}

main().catch((cause) => {
  const safeCodes = new Set(['invalid_startup_arguments', 'invalid_plan_file', 'invalid_plan', 'plan_hash_mismatch', 'invalid_authorization', 'invalid_credential', 'credential_in_plan', 'invalid_output_directory', 'unsafe_output_parent', 'output_exists', 'evidence_write_failed']);
  process.stderr.write(`${safeCodes.has(cause.code) ? cause.code : 'dynamic_run_failed'}\n`);
  process.exitCode = 1;
});
