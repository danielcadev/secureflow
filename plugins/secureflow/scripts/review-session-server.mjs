#!/usr/bin/env node

import { readFile, realpath, stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';

const MAX_CASES = 1_024;
const MAX_CASE_BYTES = 32 * 1024 * 1024;
const MAX_SESSION_BYTES = 128 * 1024 * 1024;

function fail(message) {
  process.stderr.write(`secureflow: ${message}\n`);
  process.exit(2);
}

const args = process.argv.slice(2);
let port;
let origin;
let token;
const casePaths = [];
for (let index = 0; index < args.length; index += 1) {
  const argument = args[index];
  if (argument === '--port' || argument === '--origin' || argument === '--token') {
    const value = args[index + 1];
    if (value === undefined) fail(`${argument} requires a value`);
    if (argument === '--port') port = Number(value);
    if (argument === '--origin') origin = value;
    if (argument === '--token') token = value;
    index += 1;
  } else {
    casePaths.push(argument);
  }
}

if (!Number.isInteger(port) || port < 1 || port > 65_535) fail('invalid session port');
if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(origin ?? '')) fail('invalid Review Room origin');
if (!/^[0-9a-f]{64}$/.test(token ?? '')) fail('invalid session token');
if (casePaths.length === 0 || casePaths.length > MAX_CASES) fail('invalid case count');

const cases = [];
let totalBytes = 0;
for (const casePath of casePaths) {
  const resolved = await realpath(casePath);
  const metadata = await stat(resolved);
  if (!metadata.isFile()) fail(`case is not a regular file: ${casePath}`);
  if (metadata.size > MAX_CASE_BYTES) fail(`case exceeds 32 MiB: ${casePath}`);
  totalBytes += metadata.size;
  if (totalBytes > MAX_SESSION_BYTES) fail('case set exceeds 128 MiB');
  const bytes = await readFile(resolved);
  cases.push({
    name: path.basename(resolved),
    bytes_base64: bytes.toString('base64'),
  });
}

const body = JSON.stringify({
  contract_version: 'secureflow-review-session-v1',
  cases,
});
const route = `/session/${token}`;
const server = createServer((request, response) => {
  const requestOrigin = request.headers.origin;
  if (requestOrigin !== undefined && requestOrigin !== origin) {
    response.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    response.end('Forbidden');
    return;
  }
  if (request.method !== 'GET' || request.url !== route) {
    response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    response.end('Not found');
    return;
  }
  response.writeHead(200, {
    'Access-Control-Allow-Origin': origin,
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
    'Cross-Origin-Resource-Policy': 'same-site',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
  });
  response.end(body);
});

server.listen(port, '127.0.0.1', () => {
  process.stderr.write(`SecureFlow review session ready on 127.0.0.1:${port}\n`);
});
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
