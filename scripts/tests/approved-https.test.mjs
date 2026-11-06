import test from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns/promises';
import https from 'node:https';
import tls from 'node:tls';
import { EventEmitter } from 'node:events';
import { isPublicIPv4, canonicalHttpsOrigin, validateApprovedTarget, resolveApprovedIPv4, requestApprovedHttps } from '../../plugins/secureflow/scripts/approved-https-transport.mjs';

const target = () => ({ origin: 'https://example.com', ipv4_addresses: ['8.8.8.8'], inventory_sha256: 'a'.repeat(64), asset_id: 'sf_asset_' + 'b'.repeat(64) });
const code = (expected) => (error) => error.code === expected;

test('public IPv4 classifier excludes private, shared, documentation and reserved space', () => {
  for (const value of ['0.0.0.0', '10.0.0.1', '100.64.0.1', '127.0.0.1', '169.254.1.1', '172.16.0.1', '192.0.0.1', '192.0.2.1', '192.88.99.1', '192.168.1.1', '198.18.0.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '255.255.255.255', '::1', '2130706433', '01.2.3.4', null]) assert.equal(isPublicIPv4(value), false, String(value));
  for (const value of ['8.8.8.8', '1.1.1.1', '172.32.0.1']) assert.equal(isPublicIPv4(value), true);
});

test('origin and approved target reject normalization tricks and authority overrides', () => {
  assert.deepEqual(canonicalHttpsOrigin('https://example.com'), { origin: 'https://example.com', hostname: 'example.com' });
  for (const origin of ['http://example.com', 'https://example.com/', 'https://example.com:443', 'https://example.com:8443', 'https://user@example.com', 'https://example.com?x=1', 'https://example.com#x', 'https://127.0.0.1', 'https://localhost', 'https://EXAMPLE.com', 'https://example.com.']) assert.throws(() => canonicalHttpsOrigin(origin), code('invalid_plan'));
  assert.equal(validateApprovedTarget(target()).hostname, 'example.com');
  for (const invalid of [{ ...target(), allowed: true }, { ...target(), ipv4_addresses: ['127.0.0.1'] }, { ...target(), ipv4_addresses: ['8.8.8.8', '8.8.8.8'] }, { ...target(), inventory_sha256: 'bad' }, { ...target(), asset_id: '../other' }]) assert.throws(() => validateApprovedTarget(invalid), code('invalid_plan'));
});

test('complete DNS answer must remain inside exact approved public IPv4 set', async (t) => {
  const original = dns.Resolver.prototype.resolve4;
  t.after(() => { dns.Resolver.prototype.resolve4 = original; });
  dns.Resolver.prototype.resolve4 = async () => ['8.8.8.8'];
  assert.equal(await resolveApprovedIPv4(target(), { timeoutMs: 100 }), '8.8.8.8');
  for (const values of [['8.8.8.8', '1.1.1.1'], ['127.0.0.1'], []]) {
    dns.Resolver.prototype.resolve4 = async () => values;
    await assert.rejects(resolveApprovedIPv4(target(), { timeoutMs: 100 }), code('dns_scope_mismatch'));
  }
});

test('DNS failures and stalled resolution remain bounded and sanitized', async (t) => {
  const original = dns.Resolver.prototype.resolve4;
  const originalCancel = dns.Resolver.prototype.cancel;
  t.after(() => { dns.Resolver.prototype.resolve4 = original; dns.Resolver.prototype.cancel = originalCancel; });
  dns.Resolver.prototype.resolve4 = async () => { throw Error('secret resolver details'); };
  await assert.rejects(resolveApprovedIPv4(target(), { timeoutMs: 100 }), code('dns_resolution_failed'));
  let cancelled = false;
  dns.Resolver.prototype.resolve4 = () => new Promise(() => {});
  dns.Resolver.prototype.cancel = () => { cancelled = true; };
  await assert.rejects(resolveApprovedIPv4(target(), { timeoutMs: 5 }), code('request_timeout'));
  assert.equal(cancelled, true);
});

test('request pins socket, TLS identity and certificate verification without exposing response bytes', async (t) => {
  const originals = [dns.Resolver.prototype.resolve4, https.request, tls.connect];
  t.after(() => { [dns.Resolver.prototype.resolve4, https.request, tls.connect] = originals; });
  dns.Resolver.prototype.resolve4 = async () => ['8.8.8.8'];
  let socketOptions; let requestOptions;
  tls.connect = (options) => { socketOptions = options; return new EventEmitter(); };
  https.request = (options, callback) => {
    requestOptions = options;
    const req = new EventEmitter(); req.destroy = () => {};
    req.end = () => { options.agent.createConnection(); queueMicrotask(() => { const response = new EventEmitter(); response.statusCode = 200; response.destroy = () => {}; callback(response); response.emit('data', Buffer.from('fixture')); response.emit('end'); }); };
    return req;
  };
  const result = await requestApprovedHttps({ target: target(), path: '/api/items', maxResponseBytes: 64, timeoutMs: 100 });
  assert.equal(requestOptions.host, 'example.com'); assert.equal(requestOptions.method, 'GET');
  assert.equal(socketOptions.host, '8.8.8.8'); assert.equal(socketOptions.port, 443);
  assert.equal(socketOptions.servername, 'example.com'); assert.equal(socketOptions.rejectUnauthorized, true);
  assert.equal(typeof socketOptions.checkServerIdentity, 'function');
  assert.deepEqual(Object.keys(result).sort(), ['body_bytes', 'body_sha256', 'status_code']);
  assert.equal(result.body_bytes, 7); assert.equal(JSON.stringify(result).includes('fixture'), false);
});

test('redirects, oversized bodies and invalid paths fail without a follow-up request', async (t) => {
  const originals = [dns.Resolver.prototype.resolve4, https.request];
  t.after(() => { [dns.Resolver.prototype.resolve4, https.request] = originals; });
  dns.Resolver.prototype.resolve4 = async () => ['8.8.8.8'];
  let requests = 0; let status = 302;
  https.request = (_options, callback) => {
    requests += 1; const req = new EventEmitter(); req.destroy = () => {};
    req.end = () => queueMicrotask(() => { const response = new EventEmitter(); response.statusCode = status; response.destroy = () => {}; callback(response); response.emit('data', Buffer.alloc(8)); response.emit('end'); });
    return req;
  };
  const args = { target: target(), path: '/', maxResponseBytes: 4, timeoutMs: 100 };
  await assert.rejects(requestApprovedHttps(args), code('redirect_refused')); assert.equal(requests, 1);
  status = 200;
  await assert.rejects(requestApprovedHttps(args), code('response_too_large')); assert.equal(requests, 2);
  for (const path of ['/../admin', '//other', '/a?token=x', '/%2e']) await assert.rejects(requestApprovedHttps({ ...args, path }), code('invalid_plan'));
  assert.equal(requests, 2);
});
