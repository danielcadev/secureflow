import dns from 'node:dns/promises';
import https from 'node:https';
import tls from 'node:tls';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';

const error = (code) => Object.assign(new Error(code), { code });
const reject = (code) => { throw error(code); };
const HASH = /^[a-f0-9]{64}$/;

// Conservatively exclude entire special-use blocks, including blocks that
// contain a small number of globally reachable protocol exceptions.
export function isPublicIPv4(value) {
  if (typeof value !== 'string' || net.isIP(value) !== 4) return false;
  const [a, b, c] = value.split('.').map(Number);
  return !(a === 0 || a === 10 || a === 127 || a >= 224
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && ((b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99) || b === 168))
    || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100)))
    || (a === 203 && b === 0 && c === 113));
}

export function canonicalHttpsOrigin(value) {
  if (typeof value !== 'string' || !/^[\x21-\x7e]+$/.test(value)) reject('invalid_plan');
  let url;
  try { url = new URL(value); } catch { reject('invalid_plan'); }
  const hostname = url.hostname;
  if (url.protocol !== 'https:' || value !== url.origin || url.port || url.username || url.password
    || hostname.length > 253 || net.isIP(hostname) || !hostname.includes('.')
    || hostname === 'localhost' || hostname.endsWith('.localhost')
    || !/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(hostname)
    || hostname.split('.').some((label) => label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) reject('invalid_plan');
  return { origin: url.origin, hostname };
}

export function validateApprovedTarget(target) {
  const keys = ['origin', 'ipv4_addresses', 'inventory_sha256', 'asset_id'];
  if (!target || typeof target !== 'object' || Array.isArray(target) || Object.keys(target).length !== keys.length
    || keys.some((key) => !Object.hasOwn(target, key))) reject('invalid_plan');
  const { origin, hostname } = canonicalHttpsOrigin(target.origin);
  if (!Array.isArray(target.ipv4_addresses) || target.ipv4_addresses.length < 1 || target.ipv4_addresses.length > 8
    || new Set(target.ipv4_addresses).size !== target.ipv4_addresses.length || target.ipv4_addresses.some((value) => !isPublicIPv4(value))
    || typeof target.inventory_sha256 !== 'string' || !HASH.test(target.inventory_sha256)
    || typeof target.asset_id !== 'string' || !/^sf_asset_[a-f0-9]{64}$/.test(target.asset_id)) reject('invalid_plan');
  return { origin, hostname, ipv4_addresses: [...target.ipv4_addresses], inventory_sha256: target.inventory_sha256, asset_id: target.asset_id };
}

const validateTimeout = (timeoutMs, timeoutCode) => {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 5000
    || !['request_timeout', 'authorization_expired', 'run_budget_exhausted'].includes(timeoutCode)) reject('invalid_plan');
};

// Resolve only A records, and reject the complete answer if even one record is
// outside the immutable approval. Cancellation also bounds the DNS operation.
export async function resolveApprovedIPv4(target, { timeoutMs, timeoutCode = 'request_timeout' } = {}) {
  const approved = validateApprovedTarget(target);
  validateTimeout(timeoutMs, timeoutCode);
  const resolver = new dns.Resolver();
  let timer;
  try {
    const addresses = await Promise.race([
      resolver.resolve4(approved.hostname).catch(() => { throw error('dns_resolution_failed'); }),
      new Promise((_, fail) => { timer = setTimeout(() => { fail(error(timeoutCode)); resolver.cancel(); }, Math.max(1, timeoutMs)); }),
    ]);
    if (!Array.isArray(addresses) || !addresses.length || addresses.some((address) => !isPublicIPv4(address)
      || !approved.ipv4_addresses.includes(address))) reject('dns_scope_mismatch');
    return addresses[0];
  } finally { clearTimeout(timer); }
}

// The whole DNS/TLS/body exchange shares one wall-time allowance. TLS always
// verifies the approved hostname even when ambient Node verification is off.
export async function requestApprovedHttps({ target, path, token = null, maxResponseBytes, timeoutMs, timeoutCode = 'request_timeout' }) {
  const approved = validateApprovedTarget(target);
  validateTimeout(timeoutMs, timeoutCode);
  if (typeof path !== 'string' || path.length > 1024 || !/^\/[A-Za-z0-9/_-]*$/.test(path) || path.includes('//')
    || !Number.isInteger(maxResponseBytes) || maxResponseBytes < 1 || maxResponseBytes > 65536
    || (token !== null && (typeof token !== 'string' || token.length < 1 || token.length > 512 || !/^[A-Za-z0-9._~+/-]+=*$/.test(token)))) reject('invalid_plan');
  const end = performance.now() + timeoutMs;
  const address = await resolveApprovedIPv4(target, { timeoutMs, timeoutCode });
  const remaining = end - performance.now();
  if (remaining <= 0) reject(timeoutCode);
  return new Promise((resolve, fail) => {
    let req;
    let response;
    let settled = false;
    let timer;
    let size = 0;
    const hash = createHash('sha256');
    const agent = new https.Agent({ keepAlive: false, maxCachedSessions: 0 });
    agent.createConnection = () => tls.connect({
      host: address, port: 443, family: 4, servername: approved.hostname,
      rejectUnauthorized: true, checkServerIdentity: (_hostname, cert) => tls.checkServerIdentity(approved.hostname, cert),
      ALPNProtocols: ['http/1.1'],
    });
    const settle = (code, receipt) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code) { response?.destroy(); req?.destroy(); }
      agent.destroy();
      if (code) fail(error(code)); else resolve(receipt);
    };
    const headers = { Accept: '*/*', Connection: 'close' };
    if (token !== null) headers.Authorization = `Bearer ${token}`;
    try {
      req = https.request({ host: approved.hostname, port: 443, method: 'GET', path, headers, agent, maxHeaderSize: 16384 }, (res) => {
        response = res;
        if (res.statusCode >= 300 && res.statusCode < 400) { settle('redirect_refused'); return; }
        res.on('data', (chunk) => {
          if (settled) return;
          size += chunk.length;
          if (size > maxResponseBytes) { settle('response_too_large'); return; }
          hash.update(chunk);
        });
        res.on('aborted', () => settle('transport_failed'));
        res.on('error', () => settle('transport_failed'));
        res.on('end', () => {
          if (settled) return;
          if (performance.now() >= end) { settle(timeoutCode); return; }
          settle(null, { status_code: res.statusCode, body_bytes: size, body_sha256: hash.digest('hex') });
        });
      });
      req.on('error', () => settle('transport_failed'));
      timer = setTimeout(() => settle(timeoutCode), Math.max(1, remaining));
      req.end();
    } catch { settle('transport_failed'); }
  });
}
