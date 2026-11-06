import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

function fixture(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'secureflow-plugin-install-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const plugin = path.join(root, 'plugins', 'secureflow');
  const scripts = path.join(plugin, 'scripts');
  mkdirSync(scripts, { recursive: true });
  mkdirSync(path.join(plugin, '.codex-plugin'));
  mkdirSync(path.join(root, '.agents', 'plugins'), { recursive: true });
  const marketplaceFile = path.join(root, '.agents', 'plugins', 'marketplace.json');
  writeFileSync(marketplaceFile, JSON.stringify({ name: 'personal' }));
  writeFileSync(path.join(plugin, '.codex-plugin', 'plugin.json'), JSON.stringify({ version: '1.1.0-rc.5' }));
  const installer = path.join(scripts, 'install-codex-plugin.sh');
  writeFileSync(installer, readFileSync(new URL('../../plugins/secureflow/scripts/install-codex-plugin.sh', import.meta.url)));
  const bin = path.join(root, 'bin');
  mkdirSync(bin);
  const calls = path.join(root, 'calls.jsonl');
  writeFileSync(path.join(bin, 'codex'), `#!${process.execPath}
const fs = require('node:fs');
fs.appendFileSync(process.env.SF_INSTALL_CALLS, JSON.stringify(process.argv.slice(2)) + '\\n');
if (process.argv[3] === 'marketplace' && process.argv[4] === 'list') process.stdout.write(process.env.SF_INSTALL_MARKETPLACES);
`, { mode: 0o700 });
  writeFileSync(path.join(bin, 'secureflow'), `#!${process.execPath}
process.stdout.write('secureflow ' + process.env.SF_INSTALL_VERSION + '\\n');
`, { mode: 0o700 });
  function run(version, registered = true) {
    return spawnSync('bash', [installer], {
      encoding: 'utf8', timeout: 5000,
      env: { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`,
        SF_INSTALL_VERSION: version, SF_INSTALL_CALLS: calls,
        SF_INSTALL_MARKETPLACES: JSON.stringify({ marketplaces: registered ? [{ source: root }] : [] }, null, 2) },
    });
  }
  return { root, calls, run, marketplaceFile };
}

test('a mismatched CLI cannot modify the marketplace or install the plugin', (t) => {
  const f = fixture(t);
  const result = f.run('1.1.0-rc.4');
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /CLI\/plugin version mismatch/);
  assert.equal(existsSync(f.calls), false);
});

test('a matching CLI installs from the already registered exact local source', (t) => {
  const f = fixture(t);
  const result = f.run('1.1.0-rc.5');
  assert.equal(result.status, 0, result.stderr);
  const calls = readFileSync(f.calls, 'utf8').trim().split('\n').map(JSON.parse);
  assert.deepEqual(calls, [['plugin', 'marketplace', 'list', '--json'], ['plugin', 'add', 'secureflow@personal']]);
});

test('a matching CLI registers its exact checkout before installing', (t) => {
  const f = fixture(t);
  const result = f.run('1.1.0-rc.5', false);
  assert.equal(result.status, 0, result.stderr);
  const calls = readFileSync(f.calls, 'utf8').trim().split('\n').map(JSON.parse);
  assert.deepEqual(calls, [['plugin', 'marketplace', 'list', '--json'],
    ['plugin', 'marketplace', 'add', f.root], ['plugin', 'add', 'secureflow@personal']]);
});

test('the installer selects its own marketplace rather than another personal source', (t) => {
  const f = fixture(t);
  writeFileSync(f.marketplaceFile, JSON.stringify({ name: 'secureflow-local' }));
  const result = f.run('1.1.0-rc.5', false);
  assert.equal(result.status, 0, result.stderr);
  const calls = readFileSync(f.calls, 'utf8').trim().split('\n').map(JSON.parse);
  assert.deepEqual(calls.at(-1), ['plugin', 'add', 'secureflow@secureflow-local']);
});
