#!/usr/bin/env python3
"""Synthetic public vectors only. Predictable test seeds MUST NOT become production keys.
Uses OpenSSL's independent Ed25519 implementation; private test files are temporary.
"""
import hashlib
import json
import pathlib
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent

def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def generate(destination=HERE):
    destination = pathlib.Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as scratch:
        scratch = pathlib.Path(scratch)
        keys, private, roles = {}, {}, {}
        for role, count, threshold in [('root', 3, 2), ('targets', 3, 2), ('snapshot', 2, 1), ('timestamp', 2, 1)]:
            ids = []
            for i in range(count):
                seed = hashlib.sha256(f'SecureFlow SYNTHETIC ONLY {role} {i}'.encode()).digest()
                keyfile = scratch / f'{role}-{i}.der'
                keyfile.write_bytes(bytes.fromhex('302e020100300506032b657004220420') + seed)
                public = subprocess.check_output(['openssl', 'pkey', '-inform', 'DER', '-in', str(keyfile), '-pubout', '-outform', 'DER'])[-32:]
                key = dict(keytype='ed25519', scheme='ed25519', keyval=dict(public=public.hex()))
                keyid = sha(canonical(key))
                keys[keyid] = key
                private[keyid] = keyfile
                ids.append(keyid)
            roles[role] = dict(keyids=ids, threshold=threshold)
        def signed(obj):
            role = obj['_type']
            preimage = canonical(obj)
            (destination / f'{role}.canonical').write_bytes(preimage)
            msg = scratch / 'preimage'
            msg.write_bytes(preimage)
            signatures = []
            for keyid in roles[role]['keyids'][:roles[role]['threshold']]:
                sig = subprocess.check_output(['openssl', 'pkeyutl', '-sign', '-rawin', '-keyform', 'DER', '-inkey', str(private[keyid]), '-in', str(msg)])
                signatures.append(dict(keyid=keyid, sig=sig.hex()))
            return json.dumps(dict(signed=obj, signatures=signatures), ensure_ascii=False, indent=2).encode()+b'\n'
        def base(role, expires):
            return dict(_type=role, spec_version='1.0.0', version=1, expires=expires)
        root = signed(dict(**base('root', '2027-09-12T00:00:00Z'), consistent_snapshot=True, keys=keys, roles=roles))
        manifest = (HERE / 'catalog.manifest.json').read_bytes()
        descriptor = json.loads(manifest)
        target = dict(length=len(manifest), hashes=dict(sha256=sha(manifest)), custom=dict(secureflow=dict(
            contract_version='secureflow-catalog-target-v1', publisher_id='synthetic', catalog_id='advisories', channel='stable', profile=descriptor['profile'],
            profile_policy_version=descriptor['profile_policy_version'], bundle_id=descriptor['bundle_id'], release_sequence=1,
            manifest_contract_version=descriptor['contract_version'], validation_authority=descriptor['validation_authority'])))
        targets = signed(dict(**base('targets', '2026-10-01T00:00:00Z'), publisher_note='Unicode preserved: e\u0301 / é', targets={'catalogs/advisories/stable/full.manifest.json': target}))
        def link(data):
            return dict(version=1, length=len(data), hashes=dict(sha256=sha(data)))
        snapshot = signed(dict(**base('snapshot', '2026-10-01T00:00:00Z'), meta={'targets.json': link(targets)}))
        timestamp = signed(dict(**base('timestamp', '2026-09-15T00:00:00Z'), meta={'snapshot.json': link(snapshot)}))
        for name, data in [('1.root.json',root),('1.targets.json',targets),('1.snapshot.json',snapshot),('timestamp.json',timestamp)]:
            (destination/name).write_bytes(data)
        inventory = {p.name: sha(p.read_bytes()) for p in sorted(destination.iterdir()) if p.suffix in ('.json','.zst','.canonical') and p.name!='hashes.json'}
        (destination/'hashes.json').write_text(json.dumps(inventory, indent=2)+'\n')

if __name__ == '__main__':
    generate()
