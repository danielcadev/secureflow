#!/usr/bin/env python3
"""Verify retained synthetic demo receipts and byte linkage, without network or engines.
This checks local test evidence, not an independently authenticated production publisher.
"""
import argparse
import hashlib
import json
from pathlib import Path

ALLOWED = {'catalog-bundle-verify','catalog-trust-init','catalog-trust-import',
           'catalog-trusted-verify','catalog-trusted-install','catalog-trust-status',
           'catalog-trusted-prepare','catalog-trusted-sign','catalog-trusted-assemble',
           'catalog-trusted-inspect'}

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def data(path): return json.loads(path.read_bytes())
def require(condition, message):
    if not condition: raise ValueError(message)
def local(root, name):
    path=root/name
    require(not Path(name).is_absolute() and path.resolve().is_relative_to(root.resolve()) and not path.is_symlink(),'unsafe artifact reference')
    return path

def verify(root, binary=None):
    report=data(root/'demo-receipt.json')
    require(report['contract_version']=='secureflow-trusted-catalog-demo-v1','demo contract')
    require(report['validation_authority']=='human-only','human authority')
    require(report['engine_invocations']==report['ai_transports']==report['human_decisions_created']==0,'unexpected execution or authority')
    require(report['fixture_manifest_sha256']==sha(root/'catalog.manifest.json'),'manifest substitution')
    require(report['fixture_bundle_sha256']==sha(root/'catalog.sqlite3.zst'),'bundle substitution')
    if binary: require(report['binary_sha256']==sha(binary),'binary identity mismatch')
    calls=report['calls'];require(20<=len(calls)<=256,'bounded complete ceremony')
    by_label={call['label']:call for call in calls}
    for call in calls:
        require(call['command'] in ALLOWED,'engine or other command not permitted')
        require(call['network_namespace']=='bubblewrap-unshare-all','missing network isolation')
        local(root,call['stdout']).read_bytes();local(root,call['stderr']).read_bytes()
    for label,code in [('reject-replay','TRUST_ROLLBACK'),('reject-revoked-signers','TRUST_SIGNATURE'),('reject-exact-expiry','TRUST_EXPIRY')]:
        call=by_label[label];require(call['returncode']!=0 and code in local(root,call['stderr']).read_text(),'missing rejection evidence: '+label)
    for label in ['enroll','verify','install-first','overlap-import','install-rotated','revoke-root-only','import-after-revocation','install-current','historical-inspection','recover-pending','recovered-status']:
        require(by_label[label]['returncode']==0,'missing successful stage: '+label)
    historical=data(local(root,by_label['historical-inspection']['stdout']))
    require(historical['historical'] and not historical['current_policy_acceptance'] and not historical['reserves_acceptance'],'historical output must not authorize installation')
    require(historical['policy_failures'],'expiry must remain visible in historical output')
    manifest=data(root/'catalog.manifest.json')
    require(manifest['authenticity']=='unsigned-manifest-requires-external-sha256','v1 semantics changed')
    for name in ['first.sqlite3','rotated.sqlite3','current.sqlite3','recovered.sqlite3']:
        require(sha(root/name)==manifest['payload']['database_sha256'],'installed bytes differ: '+name)
    require(not (root/'replayed.sqlite3').exists() and not (root/'revoked.sqlite3').exists(),'rejected installation published')
    for directory in ['trust','recovery-store']:
        state=data(root/directory/'state.json')
        require(state['contract_version']=='secureflow-catalog-trust-state-v1','state contract')
        require(state['pending'] is None and len(state['roots'])==3 and state['floors']['full']['sequence']==3,'state continuity/floor')
        root_metadata=json.loads(state['roots'][-1])['signed']
        initial=json.loads(state['roots'][0])['signed']
        require(not set(initial['roles']['targets']['keyids']) & set(root_metadata['roles']['targets']['keyids']),'retired target keys remain authorized')
        for receipt_id,receipt in state['completed'].items():
            require(receipt==data(root/directory/'receipts'/f'{receipt_id}.json'),'receipt differs from committed state')
            require(receipt['installation']=='complete' and receipt['integrity']=='verified' and receipt['publisher_authenticity']=='tuf-root-authorized','receipt dimensions')
            require(receipt['validation_authority']=='human-only','receipt authority')
    require(data(root/'interrupted-journal-fixture.json')['kind']=='synthetic-post-publication-journal-not-an-observed-power-loss','recovery evidence must be honestly labeled')
    return dict(result='verified-synthetic-demo-evidence',calls=len(calls),validation_authority='human-only',production_publisher_enrollment=False)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--demo',type=Path,required=True)
    parser.add_argument('--binary',type=Path)
    args=parser.parse_args()
    print(json.dumps(verify(args.demo,args.binary),sort_keys=True))
