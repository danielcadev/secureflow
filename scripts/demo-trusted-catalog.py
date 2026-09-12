#!/usr/bin/env python3
"""Hermetic synthetic catalog distribution ceremony; no engine or AI invocation.
Every SecureFlow process runs in Bubblewrap with all namespaces unshared and only
this new demo directory writable. Predictable test keys are NEVER production keys.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
NOW = '2026-09-12T12:00:00Z'
ALLOWED = {'catalog-bundle-verify', 'catalog-trust-init', 'catalog-trust-import',
           'catalog-trusted-verify', 'catalog-trusted-install', 'catalog-trust-status',
           'catalog-trusted-prepare', 'catalog-trusted-sign', 'catalog-trusted-assemble',
           'catalog-trusted-inspect'}

def sha(data): return hashlib.sha256(data).hexdigest()
def canonical(value): return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
def write(path, value):
    with path.open('x') as file: json.dump(value, file, indent=2, ensure_ascii=False)
def read(path): return json.loads(path.read_bytes())

class Demo:
    def __init__(self, binary, output):
        self.binary = binary.resolve(strict=True)
        self.output = output
        output.mkdir(mode=0o700)
        for name in ['scratch', 'metadata', 'ceremony', 'logs']:
            (output/name).mkdir(mode=0o700)
        self.calls = []
        fixture = ROOT/'tests/fixtures/trusted-catalog'
        for name in ['catalog.manifest.json','catalog.sqlite3.zst']:
            shutil.copyfile(fixture/name,output/name)
        self.manifest = read(output/'catalog.manifest.json')
        self.scope = ['--publisher','synthetic','--catalog','advisories','--channel','stable','--required-profile','full']
        self.clock = ['--verification-time',NOW,'--time-reference','repository-contained synthetic fixed clock']
        self.private = tempfile.TemporaryDirectory(prefix='secureflow-SYNTHETIC-signers-')
        self.key_paths = {}
        self.keys = {}
        self.roles = {}
        for role,count,threshold in [('root',3,2),('targets',3,2),('snapshot',2,1),('timestamp',2,1)]:
            self.roles[role] = dict(keyids=self.generate_keys(role,count),threshold=threshold)
        self.original_targets = list(self.roles['targets']['keyids'])
        self.original_root = list(self.roles['root']['keyids'])

    def generate_keys(self, label, count):
        ids=[]
        for index in range(count):
            seed = hashlib.sha256(f'SecureFlow demo SYNTHETIC ONLY {label} {index}'.encode()).digest()
            key_path = Path(self.private.name)/f'{label}-{index}.der'
            key_path.write_bytes(bytes.fromhex('302e020100300506032b657004220420')+seed)
            public = subprocess.check_output(['openssl','pkey','-inform','DER','-in',str(key_path),'-pubout','-outform','DER'])[-32:]
            value=dict(keytype='ed25519',scheme='ed25519',keyval=dict(public=public.hex()))
            keyid=sha(canonical(value));self.keys[keyid]=value;self.key_paths[keyid]=key_path;ids.append(keyid)
        return ids

    def run(self, label, command, *args, failure=None):
        assert command in ALLOWED, command
        argv=[str(self.binary),command,*map(str,args)]
        sandbox=['/usr/bin/bwrap','--die-with-parent','--new-session','--unshare-all',
                 '--ro-bind','/','/','--bind',str(self.output),str(self.output),
                 '--proc','/proc','--dev','/dev','--clearenv','--setenv','PATH','/usr/bin:/bin',
                 '--setenv','TMPDIR',str(self.output/'scratch'),'--',*argv]
        result=subprocess.run(sandbox,capture_output=True,text=True,timeout=90)
        stem=f'{len(self.calls):03d}-{label}'
        (self.output/'logs'/f'{stem}.stdout').write_text(result.stdout)
        (self.output/'logs'/f'{stem}.stderr').write_text(result.stderr)
        self.calls.append(dict(label=label,command=command,arguments=list(map(str,args)),
                               returncode=result.returncode,network_namespace='bubblewrap-unshare-all',
                               stdout=f'logs/{stem}.stdout',stderr=f'logs/{stem}.stderr'))
        if failure:
            assert result.returncode!=0 and failure in result.stderr,(label,result.stdout,result.stderr)
            return None
        assert result.returncode==0,(label,result.stdout,result.stderr)
        return json.loads(result.stdout)

    def base(self,role,version):
        expiry={'root':'2027-09-12T00:00:00Z','targets':'2026-10-01T00:00:00Z','snapshot':'2026-10-01T00:00:00Z','timestamp':'2026-09-15T00:00:00Z'}[role]
        return dict(_type=role,spec_version='1.0.0',version=version,expires=expiry)

    def ceremony(self, signed, root, destination, signer_ids, previous=None):
        role=signed['_type'];version=signed['version'];stem=f'{version}-{role}-{len(self.calls)}'
        directory=self.output/'ceremony'
        source=directory/f'{stem}.signed.json';request=directory/f'{stem}.request.json'
        write(source,signed)
        extra=[]
        if role=='targets': extra=['--manifest',self.output/'catalog.manifest.json','--bundle',self.output/'catalog.sqlite3.zst']
        self.run('prepare-'+role,'catalog-trusted-prepare','--signed-input',source,'--output',request,*extra)
        signatures=[]
        for index,keyid in enumerate(signer_ids):
            rawsig=directory/f'{stem}-{index}.sig';fragment=directory/f'{stem}-{index}.signature.json'
            subprocess.run(['openssl','pkeyutl','-sign','-rawin','-keyform','DER','-inkey',str(self.key_paths[keyid]),'-in',str(request.with_suffix('.canonical')),'-out',str(rawsig)],check=True)
            # A transition may also need old-root custodians. Their authorization
            # is verified against the previous root, then both quorums at assembly.
            signer_root=root
            if previous and keyid not in read(root)['signed']['roles'][role]['keyids']: signer_root=previous
            self.run('collect-'+role,'catalog-trusted-sign','--request',request,'--root',signer_root,'--key-id',keyid,'--signature',rawsig,'--output',fragment)
            signatures.append(fragment)
        args=['--request',request,'--root',root,'--output',destination]
        if previous: args+=['--previous-root',previous]
        for signature in signatures: args+=['--signature',signature]
        self.run('assemble-'+role,'catalog-trusted-assemble',*args)

    def root(self,version,previous=None):
        used={keyid for role in self.roles.values() for keyid in role['keyids']}
        signed=dict(**self.base('root',version),consistent_snapshot=True,keys={k:self.keys[k] for k in sorted(used)},roles=self.roles)
        authority=self.output/'ceremony'/f'{version}.authority.json';write(authority,dict(signed=signed,signatures=[]))
        out=self.output/'metadata'/f'{version}.root.json'
        self.ceremony(signed,authority,out,self.roles['root']['keyids'][:2],previous)
        return out

    def release(self,version,sequence,root,signers=None,directory=None):
        directory=directory or self.output/'metadata'
        manifest=(self.output/'catalog.manifest.json').read_bytes();m=self.manifest
        extension=dict(contract_version='secureflow-catalog-target-v1',publisher_id='synthetic',catalog_id='advisories',channel='stable',profile='full',profile_policy_version=m['profile_policy_version'],bundle_id=m['bundle_id'],release_sequence=sequence,manifest_contract_version=m['contract_version'],validation_authority=m['validation_authority'])
        targets=dict(**self.base('targets',version),targets={'catalogs/advisories/stable/full.manifest.json':dict(length=len(manifest),hashes=dict(sha256=sha(manifest)),custom=dict(secureflow=extension))})
        self.ceremony(targets,root,directory/f'{version}.targets.json',signers or self.roles['targets']['keyids'][:2])
        def link(path):
            data=path.read_bytes();return dict(version=version,length=len(data),hashes=dict(sha256=sha(data)))
        snapshot=dict(**self.base('snapshot',version),meta={'targets.json':link(directory/f'{version}.targets.json')})
        self.ceremony(snapshot,root,directory/f'{version}.snapshot.json',self.roles['snapshot']['keyids'][:1])
        timestamp=dict(**self.base('timestamp',version),meta={'snapshot.json':link(directory/f'{version}.snapshot.json')})
        # Publisher metadata outputs never overwrite. Move the old public timestamp
        # into its retained package before assembling the next immutable file.
        timestamp_path=directory/'timestamp.json'
        if timestamp_path.exists(): timestamp_path.rename(directory/f"{read(timestamp_path)['signed']['version']}.timestamp.retained.json")
        self.ceremony(timestamp,root,timestamp_path,self.roles['timestamp']['keyids'][:1])

    def inputs(self,directory=None):
        return ['--trust-store',self.output/'trust','--metadata-dir',directory or self.output/'metadata',*self.scope,'--manifest',self.output/'catalog.manifest.json','--bundle',self.output/'catalog.sqlite3.zst']

    def execute(self):
        try:
            root1=self.root(1);self.release(1,1,root1)
            old=self.output/'old-package';shutil.copytree(self.output/'metadata',old)
            self.run('legacy-integrity','catalog-bundle-verify','--manifest',self.output/'catalog.manifest.json','--bundle',self.output/'catalog.sqlite3.zst','--expected-manifest-sha256',sha((self.output/'catalog.manifest.json').read_bytes()),'--required-profile','full')
            self.run('enroll','catalog-trust-init','--trust-store',self.output/'trust','--root',root1,'--expected-root-sha256',sha(root1.read_bytes()),'--publisher','synthetic','--catalog','advisories','--channel','stable','--profile','full','--minimum-sequence',0,'--operator','synthetic independent custodian rehearsal','--authorization-reference','public synthetic fixture; no production enrollment',*self.clock)
            self.run('verify','catalog-trusted-verify',*self.inputs(),*self.clock)
            self.run('install-first','catalog-trusted-install',*self.inputs(),'--output',self.output/'first.sqlite3',*self.clock)
            new_targets=self.generate_keys('replacement-targets',3)
            self.roles['targets']['keyids']+=new_targets
            root2=self.root(2,root1);self.release(2,2,root2,new_targets[:2])
            self.run('overlap-import','catalog-trust-import','--trust-store',self.output/'trust','--metadata-dir',self.output/'metadata','--publisher','synthetic',*self.clock)
            installed=self.run('install-rotated','catalog-trusted-install',*self.inputs(),'--output',self.output/'rotated.sqlite3',*self.clock)
            self.roles['targets']['keyids']=new_targets
            root3=self.root(3,root2)
            self.run('revoke-root-only','catalog-trust-import','--trust-store',self.output/'trust','--metadata-dir',self.output/'metadata','--publisher','synthetic','--root-only',*self.clock)
            self.run('reject-replay','catalog-trusted-install',*self.inputs(old),'--output',self.output/'replayed.sqlite3',*self.clock,failure='TRUST_ROLLBACK')
            # Produce a coherent package authorized by the old root's retired keys.
            revoked=self.output/'revoked-package';revoked.mkdir(mode=0o700)
            self.release(3,3,root1,self.original_targets[:2],revoked)
            self.run('reject-revoked-signers','catalog-trusted-install',*self.inputs(revoked),'--output',self.output/'revoked.sqlite3',*self.clock,failure='TRUST_SIGNATURE')
            # That failed install durably learned timestamp/snapshot version 3.
            # Recovery uses larger metadata versions, never a hidden reset.
            self.release(4,3,root3,new_targets[:2])
            self.run('import-after-revocation','catalog-trust-import','--trust-store',self.output/'trust','--metadata-dir',self.output/'metadata','--publisher','synthetic',*self.clock)
            installed=self.run('install-current','catalog-trusted-install',*self.inputs(),'--output',self.output/'current.sqlite3',*self.clock)
            self.run('reject-exact-expiry','catalog-trusted-verify',*self.inputs(),'--verification-time','2026-09-15T00:00:00Z','--time-reference','synthetic exact expiry',failure='TRUST_EXPIRY')
            self.run('historical-inspection','catalog-trusted-inspect',*self.inputs(),'--historical','--verification-time','2026-09-15T00:00:00Z','--time-reference','synthetic historical inspection')
            # Explicit journal fixture models a crash after durable publication.
            # Real process exits and write quotas are exercised by the Rust tests.
            recovery=self.output/'recovery-store';shutil.copytree(self.output/'trust',recovery)
            state=read(recovery/'state.json');pending=dict(installed)
            pending['installation']='pending';pending['output']=str(self.output/'recovered.sqlite3');pending['state_generation']=state['generation']+1
            pending['transaction_id']=sha(b'SecureFlow explicit synthetic interrupted-install journal')
            shutil.copyfile(self.output/'current.sqlite3',self.output/'recovered.sqlite3')
            state['generation']+=1;state['pending']=dict(receipt=pending,descriptor=self.manifest['payload'])
            (recovery/'state.json').write_text(json.dumps(state,indent=2))
            write(self.output/'interrupted-journal-fixture.json',dict(kind='synthetic-post-publication-journal-not-an-observed-power-loss',transaction_id=pending['transaction_id'],output=pending['output'],state_before_sha256=sha((recovery/'state.json').read_bytes())))
            self.run('recover-pending','catalog-trust-import','--trust-store',recovery,'--metadata-dir',self.output/'metadata','--publisher','synthetic','--root-only',*self.clock)
            self.run('recovered-status','catalog-trust-status','--trust-store',recovery,'--receipt',recovery/'receipts'/f"{pending['transaction_id']}.json",*self.clock)
            assert not (self.output/'replayed.sqlite3').exists() and not (self.output/'revoked.sqlite3').exists()
            assert read(recovery/'state.json')['pending'] is None
            for state_path in [self.output/'trust/state.json',recovery/'state.json']:
                state=read(state_path);assert state['floors']['full']['sequence']==3 and len(state['roots'])==3
            report=dict(contract_version='secureflow-trusted-catalog-demo-v1',binary_sha256=sha(self.binary.read_bytes()),fixed_clock=NOW,network='all SecureFlow invocations use Bubblewrap --unshare-all',engine_invocations=0,ai_transports=0,human_decisions_created=0,validation_authority='human-only',fixture_manifest_sha256=sha((self.output/'catalog.manifest.json').read_bytes()),fixture_bundle_sha256=sha((self.output/'catalog.sqlite3.zst').read_bytes()),calls=self.calls,limitations=['Synthetic custodians are not a production human custody rehearsal.','Journal fixture is simulated; process crash and write-quota gates are separate Rust tests.','Offline state cannot establish globally latest releases or withheld revocations.'])
            write(self.output/'demo-receipt.json',report)
            print(f'trusted catalog demo artifacts retained at: {self.output}')
        finally:
            self.private.cleanup()

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    os.umask(0o077)
    assert args.output.is_absolute() and args.output.parent.resolve()==args.output.parent
    Demo(args.binary,args.output).execute()
