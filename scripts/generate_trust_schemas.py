#!/usr/bin/env python3
"""Reproduce the closed, bounded catalog trust schemas. No network resolution."""
import copy
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
MAX = 9007199254740991

def obj(properties):
    return dict(type='object', additionalProperties=False, required=list(properties), properties=properties)
def text(n=1024): return dict(type='string', minLength=1, maxLength=n)
def integer(maximum=MAX, minimum=1): return dict(type='integer', minimum=minimum, maximum=maximum)
def const(v): return dict(const=v)
def enum(*v): return dict(enum=list(v))
def array(v, n, minimum=0): return dict(type='array', items=v, minItems=minimum, maxItems=n)
def nullable(v): return dict(anyOf=[v,dict(type='null')])
def ref(v): return {'$ref':f'#/$defs/{v}'}
def mapping(v,n=4096): return dict(type='object', additionalProperties=v, maxProperties=n)

D={}
D['sha256']=dict(type='string',pattern='^[0-9a-f]{64}$')
D['identifier']=dict(type='string',pattern='^[a-z0-9][a-z0-9-]{0,63}$')
D['utc']=dict(type='string',pattern='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$',format='date-time')
D['profile']=enum('core','malicious','full')
D['scope']=obj(dict(publisher_id=ref('identifier'),catalog_id=ref('identifier'),channel=ref('identifier'),profile=ref('profile')))
D['clock']=obj(dict(verification_time=ref('utc'),time_source=enum('operator-attested','operator-trusted-system-clock'),time_reference=text()))
D['target']=obj(dict(contract_version=const('secureflow-catalog-target-v1'),**D['scope']['properties'],profile_policy_version=const('secureflow-catalog-profile-policy-v2'),bundle_id=dict(type='string',pattern='^sf_catalog_bundle_[0-9a-f]{64}$'),release_sequence=integer(),manifest_contract_version=const('secureflow-catalog-bundle-v1'),validation_authority=const('external-records-require-human-validation')))
D['policy']=obj(dict(contract_version=const('secureflow-catalog-trust-policy-v1'),publisher_id=ref('identifier'),publisher_label=text(256),catalog_id=ref('identifier'),channel=ref('identifier'),profiles=dict(**array(ref('profile'),3,1),uniqueItems=True),initial_root_sha256=ref('sha256'),minimum_root_version=integer(4294967295),minimum_sequence=integer(minimum=0),bootstrap_manifest_sha256=nullable(ref('sha256')),minimum_thresholds=const(dict(root=2,targets=2,snapshot=1,timestamp=1)),maximum_horizon_days=const(dict(root=366,targets=30,snapshot=30,timestamp=7)),operator=text(256),authorization_reference=text(),enrolled_at=ref('clock')))
D['roleEvidence']=obj(dict(version=integer(4294967295),raw_sha256=ref('sha256'),signed_sha256=ref('sha256'),expires=ref('utc'),accepted_signer_ids=dict(**array(ref('sha256'),32,1),uniqueItems=True),threshold=integer(32)))
D['receipt']=obj(dict(contract_version=const('secureflow-catalog-trust-receipt-v1'),operation=enum('verify','install'),installation=enum('not-requested','pending','complete'),transaction_id=nullable(ref('sha256')),output=nullable(dict(type='string',minLength=2,maxLength=4096,pattern='^/')),integrity=const('verified'),publisher_authenticity=const('tuf-root-authorized'),freshness=const('within-local-policy-as-of'),rollback=const('accepted-against-local-state'),scope=ref('scope'),release_sequence=integer(),initial_root_sha256=ref('sha256'),current_root_sha256=ref('sha256'),metadata=obj({k:ref('roleEvidence') for k in ['root','targets','snapshot','timestamp']}),manifest_sha256=ref('sha256'),manifest_bytes=integer(2097152),database_sha256=ref('sha256'),database_bytes=integer(17179869184),policy_sha256=ref('sha256'),clock=ref('clock'),earliest_expiry=ref('utc'),state_generation=integer(),reserves_acceptance=dict(type='boolean'),validation_authority=const('human-only'),limitations=array(text(2048),16,1)))
D['receipt']['allOf']=[{'if':{'properties':{'operation':const('verify')}},'then':{'properties':{'installation':const('not-requested'),'transaction_id':const(None),'output':const(None),'reserves_acceptance':const(False)}},'else':{'properties':{'installation':enum('pending','complete'),'transaction_id':ref('sha256'),'output':dict(type='string',minLength=2,maxLength=4096,pattern='^/'),'reserves_acceptance':const(True)}}}]
D['floor']=obj(dict(sequence=integer(minimum=0),manifest_sha256=nullable(ref('sha256'))))
D['roleRecord']=obj(dict(raw=text(2097152),evidence=ref('roleEvidence')))
D['pending']=obj(dict(receipt=ref('receipt'),descriptor=ref('database')))
D['state']=obj(dict(contract_version=const('secureflow-catalog-trust-state-v1'),policy=ref('policy'),policy_sha256=ref('sha256'),roots=array(text(65536),1024,1),roles=dict(type='object',additionalProperties=False,properties={k:ref('roleRecord') for k in ['targets','snapshot','timestamp']}),floors=dict(type='object',additionalProperties=False,properties={k:ref('floor') for k in ['core','malicious','full']}),maximum_verification_time=ref('utc'),generation=integer(),pending=nullable(ref('pending')),completed=dict(**mapping(ref('receipt')),propertyNames=ref('sha256'))))
# Freeze the existing bundle descriptor schema without creating a runtime resolver.
B=json.loads((ROOT/'schemas/secureflow-catalog-bundle-v1.schema.json').read_text())['$defs']
for k,v in B.items():
    if k not in D: D[k]=v

def used_refs(v):
    result=set()
    if isinstance(v,dict):
        for k,val in v.items():
            if k=='$ref': result.add(val.removeprefix('#/$defs/'))
            else: result.update(used_refs(val))
    elif isinstance(v,list):
        for val in v: result.update(used_refs(val))
    return result

def generate():
    for kind in ['target','policy','receipt','state']:
        name='secureflow-catalog-'+('target' if kind=='target' else 'trust-'+kind)+'-v1'
        base=copy.deepcopy(D[kind]); needed=used_refs(base)
        while True:
            expanded=needed.union(*(used_refs(D[k]) for k in needed))
            if expanded==needed: break
            needed=expanded
        schema={'$schema':'https://json-schema.org/draft/2020-12/schema','$id':'https://secureflow.dev/schemas/'+name+'.schema.json','title':name,**base,'$defs':{k:D[k] for k in sorted(needed)}}
        (ROOT/'schemas'/f'{name}.schema.json').write_text(json.dumps(schema,indent=2,ensure_ascii=False)+'\n')
if __name__=='__main__': generate()
