import json
import math
import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError
from agentguard.v2 import contracts as c
from agentguard.v2.common import canonical, strict_loads, RuntimeFault, digest, at_pointer
from agentguard.v2.schema import export
from agentguard.v2.registry import normalize_endpoint, Catalog
from agentguard.v2.policy.validator import validate_candidate
from conftest import proposal

@pytest.mark.parametrize('field,value',[('schema_version','0.2'),('unexpected',1),('manifest_version',None),('args',{'x':float('nan')}),('args',{'x':object()})])
def test_contract_rejects_bad_fields(field,value):
    data=proposal().model_dump()
    data[field]=value
    with pytest.raises((ValidationError,RuntimeFault)):
        c.ToolProposal.model_validate(data)

@pytest.mark.parametrize('raw',['{"x":1,"x":2}','{"x":NaN}','{"x":Infinity}','{"x":1e1000}','[1,]'])
def test_strict_json(raw):
    with pytest.raises(RuntimeFault):
        strict_loads(raw)

@pytest.mark.parametrize('raw',[{'x':(1,2)},{1:'a'},b'abc',float('inf')])
def test_canonical_rejects_non_json(raw):
    with pytest.raises(RuntimeFault):
        canonical(raw)

def test_digest_and_unicode_pointer():
    assert digest({'b':2,'a':1})==digest({'a':1,'b':2})
    assert at_pointer({'a/b':['中😀']},'/a~1b/0')=='中😀'
    for p in ['/a~2','/a~1b/-1','/a~1b/00']:
        with pytest.raises(RuntimeFault):
            at_pointer({'a/b':['x']},p)

def test_all_schemas_export(tmp_path,harness):
    names=export(tmp_path)
    assert len(names)>=40
    for name in names:
        schema=json.loads((tmp_path/(name+'.json')).read_text())
        Draft202012Validator.check_schema(schema)
        assert schema['additionalProperties'] is False
    schema=json.loads((tmp_path/'SessionRequest.json').read_text())
    Draft202012Validator(schema).validate(harness.request.model_dump(mode='json'))

def test_endpoint_normalization():
    assert normalize_endpoint('https://EXAMPLE.com/report')=='https://example.com:443/report'
    for value in ['https://user:password@example.com','https://example.com/report?secret=x','https://example.com/%2e%2e','file:///etc/passwd']:
        with pytest.raises(RuntimeFault):
            normalize_endpoint(value)

@pytest.mark.asyncio
async def test_policy_expansion_and_unknown_refs(harness):
    h=harness
    s=await h.session()
    _,req,old=h.runtime.components(s.session_id)
    original=c.make(c.PolicyCandidate,session_id=s.session_id,base_policy_version=old.policy_version,rules=old.rules,
        model_destination_ids=old.model_destination_ids,rationale='reason',evidence_refs=[],unresolved_requirements=[])
    tight=original.model_copy(update={'rules':[old.rules[0].model_copy(update={'max_calls':1})]})
    committed=await h.runtime.apply_policy(tight)
    assert committed.change_kind=='TIGHTENING'
    expanded=original.model_copy(update={'base_policy_version':committed.policy_version})
    with pytest.raises(RuntimeFault,match='POLICY_EXPANSION_REQUIRES_AUTHORIZATION'):
        await h.runtime.apply_policy(expanded)
    bad=tight.model_copy(update={'base_policy_version':committed.policy_version,'rules':[old.rules[0].model_copy(update={'resource_scope_ids':['invented']})]})
    with pytest.raises(RuntimeFault,match='UNKNOWN_RESOURCE'):
        await h.runtime.apply_policy(bad)

@pytest.mark.asyncio
async def test_cross_session_and_modified_call(harness):
    h=harness
    a,b=await h.session(),await h.session()
    _,out=await h.propose(a.session_id,[proposal()])
    call=out.calls[0]
    assert (await h.runtime.execute_call(call.model_copy(update={'session_id':b.session_id}))).status=='BLOCKED'
    assert (await h.runtime.execute_call(call.model_copy(update={'args':{'resource':'reports'}}))).reason_code=='CALL_BINDING_MISMATCH'
    assert h.reads==[]

def test_wire_json_rejects_duplicate_keys():
    with pytest.raises(RuntimeFault,match='DUPLICATE_JSON_KEY'):
        c.ToolProposal.model_validate_json('{"schema_version":"0.1","schema_version":"0.1"}')


def test_missing_field_does_not_create_unrestricted_policy(harness):
    data=harness.request.model_dump(mode='json')
    del data['host_policy']['rules']
    with pytest.raises(ValidationError):
        c.SessionRequest.model_validate_json(json.dumps(data))


def test_failed_result_cannot_carry_raw_content():
    with pytest.raises(ValidationError):
        c.make(c.CallResult,session_id='s',turn_id='t',call_id='c',status='BLOCKED',reason_code='BLOCKED',
            content='PRIVATE',artifact_ref=None,receipt=None)


def test_committed_handoff_examples():
    from pathlib import Path
    root=Path(__file__).resolve().parents[3]/'docs/v2/examples'
    for folder in ['normal_allow','injection_block','field_redact','guard_failure']:
        c.ContextMaterial.model_validate_json((root/folder/'material.json').read_bytes())
        c.ReviewOutcome.model_validate_json((root/folder/'outcome.json').read_bytes())
        c.BatchResult.model_validate_json((root/folder/'result.json').read_bytes())
    with pytest.raises(ValidationError):
        c.ReviewOutcome.model_validate_json((root/'guard_failure/invalid_schema.json').read_bytes())


def test_import_contract_needs_no_cloud_keys():
    import os,subprocess,sys
    environment={k:v for k,v in os.environ.items() if 'KEY' not in k and 'TOKEN' not in k}
    result=subprocess.run([sys.executable,'-c','from agentguard.v2.contracts import Permit, ReviewDecision; from agentguard.v2.ports import RuntimePort; print("offline import ok")'],env=environment,capture_output=True,text=True)
    assert result.returncode==0 and result.stdout.strip()=='offline import ok'

def test_path_prefix_symlink_and_separator(tmp_path):
    from agentguard.v2.state.lineage import public_labels
    allowed=tmp_path/'safe'
    allowed.mkdir()
    outside=tmp_path/'outside'
    outside.mkdir()
    catalog=Catalog(c.make(c.ResourceCatalog,resources=[c.make(c.ResourceScope,scope_id='safe',kind='path',root=str(allowed),labels=public_labels())],destinations=[]))
    assert catalog.matching_scopes(str(allowed/'report'))==['safe']
    import os
    candidates=[tmp_path/'safeevil'/'report',allowed/'..'/'outside'/'report']
    if os.name != 'nt':
        candidates.append(tmp_path/'safe\\report')
    for candidate in candidates:
        with pytest.raises(RuntimeFault): catalog.matching_scopes(str(candidate))
    link=allowed/'link'
    try: link.symlink_to(outside,target_is_directory=True)
    except OSError: pytest.skip('symlink creation unavailable')
    with pytest.raises(RuntimeFault):catalog.matching_scopes(str(link/'report'))


def test_remote_schema_refs_and_endpoint_edge_cases(harness):
    entry=harness.runtime.registry.get('read_document')
    with pytest.raises(RuntimeFault,match='REMOTE_SCHEMA_REFERENCE_FORBIDDEN'):
        harness.runtime.registry.register(entry.manifest.model_copy(update={'manifest_version':'v2','parameters_schema':{'$ref':'https://untrusted.invalid/schema'}}),entry.handler)
    for url in ['https://receiver.test:0/report','https://*.receiver.test/report','https://receiver.test/\nreport']:
        with pytest.raises(RuntimeFault):normalize_endpoint(url)
