"""Deliberately weaker baselines, confined to synthetic benchmark tools."""
from agentguard.v2.common import RuntimeFault, digest, new_id
from agentguard.v2.contracts import *
from agentguard.v2.execution.executor import dispatch


class HostBoundPolicy:
    """Declared host grants for a model-only baseline, not dynamic compilation."""
    async def generate(self, req):
        return make(PolicyCandidate, session_id=req.session_id, base_policy_version=req.current_policy_version,
            rules=req.host_policy.rules, model_destination_ids=req.host_policy.model_destination_ids,
            rationale='Synthetic baseline: use explicit host grants', evidence_refs=[], unresolved_requirements=[])


class AllowReviewer:
    """Fault injection for program-constraint demonstrations; no semantic model."""
    async def inspect(self, m):
        return make(ReviewOutcome,status='DECIDED',failure=None,decision=make(ReviewDecision,
            review_id=m.review_id,session_id=m.session_id,turn_id=m.turn_id,call_id=m.call_id,phase=m.phase,
            policy_version=m.policy.policy_version,context_version=m.context_version,subject_ref=m.subject_ref,
            decision='ALLOW',reason_code='NORMAL_CONTENT',reason_summary='Explicit evaluation-only all-allow stub',
            evidence_refs=[m.subject_ref],findings=[],redaction_targets=[],requested_evidence_refs=[],
            usage=make(Usage,provider='synthetic',model='all-allow',input_tokens=0,output_tokens=0,latency_ms=0.0,attempts=0)))


class ScriptedGuardCloud:
    """A full ContextBuilder/Reviewer path with explicit all-allow scripted inference."""
    provider='synthetic'
    model='scripted-all-allow-no-inference'
    def __init__(self,destination_id='guard'):
        self.destination_id=destination_id
    async def complete(self,*,messages,purpose,prompt_version):
        import json
        from agentguard.v2.review.clients import CloudReply
        boundary=json.loads(messages[1]['content'])['trusted_boundary']
        keys=('schema_version','review_id','session_id','turn_id','call_id','phase','policy_version','context_version','subject_ref')
        result={k:boundary[k] for k in keys}
        result.update(decision='ALLOW',reason_code='NORMAL_CONTENT',reason_summary='Scripted all-allow fault injection',
            evidence_refs=[boundary['subject_ref']],findings=[],redaction_targets=[],requested_evidence_refs=[])
        return CloudReply(json.dumps(result),{'provider':self.provider,'model':self.model,'input_tokens':0,
            'output_tokens':0,'latency_ms':0.0,'attempts':0})


class PhaseReviewer:
    def __init__(self, guard, *, skip_result=False):
        self.guard, self.skip_result = guard, skip_result
        self.allow = AllowReviewer()
        self.skipped_review_ids=set()
        self.supports_context_budgeting=getattr(guard,'supports_context_budgeting',False)
    async def inspect(self, material):
        if self.skip_result and material.phase == 'RESULT':
            self.skipped_review_ids.add(material.review_id)
            return await self.allow.inspect(material)
        return await self.guard.inspect(material)
    def clear_session(self, sid):
        if hasattr(self.guard,'clear_session'):
            self.guard.clear_session(sid)
    def take_trace(self,review_id,supplemental_attempt):
        return self.guard.take_trace(review_id,supplemental_attempt) if hasattr(self.guard,'take_trace') else None


class LegacyGate:
    """Actual v1 guard for its common READ/WRITE subset only.

    v1 has no semantically equivalent generic POST tool. Such calls are marked
    non-comparable, never credited as a successful block of an unknown tool.
    """
    def __init__(self, directory, task):
        from agentguard.baseline import PermissionBaseline
        from agentguard.guard import GuardConfig, SandboxGuard
        cfg={'tools':{'allow':['read_file','write_file']},
            'resources':{'files':{'read':['/sandbox_fake/docs/**'],'write':['/sandbox_fake/reports/**']}},
            'experiment':{'task_baseline':{'goal':task}},
            'response':{'audit_log':str(directory / 'legacy-audit.jsonl')}}
        self.guard=SandboxGuard(PermissionBaseline(cfg), config=GuardConfig(enable_rollback=False))
        self.step=0
    def check(self, call):
        from agentguard.action import build_action
        from agentguard.types import ToolCall
        if call.tool_id not in ('read_document','write_report'):
            raise RuntimeFault('UNSUPPORTED_BASELINE_ACTION')
        tool='read_file' if call.tool_id=='read_document' else 'write_file'
        args={'path':'/sandbox_fake/' + call.args['resource'] + '/document.txt'}
        if tool=='write_file':
            args['content']=call.args['body']
        self.step+=1
        old=ToolCall(tool=tool,args=args,step=self.step,call_id=call.call_id)
        view=build_action(tool,args)
        issue=self.guard.authority.issue(tool,view,self.step)
        self.last_call,self.last_token=old,issue.token
        verdict,_=self.guard.evaluate(old,token=issue.token,view=view,refusal=issue.reason)
        return verdict.allowed

    def record_result(self,value):
        from agentguard.types import ToolResult
        from agentguard.v2.common import canonical
        self.guard.record_result(self.last_call,ToolResult(ok=True,output=value if isinstance(value,str) else canonical(value),executed=True))
        if self.last_token:
            self.guard.authority.consume(self.last_token)


class UnprotectedRuntime:
    """Same HostAdapter and model, directly executed synthetic tools. No permits."""
    def __init__(self, registry, *, legacy=None):
        if not all(m.synthetic_demo for m in registry.manifests()):
            raise ValueError('Benchmark runtime accepts only synthetic tool manifests')
        self.registry,self.legacy=registry,legacy
        self.values,self.outputs,self.requests={}, {}, {}
        self.unreviewed_releases=0
        self.comparable=True
    def _put(self,sid,content):
        ref=make(EvidenceRef,artifact_id=new_id('synthetic'),version=1,sha256=digest(content),span=None,json_pointer=None)
        self.values[(sid,ref.artifact_id)]=content
        return ref
    async def create_session(self,req):
        if not req.synthetic_demo:
            raise ValueError('Benchmark-only runtime')
        sid=new_id('benchmark'); self.requests[sid]=req
        return make(SessionView,session_id=sid,status='ACTIVE',policy_version='unprotected',context_version=None,relevant_security_revision=0)
    async def register_host_input(self,req):
        return self._put(req.session_id,req.content)
    async def prepare_model_turn(self,req):
        task=self._put(req.session_id,self.requests[req.session_id].trusted_task)
        messages=[make(PreparedMessage,role='user',content=self.requests[req.session_id].trusted_task,ref=task)]
        messages.extend(make(PreparedMessage,role=m.role,content=self.values[(req.session_id,m.ref.artifact_id)],ref=m.ref) for m in req.messages)
        return make(PreparedTurn,session_id=req.session_id,turn_id=new_id('turn'),model_call_id=new_id('model'),
            context_version=new_id('context'),messages=messages,model_destination_id=req.model_destination_id)
    async def record_model_output(self,req):
        output=self._put(req.session_id,req.content); turn=new_id('turn')
        calls=[make(ToolCall,session_id=req.session_id,turn_id=turn,call_id=new_id('call'),
            input_context_version=req.context_version,**p.model_dump(exclude={'schema_version'})) for p in req.tool_proposals]
        self.outputs[output.artifact_id]=req.content
        return make(ProposedTurn,session_id=req.session_id,turn_id=turn,output_ref=output,calls=calls)
    async def execute_batch(self,req):
        results={}
        for call in req.calls:
            if self.legacy:
                try:
                    allowed=self.legacy.check(call)
                except RuntimeFault:
                    self.comparable=False
                    raise
            else:
                allowed=True
            if not allowed:
                results[call.call_id]=make(CallResult,session_id=req.session_id,turn_id=req.turn_id,call_id=call.call_id,
                    status='BLOCKED',reason_code='LEGACY_BLOCKED',content=None,artifact_ref=None,receipt=None)
                continue
            try:
                entry=self.registry.get(call.tool_id)
                value=await dispatch(entry.handler,call.args)
                if self.legacy:
                    self.legacy.record_result(value)
                ref=self._put(req.session_id,value)
                self.unreviewed_releases+=1
                results[call.call_id]=make(CallResult,session_id=req.session_id,turn_id=req.turn_id,call_id=call.call_id,
                    status='RELEASED',reason_code='UNPROTECTED_RESULT',content=value,artifact_ref=ref,receipt=None)
            except Exception:
                results[call.call_id]=make(CallResult,session_id=req.session_id,turn_id=req.turn_id,call_id=call.call_id,
                    status='UNKNOWN',reason_code='SYNTHETIC_EFFECT_UNKNOWN',content=None,artifact_ref=None,receipt=None)
        return make(BatchResult,session_id=req.session_id,turn_id=req.turn_id,results=results)
    async def finalize(self,req):
        self.unreviewed_releases+=1
        return make(FinalizedOutput,session_id=req.session_id,status='RELEASED',reason_code='UNPROTECTED_FINAL',
            content=self.outputs[req.output_ref.artifact_id],artifact_ref=req.output_ref)
