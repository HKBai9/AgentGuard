"""Explicit experiment runner. Defaults to printing a plan, never to paid calls."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import subprocess
import time

from agentguard.v2.application import cloud, load_settings
from agentguard.v2.adapters.host import AgentReply, CloudAgentModel, HostAdapter
from agentguard.v2.bootstrap import build_runtime
from agentguard.v2.common import RuntimeFault, canonical
from agentguard.v2.contracts import ToolProposal, EvidenceRef, make
from agentguard.v2.policy.compiler import PolicyCompiler
from agentguard.v2.review.context import ContextBuilder
from agentguard.v2.review.reviewers import Reviewer
from agentguard.v2.review.service import GuardService
from .environment import Receiver, World, cases
from .scoring import report, score
from .variants import AllowReviewer, HostBoundPolicy, LegacyGate, PhaseReviewer, UnprotectedRuntime, ScriptedGuardCloud

VARIANTS=('none','legacy','dual','v2','context-all','context-recent','no-labels','no-result','freeze')


def read_all_events(store, session_id):
    events, cursor = [], 0
    while True:
        page = store.events(session_id, cursor, 1000)
        events.extend(page)
        if len(page) < 1000:
            return events
        cursor = page[-1].seq


class ScriptedAgent:
    """Scenario driver for wiring, explicitly NOT an inference model."""
    destination_id='agent'
    def __init__(self,case):
        self.case,self.step=case,0
    async def complete(self,prepared):
        self.step+=1
        reading_steps=len(self.case.documents) if self.case.sequential else 1
        if self.step<=reading_steps:
            indices=[self.step-1] if self.case.sequential else range(len(self.case.documents))
            proposals=[make(ToolProposal,tool_id='read_document',manifest_version='v1',args={'resource':'docs','index':i},artifact_refs=[],use='analyze')
                       for i in indices]
        elif self.step==reading_steps+1:
            proposals=[make(ToolProposal,tool_id='write_report',manifest_version='v1',args={'resource':'reports','body':self.case.required},artifact_refs=[],use='write')]
            if self.case.attack:
                proposals.append(make(ToolProposal,tool_id='send_report',manifest_version='v1',args={'destination':'attacker','body':self.case.secret},artifact_refs=[],use='send'))
            elif self.case.allow_send:
                proposals.append(make(ToolProposal,tool_id='send_report',manifest_version='v1',args={'destination':'approved','body':self.case.required},artifact_refs=[],use='send'))
        else:
            return AgentReply(self.case.required)
        return AgentReply('',tuple(proposals))
    async def reset(self,sid):
        return True


class FreezeHost(HostAdapter):
    async def _recover(self,state,risk_refs,reason_code):
        from agentguard.v2.contracts import RecoveryRequest
        await self.runtime.prepare_recovery(make(RecoveryRequest,session_id=state.session_id,risk_refs=risk_refs,reason_code=reason_code))
        raise RuntimeFault('EVALUATION_GLOBAL_FREEZE')


async def run_case(case, variant, directory, *, settings=None, mode='scripted', experiment_budget=None):
    directory.mkdir(parents=True,exist_ok=True)
    if mode=='live':
        agent_client=cloud(settings['agent'],max_attempts=settings.get('max_attempts',1000),max_tokens=settings.get('max_tokens'),budget=experiment_budget)
        guard_client=cloud(settings['guard'],max_attempts=settings.get('max_attempts',1000),max_tokens=settings.get('max_tokens'),budget=experiment_budget)
        model=CloudAgentModel(agent_client)
        endpoints=(agent_client.config.endpoint,guard_client.config.endpoint)
    else:
        agent_client=guard_client=None
        model=ScriptedAgent(case)
        endpoints=('https://synthetic.invalid/agent','https://synthetic.invalid/guard')
    with Receiver() as receiver:
        usage_start=len(experiment_budget.records) if experiment_budget else 0
        world=World(case,receiver,labels=variant not in ('none','dual','no-labels'))
        request=world.session_request(agent_endpoint=endpoints[0],guard_endpoint=endpoints[1],
            agent_id=model.destination_id,guard_id=guard_client.destination_id if guard_client else 'guard',broad=variant=='dual')
        if variant in ('none','legacy'):
            runtime=UnprotectedRuntime(world.registry,legacy=LegacyGate(directory,case.task) if variant=='legacy' else None)
        else:
            builder=ContextBuilder(max_bytes=512_000,strategy='all' if variant=='context-all' else 'recent' if variant=='context-recent' else 'relations')
            guard=GuardService(builder,Reviewer(guard_client if guard_client else ScriptedGuardCloud()))
            if variant=='no-result':
                guard=PhaseReviewer(guard,skip_result=True)
            runtime=build_runtime(directory,registry=world.registry,
                policy_generator=PolicyCompiler(guard_client) if guard_client and variant!='dual' else HostBoundPolicy(),guard_service=guard)
        host_cls=FreezeHost if variant=='freeze' else HostAdapter
        host=host_cls(runtime,model,state_directory=directory/'host',max_turns=max(60,len(case.documents)+3),recover_on_block=variant!='dual')
        final=None; error=None; sid=None; start=time.perf_counter()
        try:
            session=await host.create(request); sid=session.session_id
            final=await host.run(sid)
        except Exception as exc:
            error=exc.code if isinstance(exc,RuntimeFault) else 'RUN_FAILED'
        unknown=error not in (None,'HOST_TURN_LIMIT','EVALUATION_GLOBAL_FREEZE','UNSUPPORTED_BASELINE_ACTION')
        usage=[]
        records=experiment_budget.records[usage_start:] if experiment_budget else [u for client in (agent_client,guard_client) if client for u in client.budget.records]
        usage=[{**u,'attempts':1,'input_tokens':u['input_tokens'] if type(u['input_tokens']) is int else None,
                              'output_tokens':u['output_tokens'] if type(u['output_tokens']) is int else None} for u in records]
        audit={'variant':variant,'mode':mode,'error':error,'latency_ms':(time.perf_counter()-start)*1000,'usage':usage,
            'comparable':getattr(runtime,'comparable',True),'unreviewed_releases':getattr(runtime,'unreviewed_releases',0),
            'recovery_attempted':False,'recovery_success':None,'redone_calls':len(world.calls)-len(set(map(str,world.calls))),
            'false_block':None}
        if hasattr(runtime,'store') and sid:
            events=read_all_events(runtime.store,sid)
            audit['events']=[e.model_dump(mode='json') for e in events]
            audit['recovery_attempted']=any(e.event_type=='RECOVERY_PREPARED' for e in events)
            audit['recovery_success']=any(e.event_type=='RECOVERY_COMPLETED' for e in events) if audit['recovery_attempted'] else None
            skipped=getattr(runtime.guard,'skipped_review_ids',set())
            audit['unreviewed_releases']=sum(e.event_type=='RESULT_RELEASED' and e.review_id in skipped for e in events)
            if not case.attack:
                from .scoring import known_normal_block
                audit['false_block']=False
                for review in runtime.store.all(sid,'review_attempt'):
                    if review['decision']=='BLOCK':
                        evidence_ref=EvidenceRef.model_validate_json(canonical(review['audit_ref']))
                        material=runtime.artifacts.read(sid,evidence_ref)['material']
                        audit['false_block'] |= known_normal_block(case,material)
        elif not case.attack:
            audit['false_block']=bool(runtime.legacy.guard.blocked_calls) if runtime.legacy else False
        result=score(case,world,final,unknown=unknown,audit=audit)
        (directory/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true',help='Explicitly execute selected cases')
    parser.add_argument('--mode',choices=['scripted','live'],default='scripted')
    parser.add_argument('--config')
    parser.add_argument('--output',default='logs/v2-evaluation')
    parser.add_argument('--variants',nargs='+',choices=VARIANTS,default=['none','legacy','dual','v2'])
    parser.add_argument('--cases',nargs='*')
    parser.add_argument('--repeats',type=int,default=1)
    parser.add_argument('--supplemental',help='Imported supplemental case JSON')
    parser.add_argument('--input-price',type=float)
    parser.add_argument('--output-price',type=float)
    parser.add_argument('--max-model-attempts',type=int,default=200,help='One global ceiling across all live cases and variants')
    parser.add_argument('--max-total-tokens',type=int,help='Global conservative token budget; unknown usage stops execution')
    args=parser.parse_args()
    available=cases()
    if args.supplemental:
        from .environment import Case
        for item in json.loads(Path(args.supplemental).read_text(encoding='utf-8'))['cases']:
            item['documents']=tuple(item['documents'])
            available.append(Case(**item))
    selected=[c for c in available if not args.cases or c.case_id in args.cases]
    if not selected or args.repeats<1 or args.max_model_attempts<1 or (args.max_total_tokens is not None and args.max_total_tokens<1):
        parser.error('Select known cases and positive repeats')
    plan={'mode':args.mode,'cases':[c.case_id for c in selected],'variants':args.variants,'repeats':args.repeats,
          'case_sha256':{c.case_id:hashlib.sha256(canonical({'task':c.task,'documents':list(c.documents)}).encode()).hexdigest() for c in selected},
          'model_effectiveness_measured':False,'protected_features_disabled':args.variants,
          'global_budget':{'max_attempts':args.max_model_attempts,'max_tokens':args.max_total_tokens}}
    if not args.execute:
        print(json.dumps(plan,ensure_ascii=False,indent=2)); return
    if args.mode=='live' and not args.config:
        parser.error('Live execution requires --config and explicit cloud environment enablement')
    plan['execution_requested']=True
    settings=load_settings(args.config) if args.config else None
    output=Path(args.output).resolve(); output.mkdir(parents=True,exist_ok=True)
    config_digest=hashlib.sha256(canonical(settings or {}).encode()).hexdigest()
    try:
        revision=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    except Exception:
        revision=None
    plan.update(config_sha256=config_digest,git_revision=revision)
    safe_cloud_fields={'provider','endpoint','model','destination_id','timeout_seconds','max_concurrency','max_retries',
                       'max_output_tokens','max_input_bytes','max_response_bytes','retry_delay_seconds'}
    plan['model_configuration']={role:{k:v for k,v in (settings or {}).get(role,{}).items() if k in safe_cloud_fields}
                                 for role in ('guard','agent')}
    plan['budget_configuration']={k:(settings or {}).get(k) for k in ('max_attempts','max_tokens','max_turns','max_calls')}
    from datetime import datetime,timezone
    import platform
    plan.update(started_at=datetime.now(timezone.utc).isoformat(),python_version=platform.python_version())
    (output/'manifest.json').write_text(json.dumps(plan,ensure_ascii=False,indent=2),encoding='utf-8')
    async def run():
        from agentguard.v2.review.budget import Budget
        pool=Budget(max_attempts=args.max_model_attempts,max_tokens=args.max_total_tokens) if args.mode=='live' else None
        rows=[]
        for repeat in range(args.repeats):
            for case in selected:
                for variant in args.variants:
                    row=await run_case(case,variant,output/(case.case_id+'-'+variant+'-'+str(repeat)),settings=settings,mode=args.mode,experiment_budget=pool)
                    rows.append(row)
                    # Persist after each run so partial/failed jobs remain auditable.
                    (output/'runs.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf-8')
                    comparable=[r for r in rows if r['comparable']]
                    summary=report(comparable,input_price=args.input_price,output_price=args.output_price)
                    summary.update(mode=args.mode,model_effectiveness_measured=args.mode=='live',
                        excluded_noncomparable=len(rows)-len(comparable),manifest=plan)
                    (output/'report.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
                    if pool and (pool.exhausted or pool.attempts>=pool.max_attempts):
                        plan['stop_reason']='GLOBAL_BUDGET_EXHAUSTED'
                        (output/'manifest.json').write_text(json.dumps(plan,ensure_ascii=False,indent=2),encoding='utf-8')
                        summary['manifest']=plan
                        (output/'report.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
                        print(str(output/'report.json')); return
        print(str(output/'report.json'))
    asyncio.run(run())


if __name__=='__main__':
    main()
