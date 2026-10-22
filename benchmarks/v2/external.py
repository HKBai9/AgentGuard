"""Pinned AgentDojo bridge with real environment calls and independent scorers.

Install in its separate environment. Tool effects/destinations are explicitly
mapped by the host; unknown functions are not silently labeled READ.
"""
import argparse
import asyncio
from copy import deepcopy
from importlib.metadata import distribution
import json
from pathlib import Path

from agentguard.v2.application import cloud, load_settings
from agentguard.v2.adapters.host import CloudAgentModel, HostAdapter
from agentguard.v2.bootstrap import build_runtime
from agentguard.v2.common import RuntimeFault, canonical, new_id
from agentguard.v2.contracts import *
from agentguard.v2.registry import ToolRegistry
from agentguard.v2.state.lineage import public_labels
from agentguard.v2.policy.compiler import PolicyCompiler
from agentguard.v2.review.context import ContextBuilder
from agentguard.v2.review.reviewers import Reviewer
from agentguard.v2.review.service import GuardService

AGENTDOJO_COMMIT='089ed468cf3ed0322acc66b0211f26d9d90dbf60'


def require_pinned_agentdojo():
    raw=distribution('agentdojo').read_text('direct_url.json')
    record=json.loads(raw or '{}')
    if record.get('vcs_info',{}).get('commit_id') != AGENTDOJO_COMMIT:
        raise RuntimeError('Install the exact AgentDojo VCS commit from requirements-agentdojo.txt')


def json_value(value):
    if hasattr(value,'model_dump'):
        return value.model_dump(mode='json')
    if isinstance(value,(tuple,list)):
        return [json_value(v) for v in value]
    if isinstance(value,dict):
        return {str(k):json_value(v) for k,v in value.items()}
    return value


def bridge_tools(dojo_runtime, environment, mappings, executions):
    registry=ToolRegistry()
    for name, mapping in mappings['tools'].items():
        if name not in dojo_runtime.functions:
            raise ValueError('Mapped function missing from pinned suite: '+name)
        function=dojo_runtime.functions[name]
        schema=deepcopy(function.parameters.model_json_schema())
        bindings=mapping.get('destination_bindings',{})
        destination_fields=set(mapping.get('destination_fields',[]))
        if 'SEND' in mapping['effects'] and (not bindings or not destination_fields):
            raise ValueError('SEND requires complete host-owned destination bindings')
        if bindings:
            if any(set(v)!=destination_fields for v in bindings.values()):
                raise ValueError('Every destination must bind every outgoing destination field')
            for field in destination_fields:
                schema['properties'].pop(field,None)
            schema['required']=[k for k in schema.get('required',[]) if k not in destination_fields]+['destination']
            schema['properties']['destination']={'type':'string','enum':list(bindings)}
        schema['additionalProperties']=False
        # Schema wrapper is finite; arguments are validated by both runtimes.
        def handler_factory(tool_name, binding_map):
            def handle(**args):
                args=dict(args)
                if binding_map:
                    did=args.pop('destination')
                    if did not in binding_map:
                        raise RuntimeFault('DESTINATION_OUT_OF_SCOPE')
                    args.update(deepcopy(binding_map[did]))
                # Deny nested FunctionCall execution outside Runtime gates.
                def nested(value):
                    if hasattr(value,'function') and hasattr(value,'args'):
                        return True
                    if isinstance(value,dict):
                        return any(nested(v) for v in value.values())
                    if isinstance(value,list):
                        return any(nested(v) for v in value)
                    return False
                if nested(args):
                    raise RuntimeFault('NESTED_TOOL_CALL_FORBIDDEN')
                output,error=dojo_runtime.run_function(environment,tool_name,args)
                executions.append({'function':tool_name,'args':deepcopy(args),'error':bool(error)})
                if error:
                    from agentguard.v2.execution.executor import ToolExecutionFailure
                    raise ToolExecutionFailure({'error':error})
                return json_value(output)
            return handle
        registry.register(make(ToolManifest,tool_id=name,manifest_version='agentdojo-'+AGENTDOJO_COMMIT[:12],
            parameters_schema=schema,effects=mapping['effects'],resource_parameter=None,
            destination_parameter='/destination' if bindings else None,artifact_parameters={},
            return_media_type='application/json',supports_idempotency_key=False,
            output_labels=DataLabels.model_validate_json(canonical(mapping['output_labels'])) if mapping.get('output_labels') else public_labels('external'),
            synthetic_demo=True),handler_factory(name,bindings))
    return registry


def make_pipeline(settings,mappings,directory,*,experiment_budget=None):
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.functions_runtime import FunctionCall
    class GuardedPipeline(BasePipelineElement):
        name='agentguard-v2'
        def __init__(self):
            self.records=[]
        def query(self,query,runtime,env,messages=(),extra_args=None):
            if messages:
                raise ValueError('External hidden histories must be registered before use')
            executions=[]
            usage_start=len(experiment_budget.records) if experiment_budget else 0
            registry=bridge_tools(runtime,env,mappings,executions)
            guard=cloud(settings['guard'],max_attempts=settings.get('max_attempts',1000),max_tokens=settings.get('max_tokens'),budget=experiment_budget)
            agent=cloud(settings['agent'],max_attempts=settings.get('max_attempts',1000),max_tokens=settings.get('max_tokens'),budget=experiment_budget)
            run_dir=Path(directory)/new_id('agentdojo')
            safety=build_runtime(run_dir,registry=registry,policy_generator=PolicyCompiler(guard),
                guard_service=GuardService(ContextBuilder(max_bytes=settings.get('max_review_bytes',512_000)),Reviewer(guard)))
            host=HostAdapter(safety,CloudAgentModel(agent),state_directory=run_dir/'host',max_turns=settings.get('max_turns',60))
            request=make(SessionRequest,trusted_task=query,host_policy=make(HostPolicy,
                rules=[make(PolicyRule,tool_id=m.tool_id,effect=e,resource_scope_ids=['dojo'],
                    destination_ids=list(mappings['tools'][m.tool_id].get('destination_bindings',{})),
                    allowed_uses=['analyze','write','send','reply','review','model'],max_calls=200) for m in registry.manifests() for e in m.effects],
                model_destination_ids=[make(ModelDestinationGrant,destination_id=c.destination_id,resource_scope_ids=['dojo']) for c in (guard,agent)],
                guard_destination_id=guard.destination_id,final_destination_id='user',final_use='reply',
                max_review_bytes=settings.get('max_review_bytes',512_000),permit_ttl_seconds=60,review_timeout_seconds=120.0),
                resource_catalog=make(ResourceCatalog,resources=[make(ResourceScope,scope_id='dojo',kind='logical',root='dojo',labels=public_labels('external'))],
                    destinations=[make(Destination,destination_id=c.destination_id,kind='model',address=c.config.endpoint,allowed_confidentiality=[]) for c in (guard,agent)] +
                        [make(Destination,destination_id='user',kind='user',address='agentdojo-user',allowed_confidentiality=[])] +
                        [Destination.model_validate_json(canonical(d)) for d in mappings.get('destinations',[])]),
                tool_manifests=registry.manifests(),confirmed_authorizations=mappings.get('confirmed_authorizations',[]),synthetic_demo=True)
            async def run():
                session=await host.create(request)
                return session,await host.run(session.session_id)
            session,result=asyncio.run(run())
            trace=[{'role':'user','content':[{'type':'text','content':query}]}]
            # Only actually dispatched calls enter upstream trace-based scoring.
            for call in executions:
                trace.append({'role':'assistant','content':None,'tool_calls':[
                    FunctionCall(function=call['function'],args=call['args'])]})
            trace.append({'role':'assistant','content':[{'type':'text','content':result.content or ''}], 'tool_calls':None})
            self.records.append({'session_id':session.session_id,'status':result.status,'directory':str(run_dir),
                'usage':experiment_budget.records[usage_start:] if experiment_budget else guard.budget.records+agent.budget.records,
                'executions':executions})
            return query,runtime,env,trace,extra_args or {}
    return GuardedPipeline()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True); parser.add_argument('--mapping',required=True)
    parser.add_argument('--output',default='logs/v2-agentdojo')
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--max-model-attempts',type=int,default=200)
    parser.add_argument('--max-total-tokens',type=int)
    args=parser.parse_args()
    mapping=json.loads(Path(args.mapping).read_text(encoding='utf-8'))
    if not args.execute:
        print(canonical({'mode':'plan','commit':AGENTDOJO_COMMIT,'tasks':mapping['tasks']})); return
    require_pinned_agentdojo()
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.functions_runtime import FunctionsRuntime
    suite=get_suite(mapping.get('benchmark_version','v1.2.2'),mapping.get('suite','workspace'))
    output=Path(args.output).resolve(); output.mkdir(parents=True,exist_ok=True)
    from agentguard.v2.review.budget import Budget
    pool=Budget(max_attempts=args.max_model_attempts,max_tokens=args.max_total_tokens)
    pipeline=make_pipeline(load_settings(args.config),mapping,output,experiment_budget=pool)
    rows=[]
    for entry in mapping['tasks']:
        user_task=suite.get_user_task_by_id(entry['user_task'])
        attack_task=suite.get_injection_task_by_id(entry['injection_task']) if entry.get('injection_task') else None
        env=suite.load_and_inject_default_environment(entry.get('injections',{}))
        # Exclude tasks whose known ground truth requires unsupported tools;
        # rejection of an unknown tool must not become a defense advantage.
        needed={c.function for c in user_task.ground_truth(user_task.init_environment(env.model_copy(deep=True)))}
        if attack_task:
            needed.update(c.function for c in attack_task.ground_truth(env.model_copy(deep=True)))
        row={'user_task':entry['user_task'],'injection_task':entry.get('injection_task'),'unknown':False}
        if not needed <= mapping['tools'].keys():
            row.update(excluded=True,reason='UNSUPPORTED_COMMON_SUBSET',missing=sorted(needed-mapping['tools'].keys()))
        else:
            try:
                utility,attack_success=suite.run_task_with_pipeline(pipeline,user_task,attack_task,entry.get('injections',{}))
                row.update(task_success=utility,attack_success=attack_success if attack_task else None,excluded=False)
            except Exception:
                row.update(unknown=True,task_success=None,attack_success=None,excluded=False,reason='EXTERNAL_RUN_FAILED')
        rows.append(row)
        (output/'results.json').write_text(json.dumps({'source_commit':AGENTDOJO_COMMIT,'rows':rows,
            'runs':pipeline.records,'usage_records':pool.records,'budget':{'attempts':pool.attempts,'max_attempts':pool.max_attempts,
                'tokens':pool.tokens,'usage_unknown':pool.usage_unavailable,
                'stopped':pool.exhausted or pool.attempts>=pool.max_attempts}},ensure_ascii=False,indent=2),encoding='utf-8')
        if pool.exhausted or pool.attempts>=pool.max_attempts:
            break


if __name__=='__main__':
    main()
