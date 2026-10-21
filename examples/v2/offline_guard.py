"""Run explicitly synthetic B01/B02/B03 playback, without network or credentials."""

import asyncio
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from agentguard.v2.policy.compiler import PolicyCompiler
from agentguard.v2.review.context import ContextBuilder
from agentguard.v2.review.reviewers import Reviewer
from agentguard.v2.review.service import GuardService


async def main():
    spec = importlib.util.spec_from_file_location("v2_offline_fakes", ROOT / "tests/v2/guard/fakes.py")
    fakes = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fakes)
    codec = fakes.FixtureContracts()
    results = {"mode": "synthetic_offline_playback", "public_contract_validated": False,
               "runtime_integrated": False, "policy": {}, "reviews": {}}
    for task in ("local", "send"):
        client = fakes.FakeCloudClient([fakes.fixture("policy_local_vs_send", task + "_candidate.json")])
        compiler = PolicyCompiler(client, contracts=codec)
        candidate = await compiler.generate(fakes.fixture("policy_local_vs_send", task + "_request.json"))
        results["policy"][task] = [r["effect"] for r in candidate["rules"]]
    for group in ("normal_allow", "injection_block", "field_redact", "guard_failure"):
        client = fakes.FakeCloudClient(["{" if group == "guard_failure" else
                                        fakes.fixture(group, "model_response.json")])
        guard = GuardService(ContextBuilder(contracts=codec), Reviewer(client, contracts=codec), contracts=codec)
        result = await guard.inspect(fakes.fixture(group))
        results["reviews"][group] = (result["decision"]["decision"] if result["status"] == "DECIDED"
                                      else result["failure"]["reason_code"])
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
