"""Opt-in provider transport smoke with synthetic text, not a Guard evaluation.

Does not load .env files, real artifacts, fixtures, or any Runtime implementation.
"""

import asyncio
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentguard.v2.review.boundary import strict_json
from agentguard.v2.review.budget import Budget
from agentguard.v2.review.clients import CloudClient, CloudConfig
from agentguard.v2.review.errors import GuardError


async def main():
    client = None
    try:
        client = CloudClient(CloudConfig.from_env(), budget=Budget(max_attempts=2))
        reply = await client.complete(
            messages=[{"role": "system", "content": 'Return exactly this JSON object: {"synthetic":true}.'},
                      {"role": "user", "content": "Synthetic connectivity check only."}],
            purpose="RESULT", prompt_version="synthetic-transport-smoke-0.1",
        )
        valid = strict_json(reply.content) == {"synthetic": True}
        print(json.dumps({"mode": "live_transport_smoke", "sample": "synthetic-transport-smoke-0.1",
                          "valid_json_response": valid, "usage": reply.usage, "cost": "unavailable",
                          "guard_effectiveness_measured": False}, ensure_ascii=False))
        return 0 if valid else 1
    except GuardError as exc:
        print(json.dumps({"mode": "live_transport_smoke", "error": exc.reason_code,
                          "attempts": [] if client is None else client.budget.records,
                          "cost": "unavailable"}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
