import asyncio
import importlib.util
from pathlib import Path

import pytest

# Tests are not a distribution package; load the test-only doubles explicitly.
spec = importlib.util.spec_from_file_location("v2_test_fakes", Path(__file__).parents[1] / "guard/fakes.py")
fakes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fakes)


def test_runtime_failure_playback_never_returns_raw_content():
    script = fakes.fixture("guard_failure", "runtime_script.json")
    runtime = fakes.FakeRuntime(script)
    result = asyncio.run(runtime.execute_batch(script[0]["request"]))
    assert result["items"][0]["status"] == "REVIEW_PENDING"
    assert result["items"][0]["content"] is None
    assert result["items"][0]["artifact_ref"] is None
    assert len(runtime.calls) == 1


@pytest.mark.parametrize("method", ["create_session", "prepare_model_turn", "record_model_output",
                                    "execute_batch", "finalize", "prepare_recovery", "complete_recovery"])
def test_unconfigured_runtime_never_fabricates_success(method):
    runtime = fakes.FakeRuntime([])
    with pytest.raises(AssertionError, match="exhausted"):
        asyncio.run(getattr(runtime, method)({"schema_version": "0.1"}))


def test_runtime_rejects_call_mismatch():
    script = fakes.fixture("guard_failure", "runtime_script.json")
    runtime = fakes.FakeRuntime(script)
    with pytest.raises(AssertionError, match="mismatch"):
        asyncio.run(runtime.execute_batch({"schema_version": "0.1", "call_ids": ["other-call"]}))
