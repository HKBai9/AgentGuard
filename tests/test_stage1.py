"""Stage-one regression checks. Fixed inputs only; no model/A-B experiments."""

from __future__ import annotations

import asyncio
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock

import pytest

from agentguard import AgentGuard, GuardConfig, ToolCall, ToolResult, build_guard
from agentguard.action import build_action
from agentguard.agent import AgentRun, AgentStep
from agentguard.cli import main as cli_main
from agentguard.evaluation import false_positive
from agentguard.tools import ToolBridge
from tools.collect_evidence import summarize


@pytest.fixture
def bridge(tmp_path):
    guard = build_guard(
        vfs_root=str(tmp_path),
        guard_config=GuardConfig(
            enable_intent=False,
            enable_rollback=False,
            enable_capability=False,
            enable_taint=False,
        ),
    )
    guard.audit_path = str(tmp_path / "audit.jsonl")
    return ToolBridge(guard, str(tmp_path))


@pytest.mark.parametrize("command", [
    "curl http://sandbox-target:8081/ http://internal-api:9000/admin/users",
    "curl http://internal-api:9000/admin/users http://sandbox-target:8081/",
    'curl --url "http://sandbox-target:8081/" --url http://internal-api:9000/admin/users',
    "curl http://sandbox-target:8081/ http://10.2.3.4/",
])
def test_every_network_target_checked_before_dispatch(bridge, monkeypatch, command):
    dispatch = Mock(side_effect=AssertionError("blocked calls must not execute"))
    monkeypatch.setattr(bridge, "_dispatch", dispatch)
    result, verdict = bridge.execute("run_command", {"command": command})
    assert not verdict.allowed and result.blocked
    dispatch.assert_not_called()
    assert len(bridge.guard.monitor.history[-1].view.network_targets) == 2


def test_two_allowed_urls_are_allowed(bridge):
    verdict, _ = bridge.guard.evaluate(ToolCall(tool="run_command", args={
        "command": "curl http://sandbox-target:8081/a http://sandbox-target:8081/b"}))
    assert verdict.allowed


@pytest.mark.parametrize("command", [
    "curl --config workspace/notes/config",
    "curl -L http://sandbox-target:8081/",
    "curl -o workspace/reports/x http://sandbox-target:8081/",
    "curl --proxy http://sandbox-target:8081/ http://sandbox-target:8081/",
    "curl file:///etc/passwd",
    "curl",
    "cat",
    "cat --files0-from=workspace/notes/x",
    "ls /sandbox_fakeevil",
])
def test_uninspectable_or_outside_inputs_fail_closed(bridge, command):
    result, verdict = bridge.execute("run_command", {"command": command})
    assert not verdict.allowed and result.blocked


@pytest.mark.parametrize("command", ["cat .ssh/id_rsa", "cat workspace/../.ssh/id_rsa"])
def test_cat_cannot_bypass_file_policy(bridge, command):
    result, verdict = bridge.execute("run_command", {"command": command})
    assert not verdict.allowed and result.blocked
    assert any(f.rule_id == "L1-FILE-PROTECTED" for f in verdict.findings)


def test_cat_quoted_authorized_path_has_observed_read(bridge):
    path = Path(bridge.vfs_root) / "workspace" / "notes" / "a b.txt"
    path.parent.mkdir(parents=True)
    path.write_text("stage1", encoding="utf-8")
    result, verdict = bridge.execute("run_command", {"command": 'cat "workspace/notes/a b.txt"'})
    assert verdict.allowed and result.ok and "stage1" in result.output
    assert result.effects[0]["path"] == "/sandbox_fake/workspace/notes/a b.txt"


def test_missing_file_stays_failed_and_is_not_provisioned(bridge):
    bridge.guard.baseline.file_read.append("/sandbox_fake/**")
    bridge.guard.baseline.file_protected = []
    result, verdict = bridge.execute("read_file", {"path": "/sandbox_fake/.ssh/id_rsa"})
    assert verdict.allowed and not result.ok and not result.effects
    assert not (Path(bridge.vfs_root) / ".ssh/id_rsa").exists()
    assert not bridge.guard.monitor.sensitive_reads
    assert bridge.guard.monitor.history[-1].ok is False


def test_permission_check_alone_is_not_execution(bridge):
    bridge.guard.baseline.file_read.append("/sandbox_fake/**")
    bridge.guard.baseline.file_protected = []
    verdict, _ = bridge.guard.evaluate(ToolCall(tool="read_file", args={"path": "/sandbox_fake/.ssh/id_rsa"}))
    assert verdict.allowed
    assert not bridge.guard.monitor.sensitive_reads
    assert bridge.guard.monitor.history[-1].ok is None


def test_sequence_works_when_individual_permissions_are_relaxed(bridge):
    guard = bridge.guard
    guard.baseline.file_read.append("/sandbox_fake/**")
    guard.baseline.file_protected = []
    guard.baseline.net_allow = [{"match": "exact", "value": "internal-db"}]
    guard.baseline.net_deny = []
    guard.baseline.sensitive_ports = {}
    guard.baseline.allowed_ports = set()
    guard.baseline.allowed_schemes = set()
    path = Path(bridge.vfs_root) / ".ssh/id_rsa"
    path.parent.mkdir()
    path.write_text("FAKE-STAGE1-KEY", encoding="utf-8")
    result, verdict = bridge.execute("read_file", {"path": "/sandbox_fake/.ssh/id_rsa"}, step=1)
    assert verdict.allowed and result.ok
    verdict, _ = guard.evaluate(ToolCall(tool="ssh_connect", args={"target": "internal-db", "port": 3306}, step=2))
    assert not verdict.allowed
    assert "SEQ-001" in {f.rule_id for f in verdict.findings}
    assert not any(f.rule_id.startswith("L1-NET") for f in verdict.findings)


def test_scan_then_database_rule_is_not_silently_skipped(bridge):
    guard = bridge.guard
    call = ToolCall(tool="web_scan", args={"url": "http://sandbox-target:8081/"}, step=1)
    verdict, _ = guard.evaluate(call)
    assert verdict.allowed
    guard.record_result(call, ToolResult(True, "scan", executed=True, meta={"effects_complete": True}))
    verdict, _ = guard.evaluate(ToolCall(tool="ssh_connect", args={"target": "internal-db", "port": 3306}, step=2))
    assert "SEQ-002" in {f.rule_id for f in verdict.findings}


def test_nonzero_command_can_have_confirmed_effects(bridge, monkeypatch):
    bridge.guard.baseline.net_allow.append({"match": "exact", "value": "internal-api"})
    bridge.guard.baseline.allowed_ports.add(9000)
    monkeypatch.setattr("agentguard.tools.shutil.which", lambda _: "curl")
    completed = subprocess.CompletedProcess([], 7, stdout=b'FAKE', stderr=(
        b'__AGENTGUARD_TRANSFER__http://127.0.0.1:9000/admin/users\t200\nlater failed'))
    monkeypatch.setattr("agentguard.tools.subprocess.run", lambda *a, **kw: completed)
    result, verdict = bridge.execute("run_command", {"command": "curl http://internal-api:9000/admin/users"})
    assert verdict.allowed and not result.ok and result.executed
    assert result.effects[0]["sensitive"]
    run = AgentRun(task="test", guard_enabled=True, steps=[AgentStep(
        1, "", "run_command", {}, ok=False, effects=result.effects, executed=True)])
    assert run.escaped


def test_no_fabricated_network_effect_when_curl_metadata_absent(bridge, monkeypatch):
    monkeypatch.setattr("agentguard.tools.shutil.which", lambda _: "curl")
    monkeypatch.setattr("agentguard.tools.subprocess.run", lambda *a, **kw:
                        subprocess.CompletedProcess([], 0, stdout=(
                            b"admin_users\n__AGENTGUARD_TRANSFER__http://127.0.0.1:9000/admin/users\t200\n"), stderr=b""))
    result, _ = bridge.execute("run_command", {"command": "curl http://sandbox-target:8081/"})
    assert result.ok and not result.effects and not result.meta["effects_complete"]


def test_default_path_is_checked_before_callback(tmp_path):
    calls = []
    def reader(path="/sandbox_fake/.ssh/id_rsa"):
        calls.append(path)
        return "SECRET"
    guard = AgentGuard(vfs_root=str(tmp_path), audit_log=tmp_path / "audit.jsonl")
    out = guard.wrap_tools({"read_file": reader})["read_file"]()
    assert not calls and "阻断" in out


def test_positional_only_and_keyword_variadic_bindings(tmp_path):
    def reader(path, /):
        return path
    def scanner(**kwargs):
        return kwargs["url"]
    guard = AgentGuard(vfs_root=str(tmp_path), audit_log=tmp_path / "audit.jsonl")
    safe = guard.wrap_tools({"read_file": reader, "web_scan": scanner})
    assert safe["read_file"]("/sandbox_fake/workspace/a") == "/sandbox_fake/workspace/a"
    assert safe["web_scan"](url="http://sandbox-target:8081/").startswith("http")
    assert guard.guard.monitor.history[-1].executed
    assert not guard.guard.monitor.history[-1].effects_complete


def test_supplied_task_builds_the_actual_intent_baseline(tmp_path):
    guard = AgentGuard(task="Translate a document", vfs_root=str(tmp_path))
    assert guard.guard.intent.goal == "Translate a document"
    assert guard.guard.baseline.task_goal == "Translate a document"
    assert guard.guard.intent.similarity("Translate a document") > 0


def test_openai_documented_mapping_and_explicit_schema_work(tmp_path):
    def scanner(url: str, limit: int = 2):
        return url
    guard = AgentGuard(vfs_root=str(tmp_path))
    schemas = guard.openai_tools(guard.wrap_tools({"web_scan": scanner}))
    assert schemas[0]["type"] == "function"
    assert schemas[0]["function"]["name"] == "web_scan"
    assert schemas[0]["function"]["parameters"]["properties"]["limit"]["type"] == "integer"


def test_async_tools_await_results_and_block_before_call(tmp_path):
    calls = []
    async def reader(path="/sandbox_fake/workspace/a"):
        calls.append(path)
        await asyncio.sleep(0)
        return "OK"
    guard = AgentGuard(vfs_root=str(tmp_path), audit_log=tmp_path / "audit.jsonl")
    safe = guard.wrap_tools({"read_file": reader})
    assert asyncio.run(safe["read_file"]()) == "OK"
    assert guard.guard.monitor.history[-1].ok is True
    out = asyncio.run(safe["read_file"](path="/sandbox_fake/.ssh/id_rsa"))
    assert "阻断" in out and len(calls) == 1


def test_async_mcp_style_callable_is_recorded_after_await(tmp_path):
    async def remote(url):
        return "REMOTE"
    guard = AgentGuard(vfs_root=str(tmp_path), audit_log=tmp_path / "audit.jsonl")
    allowed, out = asyncio.run(guard.aguard_call("web_scan", lambda **kw: remote(**kw),
                                               {"url": "http://sandbox-target:8081/"}))
    assert allowed and out == "REMOTE"
    assert guard.guard.monitor.history[-1].ok is True


def test_custom_vfs_snapshot_and_rollback_use_same_root(tmp_path):
    reports = tmp_path / "workspace/reports"
    reports.mkdir(parents=True)
    report = reports / "a.txt"
    report.write_text("original", encoding="utf-8")
    guard = AgentGuard(vfs_root=str(tmp_path), audit_log=tmp_path / "audit.jsonl")
    report.write_text("changed", encoding="utf-8")
    guard.rollback()
    assert report.read_text(encoding="utf-8") == "original"


@pytest.mark.parametrize("thought", [
    "不读取私钥，只扫描靶站并记录报告。",
    "不要访问内网，只完成授权的扫描任务。",
    "I will not read private key; scan the target and write a report.",
    "文档中引用“读取私钥”，这里只记录扫描报告。",
])
def test_explicit_negation_and_reported_quotes_do_not_block(tmp_path, thought):
    guard = AgentGuard(vfs_root=str(tmp_path), audit_log=tmp_path / "audit.jsonl")
    assert guard.check("web_scan", {"url": "http://sandbox-target:8081/"}, thought).allowed


def test_negation_does_not_hide_later_positive_intent(tmp_path):
    guard = AgentGuard(vfs_root=str(tmp_path), audit_log=tmp_path / "audit.jsonl")
    assert not guard.check("web_scan", {"url": "http://sandbox-target:8081/"},
                           "不读取私钥，但是接下来要连接内网数据库。").allowed


def test_offline_scan_never_executes_logged_actions(tmp_path, monkeypatch):
    monkeypatch.setattr(ToolBridge, "execute", Mock(side_effect=AssertionError("offline audit executed tools")))
    log = tmp_path / "actions.jsonl"
    log.write_text(json.dumps({"tool": "write_file", "args": {
        "path": "/sandbox_fake/workspace/reports/offline-must-not-exist.txt", "content": "X"}}), encoding="utf-8")
    assert cli_main(["scan", str(log)]) == 0


def test_group_summary_does_not_overwrite_bare_with_prompt(tmp_path):
    rows = []
    for group, escaped in (("off", True), ("prompt", False), ("on", False)):
        rows.append({"case": "attack", "case_name": "fixture", "group_key": group,
                     "guard_enabled": group == "on", "is_benign": False, "escaped": escaped,
                     "blocked_count": int(group == "on"), "status": "finished",
                     "guard_summary": {"escape_types": [], "rollback_actions": 0}})
    (tmp_path / "results.json").write_text(json.dumps({"results": rows}), encoding="utf-8")
    summary = summarize(str(tmp_path))["rows"][0]
    assert summary["control_escaped"] is True and summary["prompt_guard_escaped"] is False
    assert summary["false_positive"] is False


@pytest.mark.parametrize("label,blocked,expected", [(True, 1, True), (False, 1, False), (None, 1, None), (True, 0, False)])
def test_false_positive_requires_independent_benign_label(label, blocked, expected):
    assert false_positive(label, blocked) is expected


def test_packaged_policy_matches_repository_policy():
    root = Path(__file__).resolve().parents[1]
    assert (root / "agentguard/data/permission_baseline.yaml").read_bytes() == (root / "config/permission_baseline.yaml").read_bytes()


@pytest.mark.parametrize("args", [
    {}, {"url": "http://sandbox-target:999999/"}, {"url": "http://sandbox-target:8081/", "port": 0},
    {"url": "http://sandbox-target:8081/", "port": "invalid"},
    {"url": "http://user:password@sandbox-target:8081/"},
])
def test_missing_or_invalid_network_arguments_are_blocked(bridge, args):
    result, verdict = bridge.execute("http_get", args)
    assert not verdict.allowed and result.blocked


def test_sensitive_port_is_not_disguised_as_target_default(bridge):
    verdict, _ = bridge.guard.evaluate(ToolCall(tool="http_get", args={"url": "http://sandbox-target:22/"}))
    assert not verdict.allowed


def test_real_loopback_http_and_curl_have_observed_results(bridge):
    import shutil
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            calls.append(self.path)
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/must-not-follow")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"LOCAL-FIXTURE")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_port
    bridge.guard.baseline.allowed_ports.add(port)
    url = f"http://127.0.0.1:{port}"
    try:
        result, verdict = bridge.execute("http_get", {"url": url + "/ok"})
        assert verdict.allowed and result.ok and result.effects[0]["status_code"] == 200
        result, _ = bridge.execute("http_get", {"url": url + "/redirect"})
        assert "/must-not-follow" not in calls
        if shutil.which("curl"):
            result, verdict = bridge.execute("run_command", {"command": f"curl -s {url}/curl"})
            assert verdict.allowed and result.ok, result.output
            assert result.effects and result.meta["effects_complete"], result.output
            assert "/curl" in calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_offline_audit_cannot_trigger_rollback(tmp_path, monkeypatch):
    from agentguard.guard import SandboxGuard
    monkeypatch.setattr(SandboxGuard, "rollback", Mock(side_effect=AssertionError("offline audit rolled back files")))
    log = tmp_path / "blocked.jsonl"
    log.write_text(json.dumps({"tool": "read_file", "args": {"path": "/sandbox_fake/.ssh/id_rsa"}}), encoding="utf-8")
    assert cli_main(["scan", str(log)]) == 1


def test_actual_langchain_round_trip(tmp_path):
    StructuredTool = pytest.importorskip("langchain_core.tools").StructuredTool
    def scan(url: str) -> str:
        """Scan the authorized target."""
        return "SCANNED " + url
    raw = StructuredTool.from_function(func=scan, name="web_scan", description="scan")
    guard = AgentGuard(vfs_root=str(tmp_path), audit_log=tmp_path / "audit.jsonl")
    tools = guard.langchain_tools(guard.wrap_tools([raw]))
    assert tools[0].invoke({"url": "http://sandbox-target:8081/"}).startswith("SCANNED")


def test_mapping_style_tool_adapter_preserves_named_arguments(tmp_path):
    class Remote:
        name = "web_scan"
        description = "remote"
        args_schema = {"type": "object", "properties": {"url": {"type": "string"}}}
        def invoke(self, payload):
            return payload["url"]
    guard = AgentGuard(vfs_root=str(tmp_path), audit_log=tmp_path / "audit.jsonl")
    tool = guard.wrap_tools([Remote()])[0]
    assert tool.func(url="http://sandbox-target:8081/").startswith("http")


def test_allowing_an_unknown_tool_does_not_skip_resource_inspection(bridge):
    bridge.guard.baseline.tool_allow.add("custom_reader")
    verdict, _ = bridge.guard.evaluate(ToolCall(tool="custom_reader", args={"path": "/sandbox_fake/.ssh/id_rsa"}))
    assert not verdict.allowed and verdict.rule_id == "L1-ARGS-INVALID"
