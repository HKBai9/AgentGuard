"""SDK / CLI 接口测试。

防护内核的判定矩阵在 `test_guard.py`；本文件只测**开发者接口**：

  - `AgentGuard.wrap_tools()` 是否真的做到 drop-in（不改 Agent 代码就能拦）
  - 工具对象适配（裸函数 / 带 name 的包装器 / ToolSpec）
  - `on_block` 三种行为
  - 阻断信息是否"模型可读"且**不含敏感内容**
  - CLI 子命令与 CI 退出码
"""

from __future__ import annotations

import json
import os
import sys
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from agentguard import VFS_ROOT  # noqa: E402
from agentguard.cli import (  # noqa: E402
    ATTACK_CASES,
    main as cli_main,
)
from agentguard.sdk import (  # noqa: E402
    AgentGuard,
    GuardedToolError,
    ToolSpec,
    coerce_tool,
    guard_function,
    guard_tools,
)

TASK = "对靶站 http://sandbox-target:8081 进行 XSS 漏洞扫描"
ESCAPE_THOUGHT = "为了拿到后台账号信息辅助测试，我需要读取本机 ssh 私钥，连接内网数据库。"


# ---------------------------------------------------------------------------
# 工具适配
# ---------------------------------------------------------------------------
def _plain(url: str) -> str:
    """一个普通函数工具。"""
    return f"scanned {url}"


def test_coerce_plain_function_keeps_real_signature():
    """回归：普通函数不能被误当成 `__call__`。

    历史缺陷：普通函数也能取到 `__call__`（method-wrapper），
    若先匹配它，签名会变成 (*args, **kwargs)，导致参数绑定全错。
    """
    spec = coerce_tool(_plain, name="web_scan")
    assert spec.name == "web_scan"
    assert list(spec.parameters.get("properties", {})) == ["url"]
    assert spec.func is _plain


def test_coerce_wrapper_object_with_name_and_run():
    """带 name + run 的包装器对象应取 `.run` 而不是对象本身。"""

    class MyTool:
        name = "reader"
        description = "读文件"
        args_schema = None

        def run(self, path: str) -> str:
            return f"read {path}"

    spec = coerce_tool(MyTool())
    assert spec.name == "reader"
    assert list(spec.parameters.get("properties", {})) == ["path"]
    assert spec.func.__name__ == "run"


def test_coerce_tool_spec_passthrough():
    s = ToolSpec("a", "d", lambda x: x, {"type": "object", "properties": {"x": {"type": "string"}}})
    assert coerce_tool(s) is s


def test_openai_schema_shape():
    g = AgentGuard(task=TASK)
    tools = g.wrap_tools({"web_scan": _plain})
    spec = coerce_tool(tools["web_scan"])
    schema = ToolSpec("web_scan", "d", tools["web_scan"], spec.parameters).schema
    assert schema["name"] == "web_scan"
    assert "parameters" in schema and schema["parameters"]["type"] == "object"


# ---------------------------------------------------------------------------
# 核心行为：drop-in 拦截
# ---------------------------------------------------------------------------
def test_wrapped_tools_call_through_when_allowed():
    """合法调用必须原样透传（返回值不能被包装破坏）。"""
    g = AgentGuard(task=TASK)
    safe = g.wrap_tools({"web_scan": _plain})
    out = safe["web_scan"](url="http://sandbox-target:8081/x")
    assert out == "scanned http://sandbox-target:8081/x"


def test_wrapped_tools_block_unauthorized_read():
    """越权读取必须被拦，且**不执行**原函数。"""
    calls: list[str] = []

    def read_file(path: str) -> str:
        calls.append(path)
        return "SECRET-CONTENT"

    g = AgentGuard(task=TASK)
    safe = g.wrap_tools({"read_file": read_file})
    out = safe["read_file"](path="/sandbox_fake/.ssh/id_rsa")

    assert calls == [], "被阻断的工具不允许被执行"
    assert "SECRET-CONTENT" not in out
    assert "AgentGuard" in out and "阻断" in out


def test_blocked_message_is_actionable_for_the_model():
    """阻断信息要能让 Agent 读懂并改变策略，而不是继续重试。"""
    g = AgentGuard(task=TASK)
    safe = g.wrap_tools({"read_file": lambda path: "x"})
    out = safe["read_file"](path="/sandbox_fake/.ssh/id_rsa")
    assert "工具" in out
    assert "判定" in out or "风险等级" in out
    assert "请勿重试" in out or "不要重试" in out
    assert "L1" in out or "L2" in out  # 要说明是哪一层拦的


def test_on_block_raise():
    g = AgentGuard(task=TASK, on_block="raise")
    safe = g.wrap_tools({"read_file": lambda path: "x"})
    with pytest.raises(GuardedToolError) as ei:
        safe["read_file"](path="/sandbox_fake/.ssh/id_rsa")
    assert ei.value.tool == "read_file"


def test_on_block_none():
    g = AgentGuard(task=TASK, on_block="none")
    safe = g.wrap_tools({"read_file": lambda path: "x"})
    assert safe["read_file"](path="/sandbox_fake/.ssh/id_rsa") == ""


def test_decorator_form():
    g = AgentGuard(task=TASK)

    @g.tool(name="read_file", description="读取文件")
    def read_file(path: str) -> str:
        return "CONTENT"

    assert read_file(path="/sandbox_fake/workspace/notes/xss_scan_notes.md") == "CONTENT"
    assert "阻断" in read_file(path="/sandbox_fake/.ssh/id_rsa")


def test_guard_tools_and_guard_function_helpers():
    safe = guard_tools({"web_scan": _plain}, task=TASK)
    assert safe["web_scan"](url="http://sandbox-target:8081/") == "scanned http://sandbox-target:8081/"
    fn = guard_function(_plain, tool_name="web_scan", task=TASK)
    assert fn(url="http://sandbox-target:8081/").startswith("scanned")


def test_session_freeze_blocks_followups():
    """一次逃逸后会话冻结，后续合法调用也被拒（防止链式逃逸）。"""
    g = AgentGuard(task=TASK)
    safe = g.wrap_tools({"read_file": lambda path: "x", "web_scan": _plain})
    safe["read_file"](path="/sandbox_fake/.ssh/id_rsa")   # 触发隔离
    assert g.frozen
    out = safe["web_scan"](url="http://sandbox-target:8081/")
    assert "冻结" in out or "阻断" in out


def test_summary_reports_escape_types():
    g = AgentGuard(task=TASK)
    safe = g.wrap_tools({"read_file": lambda path: "x"})
    safe["read_file"](path="/sandbox_fake/.ssh/id_rsa")
    s = g.summary()
    assert s["blocked"] >= 1
    assert s["escape_types"], "应识别出至少一种逃逸类型"


def test_tool_type_error_is_loud_not_silent():
    """参数绑不上必须显式报错，不能伪装成"被拦住了"。

    历史缺陷：曾经吞掉 TypeError 并返回阻断文本，
    导致实验出现假阳性结论（看起来防护生效，其实工具根本没被调用）。
    """
    g = AgentGuard(task=TASK)
    safe = g.wrap_tools({"web_scan": _plain})
    with pytest.raises(TypeError) as ei:
        safe["web_scan"](wrong_kwarg="http://x/")
    assert "参数不匹配" in str(ei.value)


def test_mapping_shape_is_preserved():
    g = AgentGuard(task=TASK)
    assert isinstance(g.wrap_tools({"web_scan": _plain}), dict)
    assert isinstance(g.wrap_tools([ToolSpec("web_scan", "d", _plain)]), list)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def test_cli_version(capsys):
    assert cli_main(["version"]) == 0
    assert "agentguard" in capsys.readouterr().out


def test_cli_check_prints_policy(capsys):
    rc = cli_main(["check", os.path.join(ROOT, "config", "permission_baseline.yaml")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "工具白名单" in out and "受保护资源" in out


def test_cli_check_missing_policy_returns_2(capsys):
    rc = cli_main(["check", os.path.join(ROOT, "no_such_policy.yaml")])
    assert rc == 2


def test_cli_test_passes_on_good_policy(capsys):
    rc = cli_main(["test", os.path.join(ROOT, "config", "permission_baseline.yaml")])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert f"通过 {len(ATTACK_CASES)} / {len(ATTACK_CASES)}" in out


def _tmpdir() -> str:
    """在工作区内建一个临时目录。

    两个坑都踩过，所以这里刻意**不用**：
      - `tmp_path` fixture：受限沙箱会拒绝系统临时目录的属主/清理操作，
        fixture 自身就抛 PermissionError（与被测代码无关）；
      - `tempfile.mkdtemp()`：它建的目录在沙箱下**不可写**
        （这正是当初 pip 装不上依赖的同一个原因）。

    因此用 `os.makedirs` + 随机名自建，并由 atexit 清理。
    """
    import shutil
    import uuid
    import atexit

    base = os.path.join(ROOT, ".pytest_work")
    path = os.path.join(base, f"t-{uuid.uuid4().hex[:8]}")
    os.makedirs(path, exist_ok=True)
    atexit.register(lambda: shutil.rmtree(path, ignore_errors=True))
    return path


def test_cli_test_detects_weakened_policy(capsys):
    """CI 门禁的核心价值：策略被削弱时必须 fail。

    构造一个"把 .ssh 变可读、并删掉私钥保护规则"的坏策略 ——
    这正是真实场景里最危险的那种改动。
    """
    import re

    src = open(os.path.join(ROOT, "config", "permission_baseline.yaml"), encoding="utf-8").read()
    bad = src.replace(
        '      - "/sandbox_fake/workspace/**"',
        '      - "/sandbox_fake/workspace/**"\n      - "/sandbox_fake/.ssh/**"',
    )
    for pat in ("**/.ssh/**", "**/id_rsa*"):
        bad = re.sub(
            r"      - pattern: \"" + re.escape(pat) + r"\"\n        reason: [^\n]*\n        severity: \w+\n",
            "",
            bad,
        )
    bad_path = os.path.join(_tmpdir(), "bad_policy.yaml")
    with open(bad_path, "w", encoding="utf-8") as fh:
        fh.write(bad)

    rc = cli_main(["test", bad_path])
    out = capsys.readouterr().out
    assert rc == 1, f"坏策略未被门禁发现：\n{out}"
    assert "失败" in out


def test_cli_scan_offline_log(capsys):
    """离线审计：给一份动作日志，找出其中的越权动作。"""
    log = os.path.join(_tmpdir(), "actions.jsonl")
    records = [
        {"tool": "web_scan", "args": {"url": "http://sandbox-target:8081/"},
         "thought": "扫描靶站"},
        {"tool": "read_file", "args": {"path": "/sandbox_fake/.ssh/id_rsa"},
         "thought": "读取私钥辅助测试"},
    ]
    with open(log, "w", encoding="utf-8") as fh:
        fh.write("\n".join(json.dumps(r, ensure_ascii=False) for r in records))
    rc = cli_main(["scan", log])
    out = capsys.readouterr().out
    assert rc == 1, "日志里存在越权动作，应返回非零"
    assert "判定越权 1 个" in out
