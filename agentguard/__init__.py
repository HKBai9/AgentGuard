"""AgentGuard —— 面向安全 Agent 的边界逃逸检测与风险隔离机制。

四层防护对应四个模块：

======================  ==========================  ==================================
层                     模块                        回答的问题
======================  ==========================  ==================================
L1 权限基线（事前）     ``baseline``                这个动作在授权范围内吗？
L2 语义意图（事中）     ``intent``                  Agent 的"想法"是否已经跑偏？
L3 行为运行时（事中）   ``runtime``                 实际动作与动作序列是否异常？
L4 隔离阻断（响应）     ``guard``                   检测到越权后如何阻断、隔离、回滚？
======================  ==========================  ==================================

对外主入口是 :class:`~agentguard.guard.SandboxGuard` 与
:class:`~agentguard.tools.ToolBridge`：Agent 的每次工具调用都经过
``ToolBridge.execute()``，防护关闭与开启走的是同一条代码路径。
"""

from __future__ import annotations

import os

from .baseline import PermissionBaseline, load_baseline
from .guard import GuardConfig, SandboxGuard
from .intent import IntentChecker
from .runtime import RuntimeMonitor
from .tools import ToolBridge
from .types import (
    Decision,
    EscapeType,
    Finding,
    GuardEvent,
    Layer,
    Severity,
    ToolCall,
    ToolResult,
    Verdict,
)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CONFIG = os.path.join(PROJECT_ROOT, "config", "permission_baseline.yaml")
VFS_ROOT = os.path.join(PROJECT_ROOT, "sandbox", "sandbox_fake")

__all__ = [
    "PermissionBaseline",
    "load_baseline",
    "GuardConfig",
    "SandboxGuard",
    "IntentChecker",
    "RuntimeMonitor",
    "ToolBridge",
    "Decision",
    "EscapeType",
    "Finding",
    "GuardEvent",
    "Layer",
    "Severity",
    "ToolCall",
    "ToolResult",
    "Verdict",
    "PROJECT_ROOT",
    "DEFAULT_CONFIG",
    "VFS_ROOT",
    "build_guard",
]

__version__ = "1.0.0"


def build_guard(
    config_path: str | None = None,
    guard_config: GuardConfig | None = None,
    llm=None,
    session_id: str = "",
) -> SandboxGuard:
    """按默认路径装配一个可用的防护引擎。"""
    baseline = load_baseline(config_path or DEFAULT_CONFIG)
    # 让防护层知道虚拟文件系统的真实根（用于回滚快照）
    baseline.cfg["_vfs_root"] = VFS_ROOT
    return SandboxGuard(
        baseline,
        config=guard_config or GuardConfig(),
        llm=llm,
        session_id=session_id,
        vfs_real_root=VFS_ROOT,
    )
