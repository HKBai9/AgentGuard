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
from .guard import GuardConfig, SandboxGuard, build_guard
from .intent import IntentChecker
from .paths import DEFAULT_CONFIG_PATH as DEFAULT_CONFIG
from .paths import PROJECT_ROOT, VFS_ROOT
from .runtime import RuntimeMonitor
from .sdk import AgentGuard, GuardedToolError, ToolSpec, guard_function, guard_tool, guard_tools
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

__all__ = [
    # 开发者 SDK（推荐入口）
    "AgentGuard",
    "ToolSpec",
    "GuardedToolError",
    "guard_tools",
    "guard_tool",
    "guard_function",
    # 内核
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

__version__ = "1.1.0"
