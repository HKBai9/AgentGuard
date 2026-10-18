"""防护系统的公共数据类型。

本模块只定义数据结构，不含判断逻辑，便于单元测试与审计日志序列化。
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """风险等级。数值越大越严重，用于比较与排序。"""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented


class Decision(str, Enum):
    """对一次工具调用的处置结论。"""

    ALLOW = "ALLOW"        # 放行
    BLOCK = "BLOCK"        # 阻断本次调用
    ISOLATE = "ISOLATE"    # 阻断 + 冻结会话


class Layer(str, Enum):
    """判定发生在哪一层，用于答辩展示"检测到在哪一层"。"""

    CAPABILITY = "L0-动态权能"     # JIT 权能票据：签发/验证/撤销（预防）
    BASELINE = "L1-权限基线"       # 工具/资源白名单
    INTENT = "L2-语义意图"         # Thought 语义漂移与风险意图
    TAINT = "LT-污点感知"          # 信息流控制：污染上下文动态降权
    RUNTIME = "L3-行为运行时"      # 动作参数与时序行为链
    RESPONSE = "L4-隔离阻断"       # 应急响应策略


class EscapeType(str, Enum):
    """边界逃逸类型分类（对应 AISI Agent 逃逸事件的典型表现）。"""

    NONE = "无"
    TOOL_NOT_ALLOWED = "越权工具调用"
    CREDENTIAL_ACCESS = "敏感凭证读取"
    LATERAL_MOVEMENT = "内网横向访问"
    ACCOUNT_TAKEOVER = "账号接管尝试"
    CONFIG_TAMPER = "系统配置篡改"
    SELF_MODIFICATION = "自我修改/绕过安全策略"
    DATA_EXFILTRATION = "数据外泄"
    DANGEROUS_COMMAND = "高危命令执行"
    INTENT_DRIFT = "目标偏离（隐性逃逸）"
    SEQUENCE_ANOMALY = "可疑时序行为链"
    CAPABILITY_VIOLATION = "权能违规（无票据/过期/超配额/重放/参数越界）"
    TAINT_BLOCKED = "污点降权拦截（不可信输入触发权限收缩）"


@dataclass
class Finding:
    """一条独立的判定证据。

    一次动作可能同时命中多层规则，因此用列表而非单值。
    """

    layer: Layer
    severity: Severity
    escape_type: EscapeType
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)
    rule_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["layer"] = self.layer.value
        d["severity"] = self.severity.value
        d["escape_type"] = self.escape_type.value
        return d


@dataclass
class ToolCall:
    """Agent 发起的一次工具调用（待判定的动作）。"""

    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    step: int = 0
    thought: str = ""
    call_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_id": self.call_id,
            "step": self.step,
            "tool": self.tool,
            "args": self.args,
            "thought": self.thought,
            "ts": self.ts,
        }


@dataclass
class Verdict:
    """对一次工具调用的完整判定结果。"""

    decision: Decision
    severity: Severity
    findings: list[Finding] = field(default_factory=list)
    # 允许执行时，工具真正使用的参数（可能是脱敏/改写后的）
    effective_args: dict[str, Any] = field(default_factory=dict)
    # 命中的最高优先级规则
    rule_id: str = ""
    # 是否因此次判定冻结了会话
    session_frozen: bool = False
    latency_ms: float = 0.0

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    @property
    def summary(self) -> str:
        if self.allowed:
            return "放行：动作在权限基线内"
        if not self.findings:
            return "阻断：命中安全策略"
        f = max(self.findings, key=lambda x: x.severity.rank)
        return f"{f.escape_type.value}｜{f.reason}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "severity": self.severity.value,
            "rule_id": self.rule_id,
            "session_frozen": self.session_frozen,
            "latency_ms": round(self.latency_ms, 3),
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ToolResult:
    """工具执行结果。"""

    ok: bool
    output: str
    meta: dict[str, Any] = field(default_factory=dict)
    blocked: bool = False


@dataclass
class GuardEvent:
    """推送给 UI / 审计日志的事件。"""

    kind: str            # allow / block / isolate / rollback / intent / info
    title: str
    detail: str = ""
    severity: Severity = Severity.LOW
    step: int = 0
    tool: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d
