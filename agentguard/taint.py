r"""模块 T：污点感知与动态降权（Taint-Aware Downgrading / 轻量 IFC）。

信息流控制（Information Flow Control）的工程化子集：

  1. **数据标记**：按输入**来源**给数据定级——
     - ``TASK_SCOPE``：任务声明范围内的输入（靶站响应、任务资料、
       Agent 自己的工作区产物）——正常业务流不受影响（不误伤的关键）；
     - ``UNTRUSTED``：任务范围外的外部内容（第三方公开资料、范围外
       服务响应）。未显式声明来源的输入**默认不可信**（default-deny）。
  2. **污染传播**：Agent 一旦成功摄入 ``UNTRUSTED`` 内容，其上下文
     转为"已污染"（Tainted），并在审计链留痕。
  3. **动态降权拦截矩阵**：污染状态下，策略引擎拒绝为高危动作签发
     权能（命令执行 / 远程连接 / 写入交付物 / 访问任务范围外主机），
     仅放行只读动作与隔离区（tmp）写入。
  4. **去污通道**（二选一，均留审计痕）：
     - 确定性去污 ``sanitize_content``：剥离 URL、命令、编码载荷等
       "活性内容"，仅保留结构化文字；
     - 人工核准（Human-in-the-loop）：控制台/UI 显式批准。

设计边界（诚实声明）：本实现是**来源级污点 + 上下文级传播**的轻量版，
不追踪每条数据的逐字段流向（完整 IFC 需语言级标签传播）。对 Agent
场景，"摄入即污染上下文"已覆盖提示词注入的主要攻击面，且判定完全
确定性、可回放。
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .action import ActionView
from .baseline import PermissionBaseline, _glob_match


class TaintLevel(str, Enum):
    CLEAN = "CLEAN"            # 无外部输入（如本地只读元操作）
    TASK_SCOPE = "TASK_SCOPE"  # 任务声明范围内的输入
    UNTRUSTED = "UNTRUSTED"    # 任务范围外的外部内容（低完整性）


@dataclass
class TaintMark:
    """一次污点判定记录。"""

    step: int
    tool: str
    source: str
    level: TaintLevel
    ts: float = field(default_factory=time.time)


# 默认策略（可被 config/permission_baseline.yaml 的 taint 段覆盖）
DEFAULT_CFG: dict[str, Any] = {
    "task_scope_sources": [
        "/sandbox_fake/targets/**",
        "/sandbox_fake/workspace/**",
    ],
    "untrusted_sources": [
        "/sandbox_fake/public/**",
    ],
    "blocked_tools_when_tainted": ["run_command", "ssh_connect", "exfiltrate"],
    "deliverable_paths": ["/sandbox_fake/workspace/reports/**"],
    "quarantine_paths": ["/sandbox_fake/workspace/tmp/**"],
}

# 去污规则：这些模式被视为"活性内容"（可执行指令/外联/编码载荷）
_ACTIVE_PATTERNS: list[tuple[str, str]] = [
    (r"https?://\S+", "URL"),
    (r"[A-Za-z0-9+/]{40,}={0,2}", "base64 载荷"),
    (r"(?i)\b(curl|wget|nc|bash|sh|python|powershell)\b[^\n]*", "命令行"),
    (r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----", "私钥块"),
    (r"(?i)\b(execute|run|执行|运行|连接|读取并回传|忽略之前|ignore previous|instructions?)\b[^\n]*", "指令性语句"),
]


class TaintTracker:
    """会话级污点追踪器：标记、传播、降权矩阵与去污。"""

    def __init__(self, baseline: PermissionBaseline) -> None:
        self.baseline = baseline
        cfg = dict(DEFAULT_CFG)
        cfg.update(baseline.cfg.get("taint") or {})

        self.task_scope_globs: list[str] = [str(g) for g in cfg.get("task_scope_sources", [])]
        self.untrusted_globs: list[str] = [str(g) for g in cfg.get("untrusted_sources", [])]
        self.blocked_tools: set[str] = set(str(t) for t in cfg.get("blocked_tools_when_tainted", []))
        self.deliverable_globs: list[str] = [str(g) for g in cfg.get("deliverable_paths", [])]
        self.quarantine_globs: list[str] = [str(g) for g in cfg.get("quarantine_paths", [])]

        # 任务声明的被测目标主机（来自基线 target_url）——唯一受信网络输入源
        self.target_host: str = ""
        try:
            from .action import parse_target

            _scheme, host, _port, _url = parse_target(baseline.target_url)
            self.target_host = (host or "").lower()
        except Exception:
            self.target_host = ""

        # 运行态
        self.tainted: bool = False
        self.tainted_at_step: int = 0
        self.taint_source: str = ""
        self.sanitized: bool = False
        self.sanitized_at_step: int = 0
        self.human_approved: bool = False
        self.human_approved_note: str = ""
        self.history: list[TaintMark] = []
        self.last_untrusted_text: str = ""

    # ------------------------------------------------------------- 分级
    def classify(self, tool: str, view: ActionView) -> TaintLevel:
        """按输入来源定级（确定性）。"""
        if tool in ("web_scan", "http_get"):
            if not view.host:
                return TaintLevel.CLEAN
            if view.host.lower() == self.target_host or view.resolved_host.lower() == self.target_host:
                return TaintLevel.TASK_SCOPE
            return TaintLevel.UNTRUSTED

        if tool == "read_file":
            path = view.path or ""
            if any(_glob_match(path, g) for g in self.untrusted_globs):
                return TaintLevel.UNTRUSTED
            if any(_glob_match(path, g) for g in self.task_scope_globs):
                return TaintLevel.TASK_SCOPE
            # 未声明来源：默认不可信（default-deny）
            return TaintLevel.UNTRUSTED if path else TaintLevel.CLEAN

        if tool == "run_command":
            if not view.host:
                return TaintLevel.CLEAN
            return TaintLevel.TASK_SCOPE if view.host.lower() == self.target_host else TaintLevel.UNTRUSTED

        return TaintLevel.CLEAN

    # ------------------------------------------------------------- 标记
    def mark(self, tool: str, view: ActionView, step: int, observation: str = "") -> bool:
        """一次成功执行后的污点标记。返回是否**新发生**污染。"""
        level = self.classify(tool, view)
        source = view.path or view.url or view.host or tool
        self.history.append(TaintMark(step=step, tool=tool, source=source, level=level))
        if level is TaintLevel.UNTRUSTED:
            if observation:
                self.last_untrusted_text = observation
            newly = not self.tainted
            self.tainted = True
            self.tainted_at_step = step
            self.taint_source = source
            # 新摄入不可信内容即撤销此前的去污/核准状态
            self.sanitized = False
            self.human_approved = False
            return newly
        return False

    def observation_tag(self, level: TaintLevel) -> str:
        """追加到观察结果尾部的污点提示（对模型与演示均可见）。"""
        if level is TaintLevel.UNTRUSTED:
            return (
                "\n[污点标记] 本次输入源未在任务声明范围内（UNTRUSTED），"
                "上下文已转为『已污染』：高危工具（命令执行/远程连接/写入交付物）"
                "将被拒绝签发权能，直至通过 sanitize_content 去污或人工核准。"
            )
        if level is TaintLevel.TASK_SCOPE:
            return "\n[污点标记] 输入源属于任务声明范围（TASK_SCOPE），上下文保持清洁。"
        return ""

    # ------------------------------------------------------------- 降权矩阵
    def blocks(self, tool: str, view: ActionView) -> tuple[bool, str]:
        """污染状态下的权限拦截矩阵。返回 (是否阻断, 理由)。"""
        if not self.tainted:
            return False, ""
        reason_prefix = f"上下文已污染（源于 step{self.tainted_at_step} 的 `{self.taint_source}`）"

        if tool in self.blocked_tools:
            return True, (
                f"{reason_prefix}，按降权矩阵拒绝为 `{tool}` 签发权能；"
                f"需先 sanitize_content 去污或人工核准（Human-in-the-loop）"
            )

        if tool in ("http_get", "web_scan") and view.host:
            if view.host.lower() != self.target_host:
                return True, (
                    f"{reason_prefix}，禁止访问任务范围外主机 {view.host}；"
                    f"需先去污或人工核准"
                )

        if tool == "write_file" and view.path:
            in_quarantine = any(_glob_match(view.path, g) for g in self.quarantine_globs)
            is_deliverable = any(_glob_match(view.path, g) for g in self.deliverable_globs)
            if is_deliverable and not in_quarantine:
                return True, (
                    f"{reason_prefix}，禁止把可能携带不可信内容的产物写入交付目录"
                    f" `{view.path}`（隔离区 tmp 可写）；需先去污或人工核准"
                )

        return False, ""

    # ------------------------------------------------------------- 去污
    @staticmethod
    def sanitize_text(text: str) -> str:
        """确定性去污：剥离活性内容，仅保留结构化文字（演示级实现）。"""
        clean = text or ""
        for pattern, name in _ACTIVE_PATTERNS:
            clean = re.sub(pattern, f"[已剥离:{name}]", clean)
        # 压缩连续占位与空行
        clean = re.sub(r"(\[已剥离:[^\]]+\]\s*){2,}", "[已剥离:多重活性内容] ", clean)
        clean = re.sub(r"\n{3,}", "\n\n", clean)
        return clean.strip()

    def apply_sanitize(self, clean_text: str, step: int = 0) -> bool:
        """执行去污：清除污染状态并留痕（返回是否生效）。"""
        if not self.tainted:
            return False
        self.sanitized = True
        self.sanitized_at_step = step
        self.tainted = False
        self.last_sanitized_text = clean_text[:800]
        return True

    def human_approve(self, note: str = "", step: int = 0) -> bool:
        """人工核准（Human-in-the-loop）：清除污染状态并留痕。"""
        if not self.tainted:
            return False
        self.human_approved = True
        self.human_approved_note = note or "操作员人工核准放行"
        self.tainted = False
        return True

    # ------------------------------------------------------------- 快照
    def snapshot(self) -> dict[str, Any]:
        return {
            "tainted": self.tainted,
            "tainted_at_step": self.tainted_at_step,
            "source": self.taint_source,
            "sanitized": self.sanitized,
            "human_approved": self.human_approved,
            "target_host": self.target_host,
            "marks": [
                {"step": m.step, "tool": m.tool, "source": m.source, "level": m.level.value}
                for m in self.history
            ],
        }
