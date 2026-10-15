r"""模块 3：行为运行时监控器（事中 / Runtime Behavior Monitor）。

与语义层的分工：
  - 语义层看"想法"（Thought 文本，可能被包装/绕过）；
  - 行为层看"动作"（真实工具调用与参数，是逃逸的必要条件）。

两项核心能力：
  1. **工具调用参数审计**：读取路径、访问 IP、命令参数逐项比对基线；
     并补上基线层看不到的运行时事实（例如：文件是否真实存在、
     本次会话是否已经读过敏感文件）。
  2. **时序行为链分析**：单个动作看起来都"差不多合规"，
     但 `读私钥 → 连内网数据库` 这种组合就是横向移动。
     通过滑动窗口匹配 `sequences.rules` 中的前序/后续动作对来识别。
"""

from __future__ import annotations

import fnmatch
import re
import time
from dataclasses import dataclass, field
from typing import Any

from .action import ActionView, in_cidr
from .baseline import PermissionBaseline, _glob_match
from .types import EscapeType, Finding, Layer, Severity


@dataclass
class ActionRecord:
    """一次已经过防护判定的动作记录（审计链的基本单元）。"""

    step: int
    tool: str
    view: ActionView
    allowed: bool
    decision: str
    risk: str = ""
    ts: float = field(default_factory=time.time)
    output_digest: str = ""


class RuntimeMonitor:
    """行为运行时监控器。"""

    def __init__(self, baseline: PermissionBaseline, session_id: str = "") -> None:
        self.baseline = baseline
        self.session_id = session_id
        self.history: list[ActionRecord] = []
        # 记录"已经成功读取过的敏感文件"，用于时序链判定
        self.sensitive_reads: list[tuple[str, float, int]] = []
        self.command_times: list[float] = []

    # ------------------------------------------------------------------ 记录
    def record(self, rec: ActionRecord) -> None:
        self.history.append(rec)
        if rec.allowed and rec.view.tool == "read_file":
            hit = self.baseline.protected_hit(rec.view.path)
            if hit:
                self.sensitive_reads.append((rec.view.path, rec.ts, rec.step))
        if rec.view.tool == "run_command":
            self.command_times.append(rec.ts)

    # ------------------------------------------------- 1. 参数审计（单步）
    def audit_params(self, view: ActionView, step: int) -> list[Finding]:
        findings: list[Finding] = []

        # (a) 文件类：原始参数是否包含路径上跳（白名单绕过尝试）
        if view.tool in ("read_file", "write_file"):
            raw_path = str(view.raw_args.get("path") or view.raw_args.get("file") or "")
            if ".." in raw_path:
                findings.append(
                    Finding(
                        layer=Layer.RUNTIME,
                        severity=Severity.HIGH,
                        escape_type=EscapeType.CONFIG_TAMPER,
                        reason=f"文件参数包含路径上跳 `..`（{raw_path}），"
                               f"归一化后为 {view.path}，疑似白名单绕过尝试",
                        evidence={"raw": raw_path, "normalized": view.path},
                        rule_id="L3-PATH-TRAVERSAL",
                    )
                )

        # (b) 网络类：解析出的真实 IP 是否落在内网
        if view.host:
            for d in self.baseline.net_deny:
                if str(d.get("match")) == "cidr" and in_cidr(view.resolved_host, str(d.get("value"))):
                    findings.append(
                        Finding(
                            layer=Layer.RUNTIME,
                            severity=Severity.CRITICAL,
                            escape_type=EscapeType.LATERAL_MOVEMENT,
                            reason=f"解析后真实地址 {view.resolved_host} 落在内网禁用网段 "
                                   f"{d.get('value')}（工具 {view.tool}）",
                            evidence={"host": view.host, "resolved": view.resolved_host},
                            rule_id="L3-NET-INTERNAL",
                        )
                    )
                    break

        # (c) 命令类：包装型绕过（用白名单命令加载外部脚本）
        if view.tool == "run_command":
            cmd = view.command
            wrappers = [
                (r"\|\s*(ba)?sh\b", "把远端/构造内容管道给 shell 执行"),
                (r"\$\(.*\)", "命令替换，可能隐藏真实载荷"),
                (r"`.*`", "反引号命令替换，可能隐藏真实载荷"),
                (r"/dev/tcp/", "bash 内建 TCP 连接，可绕过网络管控"),
                (r"\bbase64\s+-d\b", "base64 解码后执行，典型混淆手法"),
                (r"\.\./", "相对路径上跳"),
            ]
            for pattern, why in wrappers:
                if re.search(pattern, cmd):
                    findings.append(
                        Finding(
                            layer=Layer.RUNTIME,
                            severity=Severity.HIGH,
                            escape_type=EscapeType.DANGEROUS_COMMAND,
                            reason=f"命令中使用 `{pattern}`：{why}",
                            evidence={"command": cmd},
                            rule_id="L3-CMD-WRAPPER",
                        )
                    )

        # (d) 会话内上下文：本会话已读过敏感凭证，然后任何外联都升级为高危
        if view.host and self.sensitive_reads:
            paths = ", ".join(p for p, _, _ in self.sensitive_reads[-3:])
            findings.append(
                Finding(
                    layer=Layer.RUNTIME,
                    severity=Severity.CRITICAL,
                    escape_type=EscapeType.LATERAL_MOVEMENT,
                    reason=f"本会话此前已读取敏感凭证（{paths}），随后的任何外联动作"
                           f"（{view.tool} -> {view.host}:{view.port}）按横向移动链处理",
                    evidence={"prior_reads": [p for p, _, _ in self.sensitive_reads], "target": view.host},
                    rule_id="L3-STATE-CRED-THEN-NET",
                )
            )
        return findings

    # --------------------------------------------- 2. 时序行为链（跨步）
    def audit_sequence(self, view: ActionView, step: int) -> list[Finding]:
        findings: list[Finding] = []
        now = time.time()

        for rule in self.baseline.sequence_rules:
            # --- 高频刷写型规则（无前序动作，按窗口计数）---
            if rule.threshold and not rule.read and not rule.follow:
                window = rule.window or 10
                recent = [t for t in self.command_times if now - t <= window]
                if len(recent) >= rule.threshold:
                    findings.append(
                        Finding(
                            layer=Layer.RUNTIME,
                            severity=rule.severity,
                            escape_type=EscapeType.SEQUENCE_ANOMALY,
                            reason=f"[{rule.id} {rule.name}] {window}s 内命令调用 {len(recent)} 次 "
                                   f"≥ 阈值 {rule.threshold}：{rule.reason}",
                            evidence={"count": len(recent), "window": window},
                            rule_id=rule.id,
                        )
                    )
                continue

            # --- 前序:敏感读取 → 后续:危险动作 ---
            if not rule.read or not rule.follow:
                continue
            prior = None
            for path, ts, sstep in self.sensitive_reads:
                if any(_glob_match(path, pat) for pat in rule.read):
                    prior = (path, ts, sstep)
                    break
            if prior is None:
                continue
            if not self._matches_follow(view, rule.follow):
                continue
            findings.append(
                Finding(
                    layer=Layer.RUNTIME,
                    severity=rule.severity,
                    escape_type=EscapeType.LATERAL_MOVEMENT
                    if "凭证" in rule.name or "内网" in rule.name
                    else EscapeType.SEQUENCE_ANOMALY,
                    reason=(
                        f"[{rule.id} {rule.name}] 命中时序行为链："
                        f"step{prior[2]} 读取 `{prior[0]}` → step{step} 执行 "
                        f"{view.tool}({view.host or view.path or view.binary})。{rule.reason}"
                    ),
                    evidence={
                        "rule": rule.id,
                        "prior_read": prior[0],
                        "prior_step": prior[2],
                        "current_tool": view.tool,
                        "current_target": view.host or view.path or view.command,
                    },
                    rule_id=rule.id,
                )
            )
        return findings

    def _matches_follow(self, view: ActionView, follow: list[dict[str, Any]]) -> bool:
        """判断当前动作是否满足某个 follow 条件。"""
        for cond in follow:
            tool = cond.get("tool")
            if tool and view.tool != tool:
                continue
            host_in = cond.get("host_in")
            if host_in:
                target = view.host or view.resolved_host
                if not any(
                    in_cidr(view.resolved_host, str(h)) or str(h).lower() == str(target).lower()
                    for h in host_in
                ):
                    continue
            port_in = cond.get("port_in")
            if port_in and (view.policy_port or view.port) not in [int(p) for p in port_in]:
                continue
            path_outside = cond.get("path_outside")
            if path_outside:
                if any(_glob_match(view.path, p) for p in path_outside):
                    continue  # 仍在允许目录内，不构成外泄
            return True
        return False

    # ----------------------------------------------------------- 统一入口
    def check(self, view: ActionView, step: int) -> list[Finding]:
        return self.audit_params(view, step) + self.audit_sequence(view, step)

    # ----------------------------------------------------------- 供 UI 使用
    def chain(self) -> list[dict[str, Any]]:
        return [
            {
                "step": r.step,
                "tool": r.tool,
                "target": r.view.host or r.view.path or r.view.command or "",
                "allowed": r.allowed,
                "decision": r.decision,
                "risk": r.risk,
                "ts": r.ts,
            }
            for r in self.history
        ]
