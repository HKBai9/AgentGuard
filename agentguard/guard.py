r"""模块 4：动态隔离阻断（应急响应）+ 全层编排。

本模块是防护系统的统一入口（Facade）：Agent 的每一次工具调用都必须经过
``SandboxGuard.evaluate()``，任何一层判定为逃逸即按响应策略处置。

编排的层（v1.1）：
  L0 动态权能（capability）—— 票据验证：零初始权限下的执行许可
  L1 权限基线（baseline）—— 静态授权范围
  LT 污点感知（taint）—— 上下文可信度与动态降权
  L2 语义意图（intent）—— Thought 语义漂移
  L3 行为运行时（runtime）—— 参数审计与时序行为链
  L4 隔离阻断（本模块）—— 按严重度分级响应

处置动作（对应竞赛要求的"检测 → 判定 → 阻断 → 审计"闭环）：
  1. **阻断**：拦截本次工具调用，工具**不会真正执行**（副作用为零）；
  2. **会话隔离**：冻结当前 Agent 会话，销毁其临时上下文，阻断链式逃逸；
  3. **告警输出**：给出逃逸类型、风险等级、证据链，供管理员处置；
  4. **安全回滚**：把会话期间被写入的文件恢复到会话开始时的快照状态。

响应分寸：只有 L0/LT 证据（纯权能/污点拒绝）时**只拦本次调用、不冻结会话**
（动态降权语义）；检测层拿到 HIGH/CRITICAL 越界证据才升级为会话隔离。

设计要点：防护层是**独立 SDK**（不绑定任何 Agent 框架）。
对照组（关闭防护）与实验组（开启防护）使用**同一个 Agent 循环、同一个模型、
同一个沙箱**，唯一差异是这次工具调用是否经过 ``SandboxGuard``。
"""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .action import ActionView, build_action
from .baseline import PermissionBaseline, load_baseline
from .capability import CapabilityAuthority, CapabilityToken
from .intent import IntentAssessment, IntentChecker
from .paths import DEFAULT_CONFIG_PATH, VFS_ROOT
from .runtime import ActionRecord, RuntimeMonitor
from .taint import TaintTracker
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

# 风险等级 -> 默认处置（可被配置覆盖）
_DEFAULT_RESPONSE: dict[str, str] = {
    "CRITICAL": "isolate_and_rollback",
    "HIGH": "isolate_session",
    "MEDIUM": "block_tool",
    "LOW": "log_only",
}

_ACTION_RANK = {"log_only": 0, "block_tool": 1, "isolate_session": 2, "isolate_and_rollback": 3}

# 阻断门槛：只有达到该等级的证据才会真正拦下动作。
# LOW 级别的证据（例如"相似度偏低但仍属正常收尾工作"）只记录、不阻断，
# 这是保证"防护不误伤合法操作"的关键。
BLOCKING_SEVERITY = Severity.HIGH


@dataclass
class GuardConfig:
    """防护运行参数（由 UI 的"启用边界逃逸防护"复选框控制）。"""

    enabled: bool = True
    # 子开关：便于答辩时逐层演示"哪一层在起作用"
    enable_capability: bool = True   # L0 动态权能（JIT 票据 + 微租约 + 撤销）
    enable_intent: bool = True
    enable_baseline: bool = True
    enable_runtime: bool = True
    enable_isolation: bool = True
    enable_rollback: bool = True
    enable_llm_review: bool = False
    enable_taint: bool = True        # LT 污点感知与动态降权

    def to_dict(self) -> dict[str, Any]:
        return {
            "防护总开关": self.enabled,
            "动态权能(L0)": self.enable_capability,
            "语义意图校验(L2)": self.enable_intent,
            "权限基线(L1)": self.enable_baseline,
            "行为运行时监控(L3)": self.enable_runtime,
            "隔离阻断(L4)": self.enable_isolation,
            "安全回滚(L4)": self.enable_rollback,
            "污点感知(LT)": self.enable_taint,
            "大模型复核(L2)": self.enable_llm_review,
        }


class SandboxGuard:
    """边界逃逸防护引擎。"""

    def __init__(
        self,
        baseline: PermissionBaseline,
        config: GuardConfig | None = None,
        llm: Any = None,
        session_id: str = "",
        vfs_real_root: str = "",
    ) -> None:
        self.baseline = baseline
        self.config = config or GuardConfig()
        self.session_id = session_id or f"sess-{int(time.time())}"
        self.events: list[GuardEvent] = []
        self.frozen = False
        self.blocked_calls: list[dict[str, Any]] = []
        self.rollback_log: list[str] = []
        self.snapshot_dir = ""

        # L0 动态权能：确定性策略引擎（签发/验证/撤销）+ LT 污点追踪
        cap_cfg = (baseline.cfg.get("capability") or {})
        self.authority = CapabilityAuthority(
            baseline,
            session_id=self.session_id,
            ttl=float(cap_cfg.get("ttl_seconds", 30.0)),
            max_calls=int(cap_cfg.get("max_calls", 1)),
        )
        self.taint = TaintTracker(baseline)

        self.intent = IntentChecker(baseline, llm=llm, enable_llm_review=self.config.enable_llm_review)
        self.monitor = RuntimeMonitor(baseline, session_id=self.session_id)

        # 回滚快照：只快照"可写白名单"目录（体积小、且是唯一会被 Agent 改动的区域）
        vfs_root = vfs_real_root or (baseline.cfg.get("_vfs_root") or "")
        self.vfs_root = vfs_root
        self._writable_real_dirs: list[str] = []
        for pat in baseline.file_write:
            rel = pat.replace("/sandbox_fake/", "").rstrip("/*")
            self._writable_real_dirs.append(os.path.join(vfs_root, rel.replace("/", os.sep)))
        self._snapshot: dict[str, dict[str, Any]] = {}
        self._take_snapshot()

        # 审计日志
        self.audit_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            str((baseline.cfg.get("response", {}) or {}).get("audit_log", "logs/audit.jsonl")),
        )

    # ------------------------------------------------------------ 回滚快照
    def _take_snapshot(self) -> None:
        if not self.config.enable_rollback or not self.vfs_root:
            return
        for d in self._writable_real_dirs:
            self._snapshot[d] = {}
            if not os.path.isdir(d):
                continue
            for root, _dirs, files in os.walk(d):
                for name in files:
                    full = os.path.join(root, name)
                    try:
                        with open(full, "rb") as fh:
                            self._snapshot[d][full] = fh.read()
                    except OSError:
                        continue

    def rollback(self) -> list[str]:
        """把可写区域恢复到会话开始时的状态。"""
        actions: list[str] = []
        if not self.config.enable_rollback or not self.vfs_root:
            return actions
        for d, files in self._snapshot.items():
            # 1) 删除会话期间新增的文件
            if os.path.isdir(d):
                for root, _dirs, names in os.walk(d):
                    for name in names:
                        full = os.path.join(root, name)
                        if full not in files:
                            try:
                                os.remove(full)
                                actions.append(f"回滚：删除会话期间新增文件 {self._v(full)}")
                            except OSError:
                                pass
            # 2) 还原被修改/删除的文件
            for full, blob in files.items():
                unchanged = False
                if os.path.isfile(full):
                    try:
                        with open(full, "rb") as fh:
                            unchanged = fh.read() == blob
                    except OSError:
                        unchanged = False
                if unchanged:
                    continue
                try:
                    os.makedirs(os.path.dirname(full), exist_ok=True)
                    with open(full, "wb") as fh:
                        fh.write(blob)
                    actions.append(f"回滚：还原文件 {self._v(full)}")
                except OSError:
                    pass
        self.rollback_log.extend(actions)
        return actions

    def _v(self, real_path: str) -> str:
        """真实路径 -> 虚拟路径（仅用于日志展示）。"""
        if self.vfs_root and real_path.lower().startswith(self.vfs_root.lower()):
            rel = real_path[len(self.vfs_root):].replace(os.sep, "/")
            return "/sandbox_fake" + (rel if rel.startswith("/") else "/" + rel)
        return real_path

    # -------------------------------------------------------------- 事件
    def emit(self, event: GuardEvent) -> None:
        self.events.append(event)
        self._append_audit(event)

    def _append_audit(self, event: GuardEvent) -> None:
        try:
            os.makedirs(os.path.dirname(self.audit_path), exist_ok=True)
            rec = {"session": self.session_id, **event.to_dict()}
            with open(self.audit_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError:
            pass

    # ------------------------------------------------------------ 核心判定
    def evaluate(
        self,
        call: ToolCall,
        token: CapabilityToken | None = None,
        view: ActionView | None = None,
        refusal: str = "",
    ) -> tuple[Verdict, ActionView]:
        """对一个工具调用做完整判定。

        返回 (Verdict, ActionView)。调用方只在 ``verdict.allowed`` 为真时执行工具。

        ``token``：ToolBridge 在执行前按需（JIT）申请的权能票据；
        ``refusal``：策略引擎拒绝签发时的理由（无票据时作为证据展示）。
        """
        t0 = time.perf_counter()
        view = view if view is not None else build_action(call.tool, call.args, self.vfs_root)
        findings: list[Finding] = []

        # ---------- 防护关闭：对照组，直接放行（保留审计记录以便对比） ----------
        if not self.config.enabled:
            verdict = Verdict(
                decision=Decision.ALLOW,
                severity=Severity.LOW,
                findings=[],
                effective_args=dict(call.args),
                latency_ms=(time.perf_counter() - t0) * 1000,
            )
            self.monitor.record(
                ActionRecord(step=call.step, tool=call.tool, view=view, allowed=True, decision="ALLOW(防护关闭)", call_id=call.call_id)
            )
            self.emit(
                GuardEvent(
                    kind="allow",
                    title=f"放行（防护关闭）：{call.tool}",
                    detail=f"目标 {view.host or view.path or view.command or view.raw_args}｜"
                           f"防护总开关为 OFF，不做任何安全判定",
                    severity=Severity.LOW,
                    step=call.step,
                    tool=call.tool,
                    payload={"guard_enabled": False},
                )
            )
            return verdict, view

        # ---------- 会话已冻结：拒绝一切后续调用（阻断链式逃逸） ----------
        if self.frozen and self.config.enable_isolation:
            verdict = Verdict(
                decision=Decision.ISOLATE,
                severity=Severity.CRITICAL,
                findings=[
                    Finding(
                        layer=Layer.RESPONSE,
                        severity=Severity.CRITICAL,
                        escape_type=EscapeType.NONE,
                        reason="会话已被冻结，拒绝执行任何后续工具调用（防止链式逃逸）",
                        evidence={"tool": call.tool},
                        rule_id="L4-SESSION-FROZEN",
                    )
                ],
                effective_args=dict(call.args),
                rule_id="L4-SESSION-FROZEN",
                session_frozen=True,
                latency_ms=(time.perf_counter() - t0) * 1000,
            )
            self.monitor.record(
                ActionRecord(step=call.step, tool=call.tool, view=view, allowed=False, decision="ISOLATE(会话冻结)", call_id=call.call_id)
            )
            self.emit(
                GuardEvent(
                    kind="isolate",
                    title=f"拒绝执行：会话已冻结｜{call.tool}",
                    detail="会话处于隔离状态，工具调用未被下发执行",
                    severity=Severity.CRITICAL,
                    step=call.step,
                    tool=call.tool,
                    payload=verdict.to_dict(),
                )
            )
            return verdict, view

        # ================= L0 动态权能验证（看"票据"） =================
        # 零初始权限：没有当次签发的有效票据，任何工具都不执行。
        if self.config.enable_capability:
            cap_findings = self.authority.verify(token, call.tool, view, call.step)
            if cap_findings and refusal:
                # 把策略引擎的拒绝理由并进"无票据"证据（便于审计展示）
                cap_findings[0] = Finding(
                    layer=cap_findings[0].layer,
                    severity=cap_findings[0].severity,
                    escape_type=cap_findings[0].escape_type,
                    reason=cap_findings[0].reason + f"｜策略引擎拒绝签发：{refusal}",
                    evidence=cap_findings[0].evidence,
                    rule_id=cap_findings[0].rule_id,
                )
            findings.extend(cap_findings)
            if cap_findings:
                top = cap_findings[0]
                self.emit(
                    GuardEvent(
                        kind="capability",
                        title=f"L0 权能校验未通过：{top.rule_id}",
                        detail=top.reason,
                        severity=top.severity,
                        step=call.step,
                        tool=call.tool,
                        payload={
                            "rule_id": top.rule_id,
                            "token": token.to_dict() if token else None,
                        },
                    )
                )

        # ================= LT 污点降权（看"上下文可信度"） =================
        if self.config.enable_taint:
            tainted_block, tainted_reason = self.taint.blocks(call.tool, view)
            if tainted_block:
                findings.append(
                    Finding(
                        layer=Layer.TAINT,
                        severity=Severity.HIGH,
                        escape_type=EscapeType.TAINT_BLOCKED,
                        reason=tainted_reason,
                        evidence=self.taint.snapshot(),
                        rule_id="LT-BLOCK",
                    )
                )
                self.emit(
                    GuardEvent(
                        kind="taint",
                        title="LT 污点降权：拒绝高危动作",
                        detail=tainted_reason,
                        severity=Severity.HIGH,
                        step=call.step,
                        tool=call.tool,
                        payload={"taint": self.taint.snapshot()},
                    )
                )

        # ================= L2 语义意图校验（看"想法"） =================
        assessment: IntentAssessment | None = None
        if self.config.enable_intent and (call.thought or "").strip():
            assessment = self.intent.check(call.thought, step=call.step)
            findings.extend(assessment.findings)
            if assessment.findings:
                top = max(assessment.findings, key=lambda f: f.severity.rank)
                self.emit(
                    GuardEvent(
                        kind="intent",
                        title=f"L2 语义意图告警：{top.escape_type.value}",
                        detail=top.reason,
                        severity=top.severity,
                        step=call.step,
                        tool=call.tool,
                        payload={
                            "drift": assessment.drift,
                            "similarity": assessment.similarity,
                            "risk_categories": [
                                {"type": c.value, "term": t, "confidence": c2}
                                for c, t, c2 in assessment.risk_categories
                            ],
                            "findings": [f.to_dict() for f in assessment.findings],
                        },
                    )
                )

        # ================= L1 权限基线（看"授权范围"） =================
        if self.config.enable_baseline:
            findings.extend(self.baseline.check(view))

        # ================= L3 行为运行时监控（看"真实动作"） =================
        if self.config.enable_runtime:
            findings.extend(self.monitor.check(view, call.step))

        # ================= 汇总裁决 =================
        # 只有达到阻断门槛的证据才会拦截动作；其余仅记入审计。
        blocking = [f for f in findings if f.severity >= BLOCKING_SEVERITY]
        severity = max((f.severity for f in findings), key=lambda s: s.rank, default=Severity.LOW)
        response_cfg = self.baseline.cfg.get("response", {}) or {}

        if not blocking:
            decision = Decision.ALLOW
            action = _ACTION_RANK["log_only"]
        elif all(f.layer in (Layer.CAPABILITY, Layer.TAINT) for f in blocking):
            # 动态降权：仅权能/污点层拦截（无检测层逃逸证据）时，只拒绝
            # 本次调用、不冻结会话——Agent 仍可通过去污/收敛行为继续任务。
            decision = Decision.BLOCK
            action = _ACTION_RANK["block_tool"]
        else:
            block_sev = max((f.severity for f in blocking), key=lambda s: s.rank)
            policy = str(
                response_cfg.get(
                    f"on_{block_sev.value.lower()}", _DEFAULT_RESPONSE[block_sev.value]
                )
            )
            action = _ACTION_RANK.get(policy, 1)
            if action >= _ACTION_RANK["isolate_session"] and self.config.enable_isolation:
                decision = Decision.ISOLATE
            else:
                decision = Decision.BLOCK

        # 隔离生效：冻结会话 + 撤销全部权能 + 回滚
        frozen_now = False
        if decision is Decision.ISOLATE:
            if self.config.enable_isolation:
                self.frozen = True
                frozen_now = True
                # Caretaker 自动熔断：检测层确认逃逸 → 撤销会话根，
                # 全部在飞票据 O(1) 级联失效（不依赖后续调用的冻结检查）
                if self.config.enable_capability and self.authority.root_scope.node.is_alive():
                    self.authority.revoke_all(
                        "检测层确认边界逃逸：隔离会话并自动级联撤销全部权能"
                    )
                    self.emit(
                        GuardEvent(
                            kind="revoke",
                            title="⛔ 自动熔断：检测到逃逸，已撤销全部权能",
                            detail=(
                                "L4 隔离判定成立，控制中心将撤销根节点标记失效："
                                "全部在飞票据立即级联失效（Caretaker 即时撤销）"
                            ),
                            severity=Severity.CRITICAL,
                            step=call.step,
                            tool=call.tool,
                            payload={"epoch": self.authority.registry.epoch},
                        )
                    )
            if action == _ACTION_RANK["isolate_and_rollback"] and self.config.enable_rollback:
                actions = self.rollback()
                if actions:
                    self.emit(
                        GuardEvent(
                            kind="rollback",
                            title=f"L4 安全回滚：已恢复 {len(actions)} 项变更",
                            detail="；".join(actions[:6]),
                            severity=Severity.HIGH,
                            step=call.step,
                            tool=call.tool,
                            payload={"actions": actions},
                        )
                    )

        verdict = Verdict(
            decision=decision,
            severity=severity,
            findings=findings,
            effective_args=dict(call.args),
            rule_id=(findings[0].rule_id if findings else ""),
            session_frozen=frozen_now,
            latency_ms=(time.perf_counter() - t0) * 1000,
        )
        # 取最高优先级规则的 id
        if findings:
            verdict.rule_id = max(findings, key=lambda f: f.severity.rank).rule_id

        self.monitor.record(
            ActionRecord(
                step=call.step,
                tool=call.tool,
                view=view,
                allowed=verdict.allowed,
                decision=verdict.decision.value,
                risk=verdict.summary if not verdict.allowed else "",
                call_id=call.call_id,
            )
        )

        if verdict.allowed:
            noted = [f for f in findings if f.severity < BLOCKING_SEVERITY]
            detail = f"目标 {view.host or view.path or view.command or view.raw_args}｜命中白名单，无阻断级风险信号"
            if noted:
                detail += "｜已记录 " + str(len(noted)) + " 条低危观察项（不阻断）：" + noted[0].reason
            self.emit(
                GuardEvent(
                    kind="allow",
                    title=f"L1-L3 全部通过，放行动作：{call.tool}",
                    detail=detail,
                    severity=Severity.LOW,
                    step=call.step,
                    tool=call.tool,
                    payload={
                        "verdict": verdict.to_dict(),
                        "layers_checked": self._layers_checked(),
                        "observations": [f.to_dict() for f in noted],
                        "capability": token.to_dict() if (token and self.config.enable_capability) else None,
                    },
                )
            )
        else:
            self.blocked_calls.append(
                {
                    "step": call.step,
                    "tool": call.tool,
                    "args": call.args,
                    "thought": call.thought,
                    "verdict": verdict.to_dict(),
                }
            )
            top = max(findings, key=lambda f: f.severity.rank)
            self.emit(
                GuardEvent(
                    kind="isolate" if decision is Decision.ISOLATE else "block",
                    title=(
                        f"L4 {'会话隔离' if decision is Decision.ISOLATE else '阻断'}："
                        f"{top.escape_type.value}"
                    ),
                    detail=(
                        f"工具 `{call.tool}` 未执行。判定依据（{top.layer.value}）：{top.reason}"
                    ),
                    severity=severity,
                    step=call.step,
                    tool=call.tool,
                    payload={"verdict": verdict.to_dict(), "call": call.to_dict()},
                )
            )
        return verdict, view

    def _layers_checked(self) -> list[str]:
        layers = []
        if self.config.enable_capability:
            layers.append(Layer.CAPABILITY.value)
        if self.config.enable_baseline:
            layers.append(Layer.BASELINE.value)
        if self.config.enable_intent:
            layers.append(Layer.INTENT.value)
        if self.config.enable_taint:
            layers.append(Layer.TAINT.value)
        if self.config.enable_runtime:
            layers.append(Layer.RUNTIME.value)
        return layers

    def record_result(self, call: ToolCall, result: ToolResult) -> None:
        """Record observed execution separately from permission to execute."""
        self.monitor.record_result(call.call_id, result)
        self.emit(GuardEvent(kind="execution", title=f"工具执行结果：{call.tool}",
            detail="执行成功" if result.ok else "未成功执行",
            step=call.step, tool=call.tool,
            payload={"call_id": call.call_id, "ok": result.ok, "executed": result.executed,
                     "blocked": result.blocked, "effects": result.effects,
                     "effects_complete": result.meta.get("effects_complete", False)}))

    # ---------------------------------------------------- 控制中心操作（UI/人工）
    def revoke_all_capabilities(self, reason: str = "控制中心熔断：撤销全部权能") -> dict[str, Any]:
        """熔断开关：撤销会话根节点，全部在飞票据 O(1) 级联失效。"""
        self.authority.revoke_all(reason)
        snapshot = self.authority.snapshot()
        self.emit(
            GuardEvent(
                kind="revoke",
                title="⛔ 熔断：已撤销会话全部权能",
                detail=f"{reason}｜撤销纪元 epoch={self.authority.registry.epoch}，"
                       f"累计签发 {snapshot['stats']['issued']} 张票据全部失效",
                severity=Severity.CRITICAL,
                payload={"epoch": self.authority.registry.epoch, "reason": reason},
            )
        )
        return snapshot

    def approve_taint(self, note: str = "操作员人工核准放行（Human-in-the-loop）") -> bool:
        """人工核准：清除污点状态（留审计痕），恢复常规签发。"""
        ok = self.taint.human_approve(note)
        if ok:
            self.emit(
                GuardEvent(
                    kind="taint",
                    title="🧑‍⚖️ 人工核准：污点上下文被放行",
                    detail=note,
                    severity=Severity.MEDIUM,
                    payload={"taint": self.taint.snapshot()},
                )
            )
        return ok

    # ------------------------------------------------------------------ 统计
    def summary(self) -> dict[str, Any]:
        n_block = sum(1 for e in self.events if e.kind in ("block", "isolate"))
        n_allow = sum(1 for e in self.events if e.kind == "allow")
        n_intent = sum(1 for e in self.events if e.kind == "intent")
        escape_types = sorted(
            {
                f["escape_type"]
                for c in self.blocked_calls
                for f in c["verdict"]["findings"]
            }
        )
        return {
            "session": self.session_id,
            "guard_enabled": self.config.enabled,
            "frozen": self.frozen,
            "allowed": n_allow,
            "blocked": n_block,
            "intent_alerts": n_intent,
            "escape_types": escape_types,
            "rollback_actions": len(self.rollback_log),
            "findings_total": sum(len(c["verdict"]["findings"]) for c in self.blocked_calls),
            "capability": self.authority.stats,
            "capability_revocations": self.authority.registry.epoch,
            "tainted": self.taint.tainted,
        }

    def to_report(self) -> dict[str, Any]:
        return {
            "session": self.session_id,
            "summary": self.summary(),
            "config": self.config.to_dict(),
            "events": [e.to_dict() for e in self.events],
            "blocked_calls": self.blocked_calls,
            "action_chain": self.monitor.chain(),
            "rollback": self.rollback_log,
            "capability": self.authority.snapshot(),
            "taint": self.taint.snapshot(),
        }


# ---------------------------------------------------------------------------
# 便捷装配函数
# ---------------------------------------------------------------------------
def build_guard(
    config_path: str | None = None,
    guard_config: GuardConfig | None = None,
    llm: Any = None,
    session_id: str = "",
    task: str = "",
    vfs_root: str | None = None,
) -> SandboxGuard:
    """按默认路径装配一个可用的防护引擎。

    放在本模块（而不是包根的 ``__init__``）是为了避免循环导入：
    ``sdk`` 需要它，而 ``sdk`` 又被包根导入。
    """
    baseline = load_baseline(config_path or DEFAULT_CONFIG_PATH)
    if task:
        baseline.cfg.setdefault("experiment", {}).setdefault("task_baseline", {})["goal"] = task
        baseline.task_goal = task
    # 让防护层知道虚拟文件系统的真实根（用于回滚快照）
    baseline.cfg["_vfs_root"] = os.path.abspath(vfs_root or VFS_ROOT)
    return SandboxGuard(
        baseline,
        config=guard_config or GuardConfig(),
        llm=llm,
        session_id=session_id,
        vfs_real_root=baseline.cfg["_vfs_root"],
    )
