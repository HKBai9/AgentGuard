r"""模块 0：动态权能层（Just-In-Time Ephemeral Capabilities）。

本模块把系统从"检查式授权"（每次调用时检查静态白名单）升级为
"权能式授权"（OCap, Object-Capability）：

  1. **零初始权限**：Agent 启动时不预置任何全局工具权限。任何动作都必须
     持有**当次签发**的权能票据（Capability Token）才会被执行。
  2. **按需签发（JIT）**：Agent 规划出具体子任务时，由确定性策略引擎
     （:class:`CapabilityAuthority`，无 LLM 参与）审核并签发票据。
     签发过程对模型完全透明（由 Agent 循环代为申请），因此对照组与
     实验组仍是"同一个 Agent、同一个模型"。
  3. **微租约（Micro-Lease）**：票据带有极严苛的约束 ——
     - TTL：默认 30 秒生命周期；
     - 配额：``max_calls=1``，单次调用即作废（天然防重放）；
     - 绑定：Trace ID（会话）+ 具体步骤号，禁止跨步骤/跨会话复用。
  4. **参数级约束（Argument Attenuation）**：票据内部硬编码参数谓词
     （Caveat，借鉴 Macaroons 的上下文约束）：读权限票据只能读白名单
     路径、网络票据只能访问白名单主机/端口、命令票据只能执行白名单
     二进制且不得命中危险模式。
  5. **离线衰减（Attenuation-only Delegation）**：父 Agent 委派子任务时，
     子作用域的权能 = 父权能 ∩ 委派声明。衰减只能收窄、不能放大，
     并通过 HMAC 链式签名保证票据不可伪造、不可丢弃衰减项。
  6. **看门人模式（Caretaker Pattern）即时级联撤销**：每张票据指向撤销
     注册表（:class:`RevocationRegistry`）中的一个节点；撤销节点 = O(1)
     标记失效，该节点派生出的**整棵子树**上的票据立即全部失效。

理论基础：
  - Mark Miller 等《Robust Composition》（OCap / Caretaker 模式）
  - Birgisson et al.《Macaroons》(NDSS'14)：带 Caveats 的凭证衰减
  （Biscuit / WASM 沙箱作为"未来工作"引用，见 docs/CAPABILITY.md。）

安全声明：HMAC 链在单进程演示环境内成立（密钥仅存于策略引擎进程内存），
跨进程部署时应换成标准 Macaroons/Biscuit 实现——接口已按此设计留好边界。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .action import ActionView, extract_hosts_from_command
from .baseline import PermissionBaseline, _glob_match
from .types import EscapeType, Finding, Layer, Severity

# 微租约默认参数（可在 config/permission_baseline.yaml 的 capability 段覆盖）
DEFAULT_TTL = 30.0
DEFAULT_MAX_CALLS = 1


# ===========================================================================
# 参数谓词（Caveat）：约束"这张票据能做什么"
# ===========================================================================
@dataclass
class Caveat:
    """票据内嵌的参数谓词。验证时逐条比对实际调用参数，违反任一条即拒绝。"""

    kind: str            # tool_in / path_glob_any / host_in / port_allowed /
                         # scheme_in / bin_in / no_pattern / net_targets_allowed
    value: Any
    note: str = ""

    def describe(self) -> str:
        return self.note or self.kind

    def check(self, view: ActionView) -> tuple[bool, str]:
        """对照一次真实调用校验谓词。返回 (是否满足, 违反说明)。"""
        if self.kind == "tool_in":
            ok = view.tool in set(self.value or [])
            return ok, f"工具 {view.tool} 不在票据允许集合 {sorted(set(self.value or []))} 内"

        if self.kind == "path_glob_any":
            if not view.path:
                return True, ""
            ok = any(_glob_match(view.path, str(p)) for p in (self.value or []))
            return ok, f"路径 {view.path} 不在票据路径谓词 {(self.value or [])} 内"

        if self.kind == "host_in":
            if not view.host:
                return True, ""
            allowed = {str(h).lower() for h in (self.value or [])}
            ok = view.host.lower() in allowed or view.resolved_host.lower() in allowed
            return ok, f"主机 {view.host} 不在票据主机谓词 {sorted(allowed)} 内"

        if self.kind == "port_allowed":
            if not (view.policy_port or view.port):
                return True, ""
            pport = view.policy_port or view.port
            allowed = set((self.value or {}).get("allowed", []) or [])
            sensitive = set((self.value or {}).get("sensitive", []) or [])
            if pport in sensitive:
                return False, f"端口 {pport} 命中票据禁止的敏感端口"
            if allowed and pport not in allowed:
                return False, f"端口 {pport} 不在票据允许端口 {sorted(allowed)} 内"
            return True, ""

        if self.kind == "scheme_in":
            if not view.scheme:
                return True, ""
            ok = view.scheme.lower() in {str(s).lower() for s in (self.value or [])}
            return ok, f"协议 {view.scheme} 不在票据允许协议 {self.value} 内"

        if self.kind == "bin_in":
            ok = (view.binary or "").lower() in {str(b).lower() for b in (self.value or [])}
            return ok, f"二进制 `{view.binary}` 不在票据允许命令 {sorted(set(map(str, self.value or [])))} 内"

        if self.kind == "no_pattern":
            for pat in self.value or []:
                try:
                    if re.search(str(pat), view.command):
                        return False, f"命令命中票据禁止模式 `{pat}`"
                except re.error:
                    continue
            return True, ""

        if self.kind == "net_targets_allowed":
            if not view.command:
                return True, ""
            spec = self.value or {}
            hosts = {str(h).lower() for h in spec.get("hosts", [])}
            allowed_ports = set(spec.get("allowed_ports", []) or [])
            sensitive = set(spec.get("sensitive_ports", []) or [])
            for host, port in extract_hosts_from_command(view.command):
                low = host.lower()
                pport = port
                if low not in hosts and low not in ("localhost", "127.0.0.1", "::1"):
                    return False, f"命令中的网络目标 {host} 不在票据允许主机内"
                if pport in sensitive:
                    return False, f"命令中的端口 {pport} 命中票据禁止的敏感端口"
                if allowed_ports and pport and pport not in allowed_ports:
                    return False, f"命令中的端口 {pport} 不在票据允许端口内"
            return True, ""

        # 未知谓词类型：默认拒绝（fail-closed）
        return False, f"未知谓词类型 {self.kind}，按默认拒绝处理"


# ===========================================================================
# 撤销注册表（Caretaker Pattern）
# ===========================================================================
@dataclass
class RevocationNode:
    """撤销树上的一个节点。

    每张票据、每个委派作用域都对应一个节点，节点按派生关系构成树：
        root -> delegate@step2 -> token#abc123
    撤销 = 把节点标记为失效（O(1)）。节点是否存活由
    "自身及全部祖先均未失效"决定，因此撤销父节点会**立即**级联失效
    整棵子树上的所有票据——这正是 Caretaker 模式的即时撤销语义。
    """

    node_id: str
    label: str
    parent: "RevocationNode | None" = None
    revoked: bool = False
    revoked_reason: str = ""
    revoked_at: float = 0.0
    created_at: float = field(default_factory=time.time)

    def path(self) -> tuple[str, ...]:
        chain: list[str] = []
        node: RevocationNode | None = self
        while node is not None:
            chain.append(node.label)
            node = node.parent
        return tuple(reversed(chain))

    def path_str(self) -> str:
        return " → ".join(self.path())

    def dead_ancestor(self) -> "RevocationNode | None":
        """返回导致本节点失效的最近被撤销祖先（含自身）；全部存活则 None。"""
        node: RevocationNode | None = self
        while node is not None:
            if node.revoked:
                return node
            node = node.parent
        return None

    def is_alive(self) -> bool:
        return self.dead_ancestor() is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "label": self.label,
            "path": list(self.path()),
            "revoked": self.revoked,
            "revoked_reason": self.revoked_reason,
        }


class RevocationRegistry:
    """内存撤销注册表：权能派生树 + 撤销纪元（Revocation Epoch）。"""

    def __init__(self) -> None:
        self._nodes: dict[str, RevocationNode] = {}
        self.epoch: int = 0
        self.revocations: list[dict[str, Any]] = []
        self.root = self._create("root", "会话根", None)

    def _create(self, label: str, display: str, parent: RevocationNode | None) -> RevocationNode:
        node = RevocationNode(
            node_id=secrets.token_hex(6),
            label=display,
            parent=parent,
        )
        self._nodes[node.node_id] = node
        return node

    def create_child(self, parent: RevocationNode, label: str) -> RevocationNode:
        return self._create(label, label, parent)

    def revoke(self, node: RevocationNode, reason: str = "") -> RevocationNode:
        """撤销一个节点：O(1) 标记，其派生子树上的全部票据立即失效。"""
        if not node.revoked:
            node.revoked = True
            node.revoked_reason = reason or "策略撤销"
            node.revoked_at = time.time()
            self.epoch += 1
            self.revocations.append(
                {
                    "node": node.path_str(),
                    "reason": node.revoked_reason,
                    "epoch": self.epoch,
                    "ts": node.revoked_at,
                }
            )
        return node

    def find(self, node_id: str) -> RevocationNode | None:
        return self._nodes.get(node_id)

    def describe(self) -> dict[str, Any]:
        return {
            "epoch": self.epoch,
            "nodes_total": len(self._nodes),
            "revocations": list(self.revocations),
            "tree": [n.to_dict() for n in self._nodes.values()],
        }


# ===========================================================================
# 作用域（衰减载体）与票据（微租约）
# ===========================================================================
@dataclass
class CapabilityScope:
    """一个权能作用域：撤销树节点 + 继承的衰减谓词 + HMAC 链签名。

    会话根作用域不带任何衰减；委派产生的子作用域 = 父作用域谓词 +
    委派时追加的谓词（只能收窄）。HMAC 链保证作用域/票据不可伪造、
    衰减项不可丢弃。
    """

    node: RevocationNode
    caveats: list[Caveat] = field(default_factory=list)
    mac: str = ""
    label: str = ""

    def path_str(self) -> str:
        return self.node.path_str()

    def tool_allowed(self, tool: str) -> tuple[bool, str]:
        """作用域继承的衰减是否允许该工具。"""
        for c in self.caveats:
            if c.kind == "tool_in" and tool not in set(c.value or []):
                return False, f"权能衰减：`{tool}` 不在父权能允许的工具集合 {sorted(set(c.value))} 内（{c.note}）"
        return True, ""


@dataclass
class CapabilityToken:
    """一张微租约权能票据。"""

    token_id: str
    tool: str
    caveats: list[Caveat]
    trace_id: str                     # 绑定会话（Trace）
    step: int                         # 绑定具体步骤，禁止跨步骤复用
    node: RevocationNode              # Caretaker 句柄（撤销树上的叶子）
    scope_path: tuple[str, ...]
    issued_at: float                  # 单调时钟
    expires_at: float
    max_calls: int
    calls: int = 0
    mac: str = ""
    scope_mac: str = ""               # 派生链父签名（用于重算票据 MAC）
    consumed_at: float | None = None

    def expired(self, now: float) -> bool:
        return now >= self.expires_at

    def exhausted(self) -> bool:
        return self.calls >= self.max_calls

    @property
    def status(self) -> str:
        if not self.node.is_alive():
            return "revoked"
        if self.consumed_at is not None and self.exhausted():
            return "consumed"
        if self.expired(time.monotonic()):
            return "expired"
        return "live"

    def to_dict(self) -> dict[str, Any]:
        return {
            "token_id": self.token_id,
            "tool": self.tool,
            "trace_id": self.trace_id,
            "step": self.step,
            "scope_path": list(self.scope_path),
            "ttl_deadline_in_s": round(max(0.0, self.expires_at - time.monotonic()), 1),
            "max_calls": self.max_calls,
            "calls": self.calls,
            "status": self.status,
            "caveats": [
                {"kind": c.kind, "value": c.value, "note": c.note} for c in self.caveats
            ],
        }


@dataclass
class IssuanceDecision:
    """策略引擎的一次签发裁决。"""

    issued: bool
    token: CapabilityToken | None = None
    reason: str = ""
    rule_id: str = ""


# ===========================================================================
# 策略引擎 + 签发者 + 看门人枢纽
# ===========================================================================
class CapabilityAuthority:
    """确定性策略引擎：签发（Issue）、验证（Verify）、消耗（Consume）、
    衰减（Derive）与撤销（Revoke）的唯一入口。

    判定完全确定性（无 LLM 参与）：同一 (工具, 参数, 作用域, 污点状态)
    永远得到同一裁决，可审计、可回放。
    """

    def __init__(
        self,
        baseline: PermissionBaseline,
        session_id: str = "",
        ttl: float = DEFAULT_TTL,
        max_calls: int = DEFAULT_MAX_CALLS,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.baseline = baseline
        self.session_id = session_id
        self.ttl = float(ttl)
        self.max_calls = int(max_calls)
        self.registry = RevocationRegistry()
        self.tokens: list[CapabilityToken] = []
        self.stats: dict[str, int] = {"requests": 0, "issued": 0, "consumed": 0, "refused": 0}
        # 会话级 HMAC 密钥：仅存在于策略引擎进程内（跨进程应换 Macaroons/Biscuit）
        self._secret = secrets.token_bytes(32)
        self._clock = clock or time.monotonic
        # 登记本引擎派生过的全部合法作用域签名：票据验证时校验其作用域
        # 确实出自这条派生链，防止攻击者用伪造的作用域签名"自洽"出票据
        self._valid_scope_macs: dict[str, str] = {}
        self.root_scope = CapabilityScope(
            node=self.registry.root,
            caveats=[],
            mac=self._hmac(self._secret, f"root|{session_id}"),
            label="session-root",
        )
        self._valid_scope_macs[self.root_scope.mac] = "session-root"

    # ------------------------------------------------------------- HMAC 链
    @staticmethod
    def _hmac(key: bytes | str, payload: str) -> str:
        if isinstance(key, str):
            key = key.encode("utf-8")
        return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _canonical_caveats(caveats: list[Caveat]) -> str:
        return json.dumps(
            [[c.kind, json.dumps(c.value, sort_keys=True, ensure_ascii=False), c.note] for c in caveats],
            ensure_ascii=False,
        )

    def _token_mac(self, token: CapabilityToken) -> str:
        payload = "|".join(
            [
                "token",
                token.token_id,
                token.tool,
                token.trace_id,
                str(token.step),
                self._canonical_caveats(token.caveats),
            ]
        )
        return self._hmac(token.scope_mac, payload)

    def mac_valid(self, token: CapabilityToken) -> bool:
        return hmac.compare_digest(self._token_mac(token), token.mac)

    # ------------------------------------------------------------ 作用域派生
    def derive_scope(
        self,
        parent: CapabilityScope,
        label: str,
        allowed_tools: list[str] | None = None,
        extra_caveats: list[Caveat] | None = None,
    ) -> CapabilityScope:
        """从父作用域派生子作用域（离线衰减）。

        子作用域的约束 = 父作用域全部约束 + 本次追加约束（只增不减，
        因此子权能恒为父权能的子集）。HMAC 链以父签名为密钥派生子签名，
        保证无法凭空伪造、也无法丢弃继承到的衰减项。
        """
        caveats = list(parent.caveats)
        if allowed_tools is not None:
            # 与父作用域已有的 tool_in 取交集（多谓词同时生效 = 交集语义）
            inherited = [c.value for c in parent.caveats if c.kind == "tool_in"]
            allowed = list(allowed_tools)
            for prev in inherited:
                allowed = [t for t in allowed if t in set(prev)]
            caveats.append(
                Caveat("tool_in", allowed, f"委派衰减：仅允许 {allowed}（父集合交集后）")
            )
        for c in extra_caveats or []:
            caveats.append(c)
        node = self.registry.create_child(parent.node, label)
        mac = self._hmac(parent.mac, f"derive|{label}|{self._canonical_caveats(caveats)}")
        scope = CapabilityScope(node=node, caveats=caveats, mac=mac, label=label)
        self._valid_scope_macs[mac] = label
        return scope

    # ------------------------------------------------------------- 参数谓词
    def _policy_caveats(self, tool: str, view: ActionView) -> tuple[list[Caveat], list[str]]:
        """把基线策略编译成本次调用的参数谓词，并校验请求参数。

        返回 (票据内嵌谓词, 违反清单)。违反清单非空 = 策略引擎拒绝签发。
        """
        b = self.baseline
        caveats: list[Caveat] = []
        violations: list[str] = []

        if tool in ("read_file", "write_file"):
            write = tool == "write_file"
            pats = list(b.file_write if write else b.file_read)
            caveats.append(
                Caveat("path_glob_any", pats, "只读/只写语义隔离：" + ("可写" if write else "可读") + "路径白名单")
            )
            if not view.path:
                violations.append(f"`{tool}` 未提供可审计的目标路径，拒绝签发")
            elif not any(_glob_match(view.path, p) for p in pats):
                violations.append(
                    f"路径 `{view.path}` 不在{'可写' if write else '可读'}白名单内，拒绝签发"
                )

        elif tool in ("web_scan", "http_get", "ssh_connect"):
            hosts = [
                str(a.get("value", "")).lower()
                for a in b.net_allow
                if str(a.get("match", "")) == "exact"
            ]
            caveats.append(Caveat("host_in", hosts, "主机白名单（网络访问谓词）"))
            caveats.append(
                Caveat(
                    "port_allowed",
                    {"allowed": sorted(b.allowed_ports), "sensitive": sorted(b.sensitive_ports)},
                    "端口谓词：允许端口 ∖ 敏感端口",
                )
            )
            caveats.append(Caveat("scheme_in", sorted(b.allowed_schemes), "协议白名单"))
            if view.host:
                # 复用 L1 的网络判定逻辑：保证 L0 与 L1 语义永远一致（单一事实来源）
                for f in b.check_network(view):
                    violations.append(f"网络参数越界：{f.reason}")

        elif tool == "run_command":
            caveats.append(Caveat("bin_in", sorted(b.cmd_allow), "命令二进制白名单"))
            caveats.append(
                Caveat("no_pattern", [p["pattern"] for p in b.cmd_patterns], "危险参数模式禁用")
            )
            caveats.append(
                Caveat(
                    "net_targets_allowed",
                    {
                        "hosts": [
                            str(a.get("value", "")).lower()
                            for a in b.net_allow
                            if str(a.get("match", "")) == "exact"
                        ],
                        "allowed_ports": sorted(b.allowed_ports),
                        "sensitive_ports": sorted(b.sensitive_ports),
                    },
                    "命令内网络目标必须落在网络白名单内",
                )
            )
            if not view.binary:
                violations.append("空命令无法审计，拒绝签发")
            else:
                for f in b.check_command(view):
                    violations.append(f"命令参数越界：{f.reason}")

        elif tool == "delegate_task":
            allowed = [str(t) for t in (view.raw_args.get("allowed_tools") or [])]
            known = [t for t in allowed if t in b.tool_allow]
            if len(known) != len(allowed):
                bad = [t for t in allowed if t not in b.tool_allow]
                violations.append(f"委派声明的工具 {bad} 不在基线白名单内，拒绝签发")
            if not str(view.raw_args.get("task") or "").strip():
                violations.append("委派未声明子任务目标，拒绝签发")

        elif tool == "sanitize_content":
            # 只读元工具：去污通道本身不产生副作用，恒可签发
            pass

        return caveats, violations

    # ----------------------------------------------------------------- 签发
    def issue(
        self,
        tool: str,
        view: ActionView,
        step: int,
        scope: CapabilityScope | None = None,
        taint_block: str = "",
    ) -> IssuanceDecision:
        """按需签发（JIT）：对模型透明，由 Agent 循环在执行前代为申请。"""
        scope = scope or self.root_scope
        self.stats["requests"] += 1

        # 1) 工具白名单（显式拒绝表优先）
        td = self.baseline.check_tool(tool)
        if not td.allowed:
            return self._refuse(tool, step, td.reason, "L0-TOOL-BASELINE")

        # 2) 作用域衰减：子权能只能是父权能的子集
        ok, why = scope.tool_allowed(tool)
        if not ok:
            return self._refuse(tool, step, why, "L0-ATTENUATE")

        # 3) 污点闸门（由调用方传入，见 taint.py 的降权矩阵）
        if taint_block:
            return self._refuse(tool, step, taint_block, "L0-TAINT")

        # 4) 参数谓词（Schema & Argument Attenuation）
        caveats, violations = self._policy_caveats(tool, view)
        if violations:
            return self._refuse(tool, step, "；".join(violations), "L0-ARG-POLICY")

        # 5) 签发微租约：TTL + 单次配额 + Trace/步骤绑定
        now = self._clock()
        token = CapabilityToken(
            token_id=f"cap-{secrets.token_hex(5)}",
            tool=tool,
            caveats=caveats,
            trace_id=self.session_id,
            step=step,
            node=self.registry.create_child(scope.node, f"token@{tool}"),
            scope_path=scope.node.path(),
            issued_at=now,
            expires_at=now + self.ttl,
            max_calls=self.max_calls,
            scope_mac=scope.mac,
        )
        token.mac = self._token_mac(token)
        self.tokens.append(token)
        self.stats["issued"] += 1
        return IssuanceDecision(True, token=token, reason="签发成功", rule_id="L0-ISSUE")

    def _refuse(self, tool: str, step: int, reason: str, rule_id: str) -> IssuanceDecision:
        self.stats["refused"] += 1
        return IssuanceDecision(False, token=None, reason=reason, rule_id=rule_id)

    # ----------------------------------------------------------------- 验证
    def verify(
        self,
        token: CapabilityToken | None,
        tool: str,
        view: ActionView,
        step: int,
    ) -> list[Finding]:
        """验证一张票据（执行前的最后关口）。空列表 = 通过。"""

        def finding(rule_id: str, reason: str, evidence: dict[str, Any] | None = None) -> Finding:
            return Finding(
                layer=Layer.CAPABILITY,
                severity=Severity.HIGH,
                escape_type=EscapeType.CAPABILITY_VIOLATION,
                reason=reason,
                evidence=evidence or {},
                rule_id=rule_id,
            )

        if token is None:
            return [
                finding(
                    "L0-NO-TOKEN",
                    "零初始权限：本次调用未持有有效权能票据，策略引擎未放行（默认拒绝）",
                    {"tool": tool, "step": step},
                )
            ]

        errs: list[tuple[str, str, dict[str, Any]]] = []
        if not self.mac_valid(token):
            errs.append(
                (
                    "L0-MAC",
                    "票据 HMAC 签名校验失败：票据被篡改或伪造",
                    {"token_id": token.token_id},
                )
            )
        if token.scope_mac not in self._valid_scope_macs:
            errs.append(
                (
                    "L0-MAC",
                    "票据所属作用域的签名不在策略引擎登记的派生链上（伪造作用域）",
                    {"token_id": token.token_id},
                )
            )
        if token.tool != tool:
            errs.append(
                (
                    "L0-TOOL-MISMATCH",
                    f"票据绑定工具 `{token.tool}`，与本次调用的 `{tool}` 不符",
                    {"token_tool": token.tool, "call_tool": tool},
                )
            )
        if token.trace_id != self.session_id:
            errs.append(
                (
                    "L0-TRACE",
                    "票据 Trace 绑定校验失败：不属于当前会话（禁止跨会话复用）",
                    {"token_trace": token.trace_id, "session": self.session_id},
                )
            )
        if token.step != step:
            errs.append(
                (
                    "L0-STEP",
                    f"票据绑定步骤 step{token.step}，禁止跨步骤复用（当前 step{step}）",
                    {"token_step": token.step, "current_step": step},
                )
            )
        dead = token.node.dead_ancestor()
        if dead is not None:
            errs.append(
                (
                    "L0-REVOKED",
                    f"票据已随权能节点级联失效：`{dead.path_str()}` 被撤销"
                    f"（{dead.revoked_reason}），Caretaker 即时撤销生效",
                    {"dead_node": dead.path_str(), "reason": dead.revoked_reason},
                )
            )
        now = self._clock()
        if token.expired(now):
            errs.append(
                (
                    "L0-TTL",
                    f"票据已过期：TTL {self.ttl:.0f}s，已存活 {now - token.issued_at:.1f}s",
                    {"ttl": self.ttl, "age_s": round(now - token.issued_at, 1)},
                )
            )
        if token.exhausted():
            errs.append(
                (
                    "L0-QUOTA",
                    f"票据调用配额已耗尽（max_calls={token.max_calls}，单次即作废，重放无效）",
                    {"max_calls": token.max_calls, "calls": token.calls},
                )
            )
        for c in token.caveats:
            ok, why = c.check(view)
            if not ok:
                errs.append(
                    (
                        "L0-CAVEAT",
                        f"参数谓词不满足（{c.describe()}）：{why}",
                        {"caveat": c.kind, "detail": why},
                    )
                )

        return [
            finding(rule, reason, ev)
            for rule, reason, ev in errs
        ]

    # ------------------------------------------------------------- 消耗/撤销
    def consume(self, token: CapabilityToken) -> None:
        """执行成功后消耗票据（配额 +1，重放立即失效）。"""
        token.calls += 1
        if token.exhausted():
            token.consumed_at = self._clock()
        self.stats["consumed"] += 1

    def revoke(self, node: RevocationNode, reason: str = "") -> RevocationNode:
        return self.registry.revoke(node, reason)

    def revoke_scope(self, scope: CapabilityScope, reason: str = "") -> None:
        self.registry.revoke(scope.node, reason)

    def revoke_all(self, reason: str = "控制中心熔断：撤销全部权能") -> None:
        """熔断开关：撤销会话根，全部在飞票据毫秒级失效。"""
        self.registry.revoke(self.registry.root, reason)

    # ----------------------------------------------------------------- 快照
    def snapshot(self) -> dict[str, Any]:
        return {
            "session": self.session_id,
            "ttl_s": self.ttl,
            "max_calls": self.max_calls,
            "stats": dict(self.stats),
            "tokens": [t.to_dict() for t in self.tokens],
            "tree": self.registry.describe(),
        }
