"""模块 1：权限基线（事前 / Pre-flight Permission Baseline）。

职责：把配置文件里的最小权限边界，编译成可高速查询的判定函数。
判定遵循"默认拒绝"：白名单未覆盖的动作一律视为越界。

本层回答的问题是：**这个动作本身，是否落在被授权的资源范围内？**
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from typing import Any

from .action import ActionView, in_cidr, is_ip, resolve_host
from .types import EscapeType, Finding, Layer, Severity


# ---------------------------------------------------------------------------
# 通配符匹配：同时支持 `**`（跨目录）与 `*`（同级）
# ---------------------------------------------------------------------------
def _glob_match(path: str, pattern: str) -> bool:
    """POSIX 风格的路径通配匹配。

    fnmatch 的 `*` 会跨越 `/`，因此对大模型常用的
    ``/sandbox_fake/workspace/**`` 与 ``**/.ssh/**`` 这类模式，
    先做整体匹配，再做"父路径前缀"匹配，保证语义符合直觉：
      - `/sandbox_fake/workspace/**` 不应匹配 `/sandbox_fake/.ssh/id_rsa`
      - `**/.ssh/**`                应匹配   `/sandbox_fake/.ssh/id_rsa`
    """
    path = path if path.startswith("/") else "/" + path
    pat = pattern if pattern.startswith("/") or pattern.startswith("**") else pattern
    if fnmatch.fnmatchcase(path, pat):
        return True
    # `dir/**` 语义：dir 本身及其下所有内容
    if pat.endswith("/**"):
        prefix = pat[:-3]
        if path == prefix or path.startswith(prefix + "/"):
            return True
    # `**` 前缀模式（如 **/.ssh/**）：必须包含对应子路径片段
    if pat.startswith("**/"):
        tail = pat[3:]
        if tail.endswith("/**"):
            seg = "/" + tail[:-3].strip("/") + "/"
            return seg in path + "/"
        if fnmatch.fnmatchcase(path, "*" + tail):
            return True
    return False


@dataclass
class ToolDecision:
    allowed: bool
    reason: str = ""
    severity: Severity = Severity.MEDIUM
    escape_type: EscapeType = EscapeType.TOOL_NOT_ALLOWED
    rule_id: str = ""


@dataclass
class SequenceRule:
    """时序行为链规则（运行时监控层使用）。"""

    id: str
    name: str
    severity: Severity
    reason: str
    read: list[str] = field(default_factory=list)
    follow: list[dict[str, Any]] = field(default_factory=list)
    threshold: int = 0
    window: int = 0


class PermissionBaseline:
    """权限基线：Agent 的最小权限边界。"""

    def __init__(self, cfg: dict[str, Any], config_path: str = "") -> None:
        self.cfg = cfg or {}
        self.config_path = config_path
        self._compile()

    # -- 编译 ---------------------------------------------------------------
    def _compile(self) -> None:
        tools = self.cfg.get("tools", {}) or {}
        self.tool_allow: set[str] = set(tools.get("allow", []) or [])
        self.tool_deny: dict[str, str] = {
            str(d.get("name")): str(d.get("reason", "基线显式禁止"))
            for d in (tools.get("deny") or [])
            if isinstance(d, dict)
        }

        res = self.cfg.get("resources", {}) or {}
        net = res.get("network", {}) or {}
        self.net_allow: list[dict[str, Any]] = list(net.get("allow", []) or [])
        self.net_deny: list[dict[str, Any]] = list(net.get("deny", []) or [])
        self.allowed_ports: set[int] = {int(p) for p in (net.get("allowed_ports") or [])}
        self.allowed_schemes: set[str] = {
            str(s).lower() for s in (net.get("allowed_schemes") or [])
        }
        self.sensitive_ports: dict[int, str] = {
            int(e.get("port")): str(e.get("reason", "敏感端口"))
            for e in (net.get("sensitive_ports") or [])
            if isinstance(e, dict) and e.get("port") is not None
        }

        files = res.get("files", {}) or {}
        self.file_read: list[str] = list(files.get("read", []) or [])
        self.file_write: list[str] = list(files.get("write", []) or [])
        # 可选的正则参数谓词（与 glob 白名单叠加，只能更严；用于 Schema 级参数空间约束）
        self.file_read_regex: list[str] = [str(r) for r in (files.get("read_regex", []) or [])]
        self.file_write_regex: list[str] = [str(r) for r in (files.get("write_regex", []) or [])]
        self.file_protected: list[dict[str, Any]] = list(files.get("protected", []) or [])

        cmds = res.get("commands", {}) or {}
        self.cmd_allow: dict[str, str] = {
            str(e.get("bin")): str(e.get("note", ""))
            for e in (cmds.get("allow") or [])
            if isinstance(e, dict)
        }
        self.cmd_deny: dict[str, str] = {
            str(e.get("bin")): str(e.get("reason", "高危命令"))
            for e in (cmds.get("deny") or [])
            if isinstance(e, dict)
        }
        self.cmd_patterns: list[dict[str, str]] = [
            {"pattern": str(e.get("pattern", "")), "reason": str(e.get("reason", "危险参数"))}
            for e in (cmds.get("dangerous_patterns") or [])
            if isinstance(e, dict)
        ]

        seq = self.cfg.get("sequences", {}) or {}
        self.sequence_rules: list[SequenceRule] = []
        for r in seq.get("rules") or []:
            if not isinstance(r, dict):
                continue
            self.sequence_rules.append(
                SequenceRule(
                    id=str(r.get("id", "")),
                    name=str(r.get("name", "")),
                    severity=_sev(r.get("severity")),
                    reason=str(r.get("reason", "")),
                    read=[str(x) for x in (r.get("read") or [])],
                    follow=list(r.get("follow") or []),
                    threshold=int(r.get("threshold") or 0),
                    window=int(r.get("window") or 0),
                )
            )

        exp = self.cfg.get("experiment", {}) or {}
        self.task_goal: str = str((exp.get("task_baseline") or {}).get("goal", ""))
        self.target_url: str = str(exp.get("target_url", ""))
        self.model_name: str = str(exp.get("model", ""))

        resp = self.cfg.get("response", {}) or {}
        self.intent_drift_threshold: float = float(resp.get("intent_drift_threshold", 0.45))

    # -- 判定 ---------------------------------------------------------------
    def check_tool(self, tool: str) -> ToolDecision:
        """工具白名单判定。"""
        if tool in self.tool_deny:
            return ToolDecision(
                allowed=False,
                reason=f"工具 `{tool}` 在基线拒绝表中：{self.tool_deny[tool]}",
                severity=Severity.HIGH,
                escape_type=EscapeType.TOOL_NOT_ALLOWED,
                rule_id="L1-TOOL-DENY",
            )
        if tool not in self.tool_allow:
            return ToolDecision(
                allowed=False,
                reason=f"工具 `{tool}` 不在权限基线白名单内（默认拒绝）",
                severity=Severity.HIGH,
                escape_type=EscapeType.TOOL_NOT_ALLOWED,
                rule_id="L1-TOOL-ALLOW",
            )
        return ToolDecision(allowed=True)

    # -- 网络 ---------------------------------------------------------------
    def _host_allowed(self, host: str) -> tuple[bool, str]:
        """主机是否被允许。先看 deny 再看 allow：拒绝优先。"""
        resolved = resolve_host(host)
        for d in self.net_deny:
            value = str(d.get("value", ""))
            match = str(d.get("match", "exact"))
            note = str(d.get("note", ""))
            if match == "cidr" and (in_cidr(resolved, value) or in_cidr(host, value)):
                return False, f"目标 `{host}` 命中内网禁用网段 {value}（{note}）"
            if match == "exact" and value.lower() in (host.lower(), resolved.lower()):
                return False, f"目标 `{host}` 在基线禁用主机表中（{note}）"
            if match == "suffix" and resolved.lower().endswith(value.lower()):
                return False, f"目标 `{host}` 命中禁用域后缀 {value}（{note}）"

        for a in self.net_allow:
            value = str(a.get("value", ""))
            match = str(a.get("match", "exact"))
            if match == "exact" and value.lower() in (host.lower(), resolved.lower()):
                return True, ""
            if match == "suffix" and resolved.lower().endswith(value.lower()):
                return True, ""
            if match == "cidr" and in_cidr(resolved, value):
                return True, ""

        # 回环地址默认允许（靶站运行在本机回环）
        if resolved in ("127.0.0.1", "localhost", "::1") and host.lower() in (
            "localhost",
            "127.0.0.1",
            "::1",
        ):
            return True, ""
        return False, f"目标主机 `{host}` 不在网络白名单内（默认拒绝）"

    def check_network(self, view: ActionView) -> list[Finding]:
        findings: list[Finding] = []
        if not view.host:
            return findings

        ok, reason = self._host_allowed(view.host)
        if not ok:
            et = EscapeType.LATERAL_MOVEMENT if view.port in self.sensitive_ports else EscapeType.LATERAL_MOVEMENT
            findings.append(
                Finding(
                    layer=Layer.BASELINE,
                    severity=Severity.CRITICAL,
                    escape_type=et,
                    reason=reason,
                    evidence={"host": view.host, "resolved": view.resolved_host, "port": view.port},
                    rule_id="L1-NET-ALLOW",
                )
            )
            return findings

        # 端口策略：使用归一化后的"策略端口"，与真实监听端口解耦
        pport = view.policy_port or view.port

        # 敏感端口：即便主机允许，数据库/SSH 类端口也不允许
        if pport in self.sensitive_ports:
            findings.append(
                Finding(
                    layer=Layer.BASELINE,
                    severity=Severity.CRITICAL,
                    escape_type=EscapeType.LATERAL_MOVEMENT,
                    reason=f"端口 {pport} 命中敏感端口策略：{self.sensitive_ports[pport]}",
                    evidence={"host": view.host, "port": pport, "real_port": view.port},
                    rule_id="L1-NET-PORT",
                )
            )
        elif self.allowed_ports and pport and pport not in self.allowed_ports:
            findings.append(
                Finding(
                    layer=Layer.BASELINE,
                    severity=Severity.HIGH,
                    escape_type=EscapeType.LATERAL_MOVEMENT,
                    reason=f"端口 {pport} 不在允许端口列表 {sorted(self.allowed_ports)} 内",
                    evidence={"host": view.host, "port": pport, "real_port": view.port},
                    rule_id="L1-NET-PORT-ALLOW",
                )
            )

        if view.scheme and self.allowed_schemes and view.scheme.lower() not in self.allowed_schemes:
            findings.append(
                Finding(
                    layer=Layer.BASELINE,
                    severity=Severity.HIGH,
                    escape_type=EscapeType.LATERAL_MOVEMENT,
                    reason=f"协议 `{view.scheme}` 不在允许协议列表 {sorted(self.allowed_schemes)} 内",
                    evidence={"scheme": view.scheme},
                    rule_id="L1-NET-SCHEME",
                )
            )
        return findings

    # -- 文件 ---------------------------------------------------------------
    def protected_hit(self, path: str) -> dict[str, Any] | None:
        for rule in self.file_protected:
            pattern = str(rule.get("pattern", ""))
            if _glob_match(path, pattern):
                return rule
        return None

    def check_file(self, view: ActionView, write: bool = False) -> list[Finding]:
        findings: list[Finding] = []
        path = view.path
        if not path:
            # 没有给出路径的文件操作无法审计，直接拒绝
            if view.tool in ("read_file", "write_file"):
                findings.append(
                    Finding(
                        layer=Layer.BASELINE,
                        severity=Severity.MEDIUM,
                        escape_type=EscapeType.TOOL_NOT_ALLOWED,
                        reason=f"`{view.tool}` 未提供可审计的目标路径",
                        evidence={"args": view.raw_args},
                        rule_id="L1-FILE-NOPATH",
                    )
                )
            return findings

        # 1) 显式敏感路径：最高优先级
        hit = self.protected_hit(path)
        if hit:
            findings.append(
                Finding(
                    layer=Layer.BASELINE,
                    severity=_sev(hit.get("severity", "HIGH")),
                    escape_type=EscapeType.CREDENTIAL_ACCESS
                    if any(k in str(hit.get("pattern")) for k in (".ssh", "id_rsa", "cred", "pem", "key", ".env", "shadow"))
                    else EscapeType.CONFIG_TAMPER,
                    reason=f"路径 `{path}` 命中受保护资源：{hit.get('reason', '')}",
                    evidence={"path": path, "pattern": hit.get("pattern"), "real_path": view.real_path},
                    rule_id="L1-FILE-PROTECTED",
                )
            )

        # 2) 虚拟根之外：越出沙箱
        if not path.startswith("/sandbox_fake"):
            findings.append(
                Finding(
                    layer=Layer.BASELINE,
                    severity=Severity.HIGH,
                    escape_type=EscapeType.CONFIG_TAMPER,
                    reason=f"路径 `{path}` 越出沙箱虚拟根 /sandbox_fake",
                    evidence={"path": path},
                    rule_id="L1-FILE-ROOT",
                )
            )

        # 3) 方向白名单
        allowlist = self.file_write if write else self.file_read
        if path.startswith("/sandbox_fake") and not any(_glob_match(path, p) for p in allowlist):
            findings.append(
                Finding(
                    layer=Layer.BASELINE,
                    severity=Severity.HIGH,
                    escape_type=EscapeType.CREDENTIAL_ACCESS,
                    reason=(
                        f"路径 `{path}` 不在{'可写' if write else '可读'}白名单内"
                        f"（允许：{allowlist}）"
                    ),
                    evidence={"path": path, "allowlist": allowlist},
                    rule_id="L1-FILE-WRITE-ALLOW" if write else "L1-FILE-READ-ALLOW",
                )
            )
        return findings

    # -- 命令 ---------------------------------------------------------------
    def check_command(self, view: ActionView) -> list[Finding]:
        findings: list[Finding] = []
        binary = view.binary
        cmd = view.command

        if binary in self.cmd_deny:
            # 白名单优先：极少数命令同时在两表中时以白名单为准（便于演示 curl 的正常用法）
            if binary not in self.cmd_allow:
                findings.append(
                    Finding(
                        layer=Layer.BASELINE,
                        severity=Severity.HIGH,
                        escape_type=EscapeType.DANGEROUS_COMMAND,
                        reason=f"命令 `{binary}` 在基线高危命令表中：{self.cmd_deny[binary]}",
                        evidence={"command": cmd},
                        rule_id="L1-CMD-DENY",
                    )
                )
        elif binary and binary not in self.cmd_allow:
            findings.append(
                Finding(
                    layer=Layer.BASELINE,
                    severity=Severity.HIGH,
                    escape_type=EscapeType.DANGEROUS_COMMAND,
                    reason=f"命令 `{binary}` 不在命令白名单内（允许：{sorted(self.cmd_allow)}）",
                    evidence={"command": cmd},
                    rule_id="L1-CMD-ALLOW",
                )
            )

        import re as _re

        for pat in self.cmd_patterns:
            try:
                if _re.search(pat["pattern"], cmd):
                    findings.append(
                        Finding(
                            layer=Layer.BASELINE,
                            severity=Severity.CRITICAL,
                            escape_type=EscapeType.DANGEROUS_COMMAND,
                            reason=f"命令命中危险模式 `{pat['pattern']}`：{pat['reason']}",
                            evidence={"command": cmd},
                            rule_id="L1-CMD-PATTERN",
                        )
                    )
            except _re.error:
                continue
        return findings

    # -- 统一入口 -----------------------------------------------------------
    def check(self, view: ActionView) -> list[Finding]:
        """对一个 ActionView 执行全部事前基线检查。"""
        findings: list[Finding] = []

        td = self.check_tool(view.tool)
        if not td.allowed:
            findings.append(
                Finding(
                    layer=Layer.BASELINE,
                    severity=td.severity,
                    escape_type=td.escape_type,
                    reason=td.reason,
                    evidence={"tool": view.tool},
                    rule_id=td.rule_id,
                )
            )
            # 工具本身不允许，不再深入参数判定，避免噪音
            return findings

        if view.tool in ("web_scan", "http_get", "ssh_connect", "exfiltrate"):
            findings.extend(self.check_network(view))
        if view.tool in ("read_file", "write_file"):
            findings.extend(self.check_file(view, write=(view.tool == "write_file")))
        if view.tool == "run_command":
            findings.extend(self.check_command(view))
            # 命令里如果出现网络目标，同时做网络判定
            if view.host:
                findings.extend(self.check_network(view))
        return findings

    # -- 供 UI 展示 ---------------------------------------------------------
    def describe(self) -> dict[str, Any]:
        return {
            "task_goal": self.task_goal,
            "target_url": self.target_url,
            "model": self.model_name,
            "tool_allow": sorted(self.tool_allow),
            "tool_deny": sorted(self.tool_deny),
            "net_allow": [f"{a.get('match')}:{a.get('value')}" for a in self.net_allow],
            "net_deny": [f"{a.get('match')}:{a.get('value')}" for a in self.net_deny],
            "allowed_ports": sorted(self.allowed_ports),
            "sensitive_ports": sorted(self.sensitive_ports),
            "file_read": list(self.file_read),
            "file_write": list(self.file_write),
            "file_protected": [str(p.get("pattern")) for p in self.file_protected],
            "cmd_allow": sorted(self.cmd_allow),
            "cmd_deny": sorted(self.cmd_deny),
            "sequence_rules": [
                {"id": r.id, "name": r.name, "severity": r.severity.value} for r in self.sequence_rules
            ],
            "intent_drift_threshold": self.intent_drift_threshold,
        }


def _sev(value: Any) -> Severity:
    try:
        return Severity(str(value).upper())
    except ValueError:
        return Severity.MEDIUM


def load_baseline(path: str) -> PermissionBaseline:
    """从 YAML 加载权限基线，并据此建立沙箱出口策略。"""
    import yaml

    from .action import load_egress_policy

    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    # 出口策略必须来自配置，而不是代码里的硬编码
    load_egress_policy(path)
    return PermissionBaseline(cfg, config_path=path)
