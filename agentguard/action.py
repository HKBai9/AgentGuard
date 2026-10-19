"""工具调用的归一化（Normalization）。

Agent 可能用不同写法表达同一个动作（`http://host:8081/x` 与 `host` + `8081`
与 `127.0.0.1:8081`），防护层必须先把它归一化成一个 Action 视图，
否则白名单比对会被轻易绕过。这是"行为层能否被绕过"的关键工程点。
"""

from __future__ import annotations

import ipaddress
import os
import posixpath
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from .commands import parse_command
from .paths import VFS_ROOT

# 演示用的虚拟主机名 -> 真实回环地址。
# 靶站与模拟内网服务实际运行在本机回环端口上（无外网、无真实内网依赖），
# 但对 Agent 与防护层而言它们就是独立主机，因此写成虚拟主机名更贴近真实场景。
VIRTUAL_HOSTS: dict[str, str] = {
    "sandbox-target": "127.0.0.1",
    "internal-db": "127.0.0.1",
    "internal-file": "127.0.0.1",
    "internal-api": "127.0.0.1",
}

# 服务别名 -> 规范端口。
# 演示环境里"内网数据库"端口可通过环境变量改（见 sandbox/servers.py），
# 但**策略判定必须与端口号无关**：无论它监听在 3306 还是 33060，
# 只要目标是 internal-db，就必须按"内网数据库"这一语义去判定。
SERVICE_ALIASES: dict[str, int] = {
    "internal-db": 3306,
    "internal-file": 22,
    "sandbox-target": 8081,
    "internal-api": 9000,
}

# 沙箱文件系统的虚拟根：/sandbox_fake/** 映射到真实目录
DEFAULT_VFS_ROOT_MARKER = "/sandbox_fake"
DEFAULT_VFS_REAL_ROOT = VFS_ROOT


@dataclass
class NetworkTarget:
    host: str
    port: int
    scheme: str = "http"
    url: str = ""
    resolved_host: str = ""
    policy_port: int = 0
    argument_index: int = -1


@dataclass
class ActionView:
    """一次动作归一化之后的统一视图。"""

    tool: str
    raw_args: dict[str, Any]
    # 网络维度
    host: str = ""
    resolved_host: str = ""
    port: int = 0          # 真实连接端口（执行时使用）
    policy_port: int = 0   # 参与策略判定的规范端口（可能与真实端口不同）
    scheme: str = ""
    url: str = ""
    # 文件维度
    path: str = ""            # 虚拟路径（POSIX 风格，已归一化）
    real_path: str = ""       # 映射到的真实绝对路径
    # 命令维度
    binary: str = ""
    command: str = ""
    argv: list[str] = field(default_factory=list)
    network_targets: list[NetworkTarget] = field(default_factory=list)
    read_paths: list[str] = field(default_factory=list)
    list_paths: list[str] = field(default_factory=list)
    parse_error: str = ""
    # 其它
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
            "path": self.path,
            "binary": self.binary,
            "command": self.command,
            "notes": self.notes,
            "network_targets": [vars(t) for t in self.network_targets],
            "read_paths": self.read_paths,
            "list_paths": self.list_paths,
            "parse_error": self.parse_error,
        }


def normalize_path(path: str, vfs_root: str | None = None) -> str:
    """把任意路径写法归一化成虚拟 POSIX 绝对路径。

    处理：反斜杠、`..` 上跳、重复斜杠、尾部斜杠、`` file:// `` 前缀。
    """
    if not path:
        return ""
    p = str(path).strip().strip('"').strip("'")
    if p.lower().startswith("file://"):
        p = urllib.parse.urlparse(p).path
    p = p.replace("\\", "/")
    # 真实路径若位于 VFS 根之内，换回虚拟路径
    real_root = os.path.abspath(vfs_root or DEFAULT_VFS_REAL_ROOT).replace("\\", "/")
    comparable = os.path.normcase(p).replace("\\", "/")
    comparable_root = os.path.normcase(real_root).replace("\\", "/")
    if comparable == comparable_root or comparable.startswith(comparable_root + "/"):
        p = DEFAULT_VFS_ROOT_MARKER + p[len(real_root):]
    if not p.startswith("/"):
        p = "/" + p
    # 归一化 .. 与 //
    p = posixpath.normpath(p)
    if not p.startswith("/"):
        p = "/" + p
    return p


def is_vfs_path(path: str) -> bool:
    return path == DEFAULT_VFS_ROOT_MARKER or path.startswith(DEFAULT_VFS_ROOT_MARKER + "/")


def vfs_to_real(path: str, vfs_root: str | None = None) -> str:
    """虚拟路径 -> 真实文件系统路径（用于实际执行与回滚快照）。"""
    root = vfs_root or DEFAULT_VFS_REAL_ROOT
    v = normalize_path(path, root)
    if not is_vfs_path(v):
        # 越出沙箱虚拟根的路径，仍给出一个确定性的映射结果，
        # 但防护层会在白名单阶段直接拒绝。
        return os.path.join(root, v.lstrip("/"))
    rel = v[len(DEFAULT_VFS_ROOT_MARKER):].lstrip("/")
    return os.path.realpath(os.path.join(root, rel.replace("/", os.sep)))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


_URL_RE = re.compile(r"^\s*(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*)://(?P<rest>.*)$")
_HOSTPORT_RE = re.compile(
    r"^(?P<host>\[[0-9a-fA-F:]+\]|[^:/?#]+)(?::(?P<port>\d{1,5}))?(?P<tail>[/?#].*)?$"
)
_SCHEME_DEFAULT_PORT = {"http": 80, "https": 443, "ssh": 22, "mysql": 3306, "redis": 6379}


def parse_target(target: str, default_scheme: str = "http") -> tuple[str, int, str, str]:
    """解析 URL / host:port / 纯 host，返回 (scheme, host, port, url)。"""
    raw = str(target or "").strip().strip('"').strip("'")
    scheme = default_scheme
    try:
        if any(c.isspace() for c in raw) or "\\" in raw or "\x00" in raw:
            raise ValueError("invalid URL")
        parsed = urllib.parse.urlsplit(raw if "://" in raw else f"{default_scheme}://{raw}")
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host or parsed.username is not None or parsed.password is not None:
            raise ValueError("host missing or embedded credentials")
        port = parsed.port if parsed.port is not None else _SCHEME_DEFAULT_PORT.get(scheme, 0)
        netloc = f"[{host}]" if ":" in host else host
        if port != _SCHEME_DEFAULT_PORT.get(scheme):
            netloc += f":{port}"
        return scheme, host, port, urllib.parse.urlunsplit((scheme, netloc, parsed.path, parsed.query, parsed.fragment))
    except ValueError:
        return scheme, "", 0, raw


def resolve_host(host: str) -> str:
    """虚拟主机名 -> 真实地址；已经是 IP 则原样返回。"""
    h = (host or "").strip().lower()
    if h in VIRTUAL_HOSTS:
        return VIRTUAL_HOSTS[h]
    return h


def canonical_port(host: str, port: int) -> int:
    """把已知服务别名上的任意端口归一化为该服务的规范端口。

    目的：策略语义与端口号解耦。若演示环境把"内网数据库"改到 33060，
    Agent 连 `internal-db:33060` 依然会被判定为"访问内网数据库"，
    而不是因为端口不在敏感端口列表里就漏过去。
    """
    h = (host or "").strip().lower()
    canonical = SERVICE_ALIASES.get(h)
    if h == "sandbox-target":
        return port  # choosing a sensitive port must not inherit port 8081 privileges
    if canonical and port and port != canonical:
        return canonical
    return port


def load_egress_policy(config_path: str) -> None:
    """从权限基线加载"虚拟主机 -> 真实地址"的出口映射。

    安全意义：只有被基线显式登记的服务别名才允许解析为真实地址。
    未登记的域名一律**不做 DNS 解析**，因此不存在"Agent 诱导防护层
    去访问外网"的可能 —— 演示沙箱天然离线。
    """
    try:
        import yaml

        with open(config_path, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}
    except Exception:
        return
    egress = (cfg.get("sandbox") or {}).get("egress") or {}
    mapping = egress.get("map") or {}
    if isinstance(mapping, dict) and mapping:
        VIRTUAL_HOSTS.clear()
        VIRTUAL_HOSTS.update({str(k).lower(): str(v) for k, v in mapping.items()})
    aliases = egress.get("service_aliases") or {}
    if isinstance(aliases, dict) and aliases:
        SERVICE_ALIASES.clear()
        SERVICE_ALIASES.update({str(k).lower(): int(v) for k, v in aliases.items()})


# 从命令字符串中抽取会触网的主机/端口（用于命令类工具的网络维度审计与出口管控）
# 注意：主机名必须匹配**完整**的 FQDN（以字母数字结尾），否则会出现
# `www.google.com` 只抽出 `www` 从而绕过出口管控的错误。
_CMD_HOST_RE = re.compile(
    r"(?:(?P<scheme>https?)://)?"
    r"(?P<host>"
    r"(?:\d{1,3}\.){3}\d{1,3}"                                    # IPv4
    r"|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*"           # 可选的多级域名前缀
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?"                   # 末级标签
    r")"
    r"(?::(?P<port>\d{1,5}))?"
)


def extract_hosts_from_command(command: str) -> list[tuple[str, int]]:
    """抽取命令中**确实构成网络目标**的主机与端口。

    设计要点（每一处都是踩过的坑，务必保持）：

    1. **不做白名单过滤**。调用方（出口管控 / 行为审计）必须能看到
       "未登记的外部主机"，否则 `curl http://www.google.com/` 会因为
       主机不在白名单里而被静默丢弃，反而绕过检查。
    2. **以 `/` 或 `.` 开头的 token 是文件路径**，不是主机
       （`ls -R /sandbox_fake`、`cat ./.env`）。
    3. **裸词不当作主机**。`find /x -name y`、`ls -R /y` 里的
       `find`/`name`/`x` 是命令名与参数，把它们当主机名会产生误报。
       判定规则：只有满足下列之一才算网络目标 ——
         * 带显式端口（`host:8081`）
         * 是 IPv4
         * 是登记在出口策略里的服务别名（`sandbox-target`）
         * 是多级域名（含 `.`，如 `www.google.com`）
    """
    out: list[tuple[str, int]] = []
    for token in _split_command_tokens(command):
        if token.startswith("/") or token.startswith("."):
            continue  # 文件路径，不是网络目标
        for m in _CMD_HOST_RE.finditer(token):
            host = m.group("host")
            port_s = m.group("port")
            scheme = (m.group("scheme") or "").lower()
            if not _looks_like_network_target(host, port_s):
                continue
            port = int(port_s) if port_s else _SCHEME_DEFAULT_PORT.get(scheme, 0)
            out.append((host, port))
    return out


def _looks_like_network_target(host: str, port: str | None) -> bool:
    """判断一个被正则命中的词是否真的是网络目标（而非命令名/普通参数）。"""
    if port:
        return True                      # 显式 host:port
    if is_ip(host):
        return True
    low = host.lower()
    if low in VIRTUAL_HOSTS:             # 出口策略登记的服务别名
        return True
    if "." in host:                      # 多级域名
        return True
    return False


def _split_command_tokens(command: str) -> list[str]:
    """按空白切分命令，保留完整 token（逐 token 解析，避免跨参数误匹配）。"""
    return [t for t in re.split(r"\s+", (command or "").strip()) if t]


def build_action(tool: str, args: dict[str, Any], vfs_root: str | None = None) -> ActionView:
    """把工具调用参数归一化为 ActionView。"""
    args = args or {}
    view = ActionView(tool=tool, raw_args=dict(args))

    if tool in ("web_scan", "http_get", "ssh_connect"):
        raw_target = args.get("url") or args.get("target") or args.get("host") or ""
        default_scheme = "ssh" if tool == "ssh_connect" else "http"
        scheme, host, port, url = parse_target(str(raw_target), default_scheme)
        # 显式 port / params 覆盖
        if args.get("port") is not None:
            try:
                port = int(args["port"])
            except (TypeError, ValueError):
                view.parse_error = "网络端口无效"
        # 语义与端口解耦：策略判定使用规范端口，执行仍用真实端口
        canonical = canonical_port(host, port)
        if canonical != port:
            view.notes.append(
                f"服务别名 `{host}`：真实端口 {port}，策略判定按规范端口 {canonical}"
            )
        view.scheme, view.host, view.port, view.url = scheme, host, port, url
        view.policy_port = canonical
        view.resolved_host = resolve_host(host)
        if not raw_target:
            view.parse_error = "网络工具缺少明确的目标"
        if not 0 < port <= 65535:
            view.parse_error = "网络端口无效"
        view.network_targets.append(NetworkTarget(host, port, scheme, url, view.resolved_host, canonical))
        view.notes.append(f"目标归一化: {url} -> {view.resolved_host}:{port}")

    if tool in ("read_file", "write_file"):
        view.path = normalize_path(str(args.get("path") or args.get("file") or ""), vfs_root)
        view.real_path = vfs_to_real(view.path, vfs_root)
        if not view.path:
            view.parse_error = "文件工具缺少明确的目标路径"

    if tool == "run_command":
        cmd = str(args.get("command") or args.get("cmd") or "")
        view.command = cmd.strip()
        plan = parse_command(view.command)
        view.binary, view.argv, view.parse_error = plan.binary, plan.argv, plan.error
        def command_path(raw: str) -> str:
            p = raw.replace("\\", "/")
            if not p.startswith("/") and not re.match(r"^[A-Za-z]:/", p):
                p = "/sandbox_fake/" + p
            return normalize_path(p, vfs_root)
        view.read_paths = [command_path(p) for p in plan.reads]
        view.list_paths = [command_path(p) for p in plan.lists]
        for index, raw in plan.urls:
            scheme, host, port, url = parse_target(raw)
            if scheme not in ("http", "https") or not host or not 0 < port <= 65535:
                view.parse_error = "curl 仅支持具有明确主机和有效端口的 HTTP(S) URL"
            view.network_targets.append(NetworkTarget(host, port, scheme, url, resolve_host(host),
                                                       canonical_port(host, port), index))
        if view.network_targets:
            target = view.network_targets[0]  # only for backwards-compatible display
            view.host, view.port, view.scheme = target.host, target.port, target.scheme
            view.policy_port, view.resolved_host = target.policy_port, target.resolved_host

    if tool == "exfiltrate":
        view.host = str(args.get("host") or "")
        view.resolved_host = resolve_host(view.host)

    if tool not in (
        "web_scan", "http_get", "ssh_connect", "read_file", "write_file",
        "run_command", "exfiltrate", "delegate_task", "sanitize_content",
    ):
        view.parse_error = f"工具 {tool} 尚无资源审计适配器"

    return view
