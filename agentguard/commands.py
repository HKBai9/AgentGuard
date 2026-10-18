"""Finite command grammar shared by inspection and the demo executor.

Unknown options fail closed: a binary allowlist cannot establish its effects.
This is intentionally not an interpreter for arbitrary shell programs.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field


@dataclass
class CommandPlan:
    argv: list[str] = field(default_factory=list)
    binary: str = ""
    urls: list[tuple[int, str]] = field(default_factory=list)
    reads: list[str] = field(default_factory=list)
    lists: list[str] = field(default_factory=list)
    error: str = ""


def parse_command(command: str) -> CommandPlan:
    plan = CommandPlan()
    try:
        lexer = shlex.shlex(command, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        lexer.escape = ""  # keep Windows paths; never execute through a shell
        plan.argv = list(lexer)
    except ValueError as exc:
        plan.error = f"命令参数无法解析：{exc}"
        return plan
    if not plan.argv:
        plan.error = "命令为空"
        return plan
    executable = plan.argv[0]
    plan.binary = executable.lower().removesuffix(".exe")
    if "/" in executable or "\\" in executable:
        plan.error = "不支持通过任意路径指定可执行文件"
        return plan
    if any(c in command for c in ("\n", "\r", "\x00", "|", ";", ">", "<", "`", "$(")) or any(
        arg in ("&", "&&") for arg in plan.argv
    ):
        plan.error = "不支持 shell 组合、重定向或命令替换"
        return plan
    args = plan.argv[1:]
    if plan.binary in ("echo", "whoami", "uname"):
        return plan
    if plan.binary in ("cat", "ls"):
        operands = []
        options = True
        for arg in args:
            if options and arg == "--":
                options = False
            elif options and arg.startswith("-"):
                allowed = "nbsETvA" if plan.binary == "cat" else "Ralh"
                if arg == "-" or arg.startswith("--") or any(c not in allowed for c in arg[1:]):
                    plan.error = f"不支持的 {plan.binary} 参数：{arg}"
                    return plan
            else:
                operands.append(arg)
        if plan.binary == "cat":
            if not operands:
                plan.error = "cat 必须提供明确的文件路径"
            plan.reads = operands
        else:
            plan.lists = operands or ["/sandbox_fake"]
        return plan
    if plan.binary == "curl":
        simple = {"--silent", "--show-error", "--include", "--head", "--verbose", "--fail", "--globoff"}
        i = 1
        while i < len(plan.argv):
            arg = plan.argv[i]
            flag, equals, value = arg.partition("=")
            if arg == "--":
                plan.urls.extend((j, plan.argv[j]) for j in range(i + 1, len(plan.argv)))
                break
            if arg in simple or (arg.startswith("-") and not arg.startswith("--") and len(arg) > 1
                                 and all(c in "sSivIfg" for c in arg[1:])):
                i += 1
                continue
            if flag in ("--url", "--max-time", "--connect-timeout", "-m"):
                if not equals:
                    i += 1
                    if i >= len(plan.argv):
                        plan.error = f"参数 {flag} 缺少值"
                        return plan
                    value = plan.argv[i]
                if flag == "--url":
                    if equals:
                        plan.error = "请使用 --url URL，便于检查和执行共享同一参数"
                        return plan
                    plan.urls.append((i, value))
                else:
                    try:
                        if not 0 < float(value) <= 25:
                            raise ValueError
                    except ValueError:
                        plan.error = "超时时间须为 0 到 25 秒之间的数值"
                        return plan
                i += 1
                continue
            if arg.startswith("-"):
                plan.error = f"尚未支持审计 curl 参数 {arg}（配置、代理、重定向、上传及文件输出均不开放）"
                return plan
            plan.urls.append((i, arg))
            i += 1
        if not plan.urls:
            plan.error = "curl 必须提供至少一个明确的目标"
        for _, url in plan.urls:
            if re.search(r"[{}\[\]]", url):
                plan.error = "不支持 curl URL 展开语法"
        return plan
    plan.error = f"命令 {plan.binary} 尚无完整的参数审计适配器"
    return plan
