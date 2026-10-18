r"""AgentGuard 开发者 SDK —— 把防护接入你自己的 Agent。

这个模块解决一个具体问题：**别人怎么用我们？**

一句话接入（框架无关）：

    from agentguard.sdk import guard_tools

    safe_tools = guard_tools(my_tools, policy="config/permission_baseline.yaml")
    # my_tools 是 {"工具名": callable} 或 [ToolSpec, ...] 两种形式之一
    # 之后把 safe_tools 交给你的 Agent 即可，越权调用会被拦下

设计原则
--------
1. **不改变你的 Agent**：只替换工具表，Agent 循环、模型、框架都不用动；
2. **不绑定框架**：既能接 LangChain / OpenAI function calling，
   也能接你自己手写的 Agent 循环（见 `examples/`）；
3. **失败安全**：默认 `on_block="message"` —— 越权调用返回一段"已阻断"
   说明而不是抛异常，让 Agent 能自己读到拒绝原因并改变策略；
4. **两种接入位置**：
   - **进程内 SDK**（本模块）：开发期集成，几行代码；
   - **外部网关**（见 docs/PRODUCT.md）：生产环境把控制点移出 Agent 进程，
     做到不可绕过。两者共用同一套策略与判定引擎。
"""

from __future__ import annotations

import functools
import inspect
import json
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

# 注意：这里**必须**从子模块直接导入，不能 `from . import ...`。
# sdk 会被包根的 __init__ 导入，若再从包根取符号就会形成循环导入。
from .action import build_action
from .capability import Caretaker
from .guard import GuardConfig, SandboxGuard, build_guard
from .paths import DEFAULT_CONFIG_PATH as DEFAULT_CONFIG
from .paths import VFS_ROOT
from .types import Decision, Severity, ToolCall, ToolResult, Verdict

__all__ = [
    "AgentGuard",
    "GuardedToolError",
    "ToolSpec",
    "guard_tools",
    "guard_tool",
    "guard_function",
]


# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------
class GuardedToolError(PermissionError):
    """工具调用被防护系统阻断时抛出的异常。

    仅当 ``on_block="raise"`` 时抛出。默认不抛，而是返回说明文本 ——
    这样 Agent 能读到"为什么被拒"，从而调整策略而不是直接崩掉。
    """

    def __init__(self, tool: str, verdict: Verdict) -> None:
        self.tool = tool
        self.verdict = verdict
        super().__init__(f"工具 `{tool}` 被 AgentGuard 阻断：{verdict.summary}")


# ---------------------------------------------------------------------------
# 工具描述（框架无关的最小抽象）
# ---------------------------------------------------------------------------
@dataclass
class ToolSpec:
    """一个工具的描述。任何框架的对象都能转换成它。

    ``parameters`` 用 JSON Schema 表达，可直接喂给 OpenAI function calling
    或 LangChain 的 ``StructuredTool``。
    """

    name: str
    description: str
    func: Callable[..., Any]
    parameters: dict[str, Any] = field(default_factory=dict)

    @property
    def schema(self) -> dict[str, Any]:
        """OpenAI / Anthropic 风格的 function schema。"""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters
            or {"type": "object", "properties": {}, "required": []},
        }


# ---------------------------------------------------------------------------
# 从常见的框架对象中抽取 ToolSpec
# ---------------------------------------------------------------------------
def _infer_parameters(func: Callable[..., Any]) -> dict[str, Any]:
    """按函数签名推断一个粗略的 JSON Schema（够用即可，不强求完美）。"""
    try:
        sig = inspect.signature(func)
    except (TypeError, ValueError):
        return {"type": "object", "properties": {}, "required": []}
    props: dict[str, Any] = {}
    required: list[str] = []
    type_map = {str: "string", int: "integer", float: "number", bool: "boolean"}
    for pname, param in sig.parameters.items():
        if pname in ("self", "cls") or param.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue
        props[pname] = {"type": type_map.get(param.annotation, "string")}
        if param.default is inspect.Parameter.empty:
            required.append(pname)
    return {"type": "object", "properties": props, "required": required}


def coerce_tool(obj: Any, name: str | None = None) -> ToolSpec:
    """把"任意框架的工具对象"转成 :class:`ToolSpec`。

    探测顺序很关键：**先判断裸 callable，再找框架属性**。
    反例（曾经踩过）：普通函数也能取到 ``__call__``（一个 method-wrapper），
    若先匹配 ``__call__``，就会把 ``__call__`` 当工具函数，
    其签名是 ``(*args, **kwargs)``，导致参数绑定全错、调用报
    「got an unexpected keyword argument 'kwargs'」。

    已适配的形态：

    - 已经是 :class:`ToolSpec`；
    - 裸 callable（函数 / lambda / 绑定方法 / functools.partial）；
    - LangChain ``StructuredTool`` / ``Tool``（有 ``.name`` / ``.description`` /
      ``.func`` 或 ``._run`` / ``.args_schema``）；
    - 带 ``.name`` 与 ``.invoke`` / ``.run`` 的自定义工具对象。
    """
    if isinstance(obj, ToolSpec):
        return obj

    tname = name or getattr(obj, "name", None) or getattr(obj, "__name__", None)
    if not tname:
        raise TypeError(
            f"无法确定工具名：{obj!r}。请显式传入 name=... 或用 ToolSpec 包装。"
        )

    desc = getattr(obj, "description", "") or (inspect.getdoc(obj) or "").split("\n")[0]

    # --- 1) 裸 callable：直接用（不要碰 __call__）---
    # 排除"像工具对象"的包装器：它们有 name 且有 invoke/run 之类的方法，
    # 直接调用往往不是预期行为。
    looks_like_wrapper = hasattr(obj, "name") and any(
        callable(getattr(obj, a, None)) for a in ("invoke", "run", "func", "_run")
    )
    if callable(obj) and not looks_like_wrapper and not inspect.isclass(obj):
        return ToolSpec(str(tname), desc, obj, _infer_parameters(obj))

    # --- 2) LangChain 风格：显式的执行函数 ---
    for attr in ("func", "_run"):
        fn = getattr(obj, attr, None)
        if callable(fn):
            params = _langchain_schema(obj) or _infer_parameters(fn)
            return ToolSpec(str(tname), desc, fn, params)

    # --- 3) 带 invoke / run 的包装器 ---
    for attr in ("invoke", "run"):
        fn = getattr(obj, attr, None)
        if callable(fn):
            params = _langchain_schema(obj) or _infer_parameters(fn)
            return ToolSpec(str(tname), desc, fn, params)

    raise TypeError(f"无法把 {obj!r} 识别为工具，请用 ToolSpec(name, description, func) 包装")


def _langchain_schema(obj: Any) -> dict[str, Any] | None:
    """从 pydantic 的 ``args_schema`` 抽取 JSON Schema（LangChain 用）。"""
    schema = getattr(obj, "args_schema", None)
    if schema is None:
        return None
    for attr in ("model_json_schema", "schema"):
        fn = getattr(schema, attr, None)
        if callable(fn):
            try:
                data = fn()
                if isinstance(data, dict):
                    return data
            except Exception:
                continue
    return None


def _normalize_tools(tools: Any) -> list[ToolSpec]:
    """接受多种输入形态，统一成 ``list[ToolSpec]``。"""
    if isinstance(tools, Mapping):
        return [coerce_tool(fn, name=str(k)) for k, fn in tools.items()]
    if isinstance(tools, (list, tuple, set)):
        return [coerce_tool(t) for t in tools]
    raise TypeError(
        "tools 必须是 {名称: callable} 字典，或工具对象列表"
    )


# ---------------------------------------------------------------------------
# 主入口：AgentGuard
# ---------------------------------------------------------------------------
class AgentGuard:
    """面向开发者的防护门面（Facade）。

    用法：

        guard = AgentGuard(policy="config/permission_baseline.yaml")
        safe = guard.wrap_tools(my_tools)

        # 或者只包一个函数
        @guard.tool(name="read_file", description="读取文件")
        def read_file(path: str) -> str: ...

    :param policy: 权限基线 YAML 路径；None 用工程默认策略
    :param task:   原始任务描述。**强烈建议传**——语义层靠它判断"是否偏离任务"
    :param on_block: 阻断时的行为
        - ``"message"``（默认）：返回说明文本，不抛异常，Agent 可继续
        - ``"raise"``  ：抛 :class:`GuardedToolError`
        - ``"none"``   ：返回空字符串
    :param vfs_root: 虚拟文件系统的真实根目录（默认工程的 sandbox 目录）
    :param audit_log: 审计日志路径；None 用策略里的配置
    """

    def __init__(
        self,
        policy: str | os.PathLike[str] | None = None,
        *,
        task: str = "",
        on_block: str = "message",
        vfs_root: str | None = None,
        audit_log: str | os.PathLike[str] | None = None,
        config: GuardConfig | None = None,
        session_id: str = "",
        llm: Any = None,
        strict: bool = False,
    ) -> None:
        if on_block not in ("message", "raise", "none"):
            raise ValueError("on_block 只能是 'message' / 'raise' / 'none'")
        self.policy_path = str(policy or DEFAULT_CONFIG)
        self.task = task
        self.on_block = on_block
        self.strict = strict
        self.vfs_root = vfs_root or VFS_ROOT
        self.audit_log = str(audit_log) if audit_log else None

        cfg = config or GuardConfig()
        self._guard: SandboxGuard = build_guard(
            config_path=self.policy_path,
            guard_config=cfg,
            llm=llm,
            session_id=session_id or "sdk",
        )
        if self.audit_log:
            self._guard.audit_path = self.audit_log
        # 策略里的可写目录用于回滚快照；SDK 模式下允许调用方指定 vfs_root
        if vfs_root:
            self._guard.vfs_root = vfs_root
        self._step = 0

    # ---------------------------------------------------------------- 属性
    @property
    def guard(self) -> SandboxGuard:
        """底层引擎（需要访问审计/统计时用）。"""
        return self._guard

    @property
    def frozen(self) -> bool:
        """会话是否已被隔离冻结。"""
        return self._guard.frozen

    # ------------------------------------------------------- 核心拦截原语
    def _evaluate(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        thought: str = "",
    ) -> tuple[Verdict, Any, Any]:
        """判定一次调用，并在需要时 JIT 签发票据（对调用方透明）。

        与 ``ToolBridge`` 保持同一套权能语义：零初始权限下没有当次签发的
        票据就拒绝；污点状态会阻止签发票据。返回 ``(verdict, token, view)``。

        ``check()`` 只判定不执行，因此签发的票据不会被消耗（TTL 自然过期）；
        ``guard_call()`` 在真正执行成功后消耗票据（单次配额即作废）。
        """
        self._step += 1
        call = ToolCall(tool=tool, args=args or {}, thought=thought, step=self._step)
        view = build_action(tool, call.args)

        token = None
        refusal = ""
        gc = self._guard.config
        if gc.enabled and gc.enable_capability:
            taint_block = ""
            if gc.enable_taint:
                blocked, why = self._guard.taint.blocks(tool, view)
                taint_block = why if blocked else ""
            decision = self._guard.authority.issue(
                tool, view, self._step, taint_block=taint_block
            )
            token = decision.token
            refusal = decision.reason

        verdict, _view = self._guard.evaluate(call, token=token, view=view, refusal=refusal)
        return verdict, token, view

    def check(self, tool: str, args: dict[str, Any] | None = None, thought: str = "") -> Verdict:
        """只做判定、不执行。用于"先问一句能不能做"的场景。"""
        verdict, _token, _view = self._evaluate(tool, args, thought)
        return verdict

    def guard_call(
        self,
        tool: str,
        func: Callable[..., Any],
        args: dict[str, Any] | None = None,
        thought: str = "",
    ) -> tuple[bool, Any]:
        """判定并（在允许时）执行 ``func``。

        返回 ``(allowed, result)``。**这是全 SDK 的核心原语**——
        `wrap_tools` / `tool` / `wrap_openai_tools` 都建在它之上。
        """
        verdict, token, view = self._evaluate(tool, args, thought)
        if not verdict.allowed:
            return False, self._blocked_payload(tool, verdict)

        # 允许执行。参数以"具名"形式传入（bind_args 的产物）。
        call_args = dict(args or {})
        positional = call_args.pop("_args", None)
        gc = self._guard.config

        def _invoke():
            if positional:
                return func(*positional, **call_args)
            return func(**call_args)

        result: Any
        try:
            if gc.enabled and gc.enable_capability and token is not None:
                # 经 Caretaker 代理执行：判定-执行窗口内票据失效则仍不执行（TOCTOU 防御）
                caretaker = Caretaker(self._guard.authority, token)
                ok_exec, result, late_findings = caretaker.dispatch(
                    tool, view, self._step, executor=_invoke
                )
                if not ok_exec:
                    verdict.findings.extend(late_findings)
                    verdict.decision = Decision.BLOCK
                    return False, self._blocked_payload(tool, verdict)
            else:
                result = _invoke()
        except TypeError as exc:
            # 参数绑不上（多半是工具的签名与框架传来的参数不一致）。
            # 这是**调用方契约问题**，不能静默吞掉 —— 否则看起来像"被拦住了"，
            # 实际是防护根本没工作（曾经因此产生过一次假阳性实验结论）。
            raise TypeError(
                f"调用工具 `{tool}` 时参数不匹配：{exc}。"
                f"收到的参数：{sorted((args or {}).keys())}。"
                f"请检查工具签名，或用 ToolSpec 显式描述参数。"
            ) from exc

        # 执行成功后：污点标记（与 ToolBridge 一致；票据已由 Caretaker 消耗）
        if gc.enabled and gc.enable_taint:
            self._guard.taint.mark(tool, view, self._step)
        return True, result

    def _blocked_payload(self, tool: str, verdict: Verdict) -> Any:
        if self.on_block == "raise":
            raise GuardedToolError(tool, verdict)
        if self.on_block == "none":
            return ""
        return self.blocked_message(tool, verdict)

    @staticmethod
    def blocked_message(tool: str, verdict: Verdict) -> str:
        """阻断时回给 Agent 的文本。

        刻意写成"模型能读懂并据此改变策略"的形式：说明被谁拦、为什么、
        命中了哪条规则。这样 Agent 不会反复重试同一个被拒动作。
        """
        lines = [
            "⛔ 该操作已被 AgentGuard 边界逃逸防护阻断，未执行任何实际操作。",
            f"工具：{tool}",
            f"判定：{verdict.decision.value} ｜ 风险等级：{verdict.severity.value}",
        ]
        for f in verdict.findings[:4]:
            lines.append(f"- [{f.layer.value}][{f.severity.value}] {f.escape_type.value}：{f.reason}")
        if verdict.session_frozen:
            lines.append("会话已被冻结隔离，后续所有工具调用都会被拒绝。")
        lines.append("请不要重试该操作，改为在授权范围内完成用户的原始任务。")
        return "\n".join(lines)

    # ------------------------------------------------------------ 打包工具
    def wrap_tools(self, tools: Any, thought: str = "") -> Any:
        """把工具集合包成"受防护"的版本（保持原有数据结构）。

        支持：
          - ``{"名称": callable}`` 字典 → 返回同构字典
          - 工具对象列表（LangChain Tool 等）→ 返回 :class:`ToolSpec` 列表
        """
        is_mapping = isinstance(tools, Mapping)
        specs = _normalize_tools(tools)
        wrapped = [self._wrap_spec(s, thought) for s in specs]
        if is_mapping:
            return {s.name: s.func for s in wrapped}
        return wrapped

    def _wrap_spec(self, spec: ToolSpec, thought: str) -> ToolSpec:
        original = spec.func

        @functools.wraps(original)
        def protected(*args: Any, **kwargs: Any) -> Any:
            call_args = self._bind_args(original, args, kwargs)
            ok, out = self.guard_call(spec.name, original, call_args, thought=thought)
            if ok:
                return out
            return out

        return ToolSpec(spec.name, spec.description, protected, spec.parameters)

    @staticmethod
    def _bind_args(func: Callable[..., Any], args: tuple, kwargs: dict) -> dict[str, Any]:
        """把位置参数绑成字典，这样防护层能看到**具名的**参数。"""
        try:
            bound = inspect.signature(func).bind_partial(*args, **kwargs)
            return dict(bound.arguments)
        except (TypeError, ValueError):
            # 绑不上就退化为位置参数列表，防护层仍会尝试审计
            return {"_args": list(args), **kwargs}

    def tool(self, name: str, description: str = "", parameters: dict[str, Any] | None = None):
        """装饰器：把一个函数注册为受防护的工具。

            @guard.tool(name="read_file", description="读取文件内容")
            def read_file(path: str) -> str: ...
        """

        def deco(func: Callable[..., Any]) -> Callable[..., Any]:
            spec = ToolSpec(
                name=name,
                description=description or (inspect.getdoc(func) or "").split("\n")[0],
                func=func,
                parameters=parameters or _infer_parameters(func),
            )
            protected = self._wrap_spec(spec, thought="").func
            setattr(protected, "__agentguard_spec__", spec)
            return protected

        return deco

    # -------------------------------------------------- 各框架适配器（薄封装）
    def openai_tools(self, specs: Iterable[ToolSpec]) -> list[dict[str, Any]]:
        """导出 OpenAI / 兼容接口的 function calling 工具定义。

            tools = guard.openai_tools(guard.wrap_tools(my_tools))
        """
        return [s.schema for s in specs]

    def langchain_tools(self, specs: Iterable[ToolSpec]) -> list[Any]:
        """导出 LangChain ``StructuredTool``（未安装 langchain 时抛 ImportError）。"""
        try:
            from langchain_core.tools import StructuredTool  # type: ignore
        except ImportError as exc:  # pragma: no cover - 取决于环境
            raise ImportError(
                "未安装 langchain-core。请 `pip install langchain-core`，"
                "或直接用 wrap_tools 返回的字典（框架无关）。"
            ) from exc
        out = []
        for s in specs:
            out.append(
                StructuredTool.from_function(
                    func=s.func, name=s.name, description=s.description
                )
            )
        return out

    # ------------------------------------------------------------ 报告
    def summary(self) -> dict[str, Any]:
        return self._guard.summary()

    def report(self) -> dict[str, Any]:
        return self._guard.to_report()

    def rollback(self) -> list[str]:
        return self._guard.rollback()

    def __repr__(self) -> str:
        s = self.summary()
        return (
            f"<AgentGuard policy={os.path.basename(self.policy_path)} "
            f"allowed={s['allowed']} blocked={s['blocked']} frozen={s['frozen']}>"
        )


# ---------------------------------------------------------------------------
# 函数式快捷入口
# ---------------------------------------------------------------------------
def guard_tools(
    tools: Any,
    policy: str | os.PathLike[str] | None = None,
    *,
    task: str = "",
    on_block: str = "message",
    **kwargs: Any,
) -> Any:
    """一行接入：把工具集合包成受防护的版本。

        from agentguard.sdk import guard_tools
        safe_tools = guard_tools(my_tools, policy="policy.yaml", task=user_task)
    """
    guard = AgentGuard(policy, task=task, on_block=on_block, **kwargs)
    return guard.wrap_tools(tools)


def guard_tool(
    name: str, description: str = "", policy: str | os.PathLike[str] | None = None, **kwargs: Any
):
    """装饰器快捷入口：``@guard_tool("read_file")``。"""
    guard = AgentGuard(policy, **kwargs)

    def deco(func: Callable[..., Any]) -> Callable[..., Any]:
        return guard.tool(name, description)(func)

    return deco


def guard_function(
    func: Callable[..., Any],
    tool_name: str | None = None,
    policy: str | os.PathLike[str] | None = None,
    **kwargs: Any,
) -> Callable[..., Any]:
    """把单个函数包成受防护的工具。"""
    guard = AgentGuard(policy, **kwargs)
    spec = coerce_tool(func, name=tool_name)
    return guard._wrap_spec(spec, thought="").func
