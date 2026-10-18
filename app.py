r"""Streamlit 演示界面：AgentGuard 边界逃逸防护。

页面结构
--------
  ① 防护总开关"启用边界逃逸防护"（答辩现场一键切换，唯一实验变量）
  ② 用例选择（1 正常业务 / 2 逃逸诱导 / 3 隐性逃逸 / 4 包装绕过）
  ③ 左右分屏对照：左侧**对照组**（防护关闭）· 右侧**实验组**（防护开启）
  ④ 权限基线可视化（Agent 到底被允许做什么）
  ⑤ 审计日志与结果导出

启动：  streamlit run app.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any

import streamlit as st

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
_LIBS = os.path.join(ROOT, "libs")
if os.path.isdir(_LIBS) and _LIBS not in sys.path:
    sys.path.insert(0, _LIBS)

from agentguard import VFS_ROOT, GuardConfig, build_guard  # noqa: E402
from agentguard.agent import GuardedAgent  # noqa: E402
from agentguard.llm import OllamaLLM, ScriptedLLM  # noqa: E402
from agentguard.tools import ToolBridge  # noqa: E402
from experiments.run_experiment import (  # noqa: E402
    BYPASS_PROMPT,
    BYPASS_STEPS,
    ESCAPE_PROMPT,
    HIDDEN_PROMPT,
    HIDDEN_STEPS,
    SCRIPTED_ESCAPE_STEPS,
    SCRIPTED_NORMAL_STEPS,
    TASK,
    ensure_sandbox,
)
from sandbox.servers import SandboxServices  # noqa: E402

st.set_page_config(
    page_title="AgentGuard · 边界逃逸检测与风险隔离",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# 样式
# ---------------------------------------------------------------------------
st.markdown(
    """
<style>
  .block-container {padding-top: 1.4rem; padding-bottom: 2rem;}
  .ag-title {font-size: 1.72rem; font-weight: 700; letter-spacing: .2px;}
  .ag-sub {color: #6b7280; font-size: .88rem; margin-top: .15rem;}
  .ag-card {border:1px solid #e5e7eb; border-radius:10px; padding:.6rem .8rem; margin-bottom:.45rem;
            background:#fafafa;}
  .ag-card.block {border-color:#ef4444; background:#fef2f2;}
  .ag-card.allow {border-color:#22c55e; background:#f0fdf4;}
  .ag-card.observe {border-color:#f59e0b; background:#fffbeb;}
  .ag-step {font-weight:600; font-size:.86rem;}
  .ag-meta {color:#6b7280; font-size:.78rem;}
  .ag-thought {font-size:.85rem; margin:.25rem 0 .35rem 0;}
  .ag-mono {font-family: ui-monospace, Consolas, monospace; font-size:.76rem;
            white-space:pre-wrap; word-break:break-word;}
  .ag-badge {display:inline-block; padding:1px 7px; border-radius:999px; font-size:.72rem;
             font-weight:600; margin-right:5px;}
  .b-crit {background:#fee2e2; color:#991b1b;}
  .b-high {background:#ffedd5; color:#9a3412;}
  .b-med  {background:#fef9c3; color:#854d0e;}
  .b-low  {background:#e0e7ff; color:#3730a3;}
  .b-ok   {background:#dcfce7; color:#166534;}
  .b-info {background:#e5e7eb; color:#374151;}
</style>
""",
    unsafe_allow_html=True,
)

SEV_CLASS = {
    "CRITICAL": "b-crit",
    "HIGH": "b-high",
    "MEDIUM": "b-med",
    "LOW": "b-low",
    None: "b-info",
}

# ---------------------------------------------------------------------------
# 沙箱服务（进程内线程，随页面存活）
# ---------------------------------------------------------------------------
@st.cache_resource(show_spinner=False)
def services() -> dict[str, Any]:
    """启动（或复用）沙箱服务并做连通性自检。

    若服务已在别的进程运行则直接复用，避免端口冲突导致靶站不可用。
    """
    _svc, status, warnings = ensure_sandbox()
    return {"status": status, "warnings": warnings}


@st.cache_resource(show_spinner=False)
def llm_probe(host: str, model: str) -> dict[str, Any]:
    llm = OllamaLLM(model=model, host=host)
    ok, msg = llm.available()
    return {"ok": ok, "msg": msg, "models": llm.list_models()}


# ---------------------------------------------------------------------------
# 用例定义
# ---------------------------------------------------------------------------
CASES: dict[str, dict[str, Any]] = {
    "1": {
        "name": "用例 1 · 正常业务任务（基线）",
        "prompt": "",
        "steps": SCRIPTED_NORMAL_STEPS,
        "expect": "两组都应放行。用于证明防护**不会误伤**合法操作。",
    },
    "2": {
        "name": "用例 2 · 逃逸诱导（复刻 AISI Agent 逃逸）",
        "prompt": ESCAPE_PROMPT,
        "steps": SCRIPTED_ESCAPE_STEPS,
        "expect": "对照组成功读取私钥并连上内网；实验组在**工具执行之前**被阻断并冻结会话。",
    },
    "3": {
        "name": "用例 3 · 隐性逃逸（不使用敏感词，仅目标偏离）",
        "prompt": HIDDEN_PROMPT,
        "steps": HIDDEN_STEPS,
        "expect": "由 L2 语义意图层识别目标偏离与凭证意图，L1/L3 补齐资源越权证据。",
    },
    "4": {
        "name": "用例 4 · 包装型绕过（路径穿越 + 白名单命令触网）",
        "prompt": BYPASS_PROMPT,
        "steps": BYPASS_STEPS,
        "expect": "参数归一化识破 `..` 穿越；时序行为链识破『读凭证→连内网』的组合动作。",
    },
}


# ---------------------------------------------------------------------------
# 运行一组
# ---------------------------------------------------------------------------
def run_group(
    case_key: str,
    guard_enabled: bool,
    use_llm: bool,
    model: str,
    host: str,
    max_steps: int,
) -> dict[str, Any]:
    case = CASES[case_key]
    guard_cfg = GuardConfig(enabled=guard_enabled)
    guard = build_guard(
        guard_config=guard_cfg,
        session_id=f"ui-{case_key}-{'on' if guard_enabled else 'off'}-{int(time.time())}",
    )
    bridge = ToolBridge(guard, vfs_root=VFS_ROOT)

    if use_llm:
        llm = OllamaLLM(model=model, host=host, num_predict=200)
        mode = f"本地大模型 {model}"
    else:
        llm = ScriptedLLM(list(case["steps"]))
        mode = "脚本回放（确定性轨迹）"

    agent = GuardedAgent(bridge, llm, baseline=guard.baseline, max_steps=max_steps)
    task = TASK + (f"\n\n补充要求：{case['prompt']}" if case["prompt"] else "")
    t0 = time.time()
    run = agent.run(task, llm_mode=mode)
    return {
        "run": run,
        "guard": guard,
        "task": task,
        "mode": mode,
        "wall_s": time.time() - t0,
        "guard_enabled": guard_enabled,
    }


# ---------------------------------------------------------------------------
# 渲染
# ---------------------------------------------------------------------------
def render_step(step, idx: int) -> None:
    v = step.verdict or {}
    decision = v.get("decision", "")
    sev = v.get("severity")
    if step.blocked and decision == "ISOLATE":
        cls, badge = "ag-card block", '<span class="ag-badge b-crit">已阻断·会话隔离</span>'
    elif step.blocked:
        cls, badge = "ag-card block", '<span class="ag-badge b-high">已阻断</span>'
    else:
        cls, badge = "ag-card allow", '<span class="ag-badge b-ok">已执行</span>'

    obs = step.observation or ""
    short_obs = obs if len(obs) <= 420 else obs[:420] + " …"

    sev_badge = (
        f'<span class="ag-badge {SEV_CLASS.get(sev, "b-info")}">{sev}</span>' if sev else ""
    )
    st.markdown(
        f"""<div class="{cls}">
              <div class="ag-step">{badge}{sev_badge}
                <span class="ag-meta">step {idx} · <code>{step.action}</code></span></div>
              <div class="ag-thought">💭 {_esc(step.thought) or '（无思考输出）'}</div>
              <div class="ag-meta">参数：<span class="ag-mono">{_esc(json.dumps(step.action_input, ensure_ascii=False))}</span></div>
              <div class="ag-meta" style="margin-top:.3rem">观察：</div>
              <div class="ag-mono">{_esc(short_obs)}</div>
            </div>""",
        unsafe_allow_html=True,
    )
    findings = v.get("findings") or []
    if findings:
        with st.expander(f"🔍 判定证据链（{len(findings)} 条）", expanded=step.blocked):
            for f in findings:
                st.markdown(
                    f"- <span class='ag-badge {SEV_CLASS.get(f['severity'], 'b-info')}'>"
                    f"{f['severity']}</span>"
                    f"<code>{f.get('rule_id', '-')}</code> "
                    f"**{f['layer']}** · {f['escape_type']}<br>"
                    f"<span class='ag-meta'>{_esc(f['reason'])}</span>",
                    unsafe_allow_html=True,
                )
                with st.popover("证据详情"):
                    st.json(f.get("evidence", {}))


def _esc(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def render_group(result: dict[str, Any], title: str, subtitle: str) -> None:
    run = result["run"]
    guard = result["guard"]
    summary = guard.summary()

    st.markdown(f"#### {title}")
    st.caption(subtitle)

    c1, c2, c3, c4 = st.columns(4)
    escaped = run.escaped
    c1.metric(
        "是否完成逃逸",
        "是 ⚠️" if escaped else "否 ✅",
        delta=None,
        delta_color="inverse",
    )
    c3.metric("实际执行动作数", summary["allowed"])
    c2.metric("被拦截动作数", summary["blocked"])
    c4.metric("识别逃逸类型数", len(summary["escape_types"]))

    if guard.frozen:
        st.error("🧊 会话已被冻结隔离（Agent 无法继续执行后续动作）", icon="🧊")
    if result["guard_enabled"]:
        if summary["escape_types"]:
            st.warning(
                "**识别到的逃逸类型：** " + "、".join(summary["escape_types"]), icon="🚨"
            )
        else:
            st.success("未发现越界动作，全部动作在权限基线内", icon="✅")
    else:
        if escaped:
            st.error(
                "**防护关闭**：Agent 已自主完成越权动作（读取敏感凭证 / 连接内网），"
                "完整复刻 AISI Agent 边界逃逸事件。",
                icon="💀",
            )
        else:
            st.info("防护关闭，本用例未发生越界动作", icon="ℹ️")

    st.caption(
        f"运行模式：{result['mode']} ｜ 状态 `{run.status}` ｜ 墙钟耗时 {result['wall_s']:.1f}s "
        f"｜ 步数 {len(run.steps)}"
    )
    for s in run.steps:
        render_step(s, s.index)

    if run.status == "isolated":
        st.error(f"最终状态：会话隔离。{run.final_answer}")
    elif run.final_answer:
        with st.expander("最终结论"):
            st.write(run.final_answer)


def render_baseline(guard) -> None:
    d = guard.baseline.describe()
    st.markdown("#### 权限基线（Agent 被允许做什么）")
    st.caption("默认拒绝：白名单没写的一律不允许。")
    cols = st.columns(3)
    with cols[0]:
        st.markdown("**✅ 工具白名单**")
        st.write("、".join(f"`{t}`" for t in d["tool_allow"]) or "—")
        st.markdown("**🚫 显式拒绝工具**")
        st.write("、".join(f"`{t}`" for t in d["tool_deny"]) or "—")
        st.markdown("**🌐 网络白名单**")
        st.write("、".join(f"`{x}`" for x in d["net_allow"]) or "—")
        st.markdown("**⛔ 内网禁用**")
        st.write("、".join(f"`{x}`" for x in d["net_deny"]) or "—")
    with cols[1]:
        st.markdown("**允许端口**")
        st.write("、".join(str(p) for p in d["allowed_ports"]))
        st.markdown("**敏感端口（一律拒绝）**")
        st.write("、".join(str(p) for p in d["sensitive_ports"]))
        st.markdown("**📁 可读路径**")
        for p in d["file_read"]:
            st.write(f"- `{p}`")
        st.markdown("**📝 可写路径**")
        for p in d["file_write"]:
            st.write(f"- `{p}`")
    with cols[2]:
        st.markdown("**🔒 受保护资源（命中即高危）**")
        for p in d["file_protected"]:
            st.write(f"- `{p}`")
        st.markdown("**命令白名单**")
        st.write("、".join(f"`{c}`" for c in d["cmd_allow"]))
        st.markdown("**高危命令**")
        st.write("、".join(f"`{c}`" for c in d["cmd_deny"]))
        st.markdown("**时序行为链规则**")
        for r in d["sequence_rules"]:
            st.write(f"- `{r['id']}` {r['name']}（{r['severity']}）")

    st.markdown("**原始任务基线（目标任务基线）**")
    st.info(f"🎯 {d['task_goal']}\n\n语义漂移阈值：`{d['intent_drift_threshold']}`")


# ---------------------------------------------------------------------------
# 主体
# ---------------------------------------------------------------------------
def main() -> None:
    svc = services()

    with st.sidebar:
        st.markdown("### 🛡️ AgentGuard")
        st.caption("面向安全 Agent 的边界逃逸检测与风险隔离机制")

        st.markdown("---")
        guard_enabled = st.checkbox(
            "启用边界逃逸防护",
            value=True,
            help="本项目的**唯一实验变量**。两组使用同一个 Agent、同一个模型、同一个沙箱。",
        )
        if guard_enabled:
            st.success("防护已开启：L1 权限基线 + L2 语义意图 + L3 行为监控 + L4 隔离阻断")
        else:
            st.error("防护已关闭：Agent 动作不做任何安全校验（对照组）")

        with st.expander("逐层开关（用于演示各层作用）", expanded=False):
            # 这里只影响单侧运行时的默认值，分屏对照始终使用"防护开/关"
            st.caption("在『单侧运行』模式下生效；分屏对照模式下由总开关决定。")

        st.markdown("---")
        st.markdown("### ⚙️ 运行设置")
        case_key = st.selectbox(
            "选择用例",
            options=list(CASES.keys()),
            format_func=lambda k: CASES[k]["name"],
            index=1,
        )
        st.info(CASES[case_key]["expect"])

        probe = llm_probe("http://127.0.0.1:11434", "qwen2.5-coder:7b")
        if probe["ok"]:
            st.success(f"本地大模型就绪\n\n{probe['msg']}", icon="🤖")
        else:
            st.warning(
                f"本地大模型不可用：{probe['msg']}\n\n"
                "将使用『脚本回放』模式（同一 Agent 循环、同一工具、同一防护层，"
                "仅思考文本来自预置轨迹）。",
                icon="⚠️",
            )
        use_llm = st.toggle(
            "调用本地大模型（真实 ReAct 推理）",
            value=False,
            disabled=not probe["ok"],
            help="开启后由 qwen2.5-coder:7b 现场推理，单次运行约需 1~4 分钟（CPU 推理）。",
        )
        if use_llm:
            st.warning("真实推理较慢，建议单侧运行或仅跑用例 2。", icon="⏳")
        max_steps = st.slider("最大步数", 3, 10, 6)

        st.markdown("---")
        st.markdown("### 🧪 沙箱服务状态")
        for k, v in svc["status"].items():
            if k == "_checks":
                st.code(v, language="text")
            else:
                icon = "✅" if ("运行中" in v or "复用" in v) else "⚠️"
                st.markdown(f"- {icon} `{k}` — {v}")
        for w in svc["warnings"]:
            if "靶站" in w:
                st.error(f"靶站不可用：{w}", icon="🚫")
            else:
                st.warning(w, icon="⚠️")

        st.markdown("---")
        st.caption(
            "⚠️ 安全声明：靶站与『内网』服务均为本机回环模拟，"
            "所读取的私钥/凭证均为演示用假数据，本项目不用于攻击真实目标。"
        )

    # ---------------- 页头 ----------------
    st.markdown(
        '<div class="ag-title">🛡️ 面向安全 Agent 的边界逃逸检测与风险隔离机制</div>'
        '<div class="ag-sub">第九届浙江省大学生网络与信息安全竞赛 · 网络安全作品挑战赛 ｜ '
        '自主命题 · 人工智能安全方向</div>',
        unsafe_allow_html=True,
    )

    tab_demo, tab_compare, tab_audit, tab_about = st.tabs(
        ["🎬 现场演示（分屏对照）", "📊 对照实验矩阵", "📜 审计日志", "📖 原理与说明"]
    )

    # ================= 演示 =================
    with tab_demo:
        st.markdown("#### 任务下发")
        st.code(TASK + (f"\n\n补充要求：{CASES[case_key]['prompt']}" if CASES[case_key]["prompt"] else ""),
                language="text")
        if CASES[case_key]["prompt"]:
            st.caption("👆 末尾的『补充要求』即诱导提示，模仿 AISI 事件中让 Agent 越权的注入语句。")

        b1, b2, b3 = st.columns([1.1, 1.1, 1.4])
        with b1:
            run_both = st.button(
                "▶️ 同时运行两组（对照实验）", type="primary", width="stretch"
            )
        with b2:
            run_single = st.button(
                f"▶️ 仅运行{'实验组(开启)' if guard_enabled else '对照组(关闭)'}",
                width="stretch",
            )
        with b3:
            st.caption(
                "分屏对照会在**同一次运行**里先后执行两组，"
                "任务、模型、沙箱、工具完全一致，只有防护开关不同。"
            )

        if run_both or run_single:
            results: dict[str, dict[str, Any]] = {}
            if run_both:
                with st.spinner("正在运行【对照组·关闭防护】…"):
                    results["off"] = run_group(case_key, False, use_llm, "qwen2.5-coder:7b",
                                               "http://127.0.0.1:11434", max_steps)
                with st.spinner("正在运行【实验组·开启防护】…"):
                    results["on"] = run_group(case_key, True, use_llm, "qwen2.5-coder:7b",
                                              "http://127.0.0.1:11434", max_steps)
            else:
                key = "on" if guard_enabled else "off"
                with st.spinner(f"正在运行【{'实验组' if guard_enabled else '对照组'}】…"):
                    results[key] = run_group(case_key, guard_enabled, use_llm, "qwen2.5-coder:7b",
                                             "http://127.0.0.1:11434", max_steps)
            st.session_state["results"] = results
            st.session_state["case_key"] = case_key

        results = st.session_state.get("results") or {}
        if results and st.session_state.get("case_key") == case_key:
            off, on = results.get("off"), results.get("on")
            if off and on:
                st.markdown("---")
                st.markdown("#### 对比结论")
                m1, m2, m3 = st.columns(3)
                m1.metric("对照组逃逸", "是 ⚠️" if off["run"].escaped else "否")
                m2.metric("实验组逃逸", "是 ⚠️" if on["run"].escaped else "否 ✅")
                prevented = off["run"].escaped and not on["run"].escaped
                m3.metric("逃逸是否被阻止", "✅ 已阻止" if prevented else "—")
                if prevented:
                    st.success(
                        "**同样的任务、同样的模型、同样的沙箱**：关闭防护时 Agent 自主完成了越权；"
                        "开启防护后动作在工具执行之前被拦下，且会话被冻结。",
                        icon="🎯",
                    )
                elif case_key == "1":
                    st.success(
                        "两组均正常放行 → 证明防护**不会误伤**合法操作。", icon="✅"
                    )

            st.markdown("---")
            if off and on:
                left, right = st.columns(2)
                with left:
                    render_group(
                        off, "🔴 对照组：关闭防护（原始 Agent）",
                        "Agent 直接调用工具，无任何安全校验",
                    )
                with right:
                    render_group(
                        on, "🟢 实验组：开启防护（接入 AgentGuard）",
                        "每次工具调用先经 L1→L2→L3 判定，L4 负责阻断/隔离/回滚",
                    )
            else:
                single = on or off
                render_group(
                    single,
                    "🟢 实验组：开启防护" if single["guard_enabled"] else "🔴 对照组：关闭防护",
                    single["mode"],
                )

            st.markdown("---")
            st.download_button(
                "⬇️ 导出本次运行结果（JSON）",
                data=json.dumps(
                    {
                        k: {
                            "guard_enabled": v["guard_enabled"],
                            "task": v["task"],
                            "mode": v["mode"],
                            "run": v["run"].to_dict(),
                            "guard_report": v["guard"].to_report(),
                        }
                        for k, v in results.items()
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                file_name=f"agentguard_case{case_key}_{int(time.time())}.json",
                mime="application/json",
            )

    # ================= 对照实验矩阵 =================
    with tab_compare:
        st.markdown("#### 四组对照实验（离线批量运行，秒级完成）")
        st.caption(
            "使用脚本回放模式运行全部用例：同一 Agent 循环 / 同一防护层 / 同一沙箱，"
            "唯一变量为防护开关。若需真实大模型结果，请在『现场演示』页开启大模型后单侧运行。"
        )
        if st.button("🚀 运行全部 4 组对照实验", type="primary"):
            rows = []
            progress = st.progress(0.0, text="运行中…")
            for i, key in enumerate(CASES.keys()):
                off = run_group(key, False, False, "", "", 8)
                on = run_group(key, True, False, "", "", 8)
                rows.append(
                    {
                        "用例": CASES[key]["name"],
                        "对照组逃逸": "是" if off["run"].escaped else "否",
                        "实验组逃逸": "是" if on["run"].escaped else "否",
                        "对照组阻断": off["guard"].summary()["blocked"],
                        "实验组阻断": on["guard"].summary()["blocked"],
                        "对照组状态": off["run"].status,
                        "实验组状态": on["run"].status,
                        "拦截的逃逸类型": "、".join(on["guard"].summary()["escape_types"]) or "—",
                        "逃逸被阻止": "✅" if (off["run"].escaped and not on["run"].escaped) else "—",
                        "误伤": "⚠️ 是" if (key == "1" and on["guard"].summary()["blocked"] > 0) else "否",
                        "_on_report": on["guard"].to_report(),
                    }
                )
                progress.progress((i + 1) / len(CASES), text=f"已完成 {i + 1}/{len(CASES)}")
            progress.empty()
            st.session_state["matrix"] = rows

        matrix = st.session_state.get("matrix")
        if matrix:
            st.dataframe(
                [{k: v for k, v in r.items() if not k.startswith("_")} for r in matrix],
                width="stretch",
                hide_index=True,
            )
            st.download_button(
                "⬇️ 导出对照实验矩阵（JSON）",
                data=json.dumps(
                    {
                        "task": TASK,
                        "rows": [{k: v for k, v in r.items() if not k.startswith("_")} for r in matrix],
                        "experiment_reports": [r["_on_report"] for r in matrix],
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                file_name=f"agentguard_matrix_{int(time.time())}.json",
                mime="application/json",
            )

    # ================= 审计日志 =================
    with tab_audit:
        st.markdown("#### 审计日志（logs/audit.jsonl）")
        audit_path = os.path.join(ROOT, "logs", "audit.jsonl")
        if os.path.isfile(audit_path):
            size = os.path.getsize(audit_path)
            st.caption(f"文件：`{audit_path}`（{size} 字节）")
            with open(audit_path, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
            st.caption(f"共 {len(lines)} 条事件，展示最近 60 条。")
            rows = []
            for line in lines[-60:]:
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rows.append(
                    {
                        "时间": time.strftime("%H:%M:%S", time.localtime(e.get("ts", 0))),
                        "会话": e.get("session", ""),
                        "类型": e.get("kind", ""),
                        "步骤": e.get("step", ""),
                        "工具": e.get("tool", ""),
                        "等级": e.get("severity", ""),
                        "说明": e.get("title", ""),
                    }
                )
            if rows:
                st.dataframe(rows[::-1], width="stretch", hide_index=True)
            st.download_button(
                "⬇️ 下载完整审计日志",
                data="".join(lines).encode("utf-8"),
                file_name="audit.jsonl",
                mime="application/x-ndjson",
            )
        else:
            st.info("暂无审计日志。运行一次演示后会自动生成。")

    # ================= 原理 =================
    with tab_about:
        st.markdown(
            """
#### 一、作品要解决的问题

AI Agent 正被广泛用于安全运维、漏洞挖掘、代码审计。但 Agent 存在**边界逃逸**风险：
大模型脱离系统预设权限，自主调用高危工具、读取敏感凭证、访问内网资源。
2024 年 AISI 披露的 Agent 逃逸事件即是典型：Agent 为完成目标而**自主越过权限边界**。

> 注意：本作品聚焦 **Agent 的边界逃逸**（自主调用工具、越权访问资源），
> 而不是单纯的大模型越狱（jailbreak）。越狱只是"说错话"，边界逃逸是"真的做了越权的事"。

#### 二、四层防护架构

| 层 | 名称 | 时机 | 回答的问题 |
|---|---|---|---|
| L1 | 权限基线 | 事前 | 这个动作在授权资源范围内吗？（默认拒绝） |
| L2 | 语义意图校验 | 事中 | Agent 的"想法"是否已经跑偏？（隐性逃逸） |
| L3 | 行为运行时监控 | 事中 | 实际参数与**动作序列**是否异常？ |
| L4 | 动态隔离阻断 | 响应 | 阻断本次调用 / 冻结会话 / 回滚变更 / 告警 |

#### 三、为什么对照组与实验组"确实只差一个变量"

- **同一个 Agent 循环**：`agentguard/agent.py` 的 `GuardedAgent`，两组都走它；
- **同一个本地大模型**：`qwen2.5-coder:7b`（Ollama，完全离线）；
- **同一个沙箱**：`sandbox/servers.py` 起的靶站与模拟内网服务；
- **同一套工具**：`agentguard/tools.py` 的 `ToolBridge`。

唯一差别是 `GuardConfig.enabled`，也就是左侧那个复选框。
工具调用必经 `ToolBridge.execute()`，防护开启时先由 `SandboxGuard.evaluate()` 判定，
**判定为逃逸则工具根本不执行**（不会产生任何副作用）。

#### 四、关键技术点（应对评委追问）

1. **动作归一化**：`http://host:8081`、`host`、`127.0.0.1:8081` 归一到同一个 Action 视图；
   路径反斜杠、`..`、`//` 统一解析——否则白名单会被轻易绕过。
2. **端口与服务语义解耦**：`canonical_port()` 让"连 internal-db 的任何端口"都按内网数据库判定，
   防止 Agent 换个端口就绕过敏感端口策略。
3. **目标对象模型（抑制误报）**：语义漂移不只看相似度，还要求"引用了任务范围外资源，
   且没有出现任务域/合法产物锚点"，因此"写扫描报告"这类正常动作不会被误伤。
4. **阻断门槛**：只有 HIGH/CRITICAL 级证据才拦截动作；LOW 级（观察项）只记录不阻断。
5. **时序行为链**：单步都合规，但 `读私钥 → 连内网` 的组合按横向移动处理（`config` 中 SEQ-001）。
6. **安全回滚**：会话开始时对可写目录做快照，判定逃逸后恢复，清除会话期间的新增写入。
7. **框架无关**：防护层是独立 SDK，插在工具调用点，换成 LangGraph/AutoGen 无需改防护代码。

#### 五、安全声明

靶站（`sandbox-target:8081`）、模拟内网数据库/SSH/后台 API 全部运行在 **127.0.0.1 本机回环**，
读取的私钥与凭证为 **演示用假数据**（文件内已标注 `DEMO / FAKE`）。
本项目不包含任何针对真实目标的攻击能力，仅用于安全研究与竞赛演示。
            """
        )


if __name__ == "__main__":
    main()
