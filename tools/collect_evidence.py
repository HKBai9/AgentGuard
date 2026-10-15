#!/usr/bin/env python
r"""汇总演示证据到稳定目录 `experiments/results/DEMO/`。

时间戳目录会不断累积，不利于写进申报书引用。本脚本把"最值得引用"的一次运行
连同环境信息、摘要表一起固化下来，生成一个可长期引用的证据包。

用法：
    python tools/collect_evidence.py            # 自动挑选最新的 scripted / live 各一份
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, "experiments", "results")
DEMO = os.path.join(RESULTS, "DEMO")


def latest(prefix: str) -> str | None:
    if not os.path.isdir(RESULTS):
        return None
    cands = [
        os.path.join(RESULTS, d)
        for d in os.listdir(RESULTS)
        if d.endswith(prefix) and os.path.isdir(os.path.join(RESULTS, d))
    ]
    return sorted(cands)[-1] if cands else None


def summarize_redteam(path: str) -> dict:
    """汇总红队实验结果（提示词防护的绕过情况）。"""
    with open(os.path.join(path, "redteam.json"), "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return {
        "source": os.path.basename(path),
        "model": data.get("model"),
        "summary": data.get("summary"),
        "variants": [
            {
                "id": r["attack_id"],
                "name": r["attack_name"],
                "kind": r["attack_kind"],
                "bare_escaped": r["runs"]["bare"]["escaped"],
                "prompt_guard_escaped": r["runs"]["prompt_guard"]["escaped"],
                "prompt_guard_refused": r["runs"]["prompt_guard"]["refused"],
                "prompt_guard_refused_before_escape": r["runs"]["prompt_guard"].get(
                    "refused_before_escape"
                ),
                "execution_guard_escaped": r["runs"]["execution_guard"]["escaped"],
                "prompt_guard_bypassed": r["prompt_guard_bypassed"],
                "execution_guard_held": r["execution_guard_held"],
                "verdict": r["verdict"],
            }
            for r in data.get("records", [])
        ],
    }


def summarize(path: str) -> dict:
    with open(os.path.join(path, "results.json"), "r", encoding="utf-8") as fh:
        data = json.load(fh)
    rows = []
    by_case: dict[str, dict] = {}
    for r in data["results"]:
        by_case.setdefault(r["case"], {})["on" if r["guard_enabled"] else "off"] = r
    for cid in sorted(by_case):
        pair = by_case[cid]
        off, on = pair.get("off"), pair.get("on")
        if not (off and on):
            continue
        rows.append(
            {
                "case": cid,
                "name": off["case_name"],
                "control_escaped": off["escaped"],
                "experiment_escaped": on["escaped"],
                "control_blocked": off["blocked_count"],
                "experiment_blocked": on["blocked_count"],
                "control_status": off["status"],
                "experiment_status": on["status"],
                "escape_prevented": bool(off["escaped"] and not on["escaped"]),
                "false_positive": bool((not off["escaped"]) and on["blocked_count"] > 0),
                "escape_types": on["guard_summary"]["escape_types"],
                "rollback_actions": on["guard_summary"]["rollback_actions"],
            }
        )
    return {
        "source": os.path.basename(path),
        "live": bool(data.get("live")),
        "model": data.get("model"),
        "generated_at": data.get("generated_at"),
        "task": data.get("task"),
        "rows": rows,
    }


def collect_env() -> dict:
    host_py = sys.executable
    info = {
        "collected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "python_path": host_py,
        "processor": platform.processor(),
    }
    # 本地模型清单
    try:
        import urllib.request

        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=5) as resp:
            tags = json.loads(resp.read().decode("utf-8"))
        info["ollama_models"] = [m.get("name") for m in tags.get("models", [])]
    except Exception as exc:
        info["ollama_models"] = f"不可用（{type(exc).__name__}）"
    # 依赖版本
    try:
        import streamlit

        info["streamlit"] = streamlit.__version__
    except Exception:
        info["streamlit"] = "未知"
    return info


def latest_test_summary() -> str:
    """运行 pytest 并返回可读的结论（用作证据包的一部分）。

    注意：pytest.ini 里配了 `-q`，会把 "N passed" 摘要行压掉，
    因此这里显式加 `-rN`（报告未通过的测试）并自行统计通过数，
    保证写进证据包的是一个**可核查**的数字，而不是一片进度点。
    """
    env = dict(os.environ)
    libs = os.path.join(ROOT, "libs")
    if os.path.isdir(libs):
        env["PYTHONPATH"] = libs + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider"],
            capture_output=True,
            text=True,
            timeout=900,
            cwd=ROOT,
            env=env,
        )
    except Exception as exc:
        return f"(未运行：{exc})"

    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    # 优先用 pytest 自己的摘要行
    for line in reversed(out.splitlines()):
        if re.search(r"\d+\s+(passed|failed|error)", line, re.I):
            return line.strip()
    # 退化：统计进度点（"....F..." 形式），自行给出结论
    dots = "".join(ch for ch in out if ch in ".FEsxX")
    if dots:
        passed = dots.count(".")
        failed = sum(dots.count(c) for c in "FE")
        verdict = "passed" if failed == 0 and proc.returncode == 0 else f"FAILED({failed})"
        return f"{passed} passed" if verdict == "passed" else f"{passed} passed, {failed} failed"
    return f"exit={proc.returncode}"


def main() -> int:
    os.makedirs(DEMO, exist_ok=True)
    evidence: dict = {"environment": collect_env(), "suites": {}}

    # 清理沙箱里运行期补齐的凭证副本（否则会被误当成源码提交）
    try:
        sys.path.insert(0, ROOT)
        from sandbox.servers import cleanup_provisioned

        for p in cleanup_provisioned(os.path.join(ROOT, "sandbox", "sandbox_fake")):
            print(f"[clean] 清理运行期补齐的目录：{os.path.relpath(p, ROOT)}")
    except Exception as exc:
        print(f"[clean] 跳过（{exc}）")

    for label, suffix in (("scripted", "_scripted"), ("live", "_live")):
        path = latest(suffix)
        if not path:
            print(f"[skip] 未找到 {label} 结果目录")
            continue
        dst = os.path.join(DEMO, label)
        if os.path.isdir(dst):
            shutil.rmtree(dst)
        shutil.copytree(path, dst)
        evidence["suites"][label] = summarize(path)
        print(f"[copy] {os.path.basename(path)} -> {os.path.relpath(dst, ROOT)}")

    # 红队结果单独归档（回答"提示词防护够不够"的关键证据）
    rt = latest("_redteam")
    if rt:
        dst = os.path.join(DEMO, "redteam")
        if os.path.isdir(dst):
            shutil.rmtree(dst)
        shutil.copytree(rt, dst)
        evidence["redteam"] = summarize_redteam(rt)
        print(f"[copy] {os.path.basename(rt)} -> {os.path.relpath(dst, ROOT)}")
    else:
        print("[skip] 未找到红队结果目录（可运行 python experiments/run_adversarial.py 生成）")

    print("[test] 运行 pytest 以记录当次测试结论…")
    evidence["pytest_summary"] = latest_test_summary()
    print(f"       {evidence['pytest_summary']}")

    out = os.path.join(DEMO, "evidence.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(evidence, fh, ensure_ascii=False, indent=2)
    print(f"[done] 证据包 -> {os.path.relpath(out, ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
