"""用 Streamlit 官方的 AppTest 无头执行 app.py，验证页面脚本真的能跑通。

普通 HTTP 探活只能证明"外壳"加载成功，无法发现脚本内的运行时异常。
AppTest 会真正执行整个脚本（含缓存服务初始化、控件渲染），
因此可以作为 UI 层的冒烟测试。

运行：  python tools/ui_smoketest.py
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
_LIBS = os.path.join(ROOT, "libs")
if os.path.isdir(_LIBS):
    sys.path.insert(0, _LIBS)

from streamlit.testing.v1 import AppTest  # noqa: E402


def main() -> int:
    print("[ui] 启动 AppTest（首次运行会初始化沙箱服务，请稍候）…")
    at = AppTest.from_file(os.path.join(ROOT, "app.py"), default_timeout=180)
    at.run()

    failures: list[str] = []
    if at.exception:
        for e in at.exception:
            failures.append(f"脚本异常: {e.value}")
    if at.error:
        for e in at.error:
            failures.append(f"st.error: {e.value}")

    print(f"[ui] 复选框数量: {len(at.checkbox)}")
    for cb in at.checkbox:
        print(f"      - {cb.label} = {cb.value}")

    if not at.checkbox:
        failures.append("未找到『启用边界逃逸防护』复选框")

    # 校验关键控件存在
    labels = [c.label for c in at.checkbox] + [s.label for s in at.selectbox]
    labels += [t.label for t in at.toggle]
    print(f"[ui] 控件标签: {labels}")
    for must in ("启用边界逃逸防护",):
        if not any(must in lb for lb in labels):
            failures.append(f"缺少控件: {must}")

    if at.selectbox:
        print(f"[ui] 用例选择: {at.selectbox[0].options}")

    # 切换复选框（关闭防护）后重跑，确认不炸
    try:
        at.checkbox[0].set_value(False).run()
        if at.exception:
            failures.append(f"关闭防护后异常: {at.exception[0].value}")
        else:
            print("[ui] 关闭防护开关后重跑：正常")
    except Exception as exc:  # pragma: no cover
        failures.append(f"切换复选框失败: {exc}")

    if failures:
        print("\n[ui] 失败：")
        for f in failures:
            print("  -", f)
        return 1

    print("\n[ui] 冒烟测试通过：页面脚本执行无异常，关键控件存在。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
