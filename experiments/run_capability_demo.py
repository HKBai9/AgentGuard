#!/usr/bin/env python
r"""权能生命周期微演示：票据签发 → 重放/伪造攻击 → 衰减 → 级联撤销。

回答的问题（答辩可直接引用）：
  Q1 零初始权限是否真的成立？      —— 没有票据的动作一律拒绝
  Q2 票据被截获后重放有用吗？      —— max_calls=1 + 步骤绑定，双保险拒绝
  Q3 票据能被伪造/篡改放宽吗？     —— HMAC 链 + 作用域登记表拒绝
  Q4 子 Agent 能继承超出父的权限吗？—— 衰减只可收窄（交集语义）
  Q5 撤销要多久生效？             —— Caretaker O(1) 标记，子树票据全部立即失效

运行：  python experiments/run_capability_demo.py
输出：  控制台判定矩阵 + experiments/results/capability_demo_<时间戳>/
"""

from __future__ import annotations

import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentguard import VFS_ROOT, GuardConfig, build_guard  # noqa: E402
from agentguard.action import build_action  # noqa: E402
from agentguard.capability import CapabilityScope, Caveat  # noqa: E402
from agentguard.tools import ToolBridge  # noqa: E402

NOTES = "/sandbox_fake/workspace/notes/xss_scan_notes.md"


def rule_ids(findings) -> list[str]:
    return [f.rule_id for f in findings]


def main() -> int:
    guard = build_guard(
        guard_config=GuardConfig(enabled=True),
        session_id=f"capdemo-{int(time.time())}",
    )
    bridge = ToolBridge(guard, vfs_root=VFS_ROOT)
    authority = guard.authority
    view_notes = build_action("read_file", {"path": NOTES})
    view_key = build_action("read_file", {"path": "/sandbox_fake/.ssh/id_rsa"})
    view_write = build_action(
        "write_file", {"path": "/sandbox_fake/workspace/reports/x.md", "content": "x"}
    )

    results: list[dict] = []

    def check(
        name: str,
        expect_rules: list[str],
        actual_rules: list[str] | None = None,
        findings=None,
        passed: bool | None = None,
        detail: str = "",
    ) -> None:
        """expect_rules：期望命中的规则（任一命中即通过）；空列表 = 期望全部放行。"""
        got = actual_rules if actual_rules is not None else rule_ids(findings or [])
        if passed is None:
            passed = any(r in got for r in expect_rules) if expect_rules else not got
        results.append(
            {
                "场景": name,
                "预期规则": " / ".join(expect_rules) or "（通过，无违规）",
                "实际规则": " / ".join(got) or "（通过，无违规）",
                "结论": "✅ 拦截成功" if passed else "❌ 未按预期",
                "说明": detail,
            }
        )

    print("=" * 78)
    print("AgentGuard L0 动态权能 · 生命周期攻击面演示")
    print(f"  会话: {authority.session_id} ｜ 微租约: TTL={authority.ttl:.0f}s, "
          f"max_calls={authority.max_calls}")
    print("=" * 78)

    # ---------------------------------------------------------------- Q1 零初始权限
    from agentguard.types import ToolCall

    verdict, _ = guard.evaluate(ToolCall(tool="read_file", args={"path": NOTES}, step=1))
    check(
        "Q1 零初始权限：无票据的调用",
        ["L0-NO-TOKEN"],
        findings=verdict.findings,
        detail="Agent 启动不带任何预置权限；没有当次签发的票据就拒绝执行",
    )

    # ---------------------------------------------------------------- 正常签发/消耗
    r, v = bridge.execute("read_file", {"path": NOTES}, thought="读取笔记", step=1)
    token = authority.tokens[-1]
    fresh = authority.issue("read_file", view_notes, step=2).token
    check(
        "正常调用：JIT 签发 + 单次消耗",
        [],
        findings=authority.verify(fresh, "read_file", view_notes, step=2),
        detail=f"刚签发的票据在自身步骤内验证通过；执行后配额耗尽"
               f"（前一张票据 {token.token_id} status={token.status}）",
    )

    # ---------------------------------------------------------------- Q2 重放
    replay = authority.verify(token, "read_file", view_notes, step=1)
    check(
        "Q2a 重放：同一票据原样重放（同参数同步骤）",
        ["L0-QUOTA"],
        findings=replay,
        detail="max_calls=1：单次调用即作废",
    )
    step_replay = authority.verify(token, "read_file", view_notes, step=2)
    check(
        "Q2b 重放：换一步骤复用票据",
        ["L0-QUOTA", "L0-STEP"],
        findings=step_replay,
        detail="配额 + 步骤绑定双重防线",
    )

    # ---------------------------------------------------------------- Q3 TTL
    ttl_token = authority.issue("read_file", view_notes, step=3).token
    ttl_token.expires_at = authority._clock() - 0.001  # 模拟时间流逝超过 TTL
    check(
        "Q3 TTL 过期：票据超过 30s 生命周期",
        ["L0-TTL"],
        findings=authority.verify(ttl_token, "read_file", view_notes, step=3),
        detail="微租约到期自动作废，无需显式撤销",
    )

    # ---------------------------------------------------------------- Q3b 伪造
    forged = authority.issue("read_file", view_notes, step=4).token
    forged.mac = "0" * 64
    check(
        "Q3b 伪造：篡改票据签名",
        ["L0-MAC"],
        findings=authority.verify(forged, "read_file", view_notes, step=4),
        detail="HMAC 链校验失败",
    )

    tampered = authority.issue("read_file", view_notes, step=5).token
    tampered.caveats.append(Caveat("path_glob_any", ["/sandbox_fake/.ssh/**"], "伪造宽松谓词"))
    check(
        "Q3c 伪造：向票据塞入宽松路径谓词",
        ["L0-MAC"],
        findings=authority.verify(tampered, "read_file", view_key, step=5),
        detail="谓词是签名覆盖的一部分，改谓词 = 签名失效",
    )

    rogue_scope = CapabilityScope(
        node=authority.root_scope.node, caveats=[], mac="f" * 64, label="forged"
    )
    rogue = authority.issue("read_file", view_notes, step=6, scope=rogue_scope).token
    check(
        "Q3d 伪造：用伪造作用域派生票据",
        ["L0-MAC"],
        findings=authority.verify(rogue, "read_file", view_notes, step=6),
        detail="作用域签名不在策略引擎登记的派生链上",
    )

    # ---------------------------------------------------------------- Q4 衰减
    child = authority.derive_scope(authority.root_scope, "sub-agent@demo", allowed_tools=["read_file"])
    dec = authority.issue("write_file", view_write, step=7, scope=child)
    check(
        "Q4 衰减：子 Agent 申请父权能已剥离的写权限",
        ["L0-ATTENUATE"],
        actual_rules=[dec.rule_id],
        passed=not dec.issued,
        detail=f"策略引擎拒签：{dec.reason[:60]}…",
    )
    grand = authority.derive_scope(child, "grandsub@demo", allowed_tools=["write_file"])
    dec2 = authority.issue("write_file", view_write, step=8, scope=grand)
    check(
        "Q4b 传递衰减：孙作用域试图恢复写权限",
        ["L0-ATTENUATE"],
        actual_rules=[dec2.rule_id],
        passed=not dec2.issued,
        detail="委派声明与继承谓词取交集，只可收窄不可放大",
    )

    # ---------------------------------------------------------------- Q5 级联撤销
    alive_token = authority.issue("read_file", view_notes, step=9, scope=child).token
    sibling = authority.derive_scope(authority.root_scope, "sub-b@demo")
    sibling_token = authority.issue("read_file", view_notes, step=9, scope=sibling).token
    authority.revoke_scope(child, "父任务结束，收回子 Agent 权能")
    check(
        "Q5a 级联撤销：撤销子作用域节点",
        ["L0-REVOKED"],
        findings=authority.verify(alive_token, "read_file", view_notes, step=9),
        detail="O(1) 标记失效，该子树全部票据立即死亡",
    )
    check(
        "Q5b 撤销精度：兄弟作用域不受影响",
        [],
        findings=authority.verify(sibling_token, "read_file", view_notes, step=9),
        detail="只失效被撤销的派生子树",
    )

    # ---------------------------------------------------------------- 熔断
    before = authority.registry.epoch
    authority.revoke_all("演示熔断开关")
    check(
        "Q5c 熔断开关：撤销会话根",
        ["L0-REVOKED"],
        findings=authority.verify(sibling_token, "read_file", view_notes, step=9),
        detail=f"epoch {before} → {authority.registry.epoch}，全部在飞票据毫秒级失效",
    )

    # ---------------------------------------------------------------- 输出
    print()
    for row in results:
        mark = row["结论"]
        print(f"  {mark}  {row['场景']}")
        print(f"         规则：{row['实际规则']} ｜ {row['说明']}")
    n_ok = sum(1 for r in results if r["结论"].startswith("✅"))
    print()
    print(f"  判定矩阵：{n_ok}/{len(results)} 项符合预期")
    print(f"  策略引擎统计：{authority.stats} ｜ 撤销纪元 epoch={authority.registry.epoch}")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    outdir = os.path.join(ROOT, "experiments", "results", f"capability_demo_{stamp}")
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(
            {
                "session": authority.session_id,
                "ttl_s": authority.ttl,
                "max_calls": authority.max_calls,
                "results": results,
                "authority_snapshot": authority.snapshot(),
            },
            fh,
            ensure_ascii=False,
            indent=2,
        )
    print(f"\n结果已写入：{outdir}")
    return 0 if n_ok == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
