# A01–A08 验收映射

2026-10-22 集成更新：本表记录 A 侧组件覆盖，不能据此认为全部双人计划已完成。最新 A/B 联调、Windows 验证、跳过项与未完成任务以 [集成验收报告](INTEGRATION_REVIEW_2026-10-22.md) 为准。当前验证入口输出到 `logs/v2-integration/verification.json`；下文的原始环境成绩保留作历史记录。

完整可重放报告由 `tools/v2/verify_runtime.py` 生成到工作区 `ai/artifacts/v2/verification.json`；包含 Python、锁定依赖、Git 状态、JUnit 计数、构建与安装结果。旧版基线是 `9308897` / 1.1.0，而非计划中提到的 1.1.1。旧版 88 项测试在原 Python 3.14.8 环境通过，v2 发布验收在 Python 3.12 环境再次运行旧版回归。

| 任务 | 实现与可核验证据 |
|---|---|
| A01 契约/外壳 | `contracts.py`, `ports.py`, `bootstrap.py`, `schemas/`；`test_contracts.py` 校验未知版本/字段、必填缺失、非法 JSON、关联、离线导入；`examples/` 提供双方样例 |
| A02 策略/登记 | `registry.py`, `policy/validator.py`, `policy/engine.py`；权限矩阵、扩张拒绝、路径/端点/引用、远程 Schema 禁止测试 |
| A03 隔离/释放 | `state/store.py`, `state/artifacts.py`, `runtime.py`；正常/阻断/字段脱敏、原文仍隔离、超时/畸形/伪造引用、不足上下文、stderr 和结构化内容测试 |
| A04 执行/并发 | `execution/`；24 个并发领取同一/两张许可、两个 Runtime 真实调用一次、参数/清单/策略/上下文/安全修订/TTL/存储内容替换、配额、共享写资源、20 个确定乱序调用；真实子进程外发后退出只记 UNKNOWN、不再发送 |
| A05 来源/门禁 | `state/lineage.py`, `prepare_model_turn`, `record_model_output`, `finalize`；10/30/60 步限制保留、AlwaysAllow 无法外发、模型目的地/最终门禁独立拒绝、字段与文档限制区分、会话/用途/工具/目的地/TTL 引用校验 |
| A06 接入/安装 | `adapters/python.py`, `adapters/mcp.py`, `gateway/`；四类假工具同一内核、同步/异步 SDK、HTTP 全流程与真 loopback 服务、官方 MCP 协议往返与未支持协议拒绝、UI 不读原文、源码目录外 wheel 安装调用 |
| A07 恢复 | `recovery/checkpoints.py`；晚发现风险影响闭包、独立输入保留、未执行许可撤销、Ack 缺失/不全保持 RECOVERING、旧上下文拒绝、已外发收据仍显示不可撤回 |
| A08 交付 | 本文、`RUNTIME.md`、锁定依赖、PowerShell/Python 验收入口、实际性能测量、干净环境安装记录；B 真实联调专门列为缺失条件，未伪造通过 |

测试替身不进入生产默认组装。`test_optional_b.py` 的跳过不是通过；具体需要 B 交付的内容见 [RUNTIME.md](RUNTIME.md)。Linux 上用 PowerShell 7 执行入口不等同已验证 Windows 原生全部部署；依赖平台变更时重新运行安装及进程故障测试。
