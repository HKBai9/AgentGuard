# v2 Guard 与应用指南

更新：2026-10-22。在此前 A/B 集成基础上，已补齐长任务上下文、原生/HTTP/LangChain 宿主、实际恢复、只读控制台和评测/场景程序。主入口见 [操作说明](v2/OPERATIONS.md)，实现清单见 [功能补齐记录](v2/FEATURE_COMPLETION.md)。本轮依用户要求不开展演示与真实云端效果验收，没有新增拦截率或费用结论。以下保留 Guard 接口和本地开发检查方法。

## 默认离线运行

使用 Python 3.12。新环境按合并后的锁定依赖安装，不能只安装 pytest/PyYAML：

```powershell
uv venv --python 3.12 .venv-v2 --seed
uv pip install --python .venv-v2/Scripts/python.exe -r requirements-v2.lock.txt
uv pip install --python .venv-v2/Scripts/python.exe --no-deps -e .
powershell -NoProfile -File tools/v2/verify_guard.ps1 -Python .venv-v2/Scripts/python.exe
powershell -NoProfile -File tools/v2/verify_runtime.ps1 -Python .venv-v2/Scripts/python.exe
.venv-v2/Scripts/python.exe examples/v2/offline_guard.py
```

已有 Python 3.12 环境也可用 `verify_guard.ps1 -Python <可执行文件路径>`。
脚本默认只运行 `tests/v2/guard`、`tests/v2/host`，不读取密钥、不发云端请求。
测试禁用外部网络；Windows asyncio 所需的回环 socketpair 例外。
公共契约测试现在必须运行；真实 A/B 组件联调在 `tests/v2/integration/test_guard_runtime.py`，不是跳过项。真实云端 factory 未配置时，独立的 live 测试才会跳过。

离线样例输出持续标识 `synthetic_offline_playback`、`public_contract_validated: true`、
`runtime_integrated: false`，预期如下：

| 样例 | 预期 |
|---|---|
| 本地报告任务 | 候选只有 READ、WRITE |
| 明确发送任务 | 增加 SEND，只引用 test_receiver |
| 正常资料 | ALLOW 候选 |
| 含注入资料 | BLOCK，并指向 Unicode 码点位置 |
| 假秘密字段 | REDACT，仅指定 JSON pointer 和预登记变换 ID |
| 模型格式故障 | FAILED / INVALID_SCHEMA，无判定、无原文释放 |

FakeRuntime 是脚本回放器，不能执行工具、脱敏、计算许可或模拟实际安全保障。
FakeCloudClient 只返回人工编写的答案；它不证明模型能识别攻击。

## 对接 A 的接口

正式组件默认使用 `PublicContracts`，只导入 A 的 `agentguard.v2.contracts`。
缺失时抛出 `ContractUnavailable`，不会回退到字典透传或 FakeCloudClient。
测试中的 `FixtureContracts` 现在调用相同公共校验器，只把返回值转成字典以便断言，不再透传。精确字段见 [共享契约](tasks/V2_SHARED_CONTRACT.md) 和 `agentguard/v2/contracts.py`；B 任务书第 7 节保留合并前的历史提案。

实际组件的组合方式为：

```python
from agentguard.v2.review.clients import CloudClient, CloudConfig
from agentguard.v2.review.budget import Budget
from agentguard.v2.review.context import ContextBuilder
from agentguard.v2.review.reviewers import Reviewer
from agentguard.v2.review.service import GuardService
from agentguard.v2.policy.compiler import PolicyCompiler

client = CloudClient(CloudConfig.from_env(), budget=Budget(max_attempts=20))
generator = PolicyCompiler(client)
guard = GuardService(ContextBuilder(), Reviewer(client))
# candidate = await generator.generate(public_policy_request)
# outcome = await guard.inspect(public_context_material)
# A 校验候选/判定，提交权限版本、执行变换和控制释放。
```

请求和回复 JSON 在 [fixtures](../tests/v2/fixtures/README.md)。`model_response.json` 不带 usage；
客户端根据供应商响应与本地计时补入。B 检查有限字段、关联绑定、已知目录 ID、证据存在性、
字段和片段位置；A 仍需检查权限包含关系、宿主配额、数据标签、对象真实性和版本。
已登记资源的超配额候选可能通过 B 的格式检查，必须由 A 拒绝。

ContextBuilder 是纯函数，保留完整本次对象、可信任务和所有安全事实；不裁剪本次内容。
它记录实际提示序列化字节数（不是 token 数），必保留项超限返回 CONTENT_TOO_LARGE。
客户端另外限制整个 HTTP 请求字节数。all/recent/relations 可切换，历史正文可选择或形成带引用的非权威摘录，安全事实不因最近 N 条限制而消失。
ACTION 不能 REDACT；RESULT/FINAL 只提出变换目标，B 不产出可交付的改写全文。

NEEDS_CONTEXT 只接受 A 预先列出的既有证据引用，不读取文件、URL 或调用工具。
Runtime 已负责补证据循环，最多一次，使用 `supplemental_attempt` 标记并记录审查尝试。B 的独立 `inspect_with_evidence` 也保留一次补充限制；两条路径都不能改变任务、对象、权限和已有证据。再次要求补证据保持失败。

可选 `request_sink` 接收实际构造并发送的消息副本、关联信息、模型和提示版本，便于 A 在
受控审计存储中记录和脱敏展示。默认不记录正文；**不要把这个 sink 接普通日志或开放 UI**。
模型的 reason_summary 也属于不可信模型输出，不能作为普通日志的安全文本。
普通用量记录只包含模型、提示版本、尝试次数、耗时、用量和错误码。
现有可选 AnalysisCache 仅缓存经过校验的模型分析，绑定会话/任务/策略/上下文/安全版本/主体/证据/模型目的地/提示版本，回读仍重验；不缓存执行许可。恢复会清理该会话分析缓存。

## 显式启用云端传输检查

默认 DeepSeek HTTPS `/chat/completions`，现可由宿主配置兼容 HTTPS endpoint，模型名由宿主配置；没有工具定义、
重定向、环境代理或自主调用循环。JSON 模式和请求格式依据供应商的
[Chat Completions 文档](https://api-docs.deepseek.com/api/create-chat-completion/)与
[JSON Output 文档](https://api-docs.deepseek.com/guides/json_mode/)，查阅于 2026-10-21。
供应商 JSON 模式不代替本地字段/证据校验，空响应、截断和工具调用响应均拒绝。

`.env.v2.example` 只有配置名和占位值，不会被自动加载。显式设置进程环境：

```powershell
$env:AGENTGUARD_V2_CLOUD_ENABLED = "1"
$env:AGENTGUARD_V2_MODEL = "<填写账户可用模型名>"
$env:AGENTGUARD_V2_DESTINATION_ID = "guard_cloud"
# 通过本地安全方式设置 AGENTGUARD_V2_API_KEY，不要粘贴到版本库/测试记录。
powershell -NoProfile -File tools/v2/verify_guard.ps1 -Python .venv-v2/Scripts/python.exe -Live
```

`-Live` 在离线检查后仅运行 `examples/v2/cloud_smoke.py`，发送硬编码的自造连通性文本，
不会读取真实文档或 fixtures；输出明确标为 `live_transport_smoke`。
这不是 Guard 效果测试，也不证明与 A 的真实隔离链路已联通。
真实 Guard 输入还必须由 A 对每份材料检查用途、标签和端点数据范围；配置客户端的 destination_id 必须匹配 host_policy.guard_destination_id，并具有对应模型授权。端点配置不能由资料或模型改变。

调用默认最多 1 次重试，配置最大 3 次；仅重试超时、429、5xx 等暂时错误。
认证错误、格式错误、拒绝、截断不重试；取消不转换成 ALLOW，也不偷偷继续新的调用。
stdlib 传输采用 socket 超时和异步截止时间；取消时等待正在进行的 HTTP 线程退出，
因此并发槽不会提前释放，但实际返回时间可能超过配置的截止时间（例如 DNS/网络操作）。
这不是可强制终止 DNS 的硬实时超时实现。

Budget 同时限制尝试次数和可选 token 预算；并发请求先保守预留，再记录实际用量。
供应商没有提供的用量为 `unavailable`。token 预算开启时，未知用量会拒绝本次结果并阻止
后续调用，不能把未知计成 0；仅设置调用次数预算则可继续到次数上限。
网络失败的收费情况未知，当前费用统一 unavailable，不声称 0 成本，也未实现货币预算。

## 失败排查

| 结果 | 含义及下一步 |
|---|---|
| ContractUnavailable | 安装或导入不完整；检查是否使用合并后的包和正确 Python 环境，不可开启透传回退 |
| MODEL_CONFIGURATION_ERROR | 云端未显式启用、无密钥/模型、配置越界；无默认假答案 |
| MODEL_DESTINATION_DENIED | A 未授权本次材料给配置的模型目的地 |
| MODEL_TIMEOUT / MODEL_UNAVAILABLE | 检查供应商及网络；保持内容隔离，查看脱敏尝试记录 |
| INVALID_SCHEMA | 模型响应结构、JSON、枚举或关联空值错误；不自动放行 |
| INVALID_REFERENCE | 错会话/调用/版本，未知资源/证据，或片段/字段不存在 |
| CONTENT_TOO_LARGE | 必保留材料或完整请求超限；首版不截断后 ALLOW |
| MISSING_EVIDENCE | 材料不全、补证据仍不足或重复补充；由 A 保持阻断/隔离 |
| BUDGET_EXHAUSTED | 次数/token 上限或未知 token 用量；不能绕过审查继续释放 |

此前的集成验收与本轮功能实现分别记录，不能把历史验证数字当成本轮云端效果。当前宿主、UI、评测程序和启动入口见功能补齐记录；真实模型效果、外部整环境评测和比赛实验仍未运行。
