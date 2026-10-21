# 人员 B 任务书：Guard、上下文、Agent 接入与验证

日期：2026-10-21。任务状态：B01 的 B 侧离线交付、B02/B03 的 S1 实现已落地；A01 公共契约联调与真实云端/Runtime 联调待完成。详见第 7 节，不将模拟结果视为整体验收。

你负责把真实任务与执行证据变成有用的安全判断，并用实际实验说明复杂模块是否有效。你承担动态策略和长任务上下文两项核心能力，也负责让主 Agent 真正接入安全运行时。界面是展示这些能力的出口，不能成为最先消耗全部时间的工作。

先读 [总任务书](../V2_TWO_PERSON_PLAN.md) 和 [共享接口约定](V2_SHARED_CONTRACT.md)。原理与研究来源见 [实施计划](../V2_IMPLEMENTATION_PLAN.md)。

## 1. 你的文件与交付范围

你拥有 `policy/compiler.py` 与 `templates/`、`review/`、`adapters/host.py` 与 `framework.py`、`ui/v2/`、`examples/v2/`、`benchmarks/v2/`。测试写入 `tests/v2/guard/`、`host/`，共同假数据放 `tests/v2/fixtures/`。

你实现 PolicyGenerator、ContextBuilder、Reviewer 和组合它们的 GuardService，依赖公共契约，不直接操作 A 的数据库、工具执行器或许可表。公共类型/依赖变更交给 A 统一落地。

你最后交付：没有工具权限的模型审查服务、可解释的证据上下文、两个宿主接入样例、六视图界面、可复核的安全/效用/费用报告及演示入口。

## 2. 第一轮立即执行

1. 在独立分支/工作目录阅读接口约定，列出你会收到的 ContextMaterial 和要返回的 ReviewDecision；不要等数据库完成。
2. 在 `tests/v2/fixtures/` 准备同工具不同任务、正常放行、注入阻断、字段脱敏、模型故障五组最小假数据，附人工预期。
3. 在自己的测试目录实现 FakeRuntime、FakeCloudClient。先跑一份固定上下文到结构化判定的离线流程。
4. 编写策略候选与单份文档审查提示初版；程序校验所有模型返回，非法输出明确失败。
5. 用 A 的公共类型替换临时内联数据。A 接口尚未实现时继续提示、上下文与宿主测试，不去自己写第二套运行时。

第一轮结束交付一个能被 A 校验的合法判定和至少一个会被拒绝的非法判定。云端测试按显式配置单独启用，不要求先有 API key 才能完成这一轮。

## 3. 分任务卡

### B01｜假数据、客户端替身与独立开发入口（S0）

**实施：**

- 按共享契约建立前五组 fixtures，每组包含请求、预期判定/状态及解释；只使用自造文档和假秘密。
- 写 FakeCloudClient、FakeRuntime 和固定 ContextMaterial；按公共 Protocol 暴露，不模仿 A 的 SQLite 内部实现。
- 建立 `tools/v2/verify_guard.ps1` 初始入口，默认只跑离线用例。
- 与 A 核对公共字段、null 语义、枚举、证据位置与文本索引。

**依赖：**共享文档即可；公共类型的小提交到达后对齐，不必等 A 服务运行。

**验收：**两人相同 fixture 解析一致；非法枚举、旧版本、越界片段都可测试；运行不需要云端密钥。

**交给 A：**共同 fixtures 及 `expected.json`。测试标准不能由待测 Guard 的答案自动生成。

### B02｜云端客户端、预算与任务策略候选（S1）

**实施：**

- `review/clients.py` 封装供应商调用，配置模型、超时、并发上限、有限重试和结构化输出；不带工具定义，不开展自主执行循环。
- `review/budget.py` 记录实际用量、时延、错误和预算；供应商不返回的用量标 unavailable。
- `policy/compiler.py` 只依据真实任务、宿主边界、已确认授权和工具/资源目录生成有限格式候选。
- 明确禁止生成可执行 Python/Rego/SQL 或新增资源身份；不把工具返回内容当成用户权限修改。
- 设置无密钥时的明确错误，不能偷偷使用假的成功答案。分析缓存包含会话/主体、任务、策略、内容、模型与提示版本等必要绑定，不缓存执行许可。

**前置：**B01。**替代品：**FakeCloudClient；A 未提供校验器前使用人工预期矩阵比较，之后接实际 validator。

**验收：**同一 SEND 工具在两个任务中产生不同权限候选；候选格式错/越界/未知资源可被 A 拒绝；预算用尽不跳过审查；固定重试上限可以观察。

**交给 A：**PolicyGenerator 实现、模型配置示例、候选与失败样本。策略提交和版本更新始终由 A 完成。

### B03｜三类审查与结构化证据（S1 起步，S2 补全）

**实施：**

- `review/reviewers.py` 提供 ACTION、RESULT、FINAL 三种独立审查请求，复用一个模型客户端即可。
- S1 先完成 RESULT 和最小 ACTION；S2 接通完整动作与最终输出。请求明确区分可信任务/权限与待检查的不可信内容。
- 返回 ALLOW/BLOCK/REDACT/NEEDS_CONTEXT、原因码、当前对象引用、风险位置及有限变换 ID。
- REDACT 只指出允许处理的位置，不直接生成将被主 Agent 使用的“已安全”全文；不能修改动作参数绕过重审。
- 输出先通过 Schema 校验；格式错误、超时或缺证据走 ReviewFailure。最多一次有边界的补证据，不让模型要求任意外部读取。

**前置：**B02；离线分支可与客户端同时写。

**验收：**A 能消费判定；伪造引用/旧 subject_ref 被拒绝；明确阻断样例含可定位证据；错误时不返回 ALLOW；敏感内容不进入普通日志。

**S1 联调交付：**用真实 Guard 接 A 的隔离释放链路，对一份正常资料和一份注入资料给出实际响应，记录模型配置与结果；不能据此宣布总体拦截率。

### B04｜长任务上下文与证据选择（S2）

**实施：**

- `review/context.py` 实现纯 ContextBuilder。输入 A 的材料，输出实际发给模型的 ReviewRequest 或材料不足状态。
- 始终保留任务、权限、当前完整对象、数据限制和未决风险；按资源与来源关系选择历史正文，辅以有界近期事件。
- 不用向量相似度 Top-K 代替权限约束。摘要必须有来源引用，不能变成新的可信指令。
- 超预算不能静默删去必保留项；本次内容无法完整审查时返回 CONTENT_TOO_LARGE。
- 做三种可切换上下文方案：预算内全历史、最近 N 条、关系证据。预算截断、材料不足和实际 token 都写入结果，避免不公平对照。
- 补齐 10/30/60 步和 20 并发 fixtures，区分 exact/possible 依赖，包含早期植入与后期外发场景。

**前置：**B03；A05 未完成时用固定 ContextMaterial。

**验收：**相同动作稳定带上必需权限/风险；限制不因最近 N 条淘汰或摘要而消失；展示包与实际发送包一致（展示时脱敏）；不存在为了降低 token 而漏审本次内容的路径。

**交给 A：**ContextBuilder、缺材料原因码与复现 fixture；A 负责提供授权证据并校验其身份。

### B05｜原生宿主、框架接入与宿主恢复（S2—S3）

**实施：**

- S2 用 `adapters/host.py` 和 `examples/v2/` 做一个原生循环：prepare_model_turn → 模型推理 → record_model_output → execute_batch/finalize。
- 框架必须把工具提议交给 Runtime，关闭绕过 Runtime 的自动直调；所有结果回调只能使用已释放版本。
- S3 在 `adapters/framework.py` 接一个框架，优先核对现有 LangChain 相关适配能否复用；实施时固定兼容版本，不同时做多框架。
- 真正送入主模型的内容必须与 A 记录的 PreparedTurn 一致；不得附加旧原始工具返回。最终输出和内部流在门禁前不可显示给用户。
- 响应 RecoveryPlan：重建消息、丢弃云端续接 ID、清理受影响 checkpoint/记忆/缓存/工作产物，返回逐项 RecoveryAck。
- 某框架不具备必要钩子时明确不支持完整恢复，不用“清空 messages”冒充完成。

**前置：**B01 可先做 FakeRuntime 的宿主循环；真实接入依赖 A05/A06，恢复依赖 A07。

**验收：**主模型看不到隔离原文；每次实际输入/工具/最终输出都有 Runtime 事件；恢复后不继续旧云端会话或自动载入污染记忆；原生与框架样例产生相同的门禁语义。

**交给 A：**HostAdapter、框架能力清单与 RecoveryAck 样例。A 算影响范围，你落实宿主清理，两者缺一不能宣称恢复成功。

### B06｜六视图控制台（S3）

**实施：**

- `ui/v2/` 先用脱敏事件 fixtures，后切换到 A 的只读查询接口；不直连 SQLite/隔离目录。
- 依次完成任务策略、执行时间线、实际 Guard 证据包、前后内容对比、来源/恢复图、真实效果与成本六个视图。
- 显示已批准、已执行、已释放、失败和 UNKNOWN 的区别；每条证据能追到版本/事件，possible 边明确标注。
- 原文对比仅限宿主标记的假数据演示对象；默认遮盖秘密。录制回放与实时 API 模式有持续可见标识。
- 第一版以信息完整和可复核为目标，配色/动画等最后处理。

**前置：**B04 确定证据结构；A 查询服务未好时用同格式 JSON。

**验收：**界面上的一次“阻断”可对应真实事件和接收器结果；界面刷新不会触发工具再执行；未知效果不会显示为攻击失败；展示的 Guard 输入来自实际请求记录。

### B07｜独立评测、对照与消融（S4，样本从 S0 开始积累）

**实施：**

- 在 `benchmarks/v2/` 建任务、假工具环境、攻击插入点和独立评分器；外发检测看本地测试接收器是否真的收到假秘密。
- 先 8 个正常任务 + 8 个攻击任务测费用和延迟，再确定固定样本列表、重复次数与总额度。
- 对比无防护、旧 1.1.1 的共同支持子集、普通双模型审查、完整 v2；模型、工具环境和任务设置保持一致。未知工具全拒绝不能算旧版防护优势。
- 消融上下文方案、数据限制传播、结果处理、全局冻结/恢复。实验开关只用于隔离评测配置，启动界面清楚标出保护被关闭的项目。
- 引入固定版本的 AgentDojo 选定任务集；InjecAgent 用作补充样例。外部评测依赖单独环境，避免破坏主工程。
- 报告正常/受攻击任务成功率、攻击真实达成率、误拦率、未审查释放、越权外发、恢复率、重做调用、p50/p95 延迟、调用数/token/费用。
- 保留未用于调提示的任务/攻击措辞；标明样本分母、重复次数与不确定性。效果未知不算防护成功。

**前置：**S4 用真实闭环；此前先完成假数据评分器。先验证评分器能判定无防护攻击成功与正常任务完成，不能只检查“Guard 返回 BLOCK”。

**验收：**报告能从保存的配置、版本、事件和评分结果重新计算；实跑/回放分开；未运行的模型或实验明确留空；A 能抽查独立评分证据。

### B08｜一键演示、使用文档与答辩材料（S4）

**实施：**

- `start_v2.ps1` 提供明确的实时/回放模式，`.env.v2.example` 只有配置名与示例占位值。
- 按总计划完成五个演示：同工具不同任务、20 读一注入、早读后泄露、Guard 全允许仍受约束、超时/乱序/副作用后异常。
- 编写使用指南、评测报告和来源/许可证清单；复制开源代码时记录 commit、文件、许可和修改。
- 整理答辩叙述：为什么不是普通双 Agent、动态策略哪里变化、上下文为何不靠全量历史、程序约束如何独立生效、恢复能做与不能做什么。
- 与 A 从干净环境完成启动/安装演练；网络不稳定时可用清楚标注的既有录制回放。

**验收：**每个演示都有启动方式、预期行为、实际证据和失败排查；成本/效果数字均有数据；没有把架构图或模拟结果写成已完成安全保证。

## 4. 你给 A 和从 A 接收的交接

| 时间 | 你给 A | A 给你 |
|---|---|---|
| S0 | fixtures、模拟模型、协议消费者 | 公共类型、Schema、接口外壳 |
| S1 | 候选生成器、审查器、用量 | 硬校验、隔离释放、错误码 |
| S2 | ContextBuilder、原生宿主、长任务样例 | 快照/来源/批次/最终输出接口 |
| S3 | 框架钩子、恢复 Ack、查询 UI | 网关、恢复计划、真实查询数据 |
| S4 | 评分证据、报告、一键演示 | 稳定运行包、故障测试、安装验证 |

## 5. 完成定义与测试入口

模型接口能返回 JSON 只是开始。每项任务还须有失败路径、真实发送内容的可观测记录、对应 fixtures、明确交接与可重复的测试。

以下是你需要交付的计划命令，当前新目录尚未实现；实现后保证默认离线运行：

```powershell
python -m pytest tests/v2/guard tests/v2/host -q
powershell -NoProfile -File tools/v2/verify_guard.ps1
```

真实 API 回归单独启用并记录模型/提示版本、样本与花费，不能混入默认单测；具体开关由你实现并写进指南。不要断言“模型必须每次答同一个措辞”，应验证输出契约、人工定义的行为预期与独立任务结果。

## 6. 可复制给 AI 的开工指令

> 阅读 docs/V2_TWO_PERSON_PLAN.md、docs/tasks/V2_SHARED_CONTRACT.md 和 docs/tasks/V2_B_GUARD.md。你现在执行人员 B 的 B01，完成后在自身负责范围继续 B02/B03。先用纯假数据、FakeRuntime 和 FakeCloudClient 建立可离线验证的流程，再按显式配置接可信云端 API。只修改 B 负责文件，不建立第二套公共类型/数据库/执行器，不给 Guard 模型工具，不把模型输出当作最终权限，不先投入 UI 美化。每项任务交付测试结果、接口样例和失败路径；需要公共类型或依赖变化时向 A 提出明确变更。

## 7. 本轮交付与给 A 的明确交接（2026-10-21）

### B 侧交付状态

| 任务 | 已交付 | 尚待联合验收 |
|---|---|---|
| B01 | 前五组纯假数据、人工 expected.json、FakeCloudClient、仅脚本回放的 FakeRuntime、固定材料、独立离线入口 | A 公共模型解析一致；Runtime 真实隔离/释放 |
| B02 | 固定可信 HTTPS 云端客户端、超时/并发/有限重试、用量与次数/token 预算、有限策略候选、无密钥明确失败 | A 校验权限包含关系与配额；生产装配、真实供应商测试 |
| B03 | RESULT/最小 ACTION/最小 FINAL、结构和绑定检查、Unicode 片段/JSON pointer、有限 REDACT、一次补证据、ReviewFailure、可选受控实际请求记录 | A 消费真实公共类型；真实 Guard 接真实隔离链路、正常/注入双样本 |

实现路径：`agentguard/v2/policy/compiler.py`、`policy/templates/`、`review/`。
没有修改 A 的公共文件、数据库、执行器、根初始化文件、依赖元数据或锁文件；没有增加 UI。
`review/context.py` 只完成 S1 的完整材料组装，不代表 B04 的长任务/关系上下文已经完成。
没有分析缓存、权限缓存或隐式假模型回退；正式组件默认要求 A 的公共 Pydantic 模型。

### 可复现验证与接口样例

Python 3.12.12，pytest 9.1.1，PyYAML 6.0.3；本地 `.venv`，未更改共享配置。

```powershell
.venv/Scripts/python.exe -m pytest tests/v2/guard tests/v2/host -o addopts= -p no:cacheprovider -q --tb=short
powershell -NoProfile -File tools/v2/verify_guard.ps1
.venv/Scripts/python.exe examples/v2/offline_guard.py
```

本轮结果：**107 passed，1 skipped**。跳过项是
`test_public_models_parse_the_same_fixtures_when_a01_is_available`：当前没有
`agentguard/v2/contracts.py` / `ports.py`。独立 PowerShell 入口通过；回放结果为
本地 READ/WRITE、发送 READ/WRITE/SEND，以及 ALLOW/BLOCK/REDACT/INVALID_SCHEMA。
测试显式阻断外网，不需要密钥。未发出真实供应商请求，未测费用/攻击拦截率。

全仓回归：`.venv/Scripts/python.exe -m pytest tests -o addopts= -p no:cacheprovider -q --tb=short`
得到 **247 passed，2 skipped（32.84s）**；跳过分别为旧版可选 `langchain_core.tools`
依赖与上述 A01 公共契约测试。`compileall` 通过。显式清除密钥并禁用云端后运行
`cloud_smoke.py`，得到 MODEL_CONFIGURATION_ERROR、0 次请求、退出码 1，符合预期失败路径。

接口样例和失败路径：

- B01：`tests/v2/fixtures/normal_allow/{material,model_response}.json`；
  `guard_failure/cases.json` 有非法枚举、旧版本、错关联和越界引用；
  `guard_failure/runtime_script.json` 是不含原文的 REVIEW_PENDING 回放。
- B02：`policy_local_vs_send/{local,send}_{request,candidate}.json` 与人工权限矩阵。
  未知资源/目的地/工具、可执行字段、非法配额、旧 base_version 会失败；
  已知范围但超过宿主配额的候选**仍须 A 拒绝**，测试明确不把 B 当 validator。
- B03：`injection_block` 含定位证据，`field_redact` 仅指向字段，`normal_allow` 还含
  `action_*` / `final_*` 样例。ACTION 脱敏、任意 URL 补证据、重复补充、旧 subject_ref、
  模型伪造 usage、正文截断、超时、预算耗尽均不产生 ALLOW。
- 客户端验证覆盖无工具定义、非流式 JSON、重试上限、并发预算竞争、未知用量、
  重定向/401/403/429/503、重复取消后 HTTP 线程仍占用并发槽、错误正文不读取。

使用与失败排查见 [使用指南](../V2_USER_GUIDE.md)，数据说明见
[fixtures README](../../tests/v2/fixtures/README.md)。云端连通性检查需显式 `-Live` 和
进程环境配置，只发送硬编码自造文本；它不代替 S1 真实 Guard 联调。

### 提请 A 落地/确认的公共变更

目前没有公共类型，以下是**待确认提案**。B 只使用临时字典与测试透传，不另建公共类或
JSON Schema。请 A 确认后统一实现，B 再对齐字典样例；不要为兼容当前 fixtures 保留两套模型。

| 编号 | 字段/依赖请求 | 原因、受影响数据与迁移 |
|---|---|---|
| A-REQ-01 | 提供 `contracts.py` 中 PolicyGenerationRequest/PolicyCandidate、ContextMaterial/ReviewRequest/ContextBuildResult、ReviewDecision/ReviewFailure/ReviewOutcome，以及 `ports.py` 的既定协议 | 正式入口目前明确报 ContractUnavailable；影响全部 fixtures。公共模型应拒绝额外字段/未知版本，并确定必填与显式 null，B 删除测试透传的联调用途 |
| A-REQ-02 | 确定 ContextMaterial：`current_object={ref,content}`、`evidence_blocks=[{ref,content}]`、`mandatory_facts={data_restrictions,unresolved_risks,lineage}`、`supplemental_history`、`available_evidence_refs`、`allowed_transform_ids`、`trusted_task/task_policy/host_constraints` | 共享文本尚未给这些容器的精确结构；影响正常/阻断/脱敏/故障组。A 确定命名和完整安全事实，B 同步所有 fixture 与 builder，不能缺字段默认无限制 |
| A-REQ-03 | 确认 `model_destination_id` + `authorized_model_destination_ids`；授权由 A 对**本次全部证据数据范围**计算。策略候选的 `model_destination_ids` 暂为字符串 ID 列表，范围由宿主目录登记 | B 在发送前拒绝未授权端点。影响全部请求及两组策略；若共享模型改为明确端点/范围记录，B 同步，不能仅因配置了 URL 就视为数据传输获准 |
| A-REQ-04 | EvidenceRef 暂用正整数 `version`、64 位小写十六进制 sha256、`span:[start,end]` 或 `json_pointer`，两个定位字段不同时使用；ACTION finding 的 `affected_action_field` 暂用参数对象 JSON pointer，其他阶段 null | 共享文档需固定这些具体语义。影响全部 refs；当前摘要是固定占位，不是正文哈希。请 A 用统一摘要实现建立对象并替换引用；B 只传回绑定值，不实现另一套哈希 |
| A-REQ-05 | 确认联合结果封套：ContextBuildResult `{schema_version,status,request,missing_evidence,reason_code}`；ReviewOutcome `{schema_version,status,decision,failure}`；ReviewFailure 暂含 `{schema_version,reason_code}` | 精确判别字段此前未定；影响所有 service 结果。READY/INCOMPLETE、DECIDED/FAILED 由 A 统一模型保证互斥，B 按最终类型同步 |
| A-REQ-06 | Usage 的 token 字段允许非负整数或字面量 `unavailable`；latency_ms 为非负数，attempts 为正整数。确认追加 MODEL_CONFIGURATION_ERROR / MODEL_UNAVAILABLE / MODEL_DESTINATION_DENIED 错误语义 | 缺用量不能作 0；供应商错误/授权失败不能冒充正常判定。影响错误/云端测试和 ReviewDecision；若 A 用 null + availability 字段表达，B 同步一种公共语义 |
| A-REQ-07 | 确认工具/目录字段：ToolManifest 的 effects/参数位置/幂等字段；resource_catalog 的 resource_scopes、destinations、model_destinations、allowed_uses；确认 confirmed_authorizations 和 trusted_evidence | 目前使用文件化内联样例，未宣称 A 已接受；影响两个策略请求。由 A 选定字段后统一替换，不在 B 加旧字段兼容层 |
| A-REQ-08 | 由 A 更新包发现、Python 3.12 基线及 Pydantic 2.x 依赖（兼容范围 `>=2,<3`，由 A 锁定测试版本）；包含 v2 各子包 | 目前 pyproject 仍只打包 agentguard 根包、Python>=3.10。B 使用 `.model_validate/.model_dump`；仅源树离线测试通过，不等于 wheel 安装通过。B 的 HTTP 客户端仅用标准库，无新增供应商 SDK 依赖 |
| A-REQ-09 | `mask_text_span` / `replace_json_string` 变换登记、ReviewDecision 再校验、补证据次数的持久绑定及默认失败保持隔离 | 变换 ID 是示例；B 不实现变换/释放。A 实现时验证对象/字段/权限，保留文档级标签，并保证进程重启不能多次补证据 |

确认/迁移应由 A 更新唯一共享模型与共享文档；如果改变既有契约语义则按约定升版本，
同次集成更新 fixtures、提示和测试。公共测试在模块出现后自动执行，字段不匹配会失败，
不会因存在一个同名模块就视为对齐完成。

### 下一步

1. A01 提供公共模型/Protocol，按上表确认字段；B 切换真实模型解析，完成 S0 解析一致性。
2. A02/A03 接入 PolicyCompiler 与 GuardService，真实隔离链路跑正常/注入两个样本，核对失败不释放。
3. 显式配置可信云端与额度后记录真实模型版本、提示版本、用量和结果；当前仍保留未运行状态。
4. S2 再继续完整 ACTION/FINAL、关系上下文与宿主适配；本轮没有越界开始 UI 美化。
