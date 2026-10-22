# AgentGuard v2 双人共享接口约定

日期：2026-10-21；集成及功能补齐：2026-10-22；契约版本：`0.1`。公共类型在 `agentguard/v2/contracts.py`，Schema 在 `agentguard/v2/schemas/`。本轮新增为兼容的可选元数据和宿主专用接口；精确字段以代码为准。功能状态见 [补齐记录](../v2/FEATURE_COMPLETION.md)，历史核查见 [集成验收报告](../v2/INTEGRATION_REVIEW_2026-10-22.md)。

合并前 A/B 各自使用了不兼容的 0.1 草案；本次统一为一套公共类型，旧 B 临时字典不再是可接受的生产输入，不维护双格式兼容层。具体冻结项：

- 所有嵌套公共对象也带 `schema_version`；EvidenceRef 的 `span`、`json_pointer` 显式为 null 或有效位置，JSON 数组在统一 JSON 解析边界转为 tuple。
- PolicyGenerationRequest 使用 `current_policy_version`；候选仍用 `base_policy_version`。初始策略生成早于任务对象登记，因此初始候选 `evidence_refs=[]`，不得编造尚不存在的任务对象引用。
- 模型授权为 `ModelDestinationGrant(destination_id, resource_scope_ids)`，保留端点对应的数据范围。ResourceCatalog 使用 `resources` 和 `destinations`，模型端点也是目的地的一种。
- ContextMaterial 使用 `subject/subject_ref`、`evidence`、`policy`、`host_policy`、`lineage`、`recent_events`；授权变换和可补证据由 Runtime 填入 `allowed_transform_ids`、`available_evidence_refs`。B 不自行生成授权。
- ReviewRequest 额外包含 `selected_evidence_refs`、`retained_mandatory_facts`、`budget_used`。budget_used 是实际提示的 UTF-8 序列化字节数，不是 token 数；all/recent/relations 均保留完整当前对象及安全事实。
- Usage 缺失用量用 null；供应商客户端内部的 unavailable 在边界统一转换。ReviewFailure 带 `usage: null` 或实测元数据，并支持配置错误、供应商不可用、模型目的地拒绝三个独立原因码。
- Runtime 每次审查最多补证据一次，`supplemental_attempt` 随材料传递并记录审查事件；Guard 不执行证据读取。
- 新增 HostInputRequest：可信宿主登记静态系统材料/有限状态反馈；HTTP 路径 `/host-inputs`，UI 无写入权限。ModelOutputRequest 可带实际 Usage；SessionRequest.synthetic_demo 默认为 false。CallResult/FinalizedOutput 可携带经验证的 risk_refs 驱动真实宿主恢复，原文仍不随未释放结果返回。
- ACTION 的隔离主体是 `{tool_id, manifest_version, args}`。affected_action_field 是 args 内指针，例如 `/destination`；EvidenceRef 对完整隔离对象定位，例如 `/args/destination`，两者不混用。
- 实际请求私有审计区记录选中证据、提示版本、缓存命中和 submitted 状态；submitted=null 表示取消等情况下传输状态未知，不能记成未调用。

关联：[总任务书](../V2_TWO_PERSON_PLAN.md)｜[A 任务书](V2_A_RUNTIME.md)｜[B 任务书](V2_B_GUARD.md)。安全与架构底线以 [实施计划](../V2_IMPLEMENTATION_PLAN.md) 为准。

## 1. 先理解双方交换什么

A 给 B 的是“本次要检查的内容，以及它所处的任务、权限、来源和历史证据”。B 给 A 的是“语义判断、理由和具体证据位置”。A 再按程序约束决定是否执行或释放。

因此，B 不是直接返回一个改好的工具结果给主 Agent，也不是返回一段让 A 随意执行的代码。所有实际工具调用、权限版本提交、隔离对象读取、脱敏执行和释放都由 A 控制。

## 2. 公共类型与依赖方向

公共类型放 `agentguard/v2/contracts.py`，公共协议放 `ports.py`，由 A 维护。使用 Python 3.12、Pydantic 类型和可序列化 JSON；B 的模块只依赖公共契约，不导入 A 的 SQLite 实现、执行器或网关。

依赖注入由 A 的 `bootstrap.py` 完成。无论使用真模型还是模拟模型，都必须实现同一个协议。

```python
# 接口形状示意；具体字段见下面各节，不是本轮新增的运行代码。
class PolicyGenerator(Protocol):                 # B 实现
    async def generate(self, req: PolicyGenerationRequest) -> PolicyCandidate: ...

class ContextBuilder(Protocol):                  # B 实现
    def build(self, material: ContextMaterial) -> ContextBuildResult: ...

class Reviewer(Protocol):                        # B 实现
    async def review(self, req: ReviewRequest) -> ReviewDecision: ...

class GuardService(Protocol):                    # B 组合前两个组件
    async def inspect(self, material: ContextMaterial) -> ReviewOutcome: ...

class RuntimePort(Protocol):                    # A 实现，B 宿主调用
    async def create_session(self, req: SessionRequest) -> SessionView: ...
    async def prepare_model_turn(self, req: PrepareTurnRequest) -> PreparedTurn: ...
    async def record_model_output(self, req: ModelOutputRequest) -> ProposedTurn: ...
    async def execute_batch(self, req: BatchRequest) -> BatchResult: ...
    async def finalize(self, req: FinalizeRequest) -> FinalizedOutput: ...
    async def prepare_recovery(self, req: RecoveryRequest) -> RecoveryPlan: ...
    async def complete_recovery(self, req: RecoveryAck) -> SessionView: ...
```

`ContextBuilder` 是纯函数，不执行工具、不发网络请求、不改状态。`GuardService` 只通过已配置的可信模型客户端推理，不向模型暴露工具列表。公共 Protocol 使用异步接口；同步 SDK 包装由 A 负责。

## 3. 通用约定

| 项目 | 统一约定 |
|---|---|
| 版本 | 传输对象都有 `schema_version: "0.1"`；不认识的版本拒绝处理 |
| ID | Runtime 分配不透明字符串 ID；测试用固定 ID。B 不把数组下标或时间戳当 call_id |
| 关联 | 审查和调用必须带 session_id、turn_id、review_id；工具审查还必须带 call_id，最终输出的 call_id 为 null |
| 时间 | 持久化与 HTTP 都使用带时区的 UTC 时间；TTL 由 A 的执行端判断 |
| 空值 | optional 字段可以明确为 null；必填缺失不能被补成“无风险/无限制” |
| JSON | 参数只接受已校验的 JSON 类型；拒绝 NaN、无穷大、重复键和不受支持对象 |
| 摘要值 | 对象内容及参数的摘要由 A 的统一实现生成；B 只原样传回绑定值，不自行实现另一套哈希规则 |
| 日志 | 普通日志记录 ID、状态、原因码和用量，不默认写原文、提示全文、密钥或完整参数 |
| 秘密 | API key 从本地配置/环境注入模型客户端；不进入任务策略、Guard 输入、fixtures 或版本库 |

审批语义、执行语义和交付语义分开记录。例如“动作已允许”不等于“工具已成功”，“工具已成功”不等于“结果已交给 Agent”。

## 4. 任务策略接口

`PolicyGenerationRequest` 包含：真实用户任务 `trusted_task`、宿主权限上限 `host_policy`、宿主确认的工具清单 `tool_manifests`、资源目录 `resource_catalog`、已确认的用户授权、当前策略版本（初次为 null）。工具返回的自然语言不能改写这些字段的信任来源。

B 返回的 `PolicyCandidate` 只是一份候选：

- `schema_version`、`session_id`、`base_policy_version`。
- `rules[]`：有限的 `tool_id`、`effect`、`resource_scope_ids`、`destination_ids`、`allowed_uses`、`max_calls`；没有允许规则即没有对应权限。
- `model_destination_ids`：哪些可信模型端点可处理哪些已有数据范围。
- `rationale`、`evidence_refs`、`unresolved_requirements`：供校验和解释使用，不能自行授予权限。

效果枚举首版为 `READ / WRITE / SEND / DELETE`；资源范围和接收端必须引用 A 的宿主目录中已经登记的 ID。路径前缀、域名/端口、允许用途和限额由 A 的目录与引擎解释，B 不生成任意表达式、代码、正则或数据库查询。

A 校验类型、未知引用、宿主上限、配额和变更关系后才创建 `TaskPolicy`，生成 `policy_version`。允许自动收紧；无法证明是收紧的变化按扩张或未知处理，不能直接应用。候选中的说明文字不影响执行器。

首批策略测试必须提前写人工预期矩阵：任务一“只生成本地报告”不含 SEND；任务二“向已指定测试端发送报告”只允许对应目的地。模型产出的策略不能反过来充当自己的标准答案。

## 5. 执行与数据对象

| 类型 | 必需内容 | 谁能写、谁使用 |
|---|---|---|
| `ToolManifest` | tool_id、manifest_version、参数 Schema、效果、资源/目的地参数位置、返回类型、是否支持幂等键 | A 从宿主配置登记；B 读取。远程描述和 MCP 注解只作待核验信息 |
| `ToolCall` | session_id、turn_id、call_id、tool_id、manifest_version、args、input_context_version、artifact_refs | B 宿主提交提议，A 校验并冻结参数 |
| `ArtifactVersion` | artifact_id、version、sha256、media_type、来源 call_id、保密标签、完整性标签、存储引用 | A 创建不可变内容版本；隔离/释放状态单独记账 |
| `ArtifactRef` | artifact_id、version、会话绑定、允许用途/工具/目的地、引用有效期 | A 颁发和解析；B 只能在对应用途使用，不是全局解密占位符 |
| `ContextSnapshot` | context_version、实际模型输入的消息/对象引用、policy_version、相关安全修订号、未决风险、模型目的地 | A 根据 B 宿主提交的实际输入记录；下一轮只能使用获准材料 |
| `LineageEdge` | source_ref、target_ref、kind=`exact` 或 `possible`、建立它的事件 ID | A 记录事实；B 组织证据与展示，不把可能关系画成精确证明 |

`exact` 只用于程序可确认的复制、拼接等关系；一次模型调用的全部输入到全部输出采用 `possible` 依赖。摘要不会自动清除保密限制。

批次内每个调用独立隔离、审查和记录。`BatchResult` 按 call_id 返回 `RELEASED / BLOCKED / REVIEW_PENDING / FAILED_KNOWN / UNKNOWN` 以及允许交付的内容或引用；失败项不能带隔离原文。只有下一轮输入材料确定后才创建新的 ContextSnapshot，不能把完成先后当成因果关系。

## 6. Guard 的上下文：哪些必须保留，哪些可以压缩

A 生成 `ContextMaterial`，B 的 ContextBuilder 将它转成 `ReviewRequest`。二者包含统一关联 ID，以及：

| 内容 | A 提供什么 | B 可以做什么 |
|---|---|---|
| 可信任务和边界 | 原任务、当前策略、宿主约束、版本绑定 | 保留；不能被历史摘要改写 |
| 本次对象 | ACTION 的完整参数、RESULT 的本次隔离内容、FINAL 的拟输出内容 | 原样审查或按明确分块方案全部覆盖；不能只看标题 |
| 必保留的安全事实 | 来源标签、用途限制、未决风险、当前动作涉及的祖先关系 | 全部保留；超预算就返回缺少上下文，不能静默裁掉 |
| 相关证据 | A 按资源/来源关系取出的不可变证据块、引用与关系边 | 按与当前动作的关系排序，选择正文，保留引用 |
| 补充历史 | 有界的近期事件及已有带引用摘要 | 可裁剪/摘要；不能覆盖上面三项 |

每个证据块有 `EvidenceRef`：`artifact_id`、`version`、`sha256`，以及可选 `json_pointer` 或 `span`。文本 span 统一为 **Python Unicode 码点、左闭右开 `[start, end)`**，不是 UTF-8 字节数，也不是浏览器 UTF-16 下标。前端只显示服务端确定的位置，不重新计算裁剪。

当前工具参数和可信任务也先由 A 登记为有版本的证据对象，避免 B 引用“刚才那个参数”这类无法核验的位置。

`ContextBuildResult` 是 `READY(ReviewRequest)` 或 `INCOMPLETE(missing_evidence, reason_code)`。ReviewRequest 记录实际选中的 evidence_refs、必保留项及预算使用情况，便于比较全历史、最近 N 条和关系证据方案。

本次材料过大且首版没有完整分块审查时，返回 `CONTENT_TOO_LARGE` 并保持隔离。不得先截断再给整体 ALLOW。后续分块必须覆盖所有分块，并有跨块风险处理，不能仅逐块检测后假定整体安全。

## 7. Guard 输出：只提出有边界的处理决定

`ReviewDecision` 必需字段：

```text
schema_version, review_id, session_id, turn_id, call_id, phase
policy_version, context_version, subject_ref
decision: ALLOW | BLOCK | REDACT | NEEDS_CONTEXT
reason_code, reason_summary
evidence_refs[]
findings[]: finding_type, affected_action_field, evidence_refs
redaction_targets[]: evidence_ref, transform_id
requested_evidence_refs[]
usage: provider, model, input_tokens, output_tokens, latency_ms, attempts
```

`phase` 为 `ACTION / RESULT / FINAL`。`subject_ref` 必须是当前被审查对象的原版本；所有绑定值必须与请求一致。`usage` 由 B 的客户端根据真实供应商响应与本地计时补入，不采信模型生成文本中的费用或用量。供应商不提供的用量标记 unavailable，不能当作 0 成本。

- **ALLOW：**A 仍执行已知权限、标签、用途和版本检查；允许只针对本次对象。
- **BLOCK：**A 拦截本次请求或内容，返回不含敏感原文的原因码。
- **REDACT：**首版仅用于 RESULT/FINAL；B 提供位置和预登记的变换 ID。A 确认引用、变换权限后生成新版本，再校验释放条件。ACTION 不自动改参数，主 Agent 必须重新提出请求并重新审查。
- **NEEDS_CONTEXT：**B 指出缺少的既有证据引用；A 只按本次会话和权限查找。最多补充一次，仍不足则保持阻断/隔离。模型不能要求程序去任意 URL、文件或工具“寻找证据”。

有实际判定时至少引用本次对象；finding 和 redaction 必须精确到可核验位置。A 检查 ID、版本、范围与字段存在性，但引用真实并不证明 B 的语义判断一定正确。

脱敏首版采用有限确定性变换，如遮盖文本片段、替换指定 JSON 字符串字段。标签收紧可接受；标签放宽仅限宿主预先批准且程序能验证的字段级变换。整份文档的保密标签不能因删掉一个字段而消失。自由改写/模型摘要不作为自动降密机制。

`ReviewOutcome` 为 `DECIDED(ReviewDecision)` 或 `FAILED(ReviewFailure)`。后者原因码包括 `MODEL_TIMEOUT / INVALID_SCHEMA / INVALID_REFERENCE / CONTENT_TOO_LARGE / BUDGET_EXHAUSTED / MISSING_EVIDENCE`。A 检出的无效判定同样按失败处理；调用方无法用异常兜底返回原文。

## 8. 单次许可：A 独立负责，B 不直接操作

Permit 至少绑定：session_id、turn_id、call_id、tool_manifest_version、args_digest、artifact_versions、policy_version、context_version、relevant_security_revision、expires_at。

状态为 `PROPOSED → REVIEWED → APPROVED → CLAIMED → SUCCEEDED / FAILED_KNOWN / UNKNOWN`；未领取时可以 REVOKED/EXPIRED。参数、资源内容或安全状态变化导致旧许可不能执行。

检查绑定/撤销/时限与 `APPROVED → CLAIMED` 必须在同一数据库事务中完成；同时对 `(session_id, call_id)` 施加执行唯一性，避免同一调用重试拿到多个许可后重复执行。

领取是授权提交点；已经启动的工具不承诺能撤回。外发后异常或在记录收据前崩溃时，标 UNKNOWN，不自动重复非幂等动作。Receipt 记录实际状态和效果证据，不用 Guard 的解释代替工具事实。

## 9. B 的宿主必须怎样接入

1. `create_session`：传入用户任务与宿主确认的配置；Runtime 请求候选策略并验证后建立任务。
2. `prepare_model_turn`：B 提交拟使用的已释放消息/引用和模型目的地，A 记录实际输入快照并返回 PreparedTurn。B 只把这一版输入交给主模型，不能再偷偷拼接原始工具回调。
3. `record_model_output`：B 把完整模型结果与 model_call_id/context_version 绑定。Runtime 登记模型输出及可能依赖，返回工具提议或最终输出提议。
4. `execute_batch`：B 把工具提议提交给 A，A 返回已审查结果。B 不持有工具后端的执行凭据，不走原框架的自动直调路径。
5. `finalize`：B 提交最终输出提议，由 A 审查和释放后才显示给用户。内部可以缓冲模型流，不能先显示后补审查。

模型在主 Agent 一侧的思考文本不是安全判定的必要前提；以可观察的输入、输出、工具提议与真实执行事实为准，不要求取得隐藏思维链。

SDK 模式依赖可信宿主遵守钩子；网关只有在后端凭据与访问路径受控时才能阻止绕过。MCP 工具代理本身看不到完整主模型上下文和最终答复，所以仍须上述宿主钩子。首版不覆盖的协议功能拒绝或明确关闭，不能透明转发后宣称已保护。

## 10. 恢复接口：A 算影响，B 清理宿主状态

A 的 `RecoveryPlan` 包含 recovery_id、affected_refs、revoked_permit_ids、safe_context_version、允许重建的消息/对象引用、必须重置的宿主状态种类、不可撤回副作用及 UNKNOWN 动作。

B 根据计划重建本地消息，丢弃旧云端 conversation/continuation ID，清理受影响的框架 checkpoint、记忆、分析缓存和会被自动读取的工作产物。B 返回 `RecoveryAck`：recovery_id、new_host_context_id、逐项完成状态和未支持项。

A 收到并校验对应 Ack 后才恢复运行；缺失必需钩子的适配器停在受限状态，不显示“已完整恢复”。宿主 Ack 是可信集成约定，不是程序对任意恶意宿主的证明。

## 11. HTTP 与控制台查询

HTTP 请求/响应复用公共 JSON 类型，不另建一套字段名。A 在 S0 提供离线 Schema，S3 提供实际服务；B 根据相同 fixtures 开发。

计划的宿主接口：

```text
POST /v2/sessions
POST /v2/sessions/{id}/model-turns/prepare
POST /v2/sessions/{id}/model-outputs
POST /v2/sessions/{id}/batches
POST /v2/sessions/{id}/finalize
POST /v2/sessions/{id}/recovery-plans
POST /v2/sessions/{id}/recovery-acks
```

计划的只读控制台接口：

```text
GET /v2/sessions/{id}
GET /v2/sessions/{id}/events?after_seq=0&limit=100
GET /v2/sessions/{id}/policy
GET /v2/sessions/{id}/graph
GET /v2/sessions/{id}/reviews/{review_id}
GET /v2/sessions/{id}/metrics
GET /v2/sessions/{id}/artifacts/{artifact_id}/versions/{version}/comparison
```

事件包含 event_id、session_id、seq、timestamp、event_type、turn_id/call_id/review_id、policy/context_version 和脱敏 payload。seq 用于分页与稳定排序，不代表并发事件之间存在因果依赖。

控制台不能直接读 SQLite 或隔离目录；实际 Guard 输入视图、内容对比和错误信息默认脱敏。只有宿主显式标记的 synthetic demo 对象才可在演示模式看原文。开发默认本机绑定，宿主写权限与 UI 查询权限分开配置。

业务 BLOCK/UNKNOWN 作为有类型的响应返回，不能混同 HTTP 500；格式错用 422、关联/版本冲突用 409、未认证/无权限用 401/403、暂不可用用 503。重试不能绕过 call_id 执行唯一性。

## 12. 共用 fixtures 与首次验收

B 在 `tests/v2/fixtures/` 维护以下文件组。A01/B01 可先在各自测试中用最小内联对象，随后统一为这些 fixtures；不能因此等待对方完整实现。

| 组名 | 主要内容 | 双方要验证的结果 |
|---|---|---|
| `policy_local_vs_send/` | 相同工具、两个任务、人工预期权限 | 候选随任务变；越界候选不提交 |
| `normal_allow/` | 正常文档、当前对象引用、合法 ALLOW | 内容只在审查后释放 |
| `injection_block/` | 假资料中的越权指令、合法 BLOCK | 原文不进入主 Agent |
| `field_redact/` | 字段级假秘密、预批准变换、REDACT | 定位准确，新版本可追踪，文档级限制不误清除 |
| `guard_failure/` | 超时、畸形 JSON、越界引用、旧版本判定 | 保持隔离，状态/错误码可见 |
| `batch_20/` | 20 个调用、乱序/重复回调、一份攻击 | call_id 正确关联，正常项可交付 |
| `long_task/` | 10/30/60 步，早读受限内容后摘要发送 | 上下文压缩不丢限制，独立接收器无越权数据 |
| `permit_faults/` | 参数替换、两个许可同一调用、执行后异常 | 拒绝旧许可，最多一次调度，UNKNOWN 不盲重试 |
| `recovery/` | 早期风险晚发现、云端续接状态、受影响记忆 | 计划/Ack 配对，旧状态不自动重入 |

S0 首先交付前五组的最小样本；其他组随 S2/S3 补齐。每组附 `expected.json`，由人工规则和工具真实效果定义预期，不由待测 Guard 给自己打分。

首次契约验收：双方解析相同 fixture；B 输出能被 A 校验；B 传错版本/会话/引用时 A 拒绝；Guard 异常时无原文释放。真实模型判别质量另行评测，不能用这组格式测试代替。
