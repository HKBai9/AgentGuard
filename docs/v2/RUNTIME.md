# AgentGuard v2 A 运行时交付说明

契约 `0.1`，发行包 `2.0.0a1`，Python **3.12**。代码位于本仓库 `agentguard/v2/`。
旧版 SDK 实现保留，旧实验和 UI 不代表 v2 效果。源码仓库外的同名草稿目录不参与构建。

本交付实现 A01–A08 的 A 侧组件与离线程序约束验收。真实 B 的 compiler、GuardService、宿主、框架钩子、UI、模型评测不在当前 checkout 中，不能把测试替身的通过写成真实 A/B 联调通过。`tests/v2/integration/test_optional_b.py` 对缺失 B 明确报告 **SKIPPED**；没有请求付费 API。引用的 `V2_TWO_PERSON_PLAN.md`、`V2_B_GUARD.md` 未提供，嵌套分工按现有 A 任务书和共享契约执行，未创建 B 的实现文件。

## 安装与验收

在仓库根目录执行，使用独立 Python 3.12 环境：

```bash
python -m venv .venv-v2
# Linux: source .venv-v2/bin/activate
# PowerShell: .venv-v2\Scripts\Activate.ps1
python -m pip install -r requirements-v2.lock.txt
python -m pip install --no-deps -e .
python -m pytest tests/v2/contracts tests/v2/runtime -q
python -m pytest tests/v2/integration -q
python tools/v2/verify_runtime.py
```

Windows 计划入口：

```powershell
powershell -NoProfile -File tools/v2/verify_runtime.ps1 -Python .venv-v2\Scripts\python.exe
```

PowerShell 7 可用 `pwsh -NoProfile -File ...`。脚本以非零退出码报告失败；输出 JSON、JUnit 和各步骤日志，默认位于工作区 `ai/artifacts/v2/`，可用 `-Output` 或 `--output` 更改。验收包括旧版回归、契约/运行时、集成、wheel 构建、在源码目录外安装和执行。`--skip-install` 明确标记未验证安装。安装冒烟使用干净的包目标目录和当前已锁定依赖；全新虚拟环境安装另见交付工作日志。

`requirements.lock.txt` 是旧版演示依赖；`requirements-v2.lock.txt` 是本次 Python 3.12 实测锁定环境，含官方 `mcp==1.28.1`。包发现仅包含 `agentguard` 及其子包；Schema 作为包内资源。构建依赖也已锁定。公共导入不会加载云端密钥、打开数据库或启动服务。

```python
from agentguard.v2.contracts import ToolCall, ReviewDecision, Permit, make
from agentguard.v2.ports import RuntimePort, PolicyGenerator, GuardService
from agentguard.v2.common import canonical, frozen_copy, strict_loads
from agentguard.v2.schema import load
schema = load("ReviewDecision")
```

`make(Type, ...)` 是 Python 侧显式补上 `schema_version="0.1"` 的构造助手；网络输入版本和所有必填安全字段仍必须存在。JSON 文本用 `Type.model_validate_json(...)`，已解码 JSON 用 `frozen_copy(Type, value)`，Python 对象用严格的 `model_validate`。JSON 时间字符串不能直接当 Python datetime 对象传入严格校验。拒绝多余字段、未知枚举/版本、NaN/Infinity、重复键、非 JSON 对象；跨字段关系和真实引用存在性还由运行时检查，不能只靠 JSON Schema 代替。

## 组装与宿主顺序

```python
from agentguard.v2.bootstrap import build_runtime
from agentguard.v2.registry import ToolRegistry

registry = ToolRegistry()
registry.register(host_confirmed_manifest, trusted_backend_handler)
runtime = build_runtime(
    private_state_directory,
    policy_generator=your_b_policy_generator,
    guard_service=your_b_guard_service,
    registry=registry,
    transforms=host_approved_transforms,
)
```

无默认允许策略/Reviewer。缺少服务会失败；测试替身只存在于 `tests/v2/conftest.py` 和明确标记的安装/演示入口，生产模块不导入测试模块。B 只实现公共 `ports.py`，无需导入 SQLite、执行器或隔离文件实现。

宿主遵循共享契约七个异步方法：

1. `create_session(SessionRequest)`：请求中清单必须与注册表完全一致；生成候选并验证宿主上限后提交版本。
2. `prepare_model_turn(PrepareTurnRequest)`：只能提交已释放的完整 EvidenceRef。返回 `PreparedTurn.messages` 才是实际模型输入，不得再补入原始回调。系统角色只接受 host 来源材料。
3. `record_model_output(ModelOutputRequest)`：绑定服务器分配的 model_call/context；持久化完整输出及工具提议，生成 call_id。相同输出可重放，修改后的相同 model_call_id 被拒绝。
4. `execute_batch(BatchRequest)`：仅执行 Runtime 已登记的提议，返回按 call_id 索引的独立结果。未领取的业务拒绝可重新审查，已经领取的调用绝不重新调度。
5. `finalize(FinalizeRequest)`：拟输出必须对应已登记的模型输出。只有 `RELEASED` 内容能显示；主模型流先缓冲。
6. `prepare_recovery(RecoveryRequest)`：按 exact/possible 依赖计算影响、冻结会话、撤销待领取许可、保留独立材料。
7. `complete_recovery(RecoveryAck)`：要求 messages、cloud_conversation、framework_checkpoints、memory、analysis_cache、work_products 全部确认重置；缺失/错误/不支持项保持 RECOVERING，实际 Ack 尝试留档。

宿主可信附件可用 `runtime.ingest(...)` 显式登记内容、标签和资源范围；这不是 UI 或模型权限。`runtime.apply_policy(candidate)` 支持可证明的收紧与版本留档；扩张必须重新取得宿主授权，当前没有自动扩张接口。

## 明确的契约补充

共享文档未穷举字段，A 将以下有限表示固定为 `0.1`：

- `ResourceCatalog` 明确 `ResourceScope` 与 `Destination`；模型许可使用 `ModelDestinationGrant(destination_id, resource_scope_ids)`，不能把模型目的地理解成可接收所有资料。
- `DataLabels` 分文档限制与 `field_restrictions`。限制中的 **null 表示该维度没有附加限制，空列表表示全部禁止**；不能省略必填字段。机密级别使用集合，接收端 `allowed_confidentiality` 必须覆盖全部标签。
- 用途是宿主有限规则里的字符串。`model` 用于主模型，`review` 用于 Guard，最终用途由 `HostPolicy.final_use` 配置。每次工具提议明确 `use`；Guard 和主模型都必须有对应资源/目的地许可。
- `ToolManifest.resource_parameter` / `destination_parameter` / `artifact_parameters` 使用 JSON Pointer；首版参数位置仅支持一层字段，例如 `/body`。参数 Schema 仅允许本地引用；不会联网解析 `$ref`。
- `ArtifactRef` 增加服务端 `ref_id`，内容由注册的 `artifact_parameters` 指定位置兑换；参数值必须是 ref_id，不能在任意文本中插值。会话、版本、过期、工具、用途、目的地、释放状态与内容摘要全部检查。底层 `Artifacts.issue_ref` 是可信宿主管理能力，不向 UI/MCP 开放。
- `Message` 使用角色 + 完整 `EvidenceRef`。有损摘要、删掉历史消息不清除已进入模型上下文的限制；模型输出按所有实际/持续暴露输入建立 `possible` 边。
- 文本 span 是 Python Unicode 码点半开区间；JSON Pointer 校验实际字段存在。REDACT 只允许 RESULT/FINAL。`TransformSpec` 只注册遮盖区间或 JSON 字符串字段；只有预批准字段变换能移除该字段限制，文档限制和派生摘要限制不会清除。
- `Receipt.effect_evidence.dispatched` 记录调度事实；成功/失败/UNKNOWN 取自执行结果，不能用 Guard 理由当成已发送证明。测试通过独立接收器记录验证真实发送次数。
- `RecoveryPlan.irreversible_final_refs` 记录曾向用户释放的最终输出；即使后来撤销其内部引用，也不声称用户已收到的文字被收回。计划中的 `IN_FLIGHT_AT_RECOVERY` 是生成计划时的执行中快照，后续实际收据以执行事件为准。
- Review 原始材料与返回值保存为不可变隔离审计对象。普通查询提供 ID、证据位置、有限原因码和数值用量，不返回提示正文、reason_summary、模型提供的自由字符串或原始错误。未知 Guard 原因码映射为 `GUARD_DECISION`，原值仍在私有审计对象中。用量缺失保持 null。

合法/非法例子位于 [`examples/`](examples/)：本地与外发权限矩阵、正常允许、阻断、字段脱敏、伪造引用/未知版本。它们是 **A 的合成接口样例**，不占用 B 维护的 `tests/v2/fixtures/`，也不是模型效果数据。可用 `python tools/v2/export_handoff.py` 重建。

## 执行、状态和故障

SQLite 使用 WAL、FULL 同步与 `BEGIN IMMEDIATE` 事务；许可绑定 call/session/turn、清单、参数摘要、不可变输入对象、策略、上下文、安全修订与 TTL。领取事务内重新检查并插入 `(session_id, call_id)` 唯一 claim、预留配额、占用共享写资源。重叠目录也互斥。模型和工具调用在事务外等待。

`CLAIMED` 是授权提交点；取消、执行异常、进程消失后的未知效果不会自动重试，即便清单声明支持幂等键。适配器只有能保证没有已提交效果时才可抛 `KnownToolFailure`。普通异常、MCP 错误及未覆盖返回类型按 UNKNOWN 处理，错误正文也入隔离库。正文、stderr、结构化结果共同审查，未审查值不能直接返回。

服务异常退出后，宿主必须先确认对状态目录拥有排他的 worker 所有权，再调用 `runtime.permits.recover_abandoned()` 将残留 CLAIMED 标为 UNKNOWN。不能在另一个活跃 worker 仍执行时调用。UNKNOWN 写入的资源锁保留；需要先独立核验真实后端效果再进行受控运维处理，当前没有自动清锁/重发接口。

批次等待点阻止在工具仍执行时创建下一模型轮。20 项乱序完成逐项关联，单项阻断不污染独立结果。恢复会撤销全部旧上下文待领取许可；已释放的独立内容可以作为新提议继续。已经启动的工具不承诺撤回，已发送/已写入及 UNKNOWN 收据在恢复计划和查询中保持可见。宿主 Ack 是可信集成协议，不是对恶意宿主的证明。

常用稳定失败码：

| 类型 | 原因码示例 | 调用方行为 |
|---|---|---|
| 策略 | `HOST_POLICY_EXCEEDED`, `UNKNOWN_RESOURCE`, `POLICY_EXPANSION_REQUIRES_AUTHORIZATION` | 修正宿主许可或候选，不靠重试扩权 |
| 调用关联 | `CALL_BINDING_MISMATCH`, `STALE_CONTEXT`, `TOOL_VERSION_CHANGED` | 新上下文重新提议 |
| 数据 | `DATA_USE_DENIED`, `DATA_DESTINATION_DENIED`, `CONFIDENTIALITY_DENIED`, `MODEL_RESOURCE_DENIED` | 不交付；需要明确授权或批准的变换 |
| 许可 | `PERMIT_NOT_APPROVED`, `PERMIT_EXPIRED`, `CALL_ALREADY_CLAIMED`, `QUOTA_EXHAUSTED`, `RESOURCE_BUSY` | 不重复执行；BUSY 可等待后重审未领取调用 |
| Guard | `MODEL_TIMEOUT`, `INVALID_SCHEMA`, `INVALID_REFERENCE`, `CONTENT_TOO_LARGE`, `MISSING_EVIDENCE`, `BUDGET_EXHAUSTED` | 保持隔离；补证最多一次 |
| 执行 | `TOOL_SUCCEEDED`, `TOOL_FAILED_BEFORE_EFFECT`, `TOOL_OUTCOME_UNKNOWN`, `WORKER_LOST_AFTER_CLAIM` | 分开展示执行与交付状态 |
| 恢复 | `SESSION_NOT_ACTIVE`, `RECOVERY_BINDING_MISMATCH`, `RECOVERY_ACK_INCOMPLETE` | 完成真实重置后再 Ack |

程序拒绝、UNKNOWN 是有类型的业务结果。HTTP 格式错 422、版本/关联冲突 409、无认证 401、权限不足 403、临时服务故障 503；不存在的资源 404。

## SDK、HTTP、MCP

`PythonSDK.register` 保留签名绑定，禁止无法明确绑定的可变/仅位置参数；`wrap`/`wrap_sync` 接收已经登记的 ToolCall，并校验参数完全一致。重试复用原 call_id；返回 CallResult，不能把未审查的 Python 原值交给主 Agent。事件循环内使用异步包装。

HTTP 正式启动需要宿主自有工厂，凭据从环境注入：

```bash
export AGENTGUARD_HOST_TOKEN='a-host-token-from-your-secret-store'
export AGENTGUARD_UI_TOKEN='a-different-readonly-token'
python -m agentguard.v2.gateway.cli --factory your_package.composition:build_runtime --host 127.0.0.1 --port 8765
```

`create_app(runtime, host_token=..., ui_token=...)` 实现共享契约的全部 7 个 POST 与 7 个 GET 接口；凭据必须不同。`GET /v2/openapi.json` 需认证。UI 不能获得隔离原文，即使查询对象是合成样本；首版不提供原文演示开关。只读策略省略自由说明，内容对比返回版本、摘要、释放状态和遮盖占位。

明确的离线联调服务（虚构四类后端 + FakeReviewer，无真实模型）：

```bash
export AGENTGUARD_OFFLINE_DEMO=1
export AGENTGUARD_DEMO_STATE=/absolute/private/demo-state
# 同样设置上面的两个不同 token
python -m agentguard.v2.gateway.cli --factory tools.v2.demo_gateway:build_demo_runtime
```

从 checkout 启动，配置请求见 `examples/policy_local_vs_send/send_request.json`。该工厂必须显式启用，不能用作生产默认配置。

MCP 使用 [官方 Python SDK](https://github.com/modelcontextprotocol/python-sdk)，锁定 `1.28.1`，提供 `create_mcp_server(runtime, session_id=...)` 与可信后端 `MCPToolBackend(client_session, remote_tool_name)`。服务只暴露 `tools/list` 和 `agentguard.execute_batch` 工具；会话由可信宿主绑定，传入完整 BatchRequest。原始后端描述不会注册新权限。客户端/backend 的认证和连接由宿主配置。普通文本块与结构化返回全部隔离；资源、图片、音频等未覆盖返回拒绝，错误正文保留私有审计。

MCP 不提供 resources/prompts/sampling/elicitation/tasks/subscriptions 等透明转发。测试用官方 SDK 的双向内存传输实际经过初始化、列工具、调用、错误处理；资源请求得到协议拒绝。MCP 代理看不到主模型的全部历史和最终答案，因此仍需七个 RuntimePort 宿主钩子。

网关只有在后端凭据、文件和网络访问路径受控时才构成强制边界。当前 SDK/网关不提供 OS 容器沙箱、DNS 固定、对抗恶意宿主任意代码、任意文件路径 TOCTOU 消除或任意后端副作用撤回。共享写锁只覆盖通过本 Runtime 的动作；真实文件/网络后端应在受控 worker 内实施路径/重定向/网络限制。直接发送可变文件路径被拒绝，需使用批准的不可变 ArtifactRef。工具后端也必须避免自行将原文写入不受控日志、回调或外部通道。

## 与 B 接续验收

`tests/v2/integration/test_optional_b.py` 接受显式 `AGENTGUARD_B_INTEGRATION_FACTORY=module:function`，工厂返回 `(runtime, SessionRequest, ToolProposal[])`。正式调用前由宿主配置真实 B 组件、模型端点与预算；默认总验收脚本清除此环境变量以保证离线。

真实 B 尚缺时，当前能验证的是协议互通、确定性权限/数据边界、故障与并发安全，不是注入识别准确率、API 成本、比赛五场景完成率或 UI 恢复效果。B 接入后须追加正常/注入/字段脱敏、宿主清理钩子和比赛场景实测，不能将离线假审查器当作语义模型成绩。

性能命令 `python tools/v2/measure_runtime.py` 测量同一个 Runtime 的 20 项批次、事务等待和持锁耗时；输出本机测量值，不设跨机器性能承诺。成本显示 unavailable；未做改变安全语义的优化。
