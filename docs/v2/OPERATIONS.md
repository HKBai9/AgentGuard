# v2 操作说明

Python 3.12。生产装配默认使用云端 API，启动不会自动执行任务。`start_v2.ps1` 从仓库根目录运行；不要把隔离库和状态目录放进 Agent 可读写的工作目录。

配置检查与 Runtime 会拒绝工具资源目录和私有存储目录的重叠（包括互为父子目录）。不能把整个项目根目录作为工具根目录，同时又把私有状态放在该根目录下面。

## 安装和配置

```powershell
python -m venv .venv-v2
.venv-v2/Scripts/python.exe -m pip install -r requirements-v2-features.lock.txt
.venv-v2/Scripts/python.exe -m pip install --no-deps -e .
```

复制 `config/v2.example.json` 为本地配置，修改 workspace、state_directory、模型名、HTTPS endpoint 和密钥的环境变量名。路径相对该配置文件解析。示例目录只有假数据，`synthetic_demo=true` 只适用于该目录；接入实际资料时设为 false。普通源码/工具库不要求工作目录有特定名字。

配置中的 guard/agent 是两个模型目的地，可以用同一供应商或不同供应商。地址精确匹配资源目录；没有重定向、环境 HTTP 代理或任务文本控制的 endpoint。适用的是 JSON chat-completions 兼容接口；供应商差异需要一个实现相同客户端接口的适配，不能保证所有厂商协议即插即用。

在当前进程设置：

```powershell
$env:AGENTGUARD_V2_CLOUD_ENABLED = '1'
$env:AGENTGUARD_GUARD_API_KEY = '<真实密钥>'
$env:AGENTGUARD_AGENT_API_KEY = '<真实密钥>'
```

不自动读取 `.env`。`.env.v2.example` 仅列出配置名，默认关闭云端；真实 `.env.v2` 已被 Git 忽略。`max_attempts` 限制每个客户端的尝试数，`max_tokens` 为可选 token 上限；用量未知时不按零费用处理。示例不会自动配置任何网络接收器。

配置可加入 `resources` 登记受限子目录及 DataLabels；整份文档和字段限制按已有 Runtime 规则传播。`transforms` 只接受宿主登记的 mask_span/mask_json_string 变换；示例 `mask_text` 只遮盖文字，不降低文档权限。只有确知字段来源的宿主，才应配置允许降低限制的字段集合。

WRITE 的目标资源必须保留源上下文的保密性、用途和接收端限制，否则返回 `RESOURCE_LABEL_DOWNGRADE`。例如，读过 private 资料后不能把派生文本写进 public 目录；应由宿主预先登记具有相应限制的输出目录。这样后续新会话重新读取文件时，限制不会丢失。宿主仍负责使不同会话对同一外部资源采用一致的标签。

## 原生宿主与网关

```powershell
# 独立原生宿主；只有最终通过门禁的内容会打印。
./start_v2.ps1 -Mode Agent -Python .venv-v2/Scripts/python.exe -Config config/v2.example.json -Task '阅读工作目录 readme.txt，生成一份简短报告到 report.txt，不外发。'

# 同时启动 localhost 网关和控制台；Ctrl+C 停止本命令启动的服务。
./start_v2.ps1 -Mode Live -Python .venv-v2/Scripts/python.exe -Config config/v2.example.json
```

Live 模式为子服务生成不同的 host/UI 临时凭据（已有环境值则复用），不打印密钥。凭据传给子进程，服务日志在状态目录下。可用 `-Task` 在启动后执行一个任务。网关默认为 `127.0.0.1:8765`，控制台为 `127.0.0.1:8502`。多机部署自行配置 HTTPS、进程权限和后端凭据隔离；默认工具包是受限文件目录操作，不是操作系统通用沙箱。

分别启动时要设置两个不同的凭据：

```powershell
$env:AGENTGUARD_HOST_TOKEN = '<宿主凭据>'
$env:AGENTGUARD_UI_TOKEN = '<另一个只读凭据>'
./start_v2.ps1 -Mode Gateway -Config config/v2.example.json
# 另一个终端继承 UI 凭据后：
./start_v2.ps1 -Mode Console
```

通过网关执行主 Agent：

```powershell
.venv-v2/Scripts/python.exe -m agentguard.v2.application --config config/v2.example.json --gateway http://127.0.0.1:8765 --task '阅读工作目录资料，写出报告，不发送。'
```

该模式只在宿主侧保存消息引用与恢复记录，不建立另一套本地 Runtime 数据库或隔离库。安装网关额外依赖 `pip install '.[gateway]'` 包含 HTTP 客户端依赖。

原生 CLI 和网关 CLI 对同一状态目录取得操作系统文件锁；已有服务持锁时第二个执行进程会拒绝启动。重启取得独占权后，遗留 CLAIMED 标记为 UNKNOWN，不重新执行，并清理遗留活动操作记录。直接嵌入 Runtime 的 SDK 宿主必须使用 `agentguard.v2.state.ownership.exclusive_worker` 管理完整进程生命周期，再调用 `runtime.permits.recover_abandoned()`；不要对仍有执行器工作的数据库调用此方法。关闭程序时须先等待执行线程退出，再释放独占权。

宿主循环严格执行 prepare_model_turn → 主模型 → record_model_output → execute_batch/finalize。主模型以 JSON 提议工具，执行器只在 Runtime 内；下一轮通过对象引用读取获准版本。工具之间的内部模型文字被登记，不展示给用户；原生循环根据任务和已释放观察重新规划，不暗中复用供应商会话/思考链。

默认工具：read_text/list_files/write_text。模型系统消息中包含工具 Schema 和绝对资源根路径。添加网络工具需在 network_destinations 中登记完整 Destination；只有 send_http 的已登记 ID 可用。添加自己的工具可使用 `tool_factory: your_package.module:factory`，工厂接收 settings、返回 ToolRegistry。该字段属于可信部署配置，不能由用户任务或模型传入。

## 接入一个框架

```python
from agentguard.v2.adapters.framework import LangChainHost

host = LangChainHost(
    runtime, your_stateless_chat_model,
    destination_id="agent", endpoint="https://your-approved-provider/chat/completions",
    state_directory="private-state/host",
)
session = await host.create(session_request)
result = await host.run(session.session_id)
if result.status == "RELEASED":
    display(result.content)
```

固定 `langchain-core==1.6.13`。传入 BaseChatModel，关闭 callbacks、cache、streaming 和外部 tracing。模型按同一 JSON 工具提议协议回答；不要绑定带执行能力的框架节点。不同供应商的 BaseChatModel 构造仍由调用方完成；adapter 的 endpoint 是宿主对模型真实目的地的声明，必须与目录一致。

自建模型实现 AgentModel.complete(prepared) 和 reset(session_id)。如果存在远程续接状态，reset 必须真正确认该续接已废弃；不能无条件返回 true。不得在 complete 中拼接没有进入 PreparedTurn 的原始工具结果或隐式记忆。

## 恢复与宿主文件

```python
# ref 来自既有结果或受影响对象；先按来源图算影响，再执行宿主重置。
plan, ack, view = await host.recover(session_id, [risk_ref])

# 框架/扩展记忆另有存储时提供实际清理钩子，返回 bool。
host.reset_hooks["memory"] = clear_my_memory
host.reset_hooks["framework_checkpoints"] = reset_my_checkpointer

# 仅登记属于该会话宿主目录内的工作文件；恢复会移到 revoked-products。
host.register_work_product(session_id, owned_draft_path)

# 重启后遇到未完成恢复，从持久恢复记录续接。
await restarted_host.resume_recovery(session_id)
```

重置项包括 messages/cloud_conversation/framework_checkpoints/memory/analysis_cache/work_products。任何一步不支持或失败，Ack 不完整，Runtime 保持 RECOVERING。完整 Ack 后才保存新 checkpoint。UNKNOWN 或 REVIEW_PENDING 会让宿主停下，不能反复 run 重新发送可能已执行的副作用。恢复计划中的不可逆回执需要操作者另行处理。

宿主在发送工具批次或最终输出请求之前先持久化 `HOST_OPERATION_PENDING`。网络中断或进程退出后，不会重新规划同一任务并换用新的 call_id。恢复请求、计划和 Ack 也写入原子恢复日志：计划响应或 Ack 响应丢失后可调用 `resume_recovery`；Runtime 只接受绑定完全一致且仍在对应恢复上下文的重复请求。完成的任务不能再次 `run`，总轮数也不会因重启重新计数。没有启用 state_directory 的嵌入式宿主只有进程内状态，不具有重启续接能力。

已知没有产生副作用的读文件失败返回 FAILED_KNOWN，让模型获得有限错误码后继续规划；它不会被误报成已外发状态未知，也不会触发无意义的上下文恢复。

## 控制台和回放

六个视图只调用鉴权查询 API，不读 SQLite 或隔离目录，也不执行工具。实际 Guard 输入来自私有审计记录，显示选中引用、实际字节数、提交状态和缓存命中。正文默认遮盖。只有服务端 `AGENTGUARD_V2_SYNTHETIC_UI=1`、会话及参与对象均被宿主标记为假数据时，才显示请求正文；普通对象比较仍遮盖。

控制台侧栏可导出当前只读回放。回放显示持续标识，并不连接模型或执行后端：

```powershell
./start_v2.ps1 -Mode Replay -Recording logs/recording.json
```

分析缓存命中只节省本次推理，仍校验全部绑定，并重新执行 Runtime 的权限/对象/许可检查。缓存不包含执行票据。普通 UI 凭据不能写入、清理缓存或提交恢复 Ack。
