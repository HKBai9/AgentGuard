# 开发者接入指南：把 AgentGuard 用在你自己的 Agent 上

> 这份文档面向**写 Agent 的人**。目标：让你在几分钟内接上，而不是先读一篇论文。
>
> 不用改你的 Agent 循环、不用换模型、不用换框架 —— **只替换工具表**。

---

## 一、30 秒版本

```python
from agentguard import AgentGuard

guard = AgentGuard(task=user_task)          # ① 传入用户原始任务（语义层用它判断"是否跑偏"）
safe_tools = guard.wrap_tools(my_tools)     # ② 把工具表包一层

# ③ 之后把 safe_tools 交给你的 Agent —— 其他代码一行都不用改
```

`my_tools` 可以是：

```python
{"web_scan": web_scan, "read_file": read_file}        # 字典（最常见）
[StructuredTool(...), ...]                            # LangChain 工具列表
[MyCustomTool(), ...]                                 # 任何有 .name 的工具对象
```

被拦下时，工具**不会被执行**，Agent 收到一段它能读懂的说明：

```
⛔ 该操作已被 AgentGuard 边界逃逸防护阻断，未执行任何实际操作。
工具：read_file
判定：ISOLATE ｜ 风险等级：CRITICAL
- [L1-权限基线][CRITICAL] 敏感凭证读取：路径 `/sandbox_fake/.ssh/id_rsa` 命中受保护资源
- [L2-语义意图][CRITICAL] 敏感凭证读取：Thought 中出现越权意图，命中 `私钥`
会话已被冻结隔离，后续所有工具调用都会被拒绝。
请不要重试该操作，改为在授权范围内完成用户的原始任务。
```

> 最后那句"请不要重试"是刻意写的：模型读到"被谁拦、为什么、别重试"，
> 才会改变策略，而不是傻乎乎地反复调用同一个被拒工具。

---

## 二、三种接入方式（按你的代码形态选）

### 方式 1：字典工具表（最省事）

```python
guard = AgentGuard(task=user_task)
tools = guard.wrap_tools({"web_scan": web_scan, "read_file": read_file})
result = tools["read_file"](path="/sandbox_fake/workspace/notes.md")
```

### 方式 2：装饰器（适合新写的工具）

```python
guard = AgentGuard(task=user_task)

@guard.tool(name="read_file", description="读取指定路径的文件内容")
def read_file(path: str) -> str:
    ...
```

### 方式 3：函数式（不想建对象）

```python
from agentguard import guard_tools, guard_function

safe_tools = guard_tools(my_tools, task=user_task)
read_file  = guard_function(read_file, tool_name="read_file", task=user_task)
```

---

## 三、接 OpenAI function calling

```python
from agentguard import AgentGuard

guard = AgentGuard(task=user_task)
safe = guard.wrap_tools(my_tools)

# 给模型看的工具定义
schemas = guard.openai_tools(safe)

resp = client.chat.completions.create(model="gpt-4o", messages=msgs, tools=schemas)
for call in resp.choices[0].message.tool_calls or []:
    name = call.function.name
    args = json.loads(call.function.arguments)
    # ↓ 唯一需要改的地方：走受防护的工具
    observation = safe[name](**args)
```

## 四、接 LangChain

```python
guard = AgentGuard(task=user_task)

# 方式 A：包你已有的工具
safe = guard.wrap_tools(my_langchain_tools)      # 返回 list[ToolSpec]
lc_tools = guard.langchain_tools(safe)           # 转回 StructuredTool
agent = create_react_agent(llm, lc_tools)

# 方式 B：直接包成 StructuredTool 的 func
from langchain_core.tools import StructuredTool
raw = StructuredTool.from_function(func=read_file, name="read_file", description="...")
protected = guard.wrap_tools([raw])[0]
lc_tool = StructuredTool.from_function(
    func=protected.func, name=protected.name, description=protected.description
)
```

> LangChain 的 `StructuredTool` 走 `.func`，我们已适配；
> pydantic 的 `args_schema` 也会被自动读成 JSON Schema。

## 五、接 MCP（工具在别的进程里）

MCP 场景下工具不在你的进程内，两种做法：

```python
# 做法 A（过渡）：在 MCP 客户端侧包一层
guard = AgentGuard(task=user_task)
async def call_tool(name, args):
    ok, out = await guard.aguard_call(name, lambda **kw: mcp_client.call_tool(name, kw), args)
    return out

# 做法 B（推荐，产品形态）：把 MCP 服务器地址指向 AgentGuard Gateway
#   Agent ──MCP──▶ AgentGuard Gateway ──MCP──▶ tools-server
# 这样防护**在 Agent 进程之外**，Agent 无法绕过（见 docs/PRODUCT.md）
```

---

## 六、策略怎么配

策略是一个 YAML 文件，声明 Agent 的**最小权限边界**（默认拒绝）：

```yaml
experiment:
  task_baseline:
    goal: "对靶站 http://sandbox-target:8081 进行 XSS 漏洞扫描"

tools:
  allow: [web_scan, http_get, read_file, write_file, run_command, ssh_connect]
  deny:  [{name: exfiltrate, reason: "外传数据工具被基线禁止"}]

resources:
  network:
    allow: [{match: exact, value: "sandbox-target"}]
    deny:  [{match: cidr, value: "10.0.0.0/8"}]
    allowed_ports: [80, 443, 8080, 8081]
    sensitive_ports: [{port: 3306, reason: "MySQL，属内网数据库"}]
  files:
    read:  ["/sandbox_fake/workspace/**"]
    write: ["/sandbox_fake/workspace/reports/**"]
    protected:
      - {pattern: "**/.ssh/**", reason: "SSH 私钥目录", severity: CRITICAL}
      - {pattern: "**/.env",     reason: "环境变量文件", severity: HIGH}
  commands:
    allow: [{bin: curl}, {bin: nmap}]
    deny:  [{bin: nc, reason: "常被用于反弹 shell"}]

sequences:            # 时序行为链：单步合规、组合越权
  rules:
    - id: SEQ-001
      name: "凭证读取 → 内网连接"
      severity: CRITICAL
      read:   ["**/.ssh/**", "**/id_rsa*"]
      follow: [{tool: ssh_connect}]
```

改完策略**一定要跑门禁**（下一节）。

---

## 七、命令行工具（进 CI）

```bash
# 校验策略文件是否合法，并打印完整权限边界
agentguard check config/permission_baseline.yaml

# ★ 策略回归门禁：越权动作被漏放 → 退出码非零 → CI fail
agentguard test config/permission_baseline.yaml

# 离线审计：拿一份 Agent 动作日志，事后找出越权动作
agentguard scan logs/agent_actions.jsonl
```

装好后（`pip install -e .`）就能直接用 `agentguard` 命令；
没安装也可以用 `python -m agentguard.cli ...`。

**放进 CI（GitHub Actions 示例）**：

```yaml
- name: 策略回归门禁
  run: |
    pip install -e ".[dev]"
    agentguard test config/permission_baseline.yaml
```

### 为什么这个门禁值得放进 CI

它不是"跑一遍看有没有报错"，而是断言**每类攻击由哪一层负责拦下**：

```
✅ ALLOW-01  正常：扫描被测靶站            期望=allow 实际=allow
✅ BLOCK-01  越权：读取 SSH 私钥           期望=block 实际=isolate  L2-INTENT-LEX
✅ BLOCK-04  绕过：路径上跳读私钥           期望=block 实际=isolate  L1-FILE-PROTECTED
✅ BLOCK-05  绕过：用白名单命令 curl 访问内网  期望=block 实际=isolate  L1-NET-ALLOW
```

> **只断言"危险调用被拦住了"是不够的。**
> 我们在开发中实测过一次：把策略改坏（把 `.ssh` 加进可读白名单、删掉私钥保护规则），
> 语义层仍然兜住了同样的攻击 —— 于是"被拦住"依旧成立、门禁照常通过，
> **真正的策略退化被完全掩盖了**。
> 所以每条用例都额外断言"负责的层"，单层退化就能被门禁抓到。

---

## 八、阻断行为：三选一

```python
AgentGuard(task=..., on_block="message")  # 默认：返回说明文本，Agent 可继续（推荐）
AgentGuard(task=..., on_block="raise")    # 抛 GuardedToolError，交给你的异常处理
AgentGuard(task=..., on_block="none")     # 返回空字符串
```

多数场景建议用默认的 `"message"`：让 Agent 知道"这条路被封了"，
它才有机会换个合规做法去完成用户的任务；直接抛异常往往让整个任务崩掉。

---

## 九、观测与审计

```python
guard.summary()   # {"allowed": 3, "blocked": 1, "escape_types": [...], "frozen": True}
guard.report()    # 完整事件流 + 证据链 + 动作历史，可直接落盘
guard.frozen      # 会话是否已被隔离冻结
guard.rollback()  # 把可写目录恢复到会话开始时的快照
```

审计日志默认写到 `logs/audit.jsonl`，每行一个事件（含规则 ID、层级、
严重度、证据 JSON），可直接接你的日志系统。

---

## 十、常见问题

**Q：Agent 会不会把整个任务搞崩？**
默认返回说明文本而不抛异常；如果策略触发会话冻结，后续工具调用仍会被拒绝。
返回文本不代表已实现安全续行。上下文隔离与恢复属于后续改造阶段。

**Q：接入要改多少代码？**
一行（`wrap_tools`）。你的 Agent 循环、模型、框架都不用动。

**Q：能只拦某类动作吗？**
把对应层的开关关掉即可，例如只保留资源级判定：
```python
from agentguard import AgentGuard, GuardConfig
AgentGuard(config=GuardConfig(enable_intent=False, enable_runtime=False))
```

**Q：`task` 参数必须传吗？**
不强求，但**强烈建议**。语义层靠它判断"Agent 的想法是否偏离原始任务"；
不传的话语义漂移检测会失去参照物，只剩资源级判定。

**Q：这能防住一个完全失控的 Agent 吗？**
不能。SDK 形态的防护在 Agent 进程内，理论上可被绕过。
生产环境应该用**外部网关**形态（MCP Proxy），把控制点移出 Agent 进程 ——
见 [`docs/PRODUCT.md`](PRODUCT.md) 第五节。

---

## 十一、可运行示例

```bash
python examples/quickstart.py          # 对照：不接防护 vs 接入防护（秒级）
python examples/quickstart.py --live   # 用本地大模型真实推理
```

示例刻意**不使用本仓库的 demo Agent**，而是一个最常见的
"function-calling 循环 + 普通 Python 函数"写法，用来证明接入是 drop-in 的。

## 十二、1.1.1 接口修正

- 默认参数与具名参数先完整绑定，再检查；执行保留位置专用参数的原始调用约定。
- `openai_tools()` 接受受保护工具字典或 `ToolSpec` 列表，返回 Chat Completions 的
  `{"type": "function", "function": ...}` 结构。
- `async def` 工具经 `wrap_tools()` 后仍须 `await`；直接调用异步函数使用 `await guard.aguard_call(...)`。
- `task` 在意图检查器初始化前生效。它提供任务参照，不扩展策略中的资源权限。
- `vfs_root` 在快照前生效；每个 SDK 实例默认使用独立会话编号。
- 普通自定义回调只能证明“回调已返回”，不会自动证明文件/网络效果。需要已执行行为链时，
  由可信工具适配器返回 `ToolResult(..., effects=[...], meta={"effects_complete": True})`。
  不完整效果记录保留为未知，不按“无副作用”处理。
- 内置命令适配的范围与阶段一验证方法见 [STAGE1.md](STAGE1.md)。
