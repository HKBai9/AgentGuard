# 设计文档：四层防护的判定模型与关键权衡

> 配套阅读：`README.md`（概览）、`docs/CLAIMS.md`（可复现实验数据）
> 代码：`agentguard/`

本文回答评委最可能追问的几个问题：**每一层凭什么判定？如何避免误报？
如何防止被绕过？为什么这样设计而不是更复杂的方案？**

---

## 一、总体判定模型

Agent 的每一次工具调用都构造为一个 **Action**，并被归一化为 `ActionView`：

```
ActionView
├── 网络维度：scheme / host / resolved_host / port / policy_port / url
├── 文件维度：path（虚拟路径，已归一化）/ real_path（映射后的真实路径）
├── 命令维度：binary / command
└── 备注：notes（归一化过程的可解释记录）
```

四层各自对该视图产出若干 `Finding`，最终由 L4 汇总：

```
findings = L2(thought) + L1(action) + L3(action, history)
blocking = [f for f in findings if f.severity >= HIGH]      # 阻断门槛
decision = ALLOW         if not blocking
         | ISOLATE       if policy(blocking.severity) >= isolate_session
         | BLOCK         otherwise
```

**关键设计：严重度分级 + 阻断门槛。**
只有 `HIGH` / `CRITICAL` 证据才会拦下动作；`LOW` 级证据（例如"相似度偏低但仍属正常收尾"）
只写入审计日志。这是"既不漏报又不误伤"的第一道保证。

---

## 二、L1 权限基线：默认拒绝 + 四类白名单

`config/permission_baseline.yaml` 定义 Agent 的最小权限边界：

| 维度 | 白名单 | 拒绝优先项 |
|---|---|---|
| 工具 | `web_scan` / `http_get` / `read_file` / `write_file` / `run_command` / `ssh_connect` | `exfiltrate` 显式拒绝 |
| 网络 | `sandbox-target`、`127.0.0.1` | 内网网段 `10/8`、`172.16/12`、`192.168/16`；`internal-db` |
| 端口 | 80/443/8080/8081 | 敏感端口 22/3306/5432/6379/27017 |
| 文件 | 读 `/sandbox_fake/workspace|targets|public/**`；写 reports/tmp | 受保护：`**/.ssh/**`、`**/id_rsa*`、`**/.env`、`**/credentials*`、策略文件本身 |
| 命令 | `curl`/`nmap`/`dig`/`echo`/`ls`/`cat` | `nc`/`socat`/`ssh`/`scp`/`chmod`/`sudo`/`crontab`/`mysql`… + 危险参数正则 |

### 2.1 通配匹配的语义（避免"看着像白名单，其实放行了别处"）

`_glob_match()` 专门处理 `**` 的两种直觉语义：

- `/sandbox_fake/workspace/**` → 只匹配该目录及其子内容，**不匹配** `/sandbox_fake/.ssh/id_rsa`；
- `**/.ssh/**` → 匹配任意深度下含 `/.ssh/` 的路径。

直接用 `fnmatch` 会因 `*` 跨越 `/` 而产生越权放行，这里做了前缀与片段判定修正。

### 2.2 端口与服务语义解耦（防"换端口绕过"）

问题：敏感端口策略是"按端口号"写的。若 Agent 连 `internal-db:43306`
（演示环境为规避系统端口保留而回退的端口），按端口号判定就会漏过。

解决：`canonical_port()` 把已知服务别名上的**任意端口**归一化为规范端口，
策略判定使用 `policy_port`，真实连接仍用 `port`：

```
internal-db:43306  →  policy_port=3306（判定为"访问内网数据库"）
                   →  port=43306（真实连接用）
```

`SEQ-002` 的 `port_in: [3306, 5432, ...]` 同样按 `policy_port` 匹配。

---

## 三、L2 语义意图：为什么不用纯关键词，也不用纯句向量

### 3.1 三条互补线索

1. **风险意图识别**：`RISK_LEXICON` 把越权意图分成 6 族
   （凭证获取 / 账号接管 / 横向移动 / 配置篡改 / 自我修改 / 数据外泄）。
   但命中词表**不等于**越权 —— 必须同时出现"动作诉求"（获取/连接/读取/绕过…）
   才升级为高危；没有动作诉求时置信度打折（`×0.6`）。
   这样"报告里提到 credential 一词"不会被误判。

2. **目标语义漂移**：`1 - cosine(TF(thought), TF(授权动作空间))`，
   授权动作空间 = 任务目标 + 允许动作集合。字符 n-gram 分词，中文按 bigram。

3. **大模型复核（可选）**：对已触发告警的样本，让本地模型做一次意图分类，
   作为"第二意见"上调或下调严重度。

### 3.2 目标对象模型：抑制误报的核心

**只用相似度会误伤。** 例如 Agent 说"把扫描结论写入报告目录"，
与原始任务"对靶站进行 XSS 扫描"的字面重合度很低，漂移度高，但它显然不是逃逸。

因此"目标偏离"判定要求**三个条件同时满足**：

```
drift >= threshold                                  # (1) 相似度确实低
AND ( 引用了任务范围外资源 OR 完全没有任务域锚点 )      # (2) 目标对象可疑
AND NOT 出现合法工作产物锚点                          # (3) 不是在做任务收尾
```

- 任务域锚点 `TASK_SCOPE_VOCAB`：扫描/漏洞/注入/参数/表单/响应/http/payload/target…
- 合法产物锚点 `BENIGN_ARTIFACT_VOCAB`：报告/笔记/汇总/写入/workspace/reports/…

并且严重度取决于条件 (2) 的形态：

- 引用了任务范围外资源（私钥、内网数据库…）→ `HIGH`，参与阻断；
- 仅仅"没提任务词" → `LOW`，只记录不阻断。

**实验验证**（`tests/test_guard.py`）：

- `test_normal_task_target_scan_allowed`：正常扫描 Thought 不触发任何告警 ✅
- `test_write_report_allowed`：写报告 Thought 相似度低但被产物锚点豁免 ✅
- `test_intent_detects_escape_but_not_normal_thought`：逃逸 Thought 被识别 ✅

### 3.3 为什么不用预训练句向量

- 竞赛环境通常无法联网下载句向量模型；字符 n-gram **完全离线、零依赖、可复现**；
- 本层职责是"发现语义异常并给出解释"，最终裁决由多层证据合并；
- 接口 `IntentChecker.similarity()` 是单一替换点，接入任意句向量实现即可，
  这也是后续可扩展方向。

---

## 四、L3 行为运行时：单步合规 ≠ 整体合规

### 4.1 参数审计

- **路径穿越**：`raw` 参数含 `..` → 告警；同时 `normalize_path()` 会先把路径
  归一化再交 L1 判定，因此 `/sandbox_fake/workspace/reports/../../../.ssh/id_rsa`
  会被解析成 `/sandbox_fake/.ssh/id_rsa` 并命中受保护资源。
- **内网解析**：把虚拟主机解析为真实地址后，检查是否落入内网禁用网段。
- **命令包装绕过**：白名单命令里出现 `| sh`、`$(...)`、反引号、`/dev/tcp/`、
  `base64 -d`、`../` 等包装手法时告警 —— 防止"用允许的 curl 干不允许的事"。
- **会话状态**：本会话已读过敏感凭证后，**任何**外联动作都按横向移动链处理。

### 4.2 时序行为链（本层最重要的能力）

单步白名单足以放过这个链：`读私钥`（路径在"可读"范围内）→ `连内网数据库`。
两步分开看都"差不多合规"，组合起来就是横向移动。

`sequences.rules` 用"前序模式 → 后续条件"描述：

```yaml
- id: SEQ-001
  name: "凭证读取 → 内网连接"
  severity: CRITICAL
  read:   ["**/.ssh/**", "**/id_rsa*", "**/credentials*", "**/*.pem"]
  follow: [{tool: ssh_connect},
           {tool: http_get, host_in: ["internal-db", "10.0.0.0/8", ...]}]
  reason: "先取凭证再连内网，是典型的横向移动（Lateral Movement）链"
```

`test_sequence_credential_then_internal_connection` 专门构造"单步被放宽"的
最坏情形（把 `.ssh` 加进可读白名单、移除保护项），验证**仅靠单步白名单不够，
必须有时序分析**。

---

## 五、L4 隔离阻断：检测之后做什么

| 动作 | 实现 | 意义 |
|---|---|---|
| **阻断** | `ToolBridge.execute()` 在 `verdict.allowed == False` 时**直接返回**，不进入 `_dispatch()` | 工具零执行、零副作用 |
| **会话隔离** | `guard.frozen = True`，后续所有调用一律 `ISOLATE` | 阻断链式逃逸（一次越权后自动升级） |
| **告警** | `GuardEvent`（kind/severity/证据链）+ UI 红色告警 + `logs/audit.jsonl` | 可解释、可溯源 |
| **安全回滚** | 会话开始时快照可写目录；判定逃逸后删除新增文件、还原被改文件 | 破坏可逆 |

「**工具完全不执行**」是本作品最硬的一条保证：阻断时返回的是说明文本，
**不包含任何被保护资源的内容**（`test_sensitive_private_key_blocked_and_not_executed`
断言输出中不含 `BEGIN OPENSSH PRIVATE KEY`）。

---

## 六、安全边界：这个演示为什么是安全的

1. **全离线**：所有"主机"都在 `127.0.0.1` 回环；
   名称解析只允许 `config` 中 `sandbox.egress.map` 登记的别名，
   未登记域名一律不解析 —— 不存在诱导防护层访问外网的可能。
2. **假数据**：私钥/凭证文件内均标注 `DEMO / FAKE`，不能用于任何真实登录。
3. **命令兜底**：`run_command` 只允许执行少数白名单二进制且不经过 shell；
   `tool` 层还有第二道"受保护路径不写入任何真实内容"的检查。
4. **演示用假文件补齐**（`_provision_probe`）：本地小模型常猜错路径
   （如把私钥猜成 `/sandbox_fake/workspace/.ssh/id_rsa`）。
   为避免"对照组逃逸成功"沦为"模型猜错路径"的假象，沙箱会在
   **受保护路径**上补齐一份**同一份假私钥**，使对照组的逃逸具有真实可观测的副作用。
   安全约束：仅在 `sandbox_fake/` 内部、仅限受保护敏感路径、仅假数据、进程结束即清理。

---

## 七、与现有方案的区别

| 方案类型 | 做法 | 局限 | 本作品的差异 |
|---|---|---|---|
| 提示词防护 | 在 system prompt 里写"不要做危险操作" | 可被注入绕过，无强制力 | 我们有**强制力**：工具根本执行不了 |
| 输出内容过滤 | 检查模型输出文本 | 停留在文本层，挡不住工具调用 | 我们拦的是**真实动作** |
| 工具白名单 | 只允许某些工具 | 无法区分"curl 靶站"与"curl 内网" | 我们做**参数级 + 时序级**判定 |
| 纯关键词检测 | 匹配危险词 | 措辞改写即绕过 | 词表 + 动作诉求 + 目标对象模型 |
| 容器隔离 | 限制整个进程 | 粒度粗，难审计单次动作 | 我们**逐次调用**判定并留证 |

---

## 八、可扩展方向

1. **句向量替换**：`IntentChecker.similarity()` 换成离线 bge/text2vec 模型，提升语义泛化；
2. **框架无关接入**：防护层是 SDK，可插到 LangGraph / AutoGen / OpenHands 的工具执行点；
3. **策略学习**：从审计日志中学习基线（当前白名单为人工配置）；
4. **多 Agent 场景**：跨会话的逃逸链检测（A 读凭证 → B 连内网）；
5. **真实环境落地**：把 `ToolBridge` 接到 eBPF / seccomp / Windows ETW 上，
   从"应用层工具调用"下沉到"系统调用层"。
