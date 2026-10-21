# B01 共同假数据（尚未通过 A01 公共契约联调）

所有文档、任务、接收器、密钥均为自造数据；没有实际文件读取或发送。
五组 `expected.json` 是人工预期，FakeCloudClient 只回放答案，不能据此测模型质量。

- `policy_local_vs_send`：相同工具清单，本地任务不含 SEND，发送任务只含 `test_receiver`。
- `normal_allow`：RESULT，加上最小 ACTION、FINAL 接口样例。
- `injection_block`：引用当前内容中的注入位置；`span` 为 Python Unicode 码点、左闭右开。
- `field_redact`：只提出 `/fake_secret` 字段替换，整份文档的限制仍保留；不执行变换。
- `guard_failure`：超时、JSON 错误、未知枚举、旧版本、错误关联、越界引用等。

`model_response.json` 不包含 usage；由客户端补入真实用量。离线回放标为 fake/unavailable。
每组 `material.json` 是临时内联字典的文件化样例，不是另一份公共模型或 JSON Schema。
`sha256` 使用固定的 64 位十六进制占位值，**不是对正文计算出的摘要**；B 不定义摘要算法。
A 建立不可变对象后应统一替换这些值及绑定引用，再验收内容摘要与释放链路。
各组复用固定 ID，只允许独立测试，不能把不同组当成同一真实会话导入。

暂定 ContextMaterial/Outcome 的字段形状与待确认点详见
[`V2_B_GUARD.md`](../../../docs/tasks/V2_B_GUARD.md) 的交接记录。
`FixtureContracts` 是测试专用透传，不宣称 Pydantic 校验通过；正式组件默认加载 A 的
`agentguard.v2.contracts`，缺失时报错，绝不回退到透传。

`guard_failure/runtime_script.json` 只证明宿主消费者收到预先编写的失败响应时没有原文。
FakeRuntime 不实现隔离、脱敏、许可或执行，更不能作为 A 的安全不变量验收证据。
