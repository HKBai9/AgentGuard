# A/B 共同假数据（2026-10-22 已统一公共契约）

所有文档、任务、接收器、密钥均为自造数据；没有实际文件读取或发送。
五组 `expected.json` 是人工预期，FakeCloudClient 只回放答案，不能据此测模型质量。

- `policy_local_vs_send`：相同工具清单，本地任务不含 SEND，发送任务只含 `test_receiver`。
- `normal_allow`：RESULT，加上最小 ACTION、FINAL 接口样例。
- `injection_block`：引用当前内容中的注入位置；`span` 为 Python Unicode 码点、左闭右开。
- `field_redact`：只提出 `/fake_secret` 字段替换，整份文档的限制仍保留；不执行变换。
- `guard_failure`：超时、JSON 错误、未知枚举、旧版本、错误关联、越界引用等。

`model_response.json` 不包含 usage；由客户端补入真实用量，公共格式缺失用量为 null，离线 provider 标为 fake。
`material.json` 和策略请求已迁移到 `agentguard/v2/contracts.py` 的实际类型；没有第二份 Schema。
内容摘要已经使用 A 的 `common.digest` 对当前正文重新计算，引用也同步更新；正式 Runtime 仍需独立核对真实隔离对象。
各组复用固定 ID，只允许独立测试，不能把不同组当成同一真实会话导入。

精确字段与集成补充见 [共享接口约定](../../../docs/tasks/V2_SHARED_CONTRACT.md)。`FixtureContracts` 调用实际 PublicContracts 校验后再转成字典；测试与正式组件使用同一套 Pydantic 模型，缺失时报错。

`guard_failure/runtime_script.json` 只证明宿主消费者收到预先编写的失败响应时没有原文。
FakeRuntime 不实现隔离、脱敏、许可或执行，更不能作为 A 的安全不变量验收证据。
