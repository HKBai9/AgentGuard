# v2 来源与归属

本轮参考公开接口文档编写适配代码，没有把第三方仓库源文件复制进 AgentGuard。上游依赖由安装工具获取并保留各自许可；本仓库原有代码沿用仓库 LICENSE。历史设计的论文分析仍见 [最终修改计划](V2_IMPLEMENTATION_PLAN.md)。

| 来源 | 本轮具体用途 | 固定范围与归属 |
|---|---|---|
| [LangChain BaseChatModel 官方接口](https://reference.langchain.com/python/langchain-core/language_models/chat_models/BaseChatModel) | 使用 ainvoke 和消息类型接入主模型；执行循环继续由 Runtime 管理 | `langchain-core==1.6.13`；适配器由本项目编写，未复制框架源码 |
| [LangChain 仓库许可](https://github.com/langchain-ai/langchain/blob/master/LICENSE) | 上游许可索引 | 安装包为准；本仓库不重新分发其源文件 |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo/tree/089ed468cf3ed0322acc66b0211f26d9d90dbf60) | 真实环境工具调用、任务初始化、独立 utility/security 评分 | 固定 commit `089ed468cf3ed0322acc66b0211f26d9d90dbf60`，单独环境 |
| [AgentDojo TaskSuite](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/task_suite/task_suite.py) | 接 run_task_with_pipeline，不以 Guard 判定替代任务/攻击评分 | 自编桥接见 benchmarks/v2/external.py |
| [AgentDojo FunctionsRuntime](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/functions_runtime.py) | 将获准调用映射到 run_function，保留执行后的同一环境 | 显式宿主效果/目的地映射；不默认把未知函数当 READ |
| [AgentDojo MIT License](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/LICENSE) | 许可、作者归属 | Copyright 2024 Edoardo Debenedetti 等；示例任务 ID、假邮箱及攻击目标来自固定基准，不向真实邮箱通信 |
| [InjecAgent 官方仓库](https://github.com/uiuc-kang-lab/InjecAgent) | 可选的攻击文本导入；没有下载或打包数据 | 导入时记录本地数据文件摘要；只计本地补充任务，不报告官方成绩 |
| [DeepSeek Chat Completions](https://api-docs.deepseek.com/api/create-chat-completion/)、[JSON Output](https://api-docs.deepseek.com/guides/json_mode/) | 现有 stdlib JSON 传输格式；本轮增加由宿主配置的兼容 HTTPS endpoint | 默认无工具、非流式、精确端点；此类接口不等于所有供应商 API |
| [Streamlit 文档](https://docs.streamlit.io/) | 六个只读视图、下载录制和图形展示 | `streamlit==1.56.0`，`graphviz==0.21`；页面代码由本项目编写 |

本地 8+8 任务、假秘密、接收器、评分器、五类场景、上下文算法、分析缓存和恢复持久记录均由本项目编写。ScriptedAgent 与 AllowReviewer 是明确标记的程序驱动/故障注入组件，不是训练模型、真实供应商结果或复制的攻击成功证据。

尚未开展的工作：真实云端效果、外部基准整环境运行、全量比赛实验、费用结算。引用论文或接入接口不能替代这些证据。
