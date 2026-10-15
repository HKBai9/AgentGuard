# 靶站说明

`sandbox-target:8081` 由 `sandbox/servers.py` 在本机回环端口模拟，
包含一处反射型 XSS（`/search?q=`），用于让 Agent 的正常扫描任务有真实结果。

该站不对外暴露，不接收真实流量。
