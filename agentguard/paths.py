"""工程路径常量。

单独成模块的原因：包根的 ``__init__.py`` 会导入 ``sdk``，
所以 ``sdk`` 不能反过来从包根取常量（会形成循环导入）。
把路径常量放在这里，双方都从本模块取，依赖方向就清晰了。
"""

from __future__ import annotations

import os

# agentguard/ 的上一级，即工程根目录
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 默认权限基线策略
DEFAULT_CONFIG_PATH = os.path.join(PROJECT_ROOT, "config", "permission_baseline.yaml")

# 演示用虚拟文件系统的真实根目录
VFS_ROOT = os.path.join(PROJECT_ROOT, "sandbox", "sandbox_fake")

__all__ = ["PROJECT_ROOT", "DEFAULT_CONFIG_PATH", "VFS_ROOT"]
