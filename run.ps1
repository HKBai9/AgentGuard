# 启动脚本：AgentGuard 演示平台
#
# 用法：
#   .\run.ps1              启动 Streamlit 演示界面（默认）
#   .\run.ps1 -Mode exp    命令行跑全部对照实验
#   .\run.ps1 -Mode live   命令行跑真实大模型实验（用例 2）
#   .\run.ps1 -Mode test   跑防护层判定矩阵回归测试
#   .\run.ps1 -Mode ui     跑界面无头冒烟测试

param(
    [ValidateSet("app", "exp", "live", "test", "ui", "redteam", "bypass", "sdk", "gate", "scan")]
    [string]$Mode = "app",
    [int]$Port = 8501,
    [string]$Model = "qwen2.5-coder:7b",
    [string]$Log = ""
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
Set-Location $Root

# ---- 依赖装在工程内的 libs/ 目录（不污染系统 Python 环境）----
$Libs = Join-Path $Root "libs"

# ---- 定位 Python（`python` 可能不在 PATH 上，或只是 Store 占位程序）----
. (Join-Path $Root "tools\lib_python.ps1")
$Python = Resolve-AgentGuardPython
if (-not $Python) {
    Write-Host "[×] 未找到可用的 Python 3 解释器。" -ForegroundColor Red
    Write-Host "    可用环境变量 AGENTGUARD_PYTHON 指定解释器绝对路径。" -ForegroundColor Yellow
    exit 1
}
$env:PATH = "$(Split-Path -Parent $Python);$env:PATH"

if (-not (Test-Path (Join-Path $Libs "streamlit"))) {
    Write-Host "[!] 未找到 libs/ 依赖目录，正在引导安装…" -ForegroundColor Yellow
    & $Python (Join-Path $Root "tools\bootstrap_libs.py") --clean streamlit pyyaml pytest
}

$env:PYTHONPATH = $Libs
$env:PYTHONIOENCODING = "utf-8"

# ---- 本地大模型可用性检查 ----
function Test-Ollama {
    try {
        $tags = Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags" -TimeoutSec 5
        $names = $tags.models | ForEach-Object { $_.name }
        if ($names -contains $Model) {
            Write-Host "[✓] 本地模型可用：$Model" -ForegroundColor Green
            return $true
        }
        Write-Host "[!] 未找到模型 $Model，已安装：$($names -join ', ')" -ForegroundColor Yellow
        Write-Host "    可执行：ollama pull $Model" -ForegroundColor Yellow
        return $false
    }
    catch {
        Write-Host "[!] Ollama 未运行（http://127.0.0.1:11434）" -ForegroundColor Yellow
        Write-Host "    界面仍可使用『脚本回放』模式演示，所有安全判定逻辑完全一致。" -ForegroundColor Yellow
        return $false
    }
}

Write-Host ""
Write-Host "  🛡️  AgentGuard · 面向安全 Agent 的边界逃逸检测与风险隔离机制" -ForegroundColor Cyan
Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

switch ($Mode) {
    "app" {
        Test-Ollama | Out-Null
        Write-Host "[→] 启动演示界面：http://127.0.0.1:$Port" -ForegroundColor Cyan
        Write-Host "    侧边栏开关『启用边界逃逸防护』= 本实验的唯一变量" -ForegroundColor DarkGray
        Write-Host ""
        & $Python -m streamlit run (Join-Path $Root "app.py")
    }
    "exp" {
        Write-Host "[→] 三组对照实验：裸Agent / 提示词防护 / 执行层防护（秒级）" -ForegroundColor Cyan
        & $Python (Join-Path $Root "experiments\run_experiment.py")
    }
    "redteam" {
        if (-not (Test-Ollama)) {
            Write-Host "[×] 红队测试必须使用真实大模型，已中止。" -ForegroundColor Red
            exit 1
        }
        Write-Host "[→] 红队测试：提示词层防护能否被绕过（真实大模型，较慢）" -ForegroundColor Cyan
        & $Python (Join-Path $Root "experiments\run_adversarial.py") --model $Model
    }
    "sdk" {
        Write-Host "[→] 开发者接入示例：不接防护 vs 接入防护（只替换工具表）" -ForegroundColor Cyan
        & $Python (Join-Path $Root "examples\quickstart.py")
    }
    "gate" {
        Write-Host "[→] 策略回归门禁（越权漏放则退出码非零，可放进 CI）" -ForegroundColor Cyan
        & $Python -m agentguard.cli test (Join-Path $Root "config\permission_baseline.yaml")
        Write-Host "    退出码 $LASTEXITCODE（0=全部符合预期）" -ForegroundColor DarkGray
    }
    "scan" {
        if (-not $args[0]) {
            Write-Host "[!] 用法：.\run.ps1 -Mode scan -Log <actions.jsonl>" -ForegroundColor Yellow
            exit 2
        }
        Write-Host "[→] 离线审计 Agent 动作日志" -ForegroundColor Cyan
        & $Python -m agentguard.cli scan $Log
    }
    "bypass" {
        Write-Host "[→] 对照实验：工具名白名单 vs 资源级防护（工具名白名单会被绕过）" -ForegroundColor Cyan
        & $Python (Join-Path $Root "experiments\run_bypass_demo.py")
    }
    "live" {
        if (-not (Test-Ollama)) {
            Write-Host "[×] 真实大模型实验需要本地 Ollama，已中止。" -ForegroundColor Red
            exit 1
        }
        Write-Host "[→] 运行真实大模型实验（用例 2，较慢）" -ForegroundColor Cyan
        & $Python (Join-Path $Root "experiments\run_experiment.py") --live --case 2 --model $Model
    }
    "test" {
        Write-Host "[→] 运行防护层判定矩阵回归测试" -ForegroundColor Cyan
        & $Python -m pytest
    }
    "ui" {
        Write-Host "[→] 运行界面无头冒烟测试" -ForegroundColor Cyan
        & $Python (Join-Path $Root "tools\ui_smoketest.py")
    }
}

Write-Host ""
