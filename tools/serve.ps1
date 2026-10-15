# 启动 Streamlit 演示服务（前台运行，适合由 harness/终端托管）。
#
# 说明：本工程运行在受限沙箱中，沙箱会在父进程退出时回收其派生的后台进程，
# 因此 `Start-Process` 式的"完全脱离"启动不可靠。本脚本改为前台运行，
# 由调用方（终端 / harness 后台任务）负责托管生命周期。
#
# 用法：
#   .\tools\serve.ps1              # 自动挑选可用端口启动
#   .\tools\serve.ps1 -Port 8600   # 指定端口

param(
    [int]$Port = 8501
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Libs = Join-Path $Root "libs"
Set-Location $Root

$env:PYTHONPATH = $Libs
$env:PYTHONIOENCODING = "utf-8"

# ---- 定位 Python 解释器 ----
# 注意：部分环境下 `python` 不在 PATH 上（或只解析到 WindowsApps 的占位程序），
# 因此这里用共享的探测函数，并把解释器所在目录加入 PATH，避免后续调用失败。
. (Join-Path $PSScriptRoot "lib_python.ps1")
$Python = Resolve-AgentGuardPython
if (-not $Python) {
    Write-Host "[×] 未找到可用的 Python 3 解释器。" -ForegroundColor Red
    Write-Host "    可用环境变量 AGENTGUARD_PYTHON 指定解释器绝对路径。" -ForegroundColor Yellow
    exit 1
}
$env:PATH = "$(Split-Path -Parent $Python);$env:PATH"
Write-Host "[i] Python: $Python" -ForegroundColor DarkGray

if (-not (Test-Path (Join-Path $Libs "streamlit"))) {
    Write-Host "[!] 未找到 libs/ 依赖，正在引导安装…" -ForegroundColor Yellow
    & $Python (Join-Path $Root "tools\bootstrap_libs.py") --clean streamlit pyyaml pytest
}

function Test-Port([int]$p) {
    $c = New-Object System.Net.Sockets.TcpClient
    try { $c.Connect("127.0.0.1", $p); return $true } catch { return $false } finally { $c.Dispose() }
}

# 从起始端口向后找可用端口，避免"端口被占用"直接失败
$chosen = 0
for ($p = $Port; $p -lt $Port + 20; $p++) {
    if (-not (Test-Port $p)) { $chosen = $p; break }
}
if ($chosen -eq 0) {
    Write-Host "[×] $Port 起 20 个端口均被占用，请手动指定 -Port" -ForegroundColor Red
    exit 1
}
if ($chosen -ne $Port) {
    Write-Host "[!] 端口 $Port 已被占用，改用 $chosen" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  🛡️  AgentGuard 演示界面" -ForegroundColor Cyan
Write-Host "  URL: http://127.0.0.1:$chosen" -ForegroundColor Green
Write-Host "  侧边栏开关『启用边界逃逸防护』= 对照实验的唯一变量" -ForegroundColor DarkGray
Write-Host "  按 Ctrl+C 停止" -ForegroundColor DarkGray
Write-Host ""

python -m streamlit run (Join-Path $Root "app.py") --server.port $chosen --server.address 127.0.0.1
exit $LASTEXITCODE
