# =============================================================================
#  AgentGuard 一键启动：本地大模型 + 演示网站
#  ---------------------------------------------------------------------------
#  用法（在工程根目录执行）：
#      .\start_demo.ps1
#
#  它会依次：
#      1. 检查/启动 Ollama 本地大模型（写入目录重定向到工作区，见 tools/ollama.ps1）
#      2. 检查/启动 Streamlit 演示网站（自动挑选可用端口）
#      3. 打印访问地址
#
#  停止：
#      Ctrl+C 关闭本窗口即可（或分别运行 tools\ollama.ps1 -Stop）
# =============================================================================

param(
    [int]$Port = 8501,
    [switch]$SkipOllama
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
Set-Location $Root

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │  AgentGuard · 面向安全 Agent 的边界逃逸检测与风险隔离机制   │" -ForegroundColor Cyan
Write-Host "  │  第九届浙江省大学生网络与信息安全竞赛 · 网络安全作品挑战赛   │" -ForegroundColor Cyan
Write-Host "  └──────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------- 1. 本地大模型
if (-not $SkipOllama) {
    Write-Host "[1/2] 检查本地大模型（Ollama）…" -ForegroundColor White
    $probe = $null
    try {
        $probe = Invoke-WebRequest -Uri "http://127.0.0.1:11434/api/tags" -TimeoutSec 4 -UseBasicParsing
    }
    catch { }

    if ($probe -and $probe.StatusCode -eq 200) {
        $models = ($probe.Content | ConvertFrom-Json).models | ForEach-Object { $_.name }
        Write-Host "      ✓ 已在运行，本地模型：$($models -join ', ')" -ForegroundColor Green
    }
    else {
        Write-Host "      × 未运行，正在启动…" -ForegroundColor Yellow
        Write-Host "        （沙箱环境需要把 Ollama 的模型/缓存目录重定向到工作区）" -ForegroundColor DarkGray
        & (Join-Path $Root "tools\ollama.ps1")
        if ($LASTEXITCODE -ne 0) {
            Write-Host "      ! Ollama 启动失败：网站仍可用『脚本回放』模式演示" -ForegroundColor Yellow
            Write-Host "        （安全判定逻辑完全一致，只是思考文本来自预置轨迹）" -ForegroundColor DarkGray
        }
    }
    Write-Host ""
}
else {
    Write-Host "[1/2] 已跳过本地大模型检查（-SkipOllama）" -ForegroundColor DarkGray
    Write-Host ""
}

# ---------------------------------------------------------------- 2. 演示网站
Write-Host "[2/2] 启动演示网站…" -ForegroundColor White

function Test-Port([int]$p) {
    $c = New-Object System.Net.Sockets.TcpClient
    try { $c.Connect("127.0.0.1", $p); return $true } catch { return $false } finally { $c.Dispose() }
}

$chosen = 0
for ($p = $Port; $p -lt $Port + 20; $p++) {
    if (-not (Test-Port $p)) { $chosen = $p; break }
}
if ($chosen -eq 0) {
    Write-Host "      × $Port 起 20 个端口都被占用，请用 -Port 指定其它端口" -ForegroundColor Red
    exit 1
}
if ($chosen -ne $Port) {
    Write-Host "      ! 端口 $Port 已被占用，改用 $chosen" -ForegroundColor Yellow
}

$Libs = Join-Path $Root "libs"
$env:PYTHONPATH = $Libs
$env:PYTHONIOENCODING = "utf-8"

# ---- 定位 Python（`python` 可能不在 PATH 上，或只是 Store 占位程序）----
. (Join-Path $Root "tools\lib_python.ps1")
$Python = Resolve-AgentGuardPython
if (-not $Python) {
    Write-Host "      × 未找到可用的 Python 3 解释器。" -ForegroundColor Red
    Write-Host "        可用环境变量 AGENTGUARD_PYTHON 指定解释器绝对路径。" -ForegroundColor Yellow
    exit 1
}
$env:PATH = "$(Split-Path -Parent $Python);$env:PATH"

if (-not (Test-Path (Join-Path $Libs "streamlit"))) {
    Write-Host "      ! 未找到 libs/ 依赖，正在引导安装（需要网络）…" -ForegroundColor Yellow
    & $Python (Join-Path $Root "tools\bootstrap_libs.py") --clean streamlit pyyaml pytest
}

Write-Host ""
Write-Host "  ══════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "   演示网站已就绪：  http://127.0.0.1:$chosen" -ForegroundColor Green
Write-Host "  ══════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "   演示要点：" -ForegroundColor White
Write-Host "     1. 侧边栏「启用边界逃逸防护」复选框 = 唯一实验变量" -ForegroundColor Gray
Write-Host "     2. 先跑【用例 1 正常业务任务】证明不误伤" -ForegroundColor Gray
Write-Host "     3. 取消勾选防护 → 跑【用例 2 逃逸诱导】→ 看 Agent 读出私钥" -ForegroundColor Gray
Write-Host "     4. 勾选防护 → 再跑一次 → 动作在工具执行前被拦下" -ForegroundColor Gray
Write-Host ""
Write-Host "   停止服务：按 Ctrl+C" -ForegroundColor DarkGray
Write-Host ""

& $Python -m streamlit run (Join-Path $Root "app.py") --server.port $chosen --server.address 127.0.0.1
exit $LASTEXITCODE
