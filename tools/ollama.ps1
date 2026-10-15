# 在本沙箱环境内启动 / 停止本地 Ollama 模型服务。
#
# 背景（很关键）
# -------------
# 本工程运行在受限文件沙箱中，只允许写工作区目录（工程根目录）。
# Ollama 默认要写 `E:\olla\manifests-v2`（模型目录）和 `C:\Users\<用户>\.ollama\cache`，
# 这两个写入都会被沙箱拒绝，导致服务虽然监听成功，但 `/api/tags` 直接返回 500，
# 表现就是"本地大模型不可用"。
#
# 本脚本的做法：
#   1. 把 Ollama 的写入目录重定向到工作区内（.ollama_models / .ollama_home）；
#   2. 首次运行把 OLLAMA_MODELS 里的模型**复制**进工作区模型库
#      （同分区复制约 400 MB/s，5 GB 模型约 10 余秒）；
#   3. 随后启动 serve。
#
# 在这台机器之外（评委的正常环境），直接用系统里的 Ollama 即可，
# 不需要本脚本 —— 它只是为了让演示在受限沙箱里也能跑起来。
#
# 用法：
#   .\tools\ollama.ps1            # 启动（幂等：已在运行则直接返回）
#   .\tools\ollama.ps1 -Stop      # 停止
#   .\tools\ollama.ps1 -Force     # 强制重新同步模型库后启动

param(
    [switch]$Stop,
    [switch]$Force,
    [string]$OllamaExe = "E:\oll\ollama.exe",
    [string]$SourceModels = $env:OLLAMA_MODELS
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$ModelsDst = Join-Path $Root ".ollama_models"
$HomeDst = Join-Path $Root ".ollama_home"

function Test-Ollama {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:11434/api/tags" -TimeoutSec 4 -UseBasicParsing
        return $r.StatusCode -eq 200
    }
    catch { return $false }
}

if ($Stop) {
    Get-Process ollama* -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "[→] 停止 ollama PID $($_.Id)" -ForegroundColor Yellow
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Host "[✓] 已停止" -ForegroundColor Green
    exit 0
}

if (Test-Ollama) {
    Write-Host "[✓] Ollama 已在运行，直接复用：http://127.0.0.1:11434" -ForegroundColor Green
    exit 0
}

if (-not (Test-Path $OllamaExe)) {
    Write-Host "[×] 未找到 ollama 可执行文件：$OllamaExe" -ForegroundColor Red
    Write-Host "    可用 -OllamaExe 指定路径。" -ForegroundColor Yellow
    exit 1
}

New-Item -ItemType Directory -Force -Path $ModelsDst, $HomeDst | Out-Null

# ---- 同步模型库（沙箱只允许写工作区，模型必须复制进来）----
if ($SourceModels -and (Test-Path $SourceModels) -and $SourceModels -ne $ModelsDst) {
    $need = $Force -or -not (Test-Path (Join-Path $ModelsDst "manifests"))
    if ($need) {
        Write-Host "[→] 同步模型库：$SourceModels -> $ModelsDst" -ForegroundColor Cyan
        Write-Host "    （同分区复制，约 400 MB/s）" -ForegroundColor DarkGray
        $sw = [Diagnostics.Stopwatch]::StartNew()
        foreach ($sub in @("blobs", "manifests", "metadata")) {
            $s = Join-Path $SourceModels $sub
            if (-not (Test-Path $s)) { continue }
            Copy-Item -Path $s -Destination $ModelsDst -Recurse -Force
        }
        $sw.Stop()
        Write-Host "[✓] 模型库同步完成（$([math]::Round($sw.Elapsed.TotalSeconds,1))s）" -ForegroundColor Green
    }
}
elseif (-not (Test-Path (Join-Path $ModelsDst "manifests"))) {
    Write-Host "[!] 未提供可用的 OLLAMA_MODELS 源目录，且工作区模型库为空。" -ForegroundColor Yellow
    Write-Host "    请设置环境变量 OLLAMA_MODELS 指向已有模型目录，或用 -SourceModels 指定。" -ForegroundColor Yellow
}

$env:OLLAMA_MODELS = $ModelsDst
$env:OLLAMA_HOME = $HomeDst
$env:HOME = $HomeDst
$env:USERPROFILE = $HomeDst

Write-Host "[→] 启动 ollama serve（写入目录已重定向到工作区）" -ForegroundColor Cyan
Write-Host "    OLLAMA_MODELS=$ModelsDst" -ForegroundColor DarkGray

& $OllamaExe serve
exit $LASTEXITCODE
