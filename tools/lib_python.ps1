# 共享工具函数：定位可用的 Python 3 解释器。
#
# 为什么需要它：
#   部分 Windows 环境里 `python` 不在 PATH 上，或只解析到 Microsoft Store 的
#   占位程序（WindowsApps\python.exe）。直接调用 `python` 会以 exit code 9009
#   失败，而且报错往往不明显（脚本看起来"跑完了"但什么都没启动）。
#
# 用法（在被 dot-source 的脚本里）：
#   . "$PSScriptRoot\lib_python.ps1"
#   $Python = Resolve-AgentGuardPython

function Resolve-AgentGuardPython {
    [CmdletBinding()]
    param()

    $candidates = @()

    if ($env:AGENTGUARD_PYTHON) { $candidates += $env:AGENTGUARD_PYTHON }

    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -notlike "*WindowsApps*") { $candidates += $cmd.Source }
    $cmd3 = Get-Command python3 -ErrorAction SilentlyContinue
    if ($cmd3 -and $cmd3.Source -notlike "*WindowsApps*") { $candidates += $cmd3.Source }

    $candidates += @(
        "C:\Users\$env:USERNAME\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "C:\Python313\python.exe",
        "C:\Python312\python.exe",
        "C:\Python311\python.exe"
    )

    if ($env:LOCALAPPDATA) {
        $glob = Get-ChildItem "$env:LOCALAPPDATA\Programs\Python" -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending
        foreach ($d in $glob) {
            $candidates += (Join-Path $d.FullName "python.exe")
        }
    }

    foreach ($c in $candidates) {
        if (-not $c -or -not (Test-Path $c)) { continue }
        # 真正执行一次，排除 WindowsApps 占位程序
        $out = & $c -c "print('ok')" 2>$null
        if ($LASTEXITCODE -eq 0 -and "$out" -eq "ok") {
            return $c
        }
    }
    return $null
}
