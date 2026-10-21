param([string]$Python = "", [switch]$Live)
$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
if (-not $Python) {
    $localPython = Join-Path $repoRoot ".venv/Scripts/python.exe"
    if (Test-Path -LiteralPath $localPython) { $Python = $localPython }
    else { $Python = "python" }
}
Push-Location -LiteralPath $repoRoot
try {
    & $Python -c "import sys; print(sys.version); sys.exit(0 if sys.version_info >= (3,12) else 2)"
    if ($LASTEXITCODE -ne 0) { throw "Python 3.12+ required; pass -Python with its executable path." }
    & $Python -m pytest tests/v2/guard tests/v2/host -q
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    if ($Live) {
        if ($env:AGENTGUARD_V2_CLOUD_ENABLED -ne "1") { throw "Live mode requires AGENTGUARD_V2_CLOUD_ENABLED=1." }
        & $Python examples/v2/cloud_smoke.py
        exit $LASTEXITCODE
    }
    Write-Output "Offline checks passed. No cloud request was made; A01 contract/runtime integration is separate."
} finally {
    Pop-Location
}
