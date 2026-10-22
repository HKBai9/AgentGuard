param(
    [string]$Python = "python",
    [string]$Output = "",
    [switch]$SkipInstall
)
$ErrorActionPreference = "Stop"
$ScriptPath = Join-Path $PSScriptRoot "verify_runtime.py"
$Arguments = @($ScriptPath, "--powershell-version", $PSVersionTable.PSVersion.ToString())
if ($Output) { $Arguments += @("--output", $Output) }
if ($SkipInstall) { $Arguments += "--skip-install" }
& $Python @Arguments
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
