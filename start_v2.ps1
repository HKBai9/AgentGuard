param(
    [ValidateSet('Live','Gateway','Agent','Console','Replay','Scenario','Evaluation','Report')]
    [string]$Mode = 'Live',
    [string]$Python = '',
    [string]$Config = 'config/v2.example.json',
    [string]$Task = '',
    [string]$Recording = '',
    [string]$Scenario = 'task_grants',
    [string]$Output = 'logs/v2-evaluation',
    [switch]$Execute,
    [switch]$Cloud
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not $Python) {
    $candidate = Join-Path $PSScriptRoot '.venv-integration/Scripts/python.exe'
    if (Test-Path -LiteralPath $candidate) { $Python = $candidate } else { $Python = 'python' }
}
if ([IO.Path]::IsPathRooted($Config)) {
    $env:AGENTGUARD_V2_CONFIG = [IO.Path]::GetFullPath($Config)
} else {
    $env:AGENTGUARD_V2_CONFIG = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $Config))
}
switch ($Mode) {
    'Live' {
        $arguments = @('-m','agentguard.v2.launch','--config',$Config)
        if ($Task) { $arguments += @('--task',$Task) }
        & $Python @arguments
    }
    'Gateway' { & $Python -m agentguard.v2.gateway.cli --factory agentguard.v2.application:factory }
    'Agent' {
        if (-not $Task) { throw '-Task is required for Agent mode' }
        & $Python -m agentguard.v2.application --config $Config --task $Task
    }
    'Console' {
        Remove-Item Env:AGENTGUARD_V2_REPLAY -ErrorAction SilentlyContinue
        & $Python -c 'from agentguard.v2.console import main; main()'
    }
    'Replay' {
        if (-not $Recording -or -not (Test-Path -LiteralPath $Recording)) { throw 'Supply an existing -Recording JSON file' }
        $env:AGENTGUARD_V2_REPLAY = (Resolve-Path -LiteralPath $Recording).Path
        & $Python -c 'from agentguard.v2.console import main; main()'
    }
    'Scenario' {
        $arguments = @('-m','benchmarks.v2.scenarios',$Scenario,'--output',$Output)
        if ($Execute) { $arguments += '--execute' }
        if ($Cloud) { $arguments += @('--mode','live','--config',$Config) }
        & $Python @arguments
    }
    'Evaluation' {
        $arguments = @('-m','benchmarks.v2.run','--output',$Output)
        if ($Execute) { $arguments += '--execute' }
        if ($Cloud) { $arguments += @('--mode','live','--config',$Config) }
        & $Python @arguments
    }
    'Report' { & $Python -m benchmarks.v2.report $Output }
}
if ($LASTEXITCODE -ne 0) { throw "AgentGuard command failed ($LASTEXITCODE)" }
