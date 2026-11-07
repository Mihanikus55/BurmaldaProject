[CmdletBinding()]
param([int]$Port = 5000)
$ErrorActionPreference = 'Stop'
$launcher = Join-Path $env:USERPROFILE '.codex\scripts\Invoke-ProjectPython.ps1'
if (Test-Path -LiteralPath $launcher) {
    & $launcher -Environment Documents -WorkingDirectory $PSScriptRoot -PythonArgs @('run_demo.py', '--port', [string]$Port)
} else {
    Push-Location -LiteralPath $PSScriptRoot
    try { & python 'run_demo.py' '--port' $Port } finally { Pop-Location }
}
