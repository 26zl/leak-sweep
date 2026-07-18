[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

if (Get-Command py.exe -ErrorAction SilentlyContinue) {
    $pythonExe = "py.exe"
    $pythonPrefix = @("-3")
} elseif (Get-Command python.exe -ErrorAction SilentlyContinue) {
    $pythonExe = "python.exe"
    $pythonPrefix = @()
} else {
    throw "Python is missing. Install Python 3.9-3.14 and rerun this script."
}

& $pythonExe @pythonPrefix -c `
    "import sys; raise SystemExit(not ((3, 9) <= sys.version_info[:2] < (3, 15)))"
if ($LASTEXITCODE -ne 0) {
    throw "Python 3.9-3.14 is required."
}

$toolHints = @{
    "git.exe" = "winget install --id Git.Git -e"
    "gh.exe" = "winget install --id GitHub.cli -e"
    "gitleaks.exe" = "winget install --id Gitleaks.Gitleaks -e"
}
foreach ($tool in $toolHints.Keys) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool is missing. Install it with: $($toolHints[$tool])"
    }
}

& $pythonExe @pythonPrefix -m venv .venv
if ($LASTEXITCODE -ne 0) {
    throw "Could not create .venv."
}

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
& $venvPython -m pip install --require-hashes -r requirements.lock
if ($LASTEXITCODE -ne 0) {
    throw "Dependency installation failed."
}

$personal = Join-Path $PSScriptRoot "personal.txt"
if (-not (Test-Path -LiteralPath $personal)) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "personal.example.txt") -Destination $personal
    Write-Host "Created personal.txt from the example; edit it with your identifiers."
}

$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $personal /inheritance:r /grant:r "*${sid}:F" /q | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Could not restrict personal.txt to the current Windows user."
}

Write-Host ""
Write-Host "Done. Next:"
Write-Host "  1. Edit personal.txt"
Write-Host "  2. Run: gh auth login (if needed)"
Write-Host "  3. Run: .\.venv\Scripts\python.exe .\sweep.py"
