# claude-guard bootstrap (Windows PowerShell).
#
# One-line install, idempotent. Detects git; clones (or pulls) into
# $env:USERPROFILE\.claude\guard, or downloads a zip from GitHub if git is
# missing. Stops any running dashboard, then runs install.py --global --yes.
#
# Usage:
#   iwr https://raw.githubusercontent.com/Gabriel-Dalton/claude-guard/main/bootstrap.ps1 -UseBasicParsing | iex

$ErrorActionPreference = "Stop"

$RepoUrl = "https://github.com/Gabriel-Dalton/claude-guard"
$ZipUrl  = "https://github.com/Gabriel-Dalton/claude-guard/archive/refs/heads/main.zip"
$InstallDir = Join-Path $env:USERPROFILE ".claude\guard"

function Write-Info  { param($m) Write-Host "[..] $m" -ForegroundColor Cyan }
function Write-Ok    { param($m) Write-Host "[ok] $m" -ForegroundColor Green }
function Write-Fail  { param($m) Write-Host "[!!] $m" -ForegroundColor Red }

function Test-Command {
    param($Name)
    $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

# Locate Python
$Python = $null
foreach ($candidate in @("python", "py", "python3")) {
    if (Test-Command $candidate) { $Python = (Get-Command $candidate).Source; break }
}
if (-not $Python) {
    Write-Fail "Python was not found on PATH. Install Python 3.9+ from python.org and retry."
    exit 1
}

# Make sure parent dir exists.
$parent = Split-Path -Parent $InstallDir
if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }

# Stop a running dashboard so files in the install dir aren't held open.
if (Test-Path (Join-Path $InstallDir "dashboard.py")) {
    try {
        & $Python (Join-Path $InstallDir "dashboard.py") --stop *> $null
    } catch {
        # ignore — older installs may not have --stop yet; the install will
        # still succeed once the dashboard exits naturally.
    }
}

if (Test-Command "git") {
    if (Test-Path (Join-Path $InstallDir ".git")) {
        Write-Info "updating $InstallDir via git pull..."
        & git -C $InstallDir pull --ff-only
        if ($LASTEXITCODE -ne 0) { Write-Fail "git pull failed."; exit 1 }
    } elseif ((Test-Path $InstallDir) -and ((Get-ChildItem -Force $InstallDir | Measure-Object).Count -gt 0)) {
        Write-Info "existing non-git install at $InstallDir; leaving files in place."
    } else {
        Write-Info "cloning $RepoUrl into $InstallDir..."
        & git clone --depth 1 $RepoUrl $InstallDir
        if ($LASTEXITCODE -ne 0) { Write-Fail "git clone failed."; exit 1 }
    }
} else {
    if (Test-Path (Join-Path $InstallDir ".git")) {
        Write-Fail "git is missing but $InstallDir is a git checkout. Install git or remove that directory first."
        exit 1
    }
    Write-Info "git not found; downloading zip..."
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("cg-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    try {
        $zip = Join-Path $tmp "cg.zip"
        Invoke-WebRequest -Uri $ZipUrl -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath $tmp -Force
        $extracted = Get-ChildItem -Path $tmp -Directory | Where-Object { $_.Name -like "claude-guard-*" } | Select-Object -First 1
        if (-not $extracted) {
            Write-Fail "could not find extracted directory in zip."
            exit 1
        }
        if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }
        Copy-Item -Path (Join-Path $extracted.FullName "*") -Destination $InstallDir -Recurse -Force
    } finally {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $tmp
    }
}

Write-Info "running installer..."
& $Python (Join-Path $InstallDir "install.py") --global --yes
if ($LASTEXITCODE -ne 0) {
    Write-Fail "install.py exited with code $LASTEXITCODE."
    exit $LASTEXITCODE
}

Write-Ok "claude-guard installed. Open a new Claude Code session."
