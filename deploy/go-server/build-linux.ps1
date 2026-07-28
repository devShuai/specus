[CmdletBinding()]
param(
    [ValidateSet("amd64", "arm64")]
    [string]$Architecture = "amd64",
    [string]$OutputRoot = "",
    [switch]$SkipFrontend,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$ServerRoot = Join-Path $RepoRoot "implementations/go/server"
$AdminWebRoot = Join-Path $RepoRoot "apps/admin-web"
$SystemdRoot = Join-Path $PSScriptRoot "systemd"

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $PSScriptRoot "out"
} elseif (-not [System.IO.Path]::IsPathRooted($OutputRoot)) {
    $OutputRoot = Join-Path (Get-Location) $OutputRoot
}
$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
$PackageName = "specus-server-linux-$Architecture"
$PackageRoot = Join-Path $OutputRoot $PackageName
$BinaryPath = Join-Path $PackageRoot "specus-server"
$ArchivePath = Join-Path $OutputRoot "$PackageName.tar.gz"

function Write-BuildLog {
    param([string]$Message)
    Write-Host "[go-server-build] $Message"
}

function Require-Command {
    param([string]$Name)
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        throw "Required command not found: $Name"
    }
    return $command.Source
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Arguments = @()
    )
    Write-Host ("+ " + ((@($Command) + $Arguments) -join " "))
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Command"
    }
}

function Test-AdminWebDependenciesCurrent {
    $packageLock = Join-Path $AdminWebRoot "package-lock.json"
    $installedLock = Join-Path $AdminWebRoot "node_modules/.package-lock.json"
    if (-not (Test-Path -LiteralPath $packageLock) -or -not (Test-Path -LiteralPath $installedLock)) {
        return $false
    }
    return (Get-Item -LiteralPath $installedLock).LastWriteTimeUtc -ge
        (Get-Item -LiteralPath $packageLock).LastWriteTimeUtc
}

function Write-Utf8NoBom {
    param(
        [string]$Path,
        [string]$Content
    )
    [System.IO.File]::WriteAllText(
        $Path,
        $Content,
        [System.Text.UTF8Encoding]::new($false)
    )
}

function Restore-EnvironmentValue {
    param(
        [string]$Name,
        [bool]$WasPresent,
        [AllowEmptyString()][string]$Value
    )
    if (-not $WasPresent) {
        Remove-Item -LiteralPath "Env:$Name" -ErrorAction SilentlyContinue
    } else {
        Set-Item -LiteralPath "Env:$Name" -Value $Value
    }
}

$go = Require-Command "go"
$git = Require-Command "git"

if (-not $SkipFrontend) {
    $npm = Require-Command "npm"
    $npmCache = Join-Path $RepoRoot ".tmp/go-server-build/npm-cache"
    New-Item -ItemType Directory -Force -Path $npmCache | Out-Null
    $hadNpmCache = Test-Path -LiteralPath "Env:npm_config_cache"
    $originalNpmCache = $env:npm_config_cache
    try {
        $env:npm_config_cache = $npmCache
        if (-not (Test-AdminWebDependenciesCurrent)) {
            Write-BuildLog "Installing admin-web dependencies"
            Push-Location $AdminWebRoot
            try {
                Invoke-Checked $npm @("ci", "--cache", $npmCache, "--prefer-offline")
            } finally {
                Pop-Location
            }
        }

        Write-BuildLog "Building admin SPA for Go embedding"
        Invoke-Checked $npm @("--prefix", $AdminWebRoot, "run", "deploy:go")
    } finally {
        Restore-EnvironmentValue "npm_config_cache" $hadNpmCache $originalNpmCache
    }
} else {
    $embeddedIndex = Join-Path $ServerRoot "web/static/index.html"
    if (-not (Test-Path -LiteralPath $embeddedIndex)) {
        throw "Embedded admin SPA is missing. Remove -SkipFrontend or generate web/static first."
    }
    Write-BuildLog "Using existing embedded admin SPA"
}

$cacheRoot = Join-Path $RepoRoot ".tmp/go-server-build"
New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null
$hadGoCache = Test-Path -LiteralPath "Env:GOCACHE"
$hadGoModCache = Test-Path -LiteralPath "Env:GOMODCACHE"
$hadGoOs = Test-Path -LiteralPath "Env:GOOS"
$hadGoArch = Test-Path -LiteralPath "Env:GOARCH"
$hadCgoEnabled = Test-Path -LiteralPath "Env:CGO_ENABLED"
$originalGoCache = $env:GOCACHE
$originalGoModCache = $env:GOMODCACHE
$originalGoOs = $env:GOOS
$originalGoArch = $env:GOARCH
$originalCgoEnabled = $env:CGO_ENABLED
$env:GOCACHE = Join-Path $cacheRoot "go-cache"
$env:GOMODCACHE = Join-Path $cacheRoot "mod-cache"
$env:GOOS = ""
$env:GOARCH = ""
$env:CGO_ENABLED = "0"

Push-Location $ServerRoot
try {
    if (-not $SkipTests) {
        Write-BuildLog "Running Go server tests on the build host"
        Invoke-Checked $go @("test", "./...")
    }

    New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
    $expectedPrefix = $OutputRoot.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    $resolvedPackageRoot = [System.IO.Path]::GetFullPath($PackageRoot)
    if (-not $resolvedPackageRoot.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean package path outside output root: $resolvedPackageRoot"
    }
    if (Test-Path -LiteralPath $resolvedPackageRoot) {
        Remove-Item -LiteralPath $resolvedPackageRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $resolvedPackageRoot | Out-Null

    Write-BuildLog "Cross-compiling linux/$Architecture"
    $env:GOOS = "linux"
    $env:GOARCH = $Architecture
    Invoke-Checked $go @(
        "build",
        "-trimpath",
        "-ldflags=-s -w",
        "-o", $BinaryPath,
        "./cmd/specus-server"
    )
} finally {
    Pop-Location
    Restore-EnvironmentValue "GOCACHE" $hadGoCache $originalGoCache
    Restore-EnvironmentValue "GOMODCACHE" $hadGoModCache $originalGoModCache
    Restore-EnvironmentValue "GOOS" $hadGoOs $originalGoOs
    Restore-EnvironmentValue "GOARCH" $hadGoArch $originalGoArch
    Restore-EnvironmentValue "CGO_ENABLED" $hadCgoEnabled $originalCgoEnabled
}

$header = [System.IO.File]::ReadAllBytes($BinaryPath)
if ($header.Length -lt 4 -or $header[0] -ne 0x7f -or $header[1] -ne 0x45 -or
    $header[2] -ne 0x4c -or $header[3] -ne 0x46) {
    throw "Cross-compiled output is not an ELF binary: $BinaryPath"
}

Copy-Item -LiteralPath $SystemdRoot -Destination (Join-Path $PackageRoot "systemd") -Recurse -Force

$commit = (& $git -C $RepoRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Unable to resolve git commit"
}
$dirtyOutput = @(& $git -C $RepoRoot status --porcelain)
$dirty = $dirtyOutput.Count -gt 0
$hash = (Get-FileHash -LiteralPath $BinaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
$binarySize = (Get-Item -LiteralPath $BinaryPath).Length
$builtAt = [DateTimeOffset]::UtcNow.ToString("o")
$goVersion = (& $go version).Trim()

$manifest = [ordered]@{
    name         = "specus-server"
    target       = "linux/$Architecture"
    commit       = $commit
    dirty        = $dirty
    builtAtUtc   = $builtAt
    goVersion    = $goVersion
    cgoEnabled   = $false
    binary       = "specus-server"
    sizeBytes    = $binarySize
    sha256       = $hash
    healthPath   = "/health"
    systemdUnit  = "specus-server-go.service"
}
Write-Utf8NoBom (Join-Path $PackageRoot "manifest.json") (($manifest | ConvertTo-Json -Depth 4) + "`n")
Write-Utf8NoBom (Join-Path $PackageRoot "SHA256SUMS") "$hash  specus-server`n"

$tar = Get-Command "tar" -ErrorAction SilentlyContinue
if ($null -ne $tar) {
    if (Test-Path -LiteralPath $ArchivePath) {
        Remove-Item -LiteralPath $ArchivePath -Force
    }
    Write-BuildLog "Creating deployment archive"
    Invoke-Checked $tar.Source @("-czf", $ArchivePath, "-C", $PackageRoot, ".")
} else {
    Write-Warning "tar was not found; package directory was created without a .tar.gz archive."
}

Write-BuildLog "Build completed"
Write-BuildLog "  package: $PackageRoot"
if (Test-Path -LiteralPath $ArchivePath) {
    Write-BuildLog "  archive: $ArchivePath"
}
Write-BuildLog "  sha256:  $hash"
