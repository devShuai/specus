[CmdletBinding()]
param(
    [Parameter()]
    [string[]] $ConfigPath = @(),

    [Parameter()]
    [string[]] $SqliteDatabase = @(),

    [Parameter()]
    [switch] $Recursive,

    [Parameter()]
    [switch] $RewriteDomain,

    [Parameter()]
    [switch] $KeepConfigFilename,

    [Parameter()]
    [switch] $KeepDatabaseFilename,

    [Parameter()]
    [switch] $NoDatabaseBackup,

    [Parameter()]
    [switch] $Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvironmentMigration = Join-Path $ScriptRoot "migrate_env.py"
$SqliteMigration = Join-Path $ScriptRoot "database\migrate_sqlite.py"

function Resolve-Python {
    foreach ($candidate in @("python3", "python")) {
        $command = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return $command.Source
        }
    }
    throw "Python 3 is required for the migration scripts."
}

function Invoke-MigrationCommand {
    param(
        [Parameter(Mandatory)]
        [string[]] $Arguments
    )

    Write-Host ("$Python " + ($Arguments -join " "))
    & $Python @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Migration command failed with exit code $LASTEXITCODE."
    }
}

if ($ConfigPath.Count -eq 0 -and $SqliteDatabase.Count -eq 0) {
    throw "Specify at least one -ConfigPath or -SqliteDatabase."
}

$Python = Resolve-Python

if ($ConfigPath.Count -gt 0) {
    $arguments = @($EnvironmentMigration)
    $arguments += $ConfigPath
    if ($Apply) {
        $arguments += "--apply"
    }
    if ($Recursive) {
        $arguments += "--recursive"
    }
    if (-not $KeepConfigFilename) {
        $arguments += "--rename-files"
    }
    if ($RewriteDomain) {
        $arguments += "--rewrite-domain"
    }
    Invoke-MigrationCommand -Arguments $arguments
}

foreach ($database in $SqliteDatabase) {
    $arguments = @($SqliteMigration, $database)
    if ($Apply) {
        $arguments += "--apply"
    }
    if ($KeepDatabaseFilename) {
        $arguments += "--keep-filename"
    }
    if ($NoDatabaseBackup) {
        $arguments += "--no-backup"
    }
    Invoke-MigrationCommand -Arguments $arguments
}

if (-not $Apply) {
    Write-Host "Plan completed. Re-run with -Apply after stopping every process that uses these files."
}
