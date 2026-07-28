param(
    [string]$Configuration = "Release",
    [string]$Output = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$usingDefaultOutput = [string]::IsNullOrWhiteSpace($Output)
if ($usingDefaultOutput) {
    $Output = Join-Path $root "out\desktop-win-x64"
} elseif (-not [System.IO.Path]::IsPathRooted($Output)) {
    $Output = Join-Path (Get-Location) $Output
}
$Output = [System.IO.Path]::GetFullPath($Output)

if ($usingDefaultOutput) {
    $outputRoot = [System.IO.Path]::GetFullPath((Join-Path $root "out"))
    $expectedPrefix = $outputRoot.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $Output.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean package path outside output root: $Output"
    }
    if (Test-Path -LiteralPath $Output) {
        Remove-Item -LiteralPath $Output -Recurse -Force
    }
} elseif ((Test-Path -LiteralPath $Output) -and
    @(Get-ChildItem -LiteralPath $Output -Force).Count -gt 0) {
    throw "Custom output directory must be empty: $Output"
}
New-Item -ItemType Directory -Force -Path $Output | Out-Null

New-Item -ItemType Directory -Force -Path `
    (Join-Path $root "..\..\..\.appdata\NuGet"), `
    (Join-Path $root "..\..\..\.nuget\packages") | Out-Null
$workspaceRoot = (Resolve-Path (Join-Path $root "..\..\..")).Path
$env:APPDATA = Join-Path $workspaceRoot ".appdata"
$env:DOTNET_CLI_HOME = $workspaceRoot
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = "1"
$env:NUGET_PACKAGES = Join-Path $workspaceRoot ".nuget\packages"

dotnet publish (Join-Path $root "src\Specus.Client.Desktop\Specus.Client.Desktop.csproj") `
    -c $Configuration `
    -r win-x64 `
    -p:SelfContained=true `
    -p:PublishSingleFile=true `
    -p:EnableCompressionInSingleFile=true `
    -p:NuGetAudit=false `
    -p:RestoreIgnoreFailedSources=true `
    -o $Output
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE"
}

Write-Host "Desktop package written to $Output"
