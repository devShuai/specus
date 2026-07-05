param(
    [string]$Configuration = "Release",
    [string]$Output = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Output)) {
    $Output = Join-Path $root "out\desktop-win-x64"
}

New-Item -ItemType Directory -Force -Path `
    (Join-Path $root "..\..\..\.appdata\NuGet"), `
    (Join-Path $root "..\..\..\.nuget\packages") | Out-Null
$workspaceRoot = (Resolve-Path (Join-Path $root "..\..\..")).Path
$env:APPDATA = Join-Path $workspaceRoot ".appdata"
$env:DOTNET_CLI_HOME = $workspaceRoot
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = "1"
$env:NUGET_PACKAGES = Join-Path $workspaceRoot ".nuget\packages"

dotnet publish (Join-Path $root "src\ShuaiTunnel.Client.Desktop\ShuaiTunnel.Client.Desktop.csproj") `
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
