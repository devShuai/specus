[CmdletBinding()]
param(
    [ValidateSet("Auto", "Frontend", "Server", "All")]
    [string]$Mode = "Auto",
    [string]$HostName = "",
    [string]$SiteUrl = "",
    [switch]$Yes,
    [switch]$DryRun,
    [switch]$NoClean,
    [switch]$KeepRemoteTemp
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

if ([string]::IsNullOrWhiteSpace($HostName)) {
    $HostName = if ($env:DEPLOY_HOST) { $env:DEPLOY_HOST } else { "ali2" }
}
if ([string]::IsNullOrWhiteSpace($SiteUrl)) {
    $SiteUrl = if ($env:DEPLOY_SITE_URL) { $env:DEPLOY_SITE_URL } else { "https://tunnel.devshuai.com" }
}

if ($HostName -notmatch '^[A-Za-z0-9][A-Za-z0-9._@-]*$') {
    throw "Invalid SSH host. Configure ports and advanced options in ~/.ssh/config."
}
if ($SiteUrl -notmatch '^https?://[A-Za-z0-9.-]+(:[0-9]+)?/?$') {
    throw "SiteUrl must be an HTTP(S) origin without a path or query."
}
$SiteUrl = $SiteUrl.TrimEnd('/')

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path

function Write-DeployLog {
    param([string]$Message)
    Write-Host "[deploy] $Message"
}

function Format-CommandArgument {
    param([string]$Value)
    if ($Value -match '\s' -or $Value.Contains('"') -or $Value.Contains("'")) {
        return '"' + $Value.Replace('"', '\"') + '"'
    }
    return $Value
}

function Invoke-DeployCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Arguments = @()
    )
    $display = @($Command) + @($Arguments | ForEach-Object { Format-CommandArgument $_ })
    Write-Host ("+ " + ($display -join " "))
    if ($DryRun) {
        return
    }
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Command"
    }
}

function Require-Command {
    param([string[]]$Names)
    foreach ($name in $Names) {
        $found = Get-Command $name -ErrorAction SilentlyContinue
        if ($null -ne $found) {
            return $found.Source
        }
    }
    throw "Required command not found: $($Names -join ' or ')"
}

Push-Location $RepoRoot
try {
    $git = Require-Command @("git.exe", "git")
    $trackedChanges = @(& $git diff --name-only HEAD)
    if ($LASTEXITCODE -ne 0) { throw "git diff failed" }
    $untrackedChanges = @(& $git ls-files --others --exclude-standard)
    if ($LASTEXITCODE -ne 0) { throw "git ls-files failed" }
    $changedPaths = @($trackedChanges + $untrackedChanges | Where-Object { $_ } | Sort-Object -Unique)

    $frontendChanged = $false
    $serverChanged = $false
    foreach ($path in $changedPaths) {
        if ($path -like "apps/admin-web/*" -or
            $path -like "protocol/schemas/*" -or
            $path -like "deploy/openresty/*") {
            $frontendChanged = $true
        }
        if ($path -eq "pom.xml" -or
            $path -like "implementations/java/common/*" -or
            $path -like "implementations/java/server/*" -or
            $path -like "deploy/java-server/*") {
            $serverChanged = $true
        }
    }

    if ($Mode -eq "Auto") {
        if ($frontendChanged -and $serverChanged) {
            $Mode = "All"
        } elseif ($frontendChanged) {
            $Mode = "Frontend"
        } elseif ($serverChanged) {
            $Mode = "Server"
        } else {
            $Mode = "All"
            Write-Warning "Auto found no deploy-relevant workspace changes; redeploying all current sources."
        }
    }

    $deployFrontend = $Mode -eq "Frontend" -or $Mode -eq "All"
    $deployServer = $Mode -eq "Server" -or $Mode -eq "All"
    $branch = (& $git branch --show-current).Trim()
    if (-not $branch) { $branch = "(detached)" }

    Write-DeployLog "deployment plan"
    Write-Host "  mode:       $Mode"
    Write-Host "  host:       $HostName"
    Write-Host "  site:       $SiteUrl"
    Write-Host "  git branch: $branch"
    if ($changedPaths.Count -gt 0) {
        Write-Host "  workspace changes ($($changedPaths.Count)):"
        $changedPaths | Select-Object -First 20 | ForEach-Object { Write-Host "    - $_" }
        if ($changedPaths.Count -gt 20) {
            Write-Host "    - ... $($changedPaths.Count - 20) more"
        }
    } else {
        Write-Host "  workspace changes: none"
    }

    if (-not $DryRun -and -not $Yes) {
        $answer = Read-Host "Continue deploying $Mode to $HostName? [y/N]"
        if ($answer -notin @("y", "Y", "yes", "YES")) {
            Write-DeployLog "cancelled"
            return
        }
    }

    $npm = "npm"
    $maven = "mvn"
    $ssh = "ssh"
    $scp = "scp"
    if (-not $DryRun) {
        $ssh = Require-Command @("ssh.exe", "ssh")
        $scp = Require-Command @("scp.exe", "scp")
        if ($deployFrontend -or $deployServer) {
            $npm = Require-Command @("npm.cmd", "npm.exe", "npm")
        }
        if ($deployServer) {
            $maven = Require-Command @("mvn.cmd", "mvn.exe", "mvn")
        }
    }

    $jarPath = Join-Path $RepoRoot "implementations/java/server/target/tunnel-server-1.0-SNAPSHOT.jar"
    $assetName = "index-dry-run.js"

    if ($deployServer) {
        $mavenArguments = @("-pl", ":tunnel-server", "-am", "-DskipTests")
        if ($NoClean) {
            Write-Warning "Using the explicit non-clean Maven fallback."
            $mavenArguments += "package"
        } else {
            $mavenArguments += @("clean", "package")
        }
        Invoke-DeployCommand $maven $mavenArguments

        if (-not $DryRun) {
            $jar = Get-ChildItem (Join-Path $RepoRoot "implementations/java/server/target/tunnel-server-*.jar") |
                Where-Object { $_.Name -notlike "*.jar.original" } |
                Sort-Object LastWriteTimeUtc -Descending |
                Select-Object -First 1
            if ($null -eq $jar) { throw "No deployable tunnel-server jar found." }
            $jarPath = $jar.FullName
        }
    }

    if ($deployFrontend) {
        Push-Location (Join-Path $RepoRoot "apps/admin-web")
        try {
            Invoke-DeployCommand $npm @("run", "build:openresty")
        } finally {
            Pop-Location
        }

        if (-not $DryRun) {
            $asset = Get-ChildItem (Join-Path $RepoRoot "apps/admin-web/dist/assets/index-*.js") |
                Sort-Object Name |
                Select-Object -First 1
            if ($null -eq $asset) { throw "No hashed frontend entry asset found." }
            $assetName = $asset.Name
        }
    }

    $deployTag = if ($DryRun) { "dry-run" } else { Get-Date -Format "yyyyMMddHHmmss" }
    $remoteRoot = "/tmp/shuai-tunnel-deploy-$deployTag-$PID"
    $deploymentStarted = $false
    $deploymentSucceeded = $false

    try {
        Invoke-DeployCommand $ssh @($HostName, "mkdir -p $remoteRoot")
        if (-not $DryRun) { $deploymentStarted = $true }

        if ($deployServer) {
            Invoke-DeployCommand $scp @($jarPath, "${HostName}:${remoteRoot}/tunnel-server.jar")
            Invoke-DeployCommand $scp @("-r", (Join-Path $RepoRoot "deploy/java-server/systemd"), "${HostName}:${remoteRoot}/java-systemd")
        }
        if ($deployFrontend) {
            Invoke-DeployCommand $scp @("-r", (Join-Path $RepoRoot "deploy/openresty"), "${HostName}:${remoteRoot}/openresty")
            Invoke-DeployCommand $scp @("-r", (Join-Path $RepoRoot "apps/admin-web/dist"), "${HostName}:${remoteRoot}/admin-web-dist")
        }

        if ($deployServer) {
            Invoke-DeployCommand $ssh @($HostName, "sudo bash $remoteRoot/java-systemd/update.sh $remoteRoot/tunnel-server.jar")
        }
        if ($deployFrontend) {
            Invoke-DeployCommand $ssh @($HostName, "sudo env ADMIN_WEB_DIST=$remoteRoot/admin-web-dist bash $remoteRoot/openresty/install-admin-web.sh")
            Invoke-DeployCommand $ssh @($HostName, "sudo openresty -s reload")
        }

        Write-DeployLog "verifying remote deployment"
        if ($deployServer) {
            Invoke-DeployCommand $ssh @($HostName, "systemctl is-active tunnel-server")
        }
        if ($deployFrontend) {
            Invoke-DeployCommand $ssh @($HostName, "sudo openresty -t")
            Invoke-DeployCommand $ssh @($HostName, "curl -kfsSI $SiteUrl/")
            Invoke-DeployCommand $ssh @($HostName, "curl -kfsSI -H 'Accept-Encoding: br, gzip' $SiteUrl/assets/$assetName")
        }

        $deploymentSucceeded = $true
        if ($DryRun) {
            Write-DeployLog "dry run completed; no build or remote command was executed"
        } else {
            Write-DeployLog "deployment completed successfully"
        }
    } finally {
        if ($deploymentStarted) {
            if ($deploymentSucceeded -and -not $KeepRemoteTemp) {
                try {
                    Invoke-DeployCommand $ssh @($HostName, "rm -rf $remoteRoot")
                } catch {
                    Write-Warning "Could not remove successful deployment temp directory: $remoteRoot"
                }
            } else {
                Write-Warning "Remote deployment files were kept for diagnosis: ${HostName}:${remoteRoot}"
            }
        }
    }
} finally {
    Pop-Location
}
