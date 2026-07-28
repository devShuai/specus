[CmdletBinding()]
param(
    [string]$HostName = "",
    [ValidateSet("amd64", "arm64")]
    [string]$Architecture = "amd64",
    [string]$EnvFile = "",
    [string]$HealthUrl = "http://127.0.0.1:8088/health",
    [string]$SiteUrl = "",
    [switch]$SkipBuild,
    [switch]$SkipFrontend,
    [switch]$SkipTests,
    [switch]$ReplaceJava,
    [switch]$Yes,
    [switch]$DryRun,
    [switch]$KeepRemoteTemp
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../../..")).Path
$GoDeployRoot = Join-Path $RepoRoot "deploy/go-server"
$BuildScript = Join-Path $GoDeployRoot "build-linux.ps1"
$PackageRoot = Join-Path $GoDeployRoot "out/specus-server-linux-$Architecture"
$BinaryPath = Join-Path $PackageRoot "specus-server"
$SystemdRoot = Join-Path $GoDeployRoot "systemd"
$AdminWebRoot = Join-Path $RepoRoot "apps/admin-web"
$AdminWebDist = Join-Path $AdminWebRoot "dist"
$OpenRestyRoot = Join-Path $RepoRoot "deploy/openresty"

if ([string]::IsNullOrWhiteSpace($HostName)) {
    $HostName = if ($env:GO_SERVER_DEPLOY_HOST) { $env:GO_SERVER_DEPLOY_HOST } else { "ali2" }
}
if ([string]::IsNullOrWhiteSpace($SiteUrl)) {
    $SiteUrl = if ($env:GO_SERVER_DEPLOY_SITE_URL) {
        $env:GO_SERVER_DEPLOY_SITE_URL
    } else {
        "https://specus.devshuai.com"
    }
}
if ($HostName -notmatch '^[A-Za-z0-9][A-Za-z0-9._@-]*$') {
    throw "Invalid SSH host. Configure ports and advanced options in ~/.ssh/config."
}
if ($HealthUrl -notmatch '^https?://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?/[A-Za-z0-9._~/-]*$') {
    throw "HealthUrl must be a loopback HTTP(S) URL without a query or fragment."
}
if ($SiteUrl -notmatch '^https?://[A-Za-z0-9.-]+(:[0-9]+)?/?$') {
    throw "SiteUrl must be an HTTP(S) origin without a path, query, or fragment."
}
$SiteUrl = $SiteUrl.TrimEnd("/")
if ($ReplaceJava -and -not [string]::IsNullOrWhiteSpace($EnvFile)) {
    throw "-ReplaceJava builds the Go environment from the remote Java environment; do not combine it with -EnvFile."
}

if (-not [string]::IsNullOrWhiteSpace($EnvFile)) {
    if (-not [System.IO.Path]::IsPathRooted($EnvFile)) {
        $EnvFile = Join-Path (Get-Location) $EnvFile
    }
    $EnvFile = [System.IO.Path]::GetFullPath($EnvFile)
    if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) {
        throw "Environment file not found: $EnvFile"
    }
}

function Write-DeployLog {
    param([string]$Message)
    Write-Host "[go-server-deploy] $Message"
}

function Require-Command {
    param([string]$Name)
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        throw "Required command not found: $Name"
    }
    return $command.Source
}

function Format-CommandArgument {
    param([string]$Value)
    if ($Value -match '\s' -or $Value.Contains('"') -or $Value.Contains("'")) {
        return '"' + $Value.Replace('"', '\"') + '"'
    }
    return $Value
}

function Invoke-Checked {
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

function ConvertTo-ShellSingleQuoted {
    param([string]$Value)
    return "'" + $Value.Replace("'", "'`"`"'`"`"'") + "'"
}

if (-not $SkipBuild) {
    $buildParameters = @{
        Architecture = $Architecture
    }
    $arguments = @("-Architecture", $Architecture)
    if ($SkipFrontend) {
        $buildParameters.SkipFrontend = $true
        $arguments += "-SkipFrontend"
    }
    if ($SkipTests) {
        $buildParameters.SkipTests = $true
        $arguments += "-SkipTests"
    }
    Write-DeployLog "Building linux/$Architecture package"
    if ($DryRun) {
        Write-Host ("+ powershell " + (Format-CommandArgument $BuildScript) + " " + ($arguments -join " "))
    } else {
        & $BuildScript @buildParameters
    }
}

$frontendAssetName = "index-dry-run.js"
if (-not $SkipFrontend) {
    $npm = Require-Command "npm"
    Write-DeployLog "Preparing OpenResty admin frontend"
    Invoke-Checked $npm @("--prefix", $AdminWebRoot, "run", "precompress")

    if (-not $DryRun) {
        $frontendIndex = Join-Path $AdminWebDist "index.html"
        if (-not (Test-Path -LiteralPath $frontendIndex -PathType Leaf)) {
            throw "OpenResty frontend is missing: $frontendIndex. Remove -SkipBuild or build apps/admin-web/dist first."
        }
        $frontendAsset = Get-ChildItem -LiteralPath (Join-Path $AdminWebDist "assets") -Filter "index-*.js" |
            Sort-Object Name |
            Select-Object -First 1
        if ($null -eq $frontendAsset) {
            throw "No hashed OpenResty frontend entry asset found under $AdminWebDist/assets."
        }
        $frontendAssetName = $frontendAsset.Name
    }
}

if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    if (-not $DryRun) {
        throw "Linux binary not found: $BinaryPath"
    }
    $binaryHash = ("0" * 64)
} else {
    $binaryHash = (Get-FileHash -LiteralPath $BinaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

$ssh = Require-Command "ssh"
$scp = Require-Command "scp"
$timestamp = Get-Date -Format "yyyyMMddHHmmss"
$remoteRoot = "/tmp/specus-go-server-deploy-$timestamp-$PID-$Architecture"
$expectedMachine = if ($Architecture -eq "amd64") { "x86_64" } else { "aarch64" }
$envDescription = if ($ReplaceJava) {
    "migrate remote Java environment with automatic rollback"
} elseif ([string]::IsNullOrWhiteSpace($EnvFile)) {
    "preserve existing; first install remains stopped"
} else {
    "use $EnvFile on first install"
}

Write-Host ""
Write-Host "Go server deployment"
Write-Host "  host:         $HostName"
Write-Host "  target:       linux/$Architecture"
Write-Host "  binary:       $BinaryPath"
Write-Host "  sha256:       $binaryHash"
Write-Host "  environment:  $envDescription"
Write-Host "  replace Java: $([bool]$ReplaceJava)"
Write-Host "  health:       $HealthUrl"
Write-Host "  OpenResty:    $(if ($SkipFrontend) { 'skip' } else { "deploy to $SiteUrl" })"
Write-Host ""

if (-not $Yes -and -not $DryRun) {
    $answer = Read-Host "Continue? [y/N]"
    if ($answer -notmatch '^(?i:y|yes)$') {
        Write-DeployLog "Cancelled"
        exit 0
    }
}

$success = $false
$localRemoteScript = $null
try {
    Invoke-Checked $ssh @($HostName, "umask 077 && mkdir -p -- $(ConvertTo-ShellSingleQuoted $remoteRoot)")
    Invoke-Checked $scp @($BinaryPath, "$($HostName):$remoteRoot/specus-server")
    Invoke-Checked $scp @("-r", $SystemdRoot, "$($HostName):$remoteRoot/systemd")
    if (-not $SkipFrontend) {
        Invoke-Checked $scp @("-r", $OpenRestyRoot, "$($HostName):$remoteRoot/openresty")
        Invoke-Checked $scp @("-r", $AdminWebDist, "$($HostName):$remoteRoot/admin-web-dist")
    }
    if (-not [string]::IsNullOrWhiteSpace($EnvFile)) {
        Invoke-Checked $scp @($EnvFile, "$($HostName):$remoteRoot/specus-server.env")
    }

    $remoteEnv = if ([string]::IsNullOrWhiteSpace($EnvFile)) { "" } else { "$remoteRoot/specus-server.env" }
    $remoteTemplate = @'
set -Eeuo pipefail

report_remote_error() {
  local status=$?
  local line="${BASH_LINENO[0]:-unknown}"
  echo "[go-server-deploy] Remote deployment failed at line $line (exit $status)" >&2
  return "$status"
}
trap report_remote_error ERR

REMOTE_ROOT=__REMOTE_ROOT__
BINARY="$REMOTE_ROOT/specus-server"
SYSTEMD_ROOT="$REMOTE_ROOT/systemd"
ENV_FILE=__ENV_FILE__
EXPECTED_HASH=__EXPECTED_HASH__
EXPECTED_MACHINE=__EXPECTED_MACHINE__
HEALTH_URL=__HEALTH_URL__
REPLACE_JAVA=__REPLACE_JAVA__

actual_machine="$(uname -m)"
if [[ "$actual_machine" != "$EXPECTED_MACHINE" ]]; then
  echo "Architecture mismatch: package expects $EXPECTED_MACHINE, remote is $actual_machine" >&2
  exit 64
fi

actual_hash="$(sha256sum "$BINARY" | awk '{print $1}')"
if [[ "$actual_hash" != "$EXPECTED_HASH" ]]; then
  echo "SHA256 mismatch: expected $EXPECTED_HASH, got $actual_hash" >&2
  exit 65
fi
chmod 0755 "$BINARY"

if [[ "$REPLACE_JAVA" == "true" ]]; then
  JAVA_SERVICE="specus-server"
  GO_SERVICE="specus-server-go"
  JAVA_ENV="/etc/specus-server/specus-server.env"

  if ! systemctl cat "$JAVA_SERVICE.service" >/dev/null 2>&1; then
    echo "Java service is not installed: $JAVA_SERVICE" >&2
    exit 67
  fi
  if ! sudo test -f "$JAVA_ENV"; then
    echo "Java environment file is missing: $JAVA_ENV" >&2
    exit 68
  fi

  if systemctl is-active --quiet "$GO_SERVICE.service" &&
     ! systemctl is-active --quiet "$JAVA_SERVICE.service"; then
    echo "[go-server-deploy] Java has already been replaced; performing a normal Go update"
    sudo env SPECUS_HEALTH_URL="$HEALTH_URL" \
      bash "$SYSTEMD_ROOT/update.sh" "$BINARY"
    exit 0
  fi
  if ! systemctl is-active --quiet "$JAVA_SERVICE.service"; then
    echo "Java service must be active before replacement so rollback remains available" >&2
    exit 69
  fi

  get_java_env() {
    sudo awk -v wanted="$1" '
      index($0, wanted "=") == 1 { value=substr($0, length(wanted)+2) }
      END { print value }
    ' "$JAVA_ENV" | tr -d '\r'
  }

  db_url="$(get_java_env SPECUS_DB_URL)"
  db_user="$(get_java_env SPECUS_DB_USERNAME)"
  db_password="$(get_java_env SPECUS_DB_PASSWORD)"
  server_port="$(get_java_env SERVER_PORT)"
  jwt_secret="$(get_java_env SPECUS_AUTH_JWT_SECRET)"
  auth_password="$(get_java_env SPECUS_AUTH_PASSWORD)"
  peer_enabled="$(get_java_env SPECUS_PEER_MESH_ENABLED)"
  turn_secret="$(get_java_env SPECUS_PEER_MESH_TURN_SHARED_SECRET)"

  case "$db_url" in
    jdbc:mysql://*) ;;
    *)
      echo "Only a Java MySQL JDBC URL can currently be migrated automatically" >&2
      exit 71
      ;;
  esac
  db_target="${db_url#jdbc:mysql://}"
  db_target="${db_target%%\?*}"
  db_host_port="${db_target%%/*}"
  db_name="${db_target#*/}"
  if [[ -z "$db_user" || -z "$db_password" || -z "$db_host_port" ||
        -z "$db_name" || "$db_name" == "$db_target" ]]; then
    echo "Java database configuration is incomplete" >&2
    exit 72
  fi
  if [[ -z "$server_port" ]]; then
    server_port="8088"
  fi
  if [[ ${#jwt_secret} -lt 32 || -z "$auth_password" ]]; then
    echo "Java authentication secrets are incomplete" >&2
    exit 73
  fi
  if [[ "$peer_enabled" == "true" && ${#turn_secret} -lt 16 ]]; then
    echo "Peer Mesh is enabled but the TURN shared secret is missing or too short" >&2
    exit 74
  fi

  GO_ENV_STAGE="$REMOTE_ROOT/specus-server-go.env"
  cleanup_staged_env() {
    rm -f -- "$GO_ENV_STAGE"
  }
  trap cleanup_staged_env EXIT
  sudo awk -F= '
    {
      key=$1
      if (key=="SERVER_PORT" || key=="JAVA_OPTS" ||
          key=="SPECUS_DB_URL" || key=="SPECUS_DB_DRIVER" ||
          key=="SPECUS_DB_USERNAME" || key=="SPECUS_DB_PASSWORD" ||
          key=="SPECUS_DB_DIALECT" || key=="SPECUS_DB_POOL_SIZE" ||
          key=="SPECUS_DB_BATCH_SIZE" ||
          key=="SPECUS_CONNECTIONSTRINGS_SPECUS" ||
          key=="SPECUS_DB_CONNECTION_STRING" ||
          key=="SPECUS_DB_PROVIDER") {
        next
      }
      print
    }
  ' "$JAVA_ENV" > "$GO_ENV_STAGE"
  mysql_dsn="${db_user}:${db_password}@tcp(${db_host_port})/${db_name}?charset=utf8mb4&collation=utf8mb4_unicode_ci&parseTime=true&loc=Asia%2FShanghai&tls=false&timeout=10s&readTimeout=30s&writeTimeout=30s"
  {
    printf '\n# Generated during Java-to-Go migration.\n'
    printf 'SPECUS_DB_PROVIDER=mysql\n'
    printf 'SPECUS_CONNECTIONSTRINGS_SPECUS=%s\n' "$mysql_dsn"
    printf 'SPECUS_MANAGEMENT_ADDR=:%s\n' "$server_port"
  } >> "$GO_ENV_STAGE"
  chmod 0600 "$GO_ENV_STAGE"

  backup_stamp="$(date +%Y%m%d-%H%M%S)"
  backup_dir="/var/backups/specus/java-to-go-$backup_stamp"
  sudo install -d -m 0700 -o root -g root "$backup_dir"
  sudo cp -a "$JAVA_ENV" "$backup_dir/specus-server.env"
  sudo cp -a /etc/systemd/system/specus-server.service "$backup_dir/specus-server.service"
  if sudo test -f /opt/specus-server/specus-server.jar; then
    sudo cp -a /opt/specus-server/specus-server.jar "$backup_dir/specus-server.jar"
  fi
  echo "[go-server-deploy] Java rollback backup: $backup_dir"
  echo "[go-server-deploy] Migrated config validated: mysql, management=:$server_port, peerMesh=$peer_enabled"

  sudo bash "$SYSTEMD_ROOT/install.sh" "$BINARY"
  sudo systemctl disable --now "$GO_SERVICE.service" >/dev/null 2>&1 || true
  sudo install -m 0640 -o root -g specus \
    "$GO_ENV_STAGE" /etc/specus-server-go/specus-server.env

  rollback_required=0
  rollback_java() {
    echo "[go-server-deploy] Go verification failed; restoring Java service" >&2
    sudo systemctl stop "$GO_SERVICE.service" >/dev/null 2>&1 || true
    sudo systemctl disable "$GO_SERVICE.service" >/dev/null 2>&1 || true
    sudo systemctl enable "$JAVA_SERVICE.service" >/dev/null 2>&1 || true
    sudo systemctl start "$JAVA_SERVICE.service" || true
    for _ in $(seq 1 45); do
      if systemctl is-active --quiet "$JAVA_SERVICE.service" &&
         curl -fsS -o /dev/null http://127.0.0.1:8088/actuator/health; then
        echo "[go-server-deploy] Java rollback is healthy" >&2
        return 0
      fi
      sleep 2
    done
    echo "[go-server-deploy] Java rollback requires manual intervention" >&2
    sudo systemctl status "$JAVA_SERVICE.service" --no-pager >&2 || true
    return 1
  }
  on_exit() {
    status=$?
    trap - EXIT
    if [[ $status -ne 0 && $rollback_required -eq 1 ]]; then
      rollback_java || true
    fi
    cleanup_staged_env
    exit "$status"
  }
  trap on_exit EXIT

  rollback_required=1
  echo "[go-server-deploy] Stopping Java service"
  sudo systemctl stop "$JAVA_SERVICE.service"
  echo "[go-server-deploy] Starting Go service"
  sudo systemctl start "$GO_SERVICE.service"

  go_healthy=false
  for _ in $(seq 1 60); do
    if systemctl is-active --quiet "$GO_SERVICE.service" &&
       curl -fsS -o /dev/null "$HEALTH_URL"; then
      go_healthy=true
      break
    fi
    sleep 2
  done
  if [[ "$go_healthy" != "true" ]]; then
    echo "Go service did not become healthy in time" >&2
    sudo systemctl status "$GO_SERVICE.service" --no-pager >&2 || true
    sudo journalctl -u "$GO_SERVICE.service" -n 100 --no-pager >&2 || true
    exit 75
  fi

  curl -fsS -o /dev/null http://127.0.0.1:8088/
  curl -fsS -o /dev/null http://127.0.0.1:8088/api/public/peer-mesh/nat-probe-config
  for tcp_port in 7010 8088; do
    if ! ss -lnt | grep -q ":${tcp_port}[[:space:]]"; then
      echo "Go service is not listening on TCP $tcp_port" >&2
      exit 76
    fi
  done
  if [[ "$peer_enabled" == "true" ]]; then
    for udp_port in 3478 3479; do
      if ! ss -lnu | grep -q ":${udp_port}[[:space:]]"; then
        echo "Go service is not listening on UDP $udp_port" >&2
        exit 77
      fi
    done
  fi

  sudo systemctl enable "$GO_SERVICE.service" >/dev/null
  sudo systemctl disable "$JAVA_SERVICE.service" >/dev/null
  rollback_required=0
  cleanup_staged_env
  trap - EXIT
  echo "[go-server-deploy] Java-to-Go replacement completed"
  echo "[go-server-deploy] Java is stopped and disabled; rollback backup: $backup_dir"
  exit 0
fi

if [[ -x /opt/specus-server-go/specus-server ]] &&
   systemctl cat specus-server-go.service >/dev/null 2>&1; then
  echo "[go-server-deploy] Updating existing installation"
  if [[ -n "$ENV_FILE" ]]; then
    echo "[go-server-deploy] Existing environment file is preserved; -EnvFile only applies to first installation."
  fi
  sudo env SPECUS_HEALTH_URL="$HEALTH_URL" \
    bash "$SYSTEMD_ROOT/update.sh" "$BINARY"
else
  echo "[go-server-deploy] Performing first installation"
  sudo bash "$SYSTEMD_ROOT/install.sh" "$BINARY"
  if [[ -n "$ENV_FILE" ]]; then
    sudo install -m 0640 -o root -g specus \
      "$ENV_FILE" /etc/specus-server-go/specus-server.env
    sudo systemctl enable --now specus-server-go.service
    for _ in $(seq 1 30); do
      if systemctl is-active --quiet specus-server-go.service &&
         curl -fsS -o /dev/null "$HEALTH_URL"; then
        echo "[go-server-deploy] First installation is healthy"
        exit 0
      fi
      sleep 2
    done
    sudo systemctl status specus-server-go.service --no-pager || true
    exit 66
  fi
  echo "[go-server-deploy] Installed but not started."
  echo "[go-server-deploy] Edit /etc/specus-server-go/specus-server.env, then run:"
  echo "[go-server-deploy]   sudo systemctl enable --now specus-server-go.service"
fi
'@
    $remoteCommand = $remoteTemplate.
        Replace("__REMOTE_ROOT__", (ConvertTo-ShellSingleQuoted $remoteRoot)).
        Replace("__ENV_FILE__", (ConvertTo-ShellSingleQuoted $remoteEnv)).
        Replace("__EXPECTED_HASH__", (ConvertTo-ShellSingleQuoted $binaryHash)).
        Replace("__EXPECTED_MACHINE__", (ConvertTo-ShellSingleQuoted $expectedMachine)).
        Replace("__HEALTH_URL__", (ConvertTo-ShellSingleQuoted $HealthUrl)).
        Replace("__REPLACE_JAVA__", (ConvertTo-ShellSingleQuoted $ReplaceJava.ToString().ToLowerInvariant())).
        Replace("`r`n", "`n")

    $localRemoteScript = Join-Path ([System.IO.Path]::GetTempPath()) `
        "specus-go-server-deploy-$timestamp-$PID-$Architecture.sh"
    if (-not $DryRun) {
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($localRemoteScript, $remoteCommand, $utf8NoBom)
    }
    $remoteScript = "$remoteRoot/deploy-remote.sh"
    Invoke-Checked $scp @($localRemoteScript, "$($HostName):$remoteScript")
    $quotedRemoteScript = ConvertTo-ShellSingleQuoted $remoteScript
    Invoke-Checked $ssh @(
        $HostName,
        "chmod 0700 -- $quotedRemoteScript && bash -- $quotedRemoteScript"
    )
    if (-not $SkipFrontend) {
        Write-DeployLog "Installing OpenResty admin frontend"
        $remoteAdminWebDist = "$remoteRoot/admin-web-dist"
        $remoteOpenRestyInstaller = "$remoteRoot/openresty/install-admin-web.sh"
        Invoke-Checked $ssh @(
            $HostName,
            "sudo env ADMIN_WEB_DIST=$(ConvertTo-ShellSingleQuoted $remoteAdminWebDist) bash -- $(ConvertTo-ShellSingleQuoted $remoteOpenRestyInstaller)"
        )
        Invoke-Checked $ssh @($HostName, "sudo openresty -t")
        Invoke-Checked $ssh @($HostName, "sudo openresty -s reload")
        Invoke-Checked $ssh @(
            $HostName,
            "curl -kfsSI -- $(ConvertTo-ShellSingleQuoted "$SiteUrl/")"
        )
        Invoke-Checked $ssh @(
            $HostName,
            "curl -kfsSI -H 'Accept-Encoding: br, gzip' -- $(ConvertTo-ShellSingleQuoted "$SiteUrl/assets/$frontendAssetName")"
        )
    }
    $success = $true
} finally {
    if (-not [string]::IsNullOrWhiteSpace($localRemoteScript) -and
        (Test-Path -LiteralPath $localRemoteScript -PathType Leaf)) {
        Remove-Item -LiteralPath $localRemoteScript -Force -ErrorAction SilentlyContinue
    }
    if ($DryRun) {
        Write-DeployLog "Dry run completed"
    } elseif ($success -and -not $KeepRemoteTemp) {
        Invoke-Checked $ssh @(
            $HostName,
            "rm -rf -- $(ConvertTo-ShellSingleQuoted $remoteRoot)"
        )
    } else {
        Write-Warning "Remote files kept for diagnosis: $HostName`:$remoteRoot"
    }
}

if ($success) {
    if ($DryRun) {
        Write-DeployLog "No remote changes were made"
    } else {
        Write-DeployLog "Deployment completed: $HostName"
    }
}
