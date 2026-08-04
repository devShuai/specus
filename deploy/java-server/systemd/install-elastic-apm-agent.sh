#!/usr/bin/env bash
# Install and optionally enable the Elastic APM Java Agent for specus-server.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
AGENT_VERSION="${ELASTIC_APM_AGENT_VERSION:-1.56.0}"
DEFAULT_AGENT_SHA256="4595ce678bfe3a3420ada95356bc85c241e287de0220251dec9d390bcdeaf2f5"
AGENT_SHA256="${ELASTIC_APM_AGENT_SHA256:-}"
AGENT_DIR="${SPECUS_APM_AGENT_DIR:-/opt/specus-server}"
AGENT_LINK="$AGENT_DIR/elastic-apm-agent.jar"
ENV_FILE="${SPECUS_ENV_FILE:-/etc/specus-server/specus-server.env}"
SERVICE_NAME="${SPECUS_SERVICE_NAME:-specus-server}"
APM_SERVER_URL="${SPECUS_APM_SERVER_URL:-http://127.0.0.1:8200}"
APM_ENVIRONMENT="${SPECUS_APM_ENVIRONMENT:-production}"
APM_SAMPLE_RATE="${SPECUS_APM_SAMPLE_RATE:-0.10}"
ENABLE_AGENT=false
RESTART_SERVICE=false
TEMP_FILE=""
BACKUP_DIR=""
ROLLBACK_READY=false
CONFIG_COMMITTED=false
SERVICE_WAS_ACTIVE=false

usage() {
  cat <<'EOF'
Usage:
  sudo ./install-elastic-apm-agent.sh [--enable] [--restart]

Options:
  --enable   Add privacy-safe Elastic APM settings to specus-server.env and
             install the current systemd unit with the optional agent hook.
  --restart  Restart an already-running specus-server after enabling the agent.
             Requires --enable.
  -h, --help Show this help.

Environment overrides:
  ELASTIC_APM_AGENT_VERSION, ELASTIC_APM_AGENT_SHA256
  SPECUS_APM_SERVER_URL, SPECUS_APM_ENVIRONMENT, SPECUS_APM_SAMPLE_RATE
  SPECUS_APM_SECRET_TOKEN, SPECUS_APM_AGENT_DIR, SPECUS_ENV_FILE
EOF
}

fail() {
  printf '[elastic-apm] error: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[elastic-apm] %s\n' "$*"
}

cleanup() {
  local status=$?
  trap - EXIT

  if [[ -n "$TEMP_FILE" && -f "$TEMP_FILE" ]]; then
    rm -f -- "$TEMP_FILE"
  fi

  if [[ $status -ne 0 && "$ROLLBACK_READY" == "true" \
        && "$CONFIG_COMMITTED" != "true" ]]; then
    log "activation failed; restoring the previous environment and systemd unit"
    cp -a -- "$BACKUP_DIR/specus-server.env" "$ENV_FILE"
    cp -a -- "$BACKUP_DIR/specus-server.service" \
      /etc/systemd/system/specus-server.service
    systemctl daemon-reload || true
    if [[ "$SERVICE_WAS_ACTIVE" == "true" ]]; then
      systemctl restart "$SERVICE_NAME" || true
    fi
  fi

  if [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]]; then
    rm -f -- "$BACKUP_DIR/specus-server.env" \
      "$BACKUP_DIR/specus-server.service"
    rmdir -- "$BACKUP_DIR" 2>/dev/null || true
  fi
  exit "$status"
}
trap cleanup EXIT

while (($# > 0)); do
  case "$1" in
    --enable)
      ENABLE_AGENT=true
      ;;
    --restart)
      RESTART_SERVICE=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
  shift
done

[[ $EUID -eq 0 ]] || fail "run this script as root or through sudo"
[[ "$AGENT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fail "invalid Elastic APM agent version: $AGENT_VERSION"
[[ "$APM_SERVER_URL" =~ ^https?://[A-Za-z0-9._-]+(:[0-9]+)?/?$ ]] \
  || fail "SPECUS_APM_SERVER_URL must be an HTTP(S) origin"
[[ "$APM_SAMPLE_RATE" =~ ^(0(\.[0-9]+)?|1(\.0+)?)$ ]] \
  || fail "SPECUS_APM_SAMPLE_RATE must be between 0.0 and 1.0"
if [[ "$RESTART_SERVICE" == "true" && "$ENABLE_AGENT" != "true" ]]; then
  fail "--restart requires --enable"
fi
if [[ -n "${SPECUS_APM_SECRET_TOKEN:-}" \
      && ! "${SPECUS_APM_SECRET_TOKEN}" =~ ^[A-Za-z0-9._~-]+$ ]]; then
  fail "SPECUS_APM_SECRET_TOKEN contains unsupported characters"
fi

if [[ -z "$AGENT_SHA256" ]]; then
  if [[ "$AGENT_VERSION" == "1.56.0" ]]; then
    AGENT_SHA256="$DEFAULT_AGENT_SHA256"
  else
    fail "ELASTIC_APM_AGENT_SHA256 is required for a non-default agent version"
  fi
fi
[[ "$AGENT_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] \
  || fail "ELASTIC_APM_AGENT_SHA256 must contain exactly 64 hexadecimal characters"

command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
install -d -m 0755 -o root -g root "$AGENT_DIR"

AGENT_FILE="$AGENT_DIR/elastic-apm-agent-$AGENT_VERSION.jar"
DOWNLOAD_URL="https://repo1.maven.org/maven2/co/elastic/apm/elastic-apm-agent/$AGENT_VERSION/elastic-apm-agent-$AGENT_VERSION.jar"

file_matches_checksum() {
  [[ -f "$1" ]] || return 1
  local actual
  actual="$(sha256sum "$1" | awk '{print $1}')"
  [[ "${actual,,}" == "${AGENT_SHA256,,}" ]]
}

if file_matches_checksum "$AGENT_FILE"; then
  log "agent $AGENT_VERSION is already installed"
else
  TEMP_FILE="$(mktemp "$AGENT_DIR/.elastic-apm-agent.XXXXXX")"
  if command -v curl >/dev/null 2>&1; then
    curl --fail --location --silent --show-error \
      --connect-timeout 10 --max-time 180 \
      "$DOWNLOAD_URL" --output "$TEMP_FILE"
  elif command -v wget >/dev/null 2>&1; then
    wget --quiet --timeout=180 --output-document="$TEMP_FILE" "$DOWNLOAD_URL"
  else
    fail "curl or wget is required to download the Elastic APM agent"
  fi

  printf '%s  %s\n' "$AGENT_SHA256" "$TEMP_FILE" | sha256sum --check --status \
    || fail "Elastic APM agent checksum verification failed"
  install -m 0644 -o root -g root "$TEMP_FILE" "$AGENT_FILE"
  rm -f -- "$TEMP_FILE"
  TEMP_FILE=""
  log "installed Elastic APM Java Agent $AGENT_VERSION"
fi

ln -sfn "$(basename "$AGENT_FILE")" "$AGENT_LINK"
chown -h root:root "$AGENT_LINK"

active_env_value() {
  local key="$1"
  [[ -f "$ENV_FILE" ]] || return 0
  awk -F= -v key="$key" '
    $0 !~ /^[[:space:]]*#/ && $1 == key {
      sub(/^[^=]*=/, "")
      print
      exit
    }
  ' "$ENV_FILE"
}

write_env_file() {
  local key="$1"
  local value="$2"
  local mode="$3"
  local current=""
  local temp=""
  local env_group="root"

  current="$(active_env_value "$key")"
  if [[ "$mode" == "default" && -n "$current" ]]; then
    return
  fi
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] \
    || fail "environment value for $key contains a newline"

  temp="$(mktemp)"
  awk -v key="$key" -v replacement="$key=$value" '
    BEGIN { replaced = 0 }
    $0 !~ /^[[:space:]]*#/ && index($0, key "=") == 1 {
      if (!replaced) {
        print replacement
        replaced = 1
      }
      next
    }
    { print }
    END {
      if (!replaced) {
        print replacement
      }
    }
  ' "$ENV_FILE" > "$temp"

  if getent group specus >/dev/null 2>&1; then
    env_group="specus"
  fi
  install -m 0640 -o root -g "$env_group" "$temp" "$ENV_FILE"
  rm -f -- "$temp"
}

if [[ "$ENABLE_AGENT" == "true" ]]; then
  [[ -f "$ENV_FILE" ]] || fail "specus environment file does not exist: $ENV_FILE"
  [[ -f /etc/systemd/system/specus-server.service ]] \
    || fail "specus-server systemd unit is not installed"
  command -v curl >/dev/null 2>&1 || fail "curl is required for the APM connectivity check"

  server_info="$(curl --fail --silent --show-error --max-time 10 "${APM_SERVER_URL%/}/")" \
    || fail "APM Server is not reachable at $APM_SERVER_URL"
  if ! grep -Eq '"publish_ready"[[:space:]]*:[[:space:]]*true' <<<"$server_info"; then
    fail "APM Server at $APM_SERVER_URL is not publish-ready"
  fi

  BACKUP_DIR="$(mktemp -d /tmp/specus-elastic-apm-enable.XXXXXX)"
  cp -a -- "$ENV_FILE" "$BACKUP_DIR/specus-server.env"
  cp -a -- /etc/systemd/system/specus-server.service \
    "$BACKUP_DIR/specus-server.service"
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    SERVICE_WAS_ACTIVE=true
  fi
  ROLLBACK_READY=true

  write_env_file "ELASTIC_APM_AGENT_OPTS" "-javaagent:$AGENT_LINK" "replace"
  write_env_file "ELASTIC_APM_RECORDING" "true" "replace"
  write_env_file "ELASTIC_APM_SERVER_URL" "$APM_SERVER_URL" "default"
  write_env_file "ELASTIC_APM_SERVICE_NAME" "specus-server" "default"
  write_env_file "ELASTIC_APM_SERVICE_VERSION" "1.0-SNAPSHOT" "default"
  write_env_file "ELASTIC_APM_ENVIRONMENT" "$APM_ENVIRONMENT" "default"
  write_env_file "ELASTIC_APM_APPLICATION_PACKAGES" "com.theshuai.specusserver" "default"
  write_env_file "ELASTIC_APM_TRANSACTION_SAMPLE_RATE" "$APM_SAMPLE_RATE" "default"
  write_env_file "ELASTIC_APM_TRANSACTION_MAX_SPANS" "200" "default"
  write_env_file "ELASTIC_APM_CAPTURE_BODY" "off" "default"
  write_env_file "ELASTIC_APM_CAPTURE_HEADERS" "false" "default"
  write_env_file "ELASTIC_APM_CENTRAL_CONFIG" "false" "default"
  write_env_file "ELASTIC_APM_DISABLE_INSTRUMENTATIONS" \
    "scheduled,opentelemetry,opentelemetry-annotations,opentelemetry-metrics" \
    "default"
  write_env_file "ELASTIC_APM_ENABLE_LOG_CORRELATION" "true" "default"
  write_env_file "ELASTIC_APM_LOG_SENDING" "false" "default"
  write_env_file "ELASTIC_APM_METRICS_INTERVAL" "30s" "default"
  write_env_file "ELASTIC_APM_EXIT_SPAN_MIN_DURATION" "5ms" "default"
  write_env_file "ELASTIC_APM_CLOUD_PROVIDER" "NONE" "default"
  write_env_file "ELASTIC_APM_TRANSACTION_IGNORE_URLS" \
    "/actuator/*,/health,/http/*,/ws/*,/api/public/media-playback/*,/api/public/transfer/downloads/*,/favicon.ico,*.js,*.css,*.jpg,*.jpeg,*.png,*.gif,*.webp,*.svg,*.woff,*.woff2" \
    "default"
  write_env_file "ELASTIC_APM_LOG_LEVEL" "INFO" "default"

  if [[ -n "${SPECUS_APM_SECRET_TOKEN:-}" ]]; then
    write_env_file "ELASTIC_APM_SECRET_TOKEN" "$SPECUS_APM_SECRET_TOKEN" "replace"
  fi

  install -m 0644 -o root -g root "$SCRIPT_DIR/specus-server.service" \
    /etc/systemd/system/specus-server.service
  systemctl daemon-reload
  log "enabled Elastic APM settings in $ENV_FILE"

  if [[ "$RESTART_SERVICE" == "true" ]]; then
    if systemctl is-active --quiet "$SERVICE_NAME"; then
      health_port="$(active_env_value SERVER_PORT)"
      health_port="${health_port:-8088}"
      systemctl restart "$SERVICE_NAME"
      deadline=$((SECONDS + 120))
      while ((SECONDS < deadline)); do
        if systemctl is-active --quiet "$SERVICE_NAME" \
          && curl --fail --silent --max-time 3 \
            "http://127.0.0.1:${health_port}/actuator/health" \
            | grep -q '"status"[[:space:]]*:[[:space:]]*"UP"'; then
          main_pid="$(systemctl show "$SERVICE_NAME" -p MainPID --value)"
          agent_loaded=false
          if [[ -n "$main_pid" && "$main_pid" != "0" ]]; then
            while IFS= read -r -d '' argument; do
              if [[ "$argument" == "-javaagent:$AGENT_LINK" ]]; then
                agent_loaded=true
              fi
            done < "/proc/$main_pid/cmdline"
          fi
          if [[ "$agent_loaded" != "true" ]]; then
            fail "$SERVICE_NAME is healthy but the Elastic APM agent was not loaded"
          fi
          log "$SERVICE_NAME restarted with Elastic APM enabled"
          CONFIG_COMMITTED=true
          break
        fi
        sleep 2
      done
      if [[ "$CONFIG_COMMITTED" != "true" ]]; then
        fail "$SERVICE_NAME did not become healthy after enabling Elastic APM"
      fi
    else
      log "$SERVICE_NAME is not running; the agent will load on its next start"
      CONFIG_COMMITTED=true
    fi
  else
    log "restart $SERVICE_NAME to load the agent"
    CONFIG_COMMITTED=true
  fi
fi

log "agent path: $AGENT_LINK"
