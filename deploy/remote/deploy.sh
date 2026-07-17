#!/usr/bin/env bash
# Build the current workspace and deploy it to the production-style remote host.
# macOS and Linux entry point. See README.md for examples.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

MODE="auto"
DEPLOY_HOST="${DEPLOY_HOST:-ali2}"
SITE_URL="${DEPLOY_SITE_URL:-https://tunnel.devshuai.com}"
ASSUME_YES="false"
DRY_RUN="false"
NO_CLEAN="false"
KEEP_REMOTE_TEMP="false"
INCLUDE_STUN="false"

usage() {
  cat <<'EOF'
Usage:
  ./deploy/remote/deploy.sh [auto|frontend|server|all] [options]

Modes:
  auto       Infer the target from local Git changes (default).
  frontend   Build and deploy the OpenResty admin frontend only.
  server     Build and deploy the Java server only.
  all        Deploy the Java server and OpenResty frontend.

Options:
  --mode <mode>       Alternative way to select a mode.
  --host <ssh-host>   SSH config host or user@host (default: ali2).
  --site-url <url>    Public origin used by frontend checks.
  --yes               Do not ask for interactive confirmation.
  --dry-run           Print the plan and commands without building or uploading.
  --no-clean          Use Maven package without clean (explicit fallback only).
  --keep-remote-temp  Keep the successful upload directory under /tmp.
  --include-stun      Deploy both standalone STUN nodes before tunnel-server.
  -h, --help          Show this help.

Environment:
  DEPLOY_HOST, DEPLOY_SITE_URL
EOF
}

log() {
  printf '[deploy] %s\n' "$*"
}

warn() {
  printf '[deploy] warning: %s\n' "$*" >&2
}

die() {
  printf '[deploy] error: %s\n' "$*" >&2
  exit 1
}

require_value() {
  local option="$1"
  local value="${2-}"
  [[ -n "$value" ]] || die "$option requires a value"
}

set_mode() {
  case "$1" in
    auto|frontend|server|all)
      MODE="$1"
      ;;
    *)
      die "unsupported mode: $1"
      ;;
  esac
}

while (($# > 0)); do
  case "$1" in
    auto|frontend|server|all)
      set_mode "$1"
      shift
      ;;
    --mode)
      require_value "$1" "${2-}"
      set_mode "$2"
      shift 2
      ;;
    --host)
      require_value "$1" "${2-}"
      DEPLOY_HOST="$2"
      shift 2
      ;;
    --site-url)
      require_value "$1" "${2-}"
      SITE_URL="$2"
      shift 2
      ;;
    --yes)
      ASSUME_YES="true"
      shift
      ;;
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    --no-clean)
      NO_CLEAN="true"
      shift
      ;;
    --keep-remote-temp)
      KEEP_REMOTE_TEMP="true"
      shift
      ;;
    --include-stun)
      INCLUDE_STUN="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ "$DEPLOY_HOST" =~ ^[A-Za-z0-9][A-Za-z0-9._@-]*$ ]] \
  || die "invalid SSH host; configure ports and advanced options in ~/.ssh/config"
[[ "$SITE_URL" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]+)?/?$ ]] \
  || die "site URL must be an HTTP(S) origin without a path or query"
SITE_URL="${SITE_URL%/}"

print_command() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
}

run() {
  print_command "$@"
  if [[ "$DRY_RUN" == "true" ]]; then
    return 0
  fi
  "$@"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

deploy_stun() {
  local script="${REPO_ROOT}/deploy/stun-server/remote/deploy.ps1"
  [[ -f "$script" ]] || die "STUN deployment script not found: $script"
  require_command pwsh

  local -a args=(-NoLogo -NoProfile -File "$script" -Target All -Yes)
  if [[ "$DRY_RUN" == "true" ]]; then
    args+=(-DryRun)
  fi
  if [[ "$NO_CLEAN" == "true" ]]; then
    args+=(-NoClean)
  fi
  if [[ "$KEEP_REMOTE_TEMP" == "true" ]]; then
    args+=(-KeepRemoteTemp)
  fi

  log "deploying standalone STUN nodes before tunnel-server"
  print_command pwsh "${args[@]}"
  pwsh "${args[@]}"
}

cd "$REPO_ROOT"
require_command git

FRONTEND_CHANGED="false"
SERVER_CHANGED="false"
CHANGED_PATHS=()

while IFS= read -r path; do
  [[ -n "$path" ]] || continue
  CHANGED_PATHS[${#CHANGED_PATHS[@]}]="$path"
  case "$path" in
    apps/admin-web/*|protocol/schemas/*|deploy/openresty/*)
      FRONTEND_CHANGED="true"
      ;;
    pom.xml|implementations/java/common/*|implementations/java/server/*|deploy/java-server/*)
      SERVER_CHANGED="true"
      ;;
  esac
done < <(
  {
    git diff --name-only HEAD
    git ls-files --others --exclude-standard
  } | LC_ALL=C sort -u
)

if [[ "$MODE" == "auto" ]]; then
  if [[ "$FRONTEND_CHANGED" == "true" && "$SERVER_CHANGED" == "true" ]]; then
    MODE="all"
  elif [[ "$FRONTEND_CHANGED" == "true" ]]; then
    MODE="frontend"
  elif [[ "$SERVER_CHANGED" == "true" ]]; then
    MODE="server"
  else
    MODE="all"
    warn "auto found no deploy-relevant workspace changes; redeploying all current sources"
  fi
fi

DEPLOY_FRONTEND="false"
DEPLOY_SERVER="false"
case "$MODE" in
  frontend)
    DEPLOY_FRONTEND="true"
    ;;
  server)
    DEPLOY_SERVER="true"
    ;;
  all)
    DEPLOY_FRONTEND="true"
    DEPLOY_SERVER="true"
    ;;
  *)
    die "internal mode error: $MODE"
    ;;
esac

log "deployment plan"
branch="$(git branch --show-current 2>/dev/null || true)"
[[ -n "$branch" ]] || branch="(detached)"
printf '  mode:       %s\n' "$MODE"
printf '  host:       %s\n' "$DEPLOY_HOST"
printf '  site:       %s\n' "$SITE_URL"
if [[ "$INCLUDE_STUN" == "true" ]]; then
  printf '  STUN:       all nodes, before tunnel-server\n'
else
  printf '  STUN:       not included\n'
fi
printf '  git branch: %s\n' "$branch"

if ((${#CHANGED_PATHS[@]} > 0)); then
  printf '  workspace changes (%s):\n' "${#CHANGED_PATHS[@]}"
  shown=0
  for path in "${CHANGED_PATHS[@]}"; do
    printf '    - %s\n' "$path"
    shown=$((shown + 1))
    if ((shown == 20 && ${#CHANGED_PATHS[@]} > shown)); then
      printf '    - ... %s more\n' "$((${#CHANGED_PATHS[@]} - shown))"
      break
    fi
  done
else
  printf '  workspace changes: none\n'
fi

if [[ "$DRY_RUN" != "true" && "$ASSUME_YES" != "true" ]]; then
  deployment_scope="$MODE"
  if [[ "$INCLUDE_STUN" == "true" ]]; then
    deployment_scope="${MODE} plus STUN"
  fi
  printf 'Continue deploying %s to %s? [y/N] ' "$deployment_scope" "$DEPLOY_HOST"
  read -r answer
  case "$answer" in
    y|Y|yes|YES)
      ;;
    *)
      log "cancelled"
      exit 0
      ;;
  esac
fi

if [[ "$INCLUDE_STUN" == "true" ]]; then
  deploy_stun
fi

if [[ "$DRY_RUN" != "true" ]]; then
  require_command ssh
  require_command scp
  if [[ "$DEPLOY_FRONTEND" == "true" || "$DEPLOY_SERVER" == "true" ]]; then
    require_command npm
  fi
  if [[ "$DEPLOY_SERVER" == "true" ]]; then
    require_command mvn
  fi
fi

JAR_PATH="${REPO_ROOT}/implementations/java/server/target/tunnel-server-1.0-SNAPSHOT.jar"
ASSET_NAME="index-dry-run.js"

if [[ "$DEPLOY_SERVER" == "true" ]]; then
  maven_args=(-pl :tunnel-server -am -DskipTests)
  if [[ "$NO_CLEAN" == "true" ]]; then
    warn "using the explicit non-clean Maven fallback"
    maven_args+=(package)
  else
    maven_args+=(clean package)
  fi
  run mvn "${maven_args[@]}"

  if [[ "$DRY_RUN" != "true" ]]; then
    JAR_PATH=""
    for candidate in "${REPO_ROOT}"/implementations/java/server/target/tunnel-server-*.jar; do
      [[ -f "$candidate" ]] || continue
      [[ "$candidate" == *.jar.original ]] && continue
      if [[ -z "$JAR_PATH" || "$candidate" -nt "$JAR_PATH" ]]; then
        JAR_PATH="$candidate"
      fi
    done
    [[ -n "$JAR_PATH" ]] || die "no deployable tunnel-server jar found"
  fi
fi

if [[ "$DEPLOY_FRONTEND" == "true" ]]; then
  pushd "${REPO_ROOT}/apps/admin-web" >/dev/null
  run npm run build:openresty
  popd >/dev/null

  if [[ "$DRY_RUN" != "true" ]]; then
    ASSET_NAME=""
    for candidate in "${REPO_ROOT}"/apps/admin-web/dist/assets/index-*.js; do
      [[ -f "$candidate" ]] || continue
      ASSET_NAME="${candidate##*/}"
      break
    done
    [[ -n "$ASSET_NAME" ]] || die "no hashed frontend entry asset found"
  fi
fi

if [[ "$DRY_RUN" == "true" ]]; then
  deploy_tag="dry-run"
else
  deploy_tag="$(date +%Y%m%d%H%M%S)-$$"
fi
REMOTE_ROOT="/tmp/shuai-tunnel-deploy-${deploy_tag}"
DEPLOY_STARTED="false"
DEPLOY_SUCCEEDED="false"

cleanup() {
  status=$?
  trap - EXIT
  if [[ "$DEPLOY_STARTED" == "true" ]]; then
    if [[ "$status" -eq 0 && "$DEPLOY_SUCCEEDED" == "true" && "$KEEP_REMOTE_TEMP" != "true" ]]; then
      print_command ssh "$DEPLOY_HOST" "rm -rf ${REMOTE_ROOT}"
      ssh "$DEPLOY_HOST" "rm -rf ${REMOTE_ROOT}" \
        || warn "could not remove successful deployment temp directory: ${REMOTE_ROOT}"
    elif [[ "$status" -eq 0 && "$DEPLOY_SUCCEEDED" == "true" ]]; then
      log "remote deployment files kept by request: ${DEPLOY_HOST}:${REMOTE_ROOT}"
    else
      warn "remote deployment files were kept for diagnosis: ${DEPLOY_HOST}:${REMOTE_ROOT}"
    fi
  fi
  exit "$status"
}
trap cleanup EXIT

run ssh "$DEPLOY_HOST" "mkdir -p ${REMOTE_ROOT}"
if [[ "$DRY_RUN" != "true" ]]; then
  DEPLOY_STARTED="true"
fi

if [[ "$DEPLOY_SERVER" == "true" ]]; then
  run scp "$JAR_PATH" "${DEPLOY_HOST}:${REMOTE_ROOT}/tunnel-server.jar"
  run scp -r "${REPO_ROOT}/deploy/java-server/systemd" "${DEPLOY_HOST}:${REMOTE_ROOT}/java-systemd"
fi

if [[ "$DEPLOY_FRONTEND" == "true" ]]; then
  run scp -r "${REPO_ROOT}/deploy/openresty" "${DEPLOY_HOST}:${REMOTE_ROOT}/openresty"
  run scp -r "${REPO_ROOT}/apps/admin-web/dist" "${DEPLOY_HOST}:${REMOTE_ROOT}/admin-web-dist"
fi

if [[ "$DEPLOY_SERVER" == "true" ]]; then
  run ssh "$DEPLOY_HOST" \
    "sudo bash ${REMOTE_ROOT}/java-systemd/update.sh ${REMOTE_ROOT}/tunnel-server.jar"
fi

if [[ "$DEPLOY_FRONTEND" == "true" ]]; then
  run ssh "$DEPLOY_HOST" \
    "sudo env ADMIN_WEB_DIST=${REMOTE_ROOT}/admin-web-dist bash ${REMOTE_ROOT}/openresty/install-admin-web.sh"
  run ssh "$DEPLOY_HOST" "sudo openresty -s reload"
fi

log "verifying remote deployment"
if [[ "$DEPLOY_SERVER" == "true" ]]; then
  run ssh "$DEPLOY_HOST" "systemctl is-active tunnel-server"
fi
if [[ "$DEPLOY_FRONTEND" == "true" ]]; then
  run ssh "$DEPLOY_HOST" "sudo openresty -t"
  run ssh "$DEPLOY_HOST" "curl -kfsSI ${SITE_URL}/"
  run ssh "$DEPLOY_HOST" \
    "curl -kfsSI -H 'Accept-Encoding: br, gzip' ${SITE_URL}/assets/${ASSET_NAME}"
fi

DEPLOY_SUCCEEDED="true"
if [[ "$DRY_RUN" == "true" ]]; then
  log "dry run completed; no build or remote command was executed"
else
  log "deployment completed successfully"
fi
