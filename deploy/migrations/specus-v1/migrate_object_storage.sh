#!/usr/bin/env bash
set -euo pipefail

APPLY=false
RESUME=false
MC_BIN="${MC_BIN:-mc}"
REMOTE=""
SOURCE_PREFIX=""
DESTINATION_PREFIX=""

usage() {
  cat <<'EOF'
Usage:
  migrate_object_storage.sh --remote ALIAS/BUCKET \
    --from OLD_PREFIX --to NEW_PREFIX [--apply] [--resume]

Examples:
  migrate_object_storage.sh --remote aliyun/private-bucket \
    --from shuai-tunnel/attachments --to specus/attachments

  migrate_object_storage.sh --remote rustfs/specus-media \
    --from shuai-tunnel/http-media --to specus/http-media --apply

The MinIO client alias must already be configured. Credentials are read by mc
and are never accepted or printed by this script. Plan mode uses mc mirror
--dry-run. Apply mode copies objects and keeps the source prefix for rollback.
EOF
}

fail() {
  echo "migration failed: $*" >&2
  exit 1
}

normalize_prefix() {
  local value="${1#/}"
  value="${value%/}"
  [[ -n "$value" ]] || fail "prefix must not be empty"
  [[ "$value" != *"\\"* ]] || fail "prefix must not contain backslashes"
  [[ "/$value/" != *"/../"* && "/$value/" != *"/./"* ]] ||
    fail "prefix must not contain dot segments"
  printf '%s' "$value"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --remote)
      [[ $# -ge 2 ]] || fail "--remote requires a value"
      REMOTE="${2%/}"
      shift 2
      ;;
    --from)
      [[ $# -ge 2 ]] || fail "--from requires a value"
      SOURCE_PREFIX="$2"
      shift 2
      ;;
    --to)
      [[ $# -ge 2 ]] || fail "--to requires a value"
      DESTINATION_PREFIX="$2"
      shift 2
      ;;
    --apply)
      APPLY=true
      shift
      ;;
    --resume)
      RESUME=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -n "$REMOTE" && "$REMOTE" == */* ]] ||
  fail "--remote must be an existing mc ALIAS/BUCKET"
SOURCE_PREFIX="$(normalize_prefix "$SOURCE_PREFIX")"
DESTINATION_PREFIX="$(normalize_prefix "$DESTINATION_PREFIX")"
[[ "$SOURCE_PREFIX" != "$DESTINATION_PREFIX" ]] ||
  fail "source and destination prefixes must differ"
command -v "$MC_BIN" >/dev/null 2>&1 || fail "mc was not found: $MC_BIN"

SOURCE="${REMOTE}/${SOURCE_PREFIX}"
DESTINATION="${REMOTE}/${DESTINATION_PREFIX}"

"$MC_BIN" stat "$REMOTE" >/dev/null

source_listing=""
if ! source_listing="$("$MC_BIN" ls --recursive "$SOURCE")"; then
  fail "cannot list source prefix: $SOURCE"
fi
if [[ -z "$source_listing" ]]; then
  echo "no source objects: $SOURCE"
  exit 0
fi

echo "source=$SOURCE"
echo "destination=$DESTINATION"

if [[ "$APPLY" != true ]]; then
  "$MC_BIN" mirror --dry-run --overwrite --retry "$SOURCE" "$DESTINATION"
  echo "plan only; rerun with --apply"
  exit 0
fi

destination_listing=""
if ! destination_listing="$("$MC_BIN" ls --recursive "$DESTINATION")"; then
  fail "cannot list destination prefix: $DESTINATION"
fi
if [[ -n "$destination_listing" && "$RESUME" != true ]]; then
  fail "destination is not empty; inspect it or rerun with --resume"
fi

mirror_flags=(--retry --summary)
if [[ "$RESUME" == true ]]; then
  mirror_flags+=(--overwrite)
fi
"$MC_BIN" mirror "${mirror_flags[@]}" "$SOURCE" "$DESTINATION"

diff_output=""
if ! diff_output="$("$MC_BIN" diff "$SOURCE" "$DESTINATION")"; then
  fail "mc diff failed"
fi
if [[ -n "$diff_output" ]]; then
  printf '%s\n' "$diff_output" >&2
  fail "source and destination prefixes differ"
fi

echo "verified=$DESTINATION"
echo "source retained for rollback: $SOURCE"
