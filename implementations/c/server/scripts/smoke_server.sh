#!/usr/bin/env bash
# Reuse is a requirement, not permission to silently spend the E2E deadline
# rebuilding and running the complete native suite.
# SPECUS_SMOKE_SERVER_BINARY selects an already-built artifact (e.g. CMake).
# With neither an override nor reuse, the default Makefile suite still runs.
specus_smoke_prepare_server() {
  local c_dir="$1"
  SPECUS_SMOKE_RESOLVED_SERVER="${SPECUS_SMOKE_SERVER_BINARY:-$c_dir/build/specus-server-c}"
  if [[ "${SPECUS_SMOKE_REUSE_BUILD:-}" != 1 && -z "${SPECUS_SMOKE_SERVER_BINARY:-}" ]]; then
    make -C "$c_dir" test || return "$?"
  fi
  if [[ ! -f "$SPECUS_SMOKE_RESOLVED_SERVER" || ! -x "$SPECUS_SMOKE_RESOLVED_SERVER" ]]; then
    printf 'missing executable C server binary: %s\n' "$SPECUS_SMOKE_RESOLVED_SERVER" >&2
    printf 'build and test it first, or unset SPECUS_SMOKE_REUSE_BUILD to use the default Makefile build\n' >&2
    return 1
  fi
}
