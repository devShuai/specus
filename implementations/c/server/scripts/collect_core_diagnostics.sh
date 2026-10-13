#!/usr/bin/env bash
# Read the original crash, never rerun the test or mask the failing test step.
set -euo pipefail
if [[ $# != 2 ]]; then
  echo "usage: $0 CORE_DIRECTORY REPOSITORY_ROOT" >&2
  exit 2
fi
core_dir=$1
repo_root=$(realpath -e -- "$2")
shopt -s nullglob
cores=("$core_dir"/core.*)
if [[ ${#cores[@]} == 0 ]]; then
  echo "No native core dumps to inspect."
  exit 0
fi
result=0
for core in "${cores[@]}"; do
  # kernel.core_pattern=core.%P.%E; Linux encodes '/' as '!' in %E.
  name=${core##*/}
  [[ $name =~ ^core\.[0-9]+\.(!.*)$ ]] || continue
  encoded_executable=${BASH_REMATCH[1]}
  # Do not process our own output if collection is invoked again.
  [[ $name != *.backtrace.txt ]] || continue
  executable=${encoded_executable//!//}
  if ! executable=$(realpath -e -- "$executable"); then
    echo "Cannot resolve executable for $core" >&2
    result=1
    continue
  fi
  case "$executable" in
    "$repo_root"/build/c-server/*|"$repo_root"/implementations/c/server/build/*) ;;
    *) echo "Refusing executable outside native test build directories: $executable" >&2; result=1; continue ;;
  esac
  report="$core.backtrace.txt"
  # Disable all auto-loading (including embedded scripts) and debug-file downloads. Backtraces
  # omit locals: CI fixtures can contain synthetic credentials, and raw cores are not uploaded.
  if ! timeout 60s gdb --batch --nx \
      -iex 'set auto-load off' -iex 'set debuginfod enabled off' \
      -iex 'set print frame-arguments none' -ex 'set pagination off' \
      -ex 'info files' -ex 'info threads' \
      -ex 'thread apply all bt' "$executable" "$core" >"$report" 2>&1; then
    result=1
  fi
  cat "$report"
done
exit "$result"
