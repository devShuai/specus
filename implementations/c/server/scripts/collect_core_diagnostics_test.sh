#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
test_dir=$(mktemp -d /tmp/specus-core-diagnostics-XXXXXX)
repo_root="$test_dir/repo with spaces"
core_dir="$test_dir/cores"
mkdir -p "$repo_root/build/c-server" "$core_dir"
executable="$repo_root/build/c-server/crash-fixture"
core="$core_dir/core.1.${executable//\//!}"
trap 'rm -f -- "$executable" "$core" "$core.backtrace.txt" "$test_dir/gdb.log"; rmdir -- "$repo_root/build/c-server" "$repo_root/build" "$repo_root" "$core_dir" "$test_dir"' EXIT
bash "$script_dir/collect_core_diagnostics.sh" "$core_dir" "$repo_root"
cc -g -O0 "$script_dir/../tests/core_crash_fixture.c" -o "$executable"
# GDB writes this deliberate fixture core without changing the host kernel's core_pattern.
gdb --batch --nx -iex 'set auto-load off' -iex 'set debuginfod enabled off' \
  -ex 'set disable-randomization off' -ex run -ex "generate-core-file $core" \
  "$executable" >"$test_dir/gdb.log" 2>&1
test -s "$core"
bash "$script_dir/collect_core_diagnostics.sh" "$core_dir" "$repo_root"
grep -q 'crash_here' "$core.backtrace.txt"
grep -q 'core_crash_fixture.c:' "$core.backtrace.txt"
# Collection is idempotent and never treats its own report as a second core.
bash "$script_dir/collect_core_diagnostics.sh" "$core_dir" "$repo_root"
test ! -e "$core.backtrace.txt.backtrace.txt"
# Executables outside the two repository build roots must not be opened by GDB.
if bash "$script_dir/collect_core_diagnostics.sh" "$core_dir" "$test_dir"; then
  echo 'Collector accepted a foreign executable' >&2
  exit 1
fi
echo 'core diagnostics tests passed'
