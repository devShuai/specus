#!/usr/bin/env bash
# Test-only helpers. Reserve the entire port set at once so endpoints within one
# fixture are distinct; never accept an unrelated Redis as readiness for our child.
specus_test_pick_ports() {
  python3 - "$@" <<'PY'
import socket
import sys

channels = []
try:
    ports = []
    for requested in sys.argv[1:]:
        port = int(requested) if requested else 0
        if not 0 <= port <= 65535:
            raise ValueError("port must be between 0 and 65535")
        channel = socket.socket()
        channels.append(channel)
        channel.bind(("127.0.0.1", port))
        ports.append(channel.getsockname()[1])
    print(" ".join(map(str, ports)))
except (OSError, ValueError) as error:
    print(f"test port allocation failed: {error}", file=sys.stderr)
    sys.exit(1)
finally:
    for channel in channels:
        channel.close()
PY
}

specus_test_wait_redis() {
  local child="$1" port="$2" log="$3" info actual
  for _ in {1..60}; do
    if ! kill -0 "$child" 2>/dev/null; then
      echo "test Redis child exited before readiness: pid=$child port=$port" >&2
      cat "$log" >&2 || true
      return 1
    fi
    if info=$(redis-cli --raw -h 127.0.0.1 -p "$port" INFO server 2>/dev/null); then
      actual=$(printf '%s\n' "$info" | tr -d '\r' | sed -n 's/^process_id://p')
      if [[ "$actual" != "$child" ]]; then
        echo "Redis ownership mismatch: expected_pid=$child actual_pid=${actual:-unknown} port=$port" >&2
        cat "$log" >&2 || true
        return 1
      fi
      echo "test Redis ready: pid=$child port=$port" >&2
      return 0
    fi
    sleep 0.05
  done
  echo "test Redis readiness deadline exceeded: pid=$child port=$port" >&2
  cat "$log" >&2 || true
  return 1
}
