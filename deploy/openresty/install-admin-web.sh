#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

ADMIN_WEB_DIST="${ADMIN_WEB_DIST:-${REPO_ROOT}/apps/admin-web/dist}"
ADMIN_WEB_ROOT="${ADMIN_WEB_ROOT:-/opt/shuai-tunnel/admin-web}"
OPENRESTY_CONF_DIR="${OPENRESTY_CONF_DIR:-/usr/local/openresty/nginx/conf/conf.d}"
OPENRESTY_BIN="${OPENRESTY_BIN:-openresty}"

if [[ ! -d "${ADMIN_WEB_DIST}" ]]; then
  echo "dist not found: ${ADMIN_WEB_DIST}" >&2
  echo "run: cd apps/admin-web && npm run build:openresty" >&2
  exit 1
fi

install -d -m 0755 "${ADMIN_WEB_ROOT}"
rm -rf "${ADMIN_WEB_ROOT:?}/"*
cp -a "${ADMIN_WEB_DIST}/." "${ADMIN_WEB_ROOT}/"

if [[ -d "${OPENRESTY_CONF_DIR}" ]]; then
  install -m 0644 "${SCRIPT_DIR}/shuai-tunnel.conf" "${OPENRESTY_CONF_DIR}/shuai-tunnel.conf"
  "${OPENRESTY_BIN}" -t
  echo "installed OpenResty config: ${OPENRESTY_CONF_DIR}/shuai-tunnel.conf"
else
  echo "skip config install, directory missing: ${OPENRESTY_CONF_DIR}" >&2
fi

echo "installed admin web: ${ADMIN_WEB_ROOT}"
echo "reload after review: sudo ${OPENRESTY_BIN} -s reload"
