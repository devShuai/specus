#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

ADMIN_WEB_DIST="${ADMIN_WEB_DIST:-${REPO_ROOT}/apps/admin-web/dist}"
ADMIN_WEB_ROOT="${ADMIN_WEB_ROOT:-/opt/specus/admin-web}"
OPENRESTY_CONF_DIR="${OPENRESTY_CONF_DIR:-/usr/local/openresty/nginx/conf/conf.d}"
OPENRESTY_CONF_NAME="${OPENRESTY_CONF_NAME:-specus.devshuai.com.conf}"
LEGACY_OPENRESTY_CONF_NAME="${LEGACY_OPENRESTY_CONF_NAME:-tunnel.devshuai.com.conf}"
INSTALL_LEGACY_REDIRECT="${INSTALL_LEGACY_REDIRECT:-1}"
OPENRESTY_BACKUP_DIR="${OPENRESTY_BACKUP_DIR:-/var/backups/specus-openresty}"
OPENRESTY_BIN="${OPENRESTY_BIN:-openresty}"

if [[ ! -d "${ADMIN_WEB_DIST}" ]]; then
  echo "dist not found: ${ADMIN_WEB_DIST}" >&2
  echo "run: cd apps/admin-web && npm run build:openresty" >&2
  exit 1
fi

install -d -m 0755 "${ADMIN_WEB_ROOT}"
rm -rf "${ADMIN_WEB_ROOT:?}/"*
cp -a "${ADMIN_WEB_DIST}/." "${ADMIN_WEB_ROOT}/"
chmod 0755 "${ADMIN_WEB_ROOT}"
find "${ADMIN_WEB_ROOT}" -type d -exec chmod 0755 {} \;
find "${ADMIN_WEB_ROOT}" -type f -exec chmod 0644 {} \;

if [[ -d "${OPENRESTY_CONF_DIR}" ]]; then
  install -m 0644 "${SCRIPT_DIR}/specus.conf" "${OPENRESTY_CONF_DIR}/${OPENRESTY_CONF_NAME}"

  if [[ "${INSTALL_LEGACY_REDIRECT}" == "1" ]]; then
    legacy_conf="${OPENRESTY_CONF_DIR}/${LEGACY_OPENRESTY_CONF_NAME}"
    if [[ -f "${legacy_conf}" ]] && ! cmp -s "${SCRIPT_DIR}/tunnel-redirect.conf" "${legacy_conf}"; then
      install -d -m 0755 "${OPENRESTY_BACKUP_DIR}"
      cp -a "${legacy_conf}" \
        "${OPENRESTY_BACKUP_DIR}/${LEGACY_OPENRESTY_CONF_NAME}.$(date -u +%Y%m%dT%H%M%SZ)"
    fi
    install -m 0644 "${SCRIPT_DIR}/tunnel-redirect.conf" "${legacy_conf}"
  fi

  "${OPENRESTY_BIN}" -t
  echo "installed OpenResty config: ${OPENRESTY_CONF_DIR}/${OPENRESTY_CONF_NAME}"
  if [[ "${INSTALL_LEGACY_REDIRECT}" == "1" ]]; then
    echo "installed legacy redirect: ${OPENRESTY_CONF_DIR}/${LEGACY_OPENRESTY_CONF_NAME}"
  fi
else
  echo "skip config install, directory missing: ${OPENRESTY_CONF_DIR}" >&2
fi

echo "installed admin web: ${ADMIN_WEB_ROOT}"
echo "reload after review: sudo ${OPENRESTY_BIN} -s reload"
