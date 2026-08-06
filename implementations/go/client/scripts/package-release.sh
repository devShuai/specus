#!/usr/bin/env bash
# 打包 Go 客户端为 macOS / Linux / Windows 可运行包。
#
# 用法:
#   scripts/package-release.sh [version]
#   version 缺省时取 `git describe --tags --always`（无 tag 时为短 commit hash）。
#
# 产物: out/release/<version>/specus-client-go-<version>-<platform>-<arch>.{tar.gz|zip}
#   - 二进制为静态交叉编译（CGO_ENABLED=0），wintun.dll 已 go:embed 进 Windows 二进制，
#     无需随包携带；包内附 client.example.jsonc，Windows 包附 Wintun LICENSE。
#   - platform/arch 命名与管理台「客户端下载」的 platform(windows|linux|macos) /
#     arch(x64|arm64) 枚举一致，可直接登记为下载链接。
#   - 同目录生成 SHA256SUMS.txt。
#
# 依赖: go、tar；zip 可选（缺失且在 Windows 上时回退 PowerShell Compress-Archive）。
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${1:-$(git describe --tags --always 2>/dev/null || echo dev)}"
BINARY="specus-client"
OUT_ROOT="out/release/${VERSION}"
STAGE_ROOT="out/stage"

# platform:goos:goarch:artifact-arch
TARGETS=(
  "linux:linux:amd64:x64"
  "linux:linux:arm64:arm64"
  "macos:darwin:amd64:x64"
  "macos:darwin:arm64:arm64"
  "windows:windows:amd64:x64"
  "windows:windows:arm64:arm64"
)

rm -rf "${OUT_ROOT}" "${STAGE_ROOT}"
mkdir -p "${OUT_ROOT}"

zip_dir() {
  # zip_dir <srcDir> <destZip>：优先 zip，Windows 上回退 Compress-Archive
  local src="$1" dest="$2"
  if command -v zip >/dev/null 2>&1; then
    # 目标必须先解析为绝对路径：进入 src 之后相对路径的 dest 会解析不到。
    local dest_abs
    dest_abs="$(cd "$(dirname "${dest}")" && pwd)/$(basename "${dest}")"
    (cd "${src}" && zip -q -r "${dest_abs}" .)
  elif command -v powershell.exe >/dev/null 2>&1; then
    powershell.exe -NoProfile -Command \
      "Compress-Archive -Path '$(cygpath -w "${src}")\\*' -DestinationPath '$(cygpath -w "${dest}")' -Force" >/dev/null
  else
    echo "error: 需要 zip 或 powershell.exe 来生成 .zip" >&2
    exit 1
  fi
}

for target in "${TARGETS[@]}"; do
  IFS=":" read -r platform goos goarch arch <<<"${target}"
  name="${BINARY}-go-${VERSION}-${platform}-${arch}"
  stage="${STAGE_ROOT}/${name}"
  mkdir -p "${stage}"

  bin="${BINARY}"
  [ "${goos}" = "windows" ] && bin="${BINARY}.exe"

  echo "==> build ${platform}/${arch} (${goos}/${goarch})"
  CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
    go build -trimpath -ldflags "-s -w" \
    -o "${stage}/${bin}" ./cmd/specus-client

  cp client.example.jsonc "${stage}/"
  if [ "${goos}" = "windows" ]; then
    # wintun.dll 已嵌入二进制，但其许可证要求随分发附带
    cp internal/client/native/windows/LICENSE.txt "${stage}/WINTUN-LICENSE.txt"
  fi

  if [ "${goos}" = "windows" ]; then
    artifact="${OUT_ROOT}/${name}.zip"
    zip_dir "${stage}" "${artifact}"
  else
    # 显式赋 0755：在 Windows 上打包时文件系统不带可执行位，直接归档会导致
    # 解压后无法运行。分两次调用是因为 getopt 参数重排会让同一命令里的多个
    # --mode 只有最后一个全局生效；--owner/--group=0 避免归档泄漏本机用户名。
    artifact="${OUT_ROOT}/${name}.tar.gz"
    plain_tar="${OUT_ROOT}/${name}.tar"
    tar -cf "${plain_tar}" -C "${stage}" \
      --owner=0 --group=0 --numeric-owner --mode=0755 "${bin}"
    tar -rf "${plain_tar}" -C "${stage}" \
      --owner=0 --group=0 --numeric-owner --mode=0644 client.example.jsonc
    gzip -9 -f "${plain_tar}"
  fi
  echo "    -> ${artifact}"
done

rm -rf "${STAGE_ROOT}"

(
  cd "${OUT_ROOT}"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- * >SHA256SUMS.txt
  else
    shasum -a 256 -- * >SHA256SUMS.txt
  fi
)

echo
echo "release ${VERSION} 打包完成:"
ls -lh "${OUT_ROOT}"
