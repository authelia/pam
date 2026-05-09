#!/usr/bin/env bash
# shim/build-all.sh - Cross-compile pam_authelia.so for every libc/arch combination
# supported by the authelia/crossbuild container. Invoked by GoReleaser's before.hooks.
#
# Output layout: shim/dist/linux-<arch>-<libc>/pam_authelia.so

set -euo pipefail

SHIM_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST_DIR="${SHIM_DIR}/dist"

VERSION="${VERSION:-0.0.0-dev}"

# musl relies on a fortify-shim header directory shipped with the crossbuild
# container. Use -isystem (not -I) so the upstream fortify-headers project's
# minor pedantic-mode violations don't trip our -Werror -pedantic build.
MUSL_EXTRA_CPPFLAGS='-isystem /usr/local/include/fortify'

# target=<libc>:<arch>:<cc>
TARGETS=(
  "glibc:amd64:gcc"
  "glibc:arm:arm-linux-gnueabihf-gcc"
  "glibc:arm64:aarch64-linux-gnu-gcc"
  "musl:amd64:x86_64-linux-musl-cc"
  "musl:arm:arm-linux-musleabihf-cc"
  "musl:arm64:aarch64-linux-musl-cc"
)

build_target() {
  local libc="$1" arch="$2" cc="$3"
  local out_dir="${DIST_DIR}/linux-${arch}-${libc}"
  local extra_cppflags=""

  if [[ "${libc}" == "musl" ]]; then
    extra_cppflags="${MUSL_EXTRA_CPPFLAGS}"
  fi

  echo "--- Building pam_authelia.so for linux/${arch} (${libc}) with ${cc}"

  mkdir -p "${out_dir}"

  make -C "${SHIM_DIR}" clean >/dev/null
  make -C "${SHIM_DIR}" \
    CC="${cc}" \
    VERSION="${VERSION}" \
    EXTRA_CPPFLAGS="${extra_cppflags}" \
    all

  cp "${SHIM_DIR}/pam_authelia.so" "${out_dir}/pam_authelia.so"
}

rm -rf "${DIST_DIR}"

for entry in "${TARGETS[@]}"; do
  IFS=':' read -r libc arch cc <<< "${entry}"
  build_target "${libc}" "${arch}" "${cc}"
done

make -C "${SHIM_DIR}" clean >/dev/null

echo "--- Shim build artifacts:"
find "${DIST_DIR}" -name 'pam_authelia.so' -print
