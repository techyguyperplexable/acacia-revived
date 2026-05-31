#!/usr/bin/env bash
set -euo pipefail

KERNEL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACKAGES_DIR="${PACKAGES_DIR:-$KERNEL_DIR/../packages}"

mkdir -p "$PACKAGES_DIR"

docker run --rm \
    -v "$PACKAGES_DIR:/buildd" \
    -v "$KERNEL_DIR:/buildd/sources" \
    -i quay.io/droidian/build-essential:current-amd64 \
    bash -lc '
        set -euo pipefail
        apt-get update
        apt-get install -y linux-packaging-snippets device-tree-compiler
        cd /buildd/sources
        if [ "${REGENERATE_CONTROL:-0}" = "1" ]; then
            rm -f debian/control
            debian/rules debian/control
        fi
        RELENG_HOST_ARCH=arm64 releng-build-package
    '

echo "Kernel packages are in $PACKAGES_DIR"
