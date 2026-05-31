#!/usr/bin/env bash
set -euo pipefail

KERNEL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOLS_DIR="${DROIDIAN_BUILD_TOOLS:-$KERNEL_DIR/../droidian-build-tools}"
PACKAGES_DIR="${PACKAGES_DIR:-$KERNEL_DIR/../packages}"
DEVICE_DIR="$TOOLS_DIR/bin/droidian/vendor/samsung/r8q"
ADAPTATION_SRC="$KERNEL_DIR/droidian/adaptation-samsung-r8q"
ADAPTATION_DST="$DEVICE_DIR/packages/adaptation-samsung-r8q"

if [ ! -d "$TOOLS_DIR/.git" ]; then
    git clone https://github.com/droidian-releng/droidian-build-tools "$TOOLS_DIR"
fi

cd "$TOOLS_DIR/bin"

if [ ! -d "$DEVICE_DIR" ]; then
    ./droidian-new-device -v samsung -n r8q -c arm64 -a 30 -r phone -d droidian
fi

mkdir -p "$ADAPTATION_DST"
rsync -a --delete "$ADAPTATION_SRC/" "$ADAPTATION_DST/"

cd "$ADAPTATION_DST"
"$TOOLS_DIR/bin/droidian-build-package"

mkdir -p "$DEVICE_DIR/droidian/images" "$DEVICE_DIR/droidian/local-packages"
find "$PACKAGES_DIR" -maxdepth 1 -type f -name '*.deb' -exec cp -f {} "$DEVICE_DIR/droidian/local-packages/" \;
cp "$KERNEL_DIR/droidian/rootfs/community_devices.yml" "$DEVICE_DIR/droidian/community_devices.yml"

docker run --rm --privileged multiarch/qemu-user-static --reset -p yes

cd "$DEVICE_DIR/droidian"
docker run --privileged \
    -v "$PWD/images:/buildd/out" \
    -v /dev:/host-dev \
    -v /sys/fs/cgroup:/sys/fs/cgroup \
    -v "$PWD:/buildd/sources" \
    --security-opt seccomp:unconfined \
    --cgroupns host \
    quay.io/droidian/rootfs-builder:current-amd64 \
    /bin/sh -c 'cd /buildd/sources; DROIDIAN_VERSION="next" ./generate_device_recipe.py samsung_r8q arm64 phosh phone 30 && debos --disable-fakemachine generated/droidian.yaml'

echo "Rootfs images are in $DEVICE_DIR/droidian/images"
