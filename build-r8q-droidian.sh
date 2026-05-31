#!/usr/bin/env bash
set -euo pipefail

DEFCONFIG="vendor/kona-not_defconfig vendor/samsung/kona-sec-not.config vendor/samsung/r8q.config"
OUT_DIR="${OUT_DIR:-$(pwd)/out-droidian}"
TC_DIR="${TC_DIR:-$(pwd)/tc/clang-r522817}"
BOOT_DIR="$OUT_DIR/arch/arm64/boot"
DTS_DIR="$BOOT_DIR/dts/vendor/qcom"

if [ ! -d "$TC_DIR/bin" ]; then
    if [ "${FETCH_TOOLCHAIN:-0}" = "1" ]; then
        git clone --depth=1 -b 18 https://gitlab.com/ThankYouMario/android_prebuilts_clang-standalone "$TC_DIR"
    else
        echo "Missing clang toolchain: $TC_DIR"
        echo "Run FETCH_TOOLCHAIN=1 ./build-r8q-droidian.sh to fetch it, or set TC_DIR to an existing clang-r522817 tree."
        exit 1
    fi
fi

export PATH="$TC_DIR/bin:$PATH"

mkdir -p "$OUT_DIR"
echo "[*] Building Droidian/Halium config for r8q"
make O="$OUT_DIR" ARCH=arm64 $DEFCONFIG
KCONFIG_CONFIG="$OUT_DIR/.config" scripts/kconfig/merge_config.sh -m "$OUT_DIR/.config" droidian/r8q-halium.config
make O="$OUT_DIR" ARCH=arm64 olddefconfig

COMMON_MAKE_ARGS=(
    -j"$(nproc --all)"
    O="$OUT_DIR"
    ARCH=arm64
    CC=clang
    LD=ld.lld
    AS=llvm-as
    AR=llvm-ar
    NM=llvm-nm
    OBJCOPY=llvm-objcopy
    OBJDUMP=llvm-objdump
    STRIP=llvm-strip
    CROSS_COMPILE=aarch64-linux-gnu-
    CROSS_COMPILE_ARM32=arm-linux-gnueabi-
    LLVM=1
    LLVM_IAS=1
)

echo "[*] Building dtbo.img"
make "${COMMON_MAKE_ARGS[@]}" dtbo.img

echo "[*] Building Image"
make "${COMMON_MAKE_ARGS[@]}" Image

if [ ! -f "$BOOT_DIR/Image" ]; then
    echo "Kernel Image was not produced at $BOOT_DIR/Image"
    exit 1
fi

if [ ! -d "$DTS_DIR" ]; then
    echo "Compiled DTB directory missing: $DTS_DIR"
    exit 1
fi

echo "[*] Generating concatenated Samsung/QCOM DTB: $BOOT_DIR/kona.dtb"
find "$DTS_DIR" -type f -name "*.dtb" | sort | xargs cat > "$BOOT_DIR/kona.dtb"

echo "[*] Droidian kernel artifacts:"
echo "    $BOOT_DIR/Image"
echo "    $BOOT_DIR/dtbo.img"
echo "    $BOOT_DIR/kona.dtb"
