SECONDS=0 # builtin bash timer

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

export TG_BOT_TOKEN=
export TG_CHAT_ID=

tg_post_msg() {
    curl -s -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
        -d chat_id="${TG_CHAT_ID}" \
        -d parse_mode="HTML" \
        -d text="$1"
}

# ===== AnyKernel3 =====
AK3_REPO="https://github.com/skye-tachyon/AnyKernel3"
AK3_BRANCH="gts7lwifi"
AK3_DIR="$(pwd)/android/AnyKernel3"

ZIPNAME="Acacia-CI-$(date '+%Y%m%d').zip"
TC_DIR="$(pwd)/tc/clang-r522817"
DEFCONFIG="vendor/kona-not_defconfig vendor/samsung/kona-sec-not.config vendor/samsung/gts7lwifi.config"

OUT_DIR="$(pwd)/out"
BOOT_DIR="$OUT_DIR/arch/arm64/boot"
DTS_DIR="$BOOT_DIR/dts/vendor/qcom"

KERNEL_VERSION=$(make kernelversion)
CHANGELOG=$(git log --oneline -n 10)

if [ -n "$TG_BOT_TOKEN" ] && [ -n "$TG_CHAT_ID" ]; then
    tg_post_msg "<b>🔨 Build Started</b>%0A<b>Device:</b> gts7lwifi%0A<b>Kernel Version:</b> ${KERNEL_VERSION}%0A<b>Compiler:</b> Clang r522817"
fi

if test -z "$(git rev-parse --show-cdup 2>/dev/null)" &&
   head=$(git rev-parse --verify HEAD 2>/dev/null); then
    ZIPNAME="${ZIPNAME::-4}-$(echo $head | cut -c1-8)-gts7lwifi.zip"
fi

export PATH="$TC_DIR/bin:$PATH"

if ! [ -d "$TC_DIR" ]; then
    echo -e "${YELLOW}AOSP clang not found! Cloning to $TC_DIR...${NC}"
    if ! git clone --depth=1 -b 18 https://gitlab.com/ThankYouMario/android_prebuilts_clang-standalone "$TC_DIR"; then
        echo -e "${RED}Cloning failed! Aborting...${NC}"
        exit 1
    fi
fi

mkdir -p out
echo -e "${YELLOW}building with: $DEFCONFIG${NC}"

make O=out ARCH=arm64 $DEFCONFIG
make O=out ARCH=arm64 olddefconfig

echo -e "\n${YELLOW}Starting compilation...${NC}\n"

make -j$(nproc --all) O=out ARCH=arm64 \
    CC=clang LD=ld.lld AS=llvm-as AR=llvm-ar NM=llvm-nm \
    OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump STRIP=llvm-strip \
    CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_ARM32=arm-linux-gnueabi- \
    LLVM=1 LLVM_IAS=1 dtbo.img
    
make -j$(nproc --all) O=out ARCH=arm64 \
    CC=clang LD=ld.lld AS=llvm-as AR=llvm-ar NM=llvm-nm \
    OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump STRIP=llvm-strip \
    CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_ARM32=arm-linux-gnueabi- \
    LLVM=1 LLVM_IAS=1 Image
    
if [ -f "$BOOT_DIR/Image" ]; then
    echo -e "${GREEN}Kernel Image found!${NC}"
    
    if [ -d "$DTS_DIR" ]; then
        echo -e "${BLUE}Generating dtb from $DTS_DIR...${NC}"
        cat $(find "$DTS_DIR" -type f -name "*.dtb" | sort) > "$BOOT_DIR/kona.dtb"
        
        if [ -f "$BOOT_DIR/kona.dtb" ]; then
            echo -e "${GREEN}dtb generated successfully!${NC}"
        else
            echo -e "${RED}Failed to generate kona.dtb! Check if dtbs were compiled.${NC}"
            exit 1
        fi
    else
        echo -e "${RED}DTS directory not found. Compilation might be incomplete.${NC}"
        exit 1
    fi
else
    echo -e "\n${RED}Compilation failed! Image not found.${NC}"
    exit 1
fi

rm -rf AnyKernel3
echo "[*] Cloning AnyKernel3 for $AK3_BRANCH"
git clone -q -b "$AK3_BRANCH" "$AK3_REPO" AnyKernel3 || exit 1

echo -e "Preparing zip...\n"

cp "$BOOT_DIR/dtbo.img" AnyKernel3/dtbo.img
cp "$BOOT_DIR/Image" AnyKernel3/Image
cp "$BOOT_DIR/kona.dtb" AnyKernel3/kona.dtb

cd AnyKernel3

zip -r9 "../$ZIPNAME" * -x .git README.md *placeholder
cd ..

echo -e "\n${GREEN}Completed in $((SECONDS / 60)) minute(s) and $((SECONDS % 60)) second(s)!${NC}"
echo -e "${GREEN}Zip: $ZIPNAME${NC}"

if [ -n "$TG_BOT_TOKEN" ] && [ -n "$TG_CHAT_ID" ]; then
    echo -e "\n${BLUE}Uploading to Telegram...${NC}"
    curl -s -F document=@"$ZIPNAME" "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendDocument" \
        -F chat_id="${TG_CHAT_ID}" \
        -F parse_mode="HTML" \
        -F caption="<b>✅ Build Finished</b>%0A<b>Device:</b> gts7lwifi%0A<b>Kernel Version:</b> ${KERNEL_VERSION}%0A<b>Time:</b> $((SECONDS / 60))m $((SECONDS % 60))s%0A<b>Zip:</b> $ZIPNAME%0A%0A<b>Changelog:</b>%0A<code>${CHANGELOG}</code>"
fi
