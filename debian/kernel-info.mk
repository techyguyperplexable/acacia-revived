# Droidian/Halium kernel package metadata for Samsung Galaxy S20 FE 5G (r8q).
# Values are mapped from build-r8q.sh and the Droidian porting guide.

VARIANT = android
KERNEL_BASE_VERSION = 4.19.325

# Verify this against a stock r8q boot.img with droidian/scripts/extract-bootimg-info.sh
# before publishing flashable packages. These are the standard Android 10/QCOM
# header v2 defaults plus Droidian's required console/LVM arguments.
KERNEL_BOOTIMAGE_CMDLINE = console=tty0 androidboot.hardware=qcom androidboot.configfs=true androidboot.usbcontroller=a600000.dwc3 firmware_class.path=/vendor/firmware_mnt/image loop.max_part=7 systemd.unified_cgroup_hierarchy=0 droidian.lvm.prefer
KERNEL_BOOTIMAGE_PAGE_SIZE = 4096
KERNEL_BOOTIMAGE_BASE_OFFSET = 0x00000000
KERNEL_BOOTIMAGE_KERNEL_OFFSET = 0x00008000
KERNEL_BOOTIMAGE_INITRAMFS_OFFSET = 0x01000000
KERNEL_BOOTIMAGE_SECONDIMAGE_OFFSET = 0x00f00000
KERNEL_BOOTIMAGE_TAGS_OFFSET = 0x00000100
KERNEL_BOOTIMAGE_DTB_OFFSET = 0x01f00000
KERNEL_BOOTIMAGE_VERSION = 2

DEVICE_VENDOR = samsung
DEVICE_MODEL = r8q
DEVICE_FULL_NAME = Samsung Galaxy S20 FE 5G
DEVICE_VBMETA_IS_SAMSUNG = 1

# build-r8q.sh uses this exact sequence.
KERNEL_DEFCONFIG = vendor/kona-not_defconfig vendor/samsung/kona-sec-not.config vendor/samsung/r8q.config
KERNEL_CONFIG_USE_FRAGMENTS = 1
KERNEL_ARCH = arm64
KERNEL_BUILD_TARGET = Image

# build-r8q.sh produces out/arch/arm64/boot/Image, dtbo.img, and kona.dtb.
KERNEL_IMAGE_WITH_DTB = 1
KERNEL_IMAGE_DTB = arch/arm64/boot/kona.dtb
KERNEL_IMAGE_WITH_DTB_OVERLAY = 1
KERNEL_IMAGE_DTB_OVERLAY = arch/arm64/boot/dtbo.img

BUILD_CROSS = 1
BUILD_TRIPLET = aarch64-linux-gnu-
BUILD_CLANG_TRIPLET = aarch64-linux-gnu-
BUILD_CC = clang
BUILD_PATH = /usr/lib/llvm-android-14.0-r450784d/bin
DEB_TOOLCHAIN = linux-initramfs-halium-generic:arm64, binutils-aarch64-linux-gnu, binutils-arm-linux-gnueabi, gcc-arm-linux-gnueabi, clang-android-14.0-r450784d
DEB_BUILD_ON = amd64
DEB_BUILD_FOR = arm64

# Keep automatic boot flashing disabled until FLASH_INFO_* is verified on a
# real r8q device. Wrong Samsung model matching can flash the wrong partition.
FLASH_ENABLED = 0
# FLASH_INFO_MANUFACTURER = samsung
# FLASH_INFO_MODEL = SM-G781B
# FLASH_INFO_CPU = Qualcomm Technologies, Inc KONA
# FLASH_INFO_DEVICE_IDS = r8q,kona,sm8250
