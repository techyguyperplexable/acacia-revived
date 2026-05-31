#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /path/to/stock-r8q-boot.img" >&2
    exit 2
fi

BOOT_IMG="$1"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

if command -v unpackbootimg >/dev/null 2>&1; then
    if unpackbootimg --boot_img "$BOOT_IMG" --out "$WORKDIR" >/dev/null 2>&1; then
        :
    elif unpackbootimg -i "$BOOT_IMG" -o "$WORKDIR" >/dev/null 2>&1; then
        :
    else
        echo "unpackbootimg failed for $BOOT_IMG" >&2
        exit 1
    fi
else
    echo "unpackbootimg is required. Run this inside quay.io/droidian/build-essential:current-amd64." >&2
    exit 1
fi

echo "# Copy verified values into debian/kernel-info.mk"
find "$WORKDIR" -maxdepth 1 -type f | sort | while read -r file; do
    case "$file" in
        *.cmdline) echo "KERNEL_BOOTIMAGE_CMDLINE = $(cat "$file") console=tty0 droidian.lvm.prefer" ;;
        *.pagesize) echo "KERNEL_BOOTIMAGE_PAGE_SIZE = $(cat "$file")" ;;
        *.base) echo "KERNEL_BOOTIMAGE_BASE_OFFSET = $(cat "$file")" ;;
        *.kernel_offset) echo "KERNEL_BOOTIMAGE_KERNEL_OFFSET = $(cat "$file")" ;;
        *.ramdisk_offset) echo "KERNEL_BOOTIMAGE_INITRAMFS_OFFSET = $(cat "$file")" ;;
        *.second_offset) echo "KERNEL_BOOTIMAGE_SECONDIMAGE_OFFSET = $(cat "$file")" ;;
        *.tags_offset) echo "KERNEL_BOOTIMAGE_TAGS_OFFSET = $(cat "$file")" ;;
        *.dtb_offset) echo "KERNEL_BOOTIMAGE_DTB_OFFSET = $(cat "$file")" ;;
        *.header_version) echo "KERNEL_BOOTIMAGE_VERSION = $(cat "$file")" ;;
    esac
done
