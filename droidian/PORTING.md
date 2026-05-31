# Droidian/Halium r8q Port

This tree now contains the kernel-side Droidian packaging and the device
adaptation scaffold from the Droidian porting guide.

## Kernel

Local artifact build, using the same toolchain path as `build-r8q.sh`:

```sh
./build-r8q-droidian.sh
```

If the r522817 clang tree is not already present under `tc/`, fetch it first:

```sh
FETCH_TOOLCHAIN=1 ./build-r8q-droidian.sh
```

Debian package build, using Droidian's container:

```sh
droidian/scripts/build-kernel-debs.sh
```

The package metadata lives in `debian/kernel-info.mk`. The build uses the r8q
config stack from `build-r8q.sh` and adds `droidian/r8q-halium.config`.

Before flashing a generated boot image, extract a stock r8q boot image and copy
the verified offsets/cmdline into `debian/kernel-info.mk`:

```sh
droidian/scripts/extract-bootimg-info.sh boot.img
```

Automatic `flash-bootimage` installation is disabled until the exact Samsung
model and `/proc/cpuinfo` match strings are verified on the target device.

## Rootfs

Build the kernel packages first, then bootstrap the Droidian build-tools
workspace and rootfs:

```sh
droidian/scripts/build-kernel-debs.sh
droidian/scripts/bootstrap-rootfs.sh
```

The rootfs script follows the guide's device template values:

```text
vendor=samsung
codename=r8q
arch=arm64
apiver=30
role=phone
desktop=phosh
```

The generated image will be under the Droidian build-tools workspace:

```text
../droidian-build-tools/bin/droidian/vendor/samsung/r8q/droidian/images/
```

## Current Bring-Up State

Implemented:

- Halium/LXC-oriented kernel fragment for namespaces, cgroups, binderfs,
  ashmem, devtmpfs, overlayfs, diagnostics, uinput, VT, and framebuffer console.
- Droidian kernel Debian packaging skeleton with Samsung vbmeta mode and r8q
  build metadata.
- Rootfs/adaptation package scaffold for `adaptation-samsung-r8q`.
- Scripts for kernel deb build, local Droidian artifact build, boot image
  metadata extraction, and rootfs bootstrap.

Still device-required:

- Verify boot image offsets and cmdline from a stock r8q `boot.img`.
- Replace the package repository placeholder and GPG key.
- Enable `FLASH_ENABLED` only after live-device manufacturer/model/CPU strings
  are confirmed.
- Test first boot and run `lxc-checkconfig` on device for any remaining kernel
  options.
