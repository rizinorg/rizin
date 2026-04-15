#!/bin/sh
set -eux

MINSTACK_VERSION=v12

# Download the linux kernel image, opensbi firmware, and the busybox userspace from the minstack repo
wget -q "https://github.com/moste00/riscv-minstack/releases/download/${MINSTACK_VERSION}/rv32-Image"
wget -q "https://github.com/moste00/riscv-minstack/releases/download/${MINSTACK_VERSION}/rv32-fw_dynamic.bin"
wget -q "https://github.com/moste00/riscv-minstack/releases/download/${MINSTACK_VERSION}/rv32-busybox"

#---------------------------------------------------------------------------------------------------------------------
cd rizin
# Setup cross file
sed -i "s|<<path-to-bootlin-installation>>|${BOOTLIN_INSTALLATION}|g" doc/examples/cross_builds/meson-linux-riscv32.ini
export PATH="${BOOTLIN_TOOLS}:${PATH}"

# Build Rizin
meson setup build --cross-file doc/examples/cross_builds/meson-linux-riscv32.ini
meson compile -C build || true # Expected to fail due to Zydis bug on RISC-V 32-bit
# Quick and dirty fix for Zydis compilation error, remove when upstream merges a fix and we bump
patch -p1 < patches/fix_zydis_amalgamated_riscv32_build
# Build again
meson compile -C build

file build/binrz/rizin/rizin
cd ..
#---------------------------------------------------------------------------------------------------------------------

# Create a init config for busybox
cat << EOF > inittab
::sysinit:/mount -t proc proc /proc
::sysinit:/mount -t sysfs sysfs /sys
::sysinit:/mount -t devtmpfs devtmpfs /dev
::sysinit:/mount -t tmpfs -o size=128M,nodev,nosuid tmpfs /tmp
::wait:$@
::once:/poweroff -f
EOF

# Describe the boot filesystem
cat << EOF > initramfs
dir /bin 0755 0 0
dir /etc 0755 0 0
dir /lib 0755 0 0
dir /tmp 1777 0 0
dir /proc 0755 0 0
dir /sys 0755 0 0 
dir /dev 0755 0 0

nod /dev/console 0600 0 0 c 5 1

file /bin/busybox rv32-busybox 0755 0 0
slink /init /bin/busybox 0777 0 0
slink /mount /bin/busybox 0777 0 0
slink /poweroff /bin/busybox 0777 0 0
file /etc/inittab inittab 0644 0 0

file /lib/ld-musl-riscv32.so.1 ${BOOTLIN_INSTALLATION}/riscv32-buildroot-linux-musl/sysroot/lib/ld-musl-riscv32.so.1 0755 0 0
file /bin/rizin rizin/build/binrz/rizin/rizin 0755 0 0
EOF

# Generate the boot filesystem
gcc rizin/sys/gen_cpio_script.c -O3 -o gen_cpio
./gen_cpio initramfs > initrd_rv32.cpio