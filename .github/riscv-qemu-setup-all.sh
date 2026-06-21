#!/bin/sh
set -eux

LINUX_IMG=linux-image-6.12.73+deb13-riscv64_6.12.73-1_riscv64.deb
DEBIAN_SERVER=https://ftp.debian.org/debian/pool/main/l/linux
BUSYBOX_PATH=busybox-1.30.1-riscv64
BUSYBOX_VERSION=9d220791e5917fc2190c5cf405a014a483c01d86
LIB_PATH=/usr/riscv64-linux-gnu/lib
LIB_C=libc.so.6
LIB_M=libm.so.6
DYN_LD=ld-linux-riscv64-lp64d.so.1
TEST_BIN_URL=https://raw.githubusercontent.com/rizinorg/rizin-testbins/master/elf/riscv_bitmanip
# Fetch the kernel package
wget "$DEBIAN_SERVER/$LINUX_IMG"
# Extract
dpkg-deb -x "$LINUX_IMG" linux-image

# Fetch busybox
git clone https://github.com/rcore-os/busybox-prebuilts.git busybox
cd busybox && git checkout "$BUSYBOX_VERSION" && cd ..

# Cross-compile the Rizin repo
cd rizin
meson setup build --cross-file doc/examples/cross_builds/meson-linux-riscv64.ini
meson compile -C build
cd ..

# Create a rootfs
mkdir -p rootfs 
mkdir -p rootfs/bin rootfs/lib rootfs/tmp rootfs/proc rootfs/etc rootfs/test/bins/elf rootfs/test/db/archos/linux-riscv64

# Simple copying of rizin binaries and .so libs doesn't work, as it skips sdb generaton and other important steps
# Install to a custom prefix instead
cd rizin && DESTDIR=../../rootfs/ meson install -C build && cd ..
wget ${TEST_BIN_URL} && cp riscv_bitmanip rootfs/test/bins/elf/riscv_bitmanip && chmod +x rootfs/test/bins/elf/riscv_bitmanip
cp rizin/test/db/archos/linux-riscv64/dbg_basic rootfs/test/db/archos/linux-riscv64/dbg_basic

# libc and libm, dynamic linker
cp "$LIB_PATH/$LIB_C" "$LIB_PATH/$LIB_M" "$LIB_PATH/$DYN_LD" rootfs/lib/

# Copy busybox to rootfs
cp "busybox/$BUSYBOX_PATH/busybox" rootfs/bb

# Make busybox the init launcher, poweroff, the shell, and mount
ln -s bb rootfs/init
ln -s bb rootfs/poweroff
ln -s bb rootfs/mount
ln -s ../bb rootfs/bin/sh

# Make the inittab
cat << EOF > rootfs/etc/inittab
::sysinit:/mount -t tmpfs -o size=128M,nodev,nosuid tmpfs /tmp
::sysinit:/mount -t proc proc /proc
::wait:/bin/sh -c "export PATH=/usr/local/bin && cd /test && rz-test db/archos/linux-riscv64"
::once:/poweroff -f
EOF

# filesystem state 
# rootfs
# /
# ├── bb
# ├── init -> bb
# ├── poweroff -> bb
# ├── mount -> bb
# ├── lib/
# │   ├── libc.so.6
# │   ├── libm.so.6
# │   ├── ld-linux-riscv64-lp64d.so.1
# ├── tmp/
# │   └── (mounted by kernel)
# ├── proc/
# │   └── (mounted by kernel)
# └── etc/
# |   └── inittab
# ├── test
# │   ├── bins
# │   │   └── elf
# │   └── db
# │       └── archos
# │           └── linux-riscv64
# └── usr
#    └── local
#        ├── bin
#        │   ├── rizin
#        │   ├── rz-ar
#        │   ├── rz-asm
#        │   ├── rz-ax
#        │   ├── rz-bin
#        │   ├── rz-diff
#        │   ├── rz-find
#        │   ├── rz-gg
#        │   ├── rz-hash
#        │   ├── rz-run
#        │   ├── rz-sign
#        │   └── rz-test
#        ├── include 
#        | ....
#        | ....
echo "#########################################################################"
# for debugging, always check the output tree against the intended tree above
tree rootfs
echo "#########################################################################"

# Package the whole thing into an initrd archive
cd rootfs
find . | cpio -o -H newc | gzip > ../initrd.cpio.gz
