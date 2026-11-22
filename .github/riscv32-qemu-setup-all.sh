#!/bin/sh
set -eux

MINSTACK_VERSION=v17

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
# Build again
meson compile -C build

# Install to a custom prefix
mkdir -p ../rootfs-rv32
DESTDIR=../../rootfs-rv32 meson install -C build
cd ..

# Download the test binary (TODO: Change to rizinorg/rizin-testbins when the test binary PR is merged to rizinorg's repo)
TEST_BIN_URL=https://raw.githubusercontent.com/moste00/rizin-testbins/riscv_bitmanip_32bit/elf/riscv_bitmanip_32
wget ${TEST_BIN_URL} -O riscv_bitmanip_32
#---------------------------------------------------------------------------------------------------------------------

# Create a init config for busybox
cat << EOF > inittab
::sysinit:/mount -t proc proc /proc
::sysinit:/mount -t sysfs sysfs /sys
::sysinit:/mount -t devtmpfs devtmpfs /dev
::sysinit:/mount -t tmpfs -o size=128M,nodev,nosuid tmpfs /tmp
::sysinit:/mkdir -p /mnt
::sysinit:/mount -t ext4 /dev/vda /mnt
::wait:/bin/sh -c "export PATH=/mnt/usr/local/bin && cd /test && rz-test db/archos/linux-riscv32"
::once:/poweroff -f
EOF

# Describe a skeletal in-memory filesystem for booting (without Rizin installation)
cat << EOF > initramfs
dir /bin 0755 0 0
dir /etc 0755 0 0
dir /lib 0755 0 0
dir /tmp 1777 0 0
dir /proc 0755 0 0
dir /sys 0755 0 0 
dir /dev 0755 0 0
dir /test 0755 0 0
dir /test/bins 0755 0 0
dir /test/bins/elf 0755 0 0
dir /test/db 0755 0 0
dir /test/db/archos 0755 0 0
dir /test/db/archos/linux-riscv32 0755 0 0

nod /dev/console 0600 0 0 c 5 1

file /bin/busybox rv32-busybox 0755 0 0
slink /init /bin/busybox 0777 0 0
slink /mount /bin/busybox 0777 0 0
slink /poweroff /bin/busybox 0777 0 0
slink /bin/sh /bin/busybox 0777 0 0
slink /mkdir /bin/busybox 0777 0 0

file /etc/inittab inittab 0644 0 0

file /test/bins/elf/riscv_bitmanip_32 riscv_bitmanip_32 0755 0 0
file /test/db/archos/linux-riscv32/dbg_basic rizin/test/db/archos/linux-riscv32/dbg_basic 0644 0 0
file /lib/ld-musl-riscv32.so.1 ${BOOTLIN_INSTALLATION}/riscv32-buildroot-linux-musl/sysroot/lib/ld-musl-riscv32.so.1 0755 0 0
EOF

# Generate the boot filesystem
gcc rizin/sys/gen_cpio_script.c -O3 -o gen_cpio
./gen_cpio initramfs > initrd_rv32.cpio

# Pack the Rizin installation into an ext4 filesystem
# (ext4 is necessary because Rizin cross-built into rv32, using musl and statically linked, is too big to fit in an initramfs)
truncate -s 4G rootfs-rv32.ext4
mkfs.ext4 -d rootfs-rv32 rootfs-rv32.ext4
