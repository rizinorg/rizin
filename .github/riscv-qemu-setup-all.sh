# Fetch the kernel package
wget \
    https://ftp.debian.org/debian/pool/main/l/linux/linux-image-6.12.73+deb13-riscv64_6.12.73-1_riscv64.deb

# Extract
dpkg-deb -x linux-image-6.12.73+deb13-riscv64_6.12.73-1_riscv64.deb linux-image

# Fetch busybox
git clone https://github.com/rcore-os/busybox-prebuilts.git busybox

# Cross-compile the Rizin repo
cd rizin
meson setup build --cross-file doc/examples/cross_builds/meson-linux-riscv64.ini
meson compile -C build
cd ..

# Create a rootfs
mkdir -p rootfs 
mkdir -p rootfs/lib rootfs/tmp rootfs/proc rootfs/etc

# Copy all .so files from the build directory to rootfs/lib (only the real ones, not shorthand symlinks)
find rizin/build/librz/ -name "*.so.[0-9].[0-9].[0-9]" -type f \
 -exec cp {} rootfs/lib/ \; \
 -exec sh -c 'echo "linking $(basename "${1%.*}") -> $(basename "$1")"; ln -sf "$(basename "$1")" "rootfs/lib/$(basename "${1%.*}")"' _ {} \; # symlinking all *.so.0.9 to *.so.0.9.0

# Copy rizin binary
cp rizin/build/binrz/rizin/rizin rootfs/rizin


# libc and libm
cp /usr/riscv64-linux-gnu/lib/libc.so.6 rootfs/lib/
cp /usr/riscv64-linux-gnu/lib/libm.so.6 rootfs/lib/
# dynamic linker 
cp /usr/riscv64-linux-gnu/lib/ld-linux-riscv64-lp64d.so.1 rootfs/lib/

# Copy busybox to rootfs
cp busybox/busybox-1.30.1-riscv64/busybox rootfs/bb

# Make busybox the init launcher, poweroff, and mount
ln -s bb rootfs/init
ln -s bb rootfs/poweroff
ln -s bb rootfs/mount

# Make the inittab
cat << EOF > rootfs/etc/inittab
::sysinit:/mount -t proc proc /proc
::wait:$@
::once:/poweroff -f
EOF

# filesystem state 
# rootfs
# /
# ├── rizin
# ├── bb
# ├── init -> bb
# ├── poweroff -> bb
# ├── mount -> bb
# ├── lib/
# │   ├── libc.so.6
# │   ├── libm.so.6
# │   ├── ld-linux-riscv64-lp64d.so.1
# │   ├── librz_arch.so.0.9.0
# │   ├── librz_arch.so.0.9 -> librz_arch.so.0.9.0
# │   ├── librz_bin.so.0.9.0
# │   ├── librz_bin.so.0.9 -> librz_bin.so.0.9.0
# │   └── ... (*.so.0.9.0 objs + *.so.0.9 symlinks)
# ├── tmp/
# │   └── (empty)
# ├── proc/
# │   └── (mounted by kernel)
# └── etc/
#     └── inittab
echo "#########################################################################"
# for debugging, always check the output tree against the intended tree above
tree rootfs
echo "#########################################################################"

# Package the whole thing into an initrd archive
cd rootfs
find . | cpio -o -H newc | gzip > ../initrd.cpio.gz
cd ..
