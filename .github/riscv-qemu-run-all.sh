 qemu-system-riscv64 \
    -machine virt -cpu rv64 -m 512M \
    -kernel linux-image/boot/vmlinux-6.12.73+deb13-riscv64 \
    -initrd initrd.cpio.gz \
    -append "console=ttyS0,115200 earlycon" \
    -nographic
