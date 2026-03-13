set -e 
sudo apt-get update
sudo apt-get install -y \
    qemu-system-riscv64 \
    gcc-riscv64-linux-gnu \
    g++-riscv64-linux-gnu \
    binutils-riscv64-linux-gnu \
    cpio
pip3 install meson ninja
