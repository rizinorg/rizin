#!/bin/sh

# Updates
sudo pacman -Syu

git clone --depth=1 https://github.com/rizinorg/rizin
cd rizin && ./sys/install.sh
