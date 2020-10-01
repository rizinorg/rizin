#!/bin/sh

rm -rf shlr/capstone
make mrproper
cp -f plugins.static.nogpl.cfg plugins.cfg
./configure --prefix=/usr --with-librz
make -j4
