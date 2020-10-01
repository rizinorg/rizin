#!/bin/sh
cd `dirname $PWD/$0`/..

sys/clone-r2-bindings.sh
sys/install.sh
make dist

cd rizin-bindings || exit 1
./configure --prefix=/usr --enable-devel
make mrproper
cd python
make
cd ..
make dist

DD=/tmp/r2
rm -rf $DD
mkdir $DD
cp ../rizin-bindings-`make version`.tar.gz $DD
cd ..
cp ../rizin-`make version`.tar.gz $DD
echo distribution tarballs have been copied to $DD
