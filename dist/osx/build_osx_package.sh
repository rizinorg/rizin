#!/bin/sh -eu
#
# Script to create a OSX .pkg file to install Rizin

VERSION=$(./sys/version.py)
RIZINDIR=$(pwd)
RIZININSTALL=/tmp/rizin-install
OSXPKGDIR=/tmp/osxpkgtmp

rm -rf buildtmp
mkdir buildtmp
meson buildtmp --buildtype=release -Duse_libuv=false -Dlocal=disabled --prefix=/usr/local
rm -rf "${RIZININSTALL}"
DESTDIR="${RIZININSTALL}" ninja -C buildtmp install
rm -rf buildtmp

rm -rf "${OSXPKGDIR}"
mkdir "${OSXPKGDIR}"
cp -rv "${RIZINDIR}/dist/osx/rizin.unpkg/" "${OSXPKGDIR}/"

cd "${RIZININSTALL}" && find . | cpio -o --format odc | gzip -c > "${OSXPKGDIR}/Payload"
mkbom "${RIZININSTALL}" "${OSXPKGDIR}/Bom"
pkgutil --flatten "${OSXPKGDIR}" "${RIZINDIR}/dist/osx/rizin.pkg"

cd "${RIZINDIR}/dist/osx" && productbuild --resources Resources --distribution Distribution "rizin-${VERSION}.pkg"
mv "${RIZINDIR}/dist/osx/rizin-${VERSION}.pkg" "${RIZINDIR}/rizin-${VERSION}.pkg"

rm "${RIZINDIR}/dist/osx/rizin.pkg"
rm -rf "${OSXPKGDIR}"
rm -rf "${RIZININSTALL}"