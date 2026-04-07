#!/bin/sh -eu
#
# Script to create a macOS .pkg file to install Rizin

VERSION=$(python3 ./sys/version.py)
RIZINDIR=$(pwd)
RIZININSTALL=/tmp/rizin-install
MACOSPKGDIR=/tmp/macospkgtmp

rm -rf buildtmp
mkdir buildtmp
meson buildtmp --buildtype=release -Denable_tests=false -Dlocal=disabled --prefix=/usr/local
rm -rf "${RIZININSTALL}"
DESTDIR="${RIZININSTALL}" ninja -C buildtmp install
rm -rf buildtmp

rm -rf "${MACOSPKGDIR}"
mkdir "${MACOSPKGDIR}"
cp -rv "${RIZINDIR}/dist/macos/rizin.unpkg/" "${MACOSPKGDIR}/"

cd "${RIZININSTALL}" && find . | cpio -o --format odc | gzip -c > "${MACOSPKGDIR}/Payload"
mkbom "${RIZININSTALL}" "${MACOSPKGDIR}/Bom"
pkgutil --flatten "${MACOSPKGDIR}" "${RIZINDIR}/dist/macos/rizin.pkg"

convert -size 620x418 xc:none -background none /tmp/bg.png || { echo convert failed, is imagemagick installed?; exit 1; }
composite -geometry +30+230 -background none \( "${RIZINDIR}/doc/img/rizin.svg" -resize 25% \) /tmp/bg.png  -colorspace sRGB "${RIZINDIR}/dist/macos/Resources/rizin-logo.png"

cd "${RIZINDIR}/dist/macos" && productbuild --resources Resources --distribution Distribution "rizin-${VERSION}.pkg"
mv "${RIZINDIR}/dist/macos/rizin-${VERSION}.pkg" "${RIZINDIR}/rizin-${VERSION}.pkg"

rm "${RIZINDIR}/dist/macos/rizin.pkg"
rm -rf "${MACOSPKGDIR}"
rm -rf "${RIZININSTALL}"
