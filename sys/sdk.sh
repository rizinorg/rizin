#!/bin/sh

WRKDIR=/tmp
SDKDIR=${WRKDIR}/rizin-sdk
if [ -n "$1" ]; then
	if [ -f "$1" ]; then
		echo "Target directory exists. Cant build the SDK in there"
		exit 1
	fi
	SDKDIR="$1"
fi

# Builds an SDK to build stuff for rbin
export CFLAGS="-Os -fPIC"
make mrproper
if [ -z "${RZ_PLUGINS_CFG}" ]; then
	RZ_PLUGINS_CFG=plugins.bin.cfg
fi
cp -f "${RZ_PLUGINS_CFG}" plugins.cfg
#./configure-plugins
./configure --prefix="$PREFIX" --with-librz --without-libuv --without-gpl || exit 1
#--disable-loadlibs || exit 1
make -j8 || exit 1
rm -rf "${SDKDIR}"
mkdir -p "${SDKDIR}"/lib
rm -f librz/librz.a
cp -rf librz/include "${SDKDIR}"
mkdir -p "${SDKDIR}/include/sdb"
cp -rf shlr/sdb/src/*.h "${SDKDIR}/include/sdb/"
FILES=`find librz shlr -iname '*.a'`
cp -f ${FILES} "${SDKDIR}"/lib
OS=`uname`
AR=`uname -m`
SF=rizin-sdk-${OS}-${AR}

(
cd "${WRKDIR}"
mv rizin-sdk "${SF}"
zip -r "${SF}".zip "${SF}"
)
mv "${WRKDIR}/${SF}" .
mv "${WRKDIR}/${SF}".zip .
ln -fs "${SF}" rizin-sdk
