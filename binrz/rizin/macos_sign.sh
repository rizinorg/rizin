#!/bin/sh
#
# Helper script for the build process to apply entitlements

ENTITLEMENT="$1"
SRC="$2"
if [ "$#" -ne 2 ]; then
        DST="$3"

        rm -f "${DST}"
        cp -a "${SRC}" "${DST}"
else
        DST="${MESON_INSTALL_DESTDIR_PREFIX}/${SRC}"
fi

codesign --entitlements "${ENTITLEMENT}" --force -s - "${DST}"
