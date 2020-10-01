#!/bin/sh
set -e

mkdir -p "${DESTDIR}/${MESON_INSTALL_PREFIX}/bin"
cd "${DESTDIR}/${MESON_INSTALL_PREFIX}/bin"

TOOLS="rz_hash rz_run rz_asm rz_bin rz_gg rz_agent rz_diff rz_find rassign2 rz_ax r2"

for TOOL in $TOOLS ; do
    ln -sf rizin $TOOL ;
done
