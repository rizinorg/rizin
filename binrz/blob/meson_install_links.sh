#!/bin/sh
#
# SPDX-FileCopyrightText: 2020 RizinOrg <info@rizin.re>
# SPDX-License-Identifier: LGPL-3.0-only
set -e

mkdir -p "${DESTDIR}/${MESON_INSTALL_PREFIX}/bin"
cd "${DESTDIR}/${MESON_INSTALL_PREFIX}/bin"

TOOLS="rz-hash rz-run rz-asm rz-bin rz-gg rz-diff rz-find rz-sign rz-ax"

for TOOL in $TOOLS ; do
    ln -sf rizin "$TOOL" ;
done
