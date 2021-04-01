#!/bin/sh
#
# SPDX-FileCopyrightText: 2020 RizinOrg <info@rizin.re>
# SPDX-License-Identifier: LGPL-3.0-only
#
# Helper script for the build process to apply entitlements

IS_INSTALL="$1"
ENTITLEMENT="$2"
SRC="$3"

if [ "$IS_INSTALL" = "true" ] ; then
    SRC="${MESON_INSTALL_DESTDIR_PREFIX}/${SRC}"
fi

codesign --entitlements "${ENTITLEMENT}" --force -s - "${SRC}"
