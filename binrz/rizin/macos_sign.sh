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

# The --entitlements arg was only added in Mac OS X 10.6 Snow Leopard / Xcode 3.2 / security_systemkeychain-36515.
# Moreover, our build system adds load mach-o load commands that the ancient codesign does not recognize either so let's skip it.
# uname -r is
#   9.<something> for 10.5
#   10.<something> for 10.6
#   ...
OSVER=$(uname -r)
if [ "${OSVER%%.*}" -lt 10 ]; then
	echo "Detected Mac OS X < 10.6, skipping codesign."
	exit 0
fi

codesign --entitlements "${ENTITLEMENT}" --force -s - "${SRC}"
