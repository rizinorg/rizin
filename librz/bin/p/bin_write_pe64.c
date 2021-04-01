// SPDX-FileCopyrightText: 2009-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#define RZ_BIN_PE64 1
#include "bin_write_pe.c"

RzBinWrite rz_bin_write_pe64 = {
	.scn_perms = &scn_perms
};
