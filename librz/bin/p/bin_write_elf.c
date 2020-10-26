// SPDX-License-Identifier: LGPL-3.0-only

#include "bin_write_elf.inc"

RzBinWrite rz_bin_write_elf = {
	.scn_resize = &scn_resize,
	.scn_perms = &scn_perms,
	.rpath_del = &rpath_del,
	.entry = &chentry,
};
