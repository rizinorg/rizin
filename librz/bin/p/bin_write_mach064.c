/* radare - LGPL - Copyright 2016 pancake */

#define RZ_BIN_MACH064 1
#include "bin_write_mach0.c"

RzBinWrite rz_bin_write_mach064 = {
#if 0
	.scn_resize = &scn_resize,
	.scn_perms = &scn_perms,
	.rpath_del = &rpath_del,
	.entry = &chentry,
#endif
	.addlib = &addlib,
};
