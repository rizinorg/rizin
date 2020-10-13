/* radare - LGPL - Copyright 2009-2019 - pancake, nibble */

#include <rz_types.h>
#include <rz_bin.h>
#include "pe/pe.h"

static bool scn_perms(RzBinFile *bf, const char *name, int perms) {
	return PE_(rz_bin_pe_section_perms) (bf, name, perms);
}

#if !RZ_BIN_PE64
RzBinWrite rz_bin_write_pe = {
	.scn_perms = &scn_perms
};
#endif
