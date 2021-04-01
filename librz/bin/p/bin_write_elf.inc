// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_bin.h>
#include "elf/elf.h"

static ut64 scn_resize(RzBinFile *bf, const char *name, ut64 size) {
	return Elf_(rz_bin_elf_resize_section)(bf, name, size);
}

static bool scn_perms(RzBinFile *bf, const char *name, int perms) {
	return Elf_(rz_bin_elf_section_perms)(bf, name, perms);
}

static int rpath_del(RzBinFile *bf) {
	return Elf_(rz_bin_elf_del_rpath)(bf);
}

static bool chentry(RzBinFile *bf, ut64 addr) {
	return Elf_(rz_bin_elf_entry_write)(bf, addr);
}
