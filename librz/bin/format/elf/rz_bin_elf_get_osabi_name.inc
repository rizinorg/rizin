// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static inline int noodle(ELFOBJ *bin, const char *s) {
	if (rz_buf_size(bin->b) <= 64) {
		return 0;
	}
	ut8 tmp[64];
	rz_buf_read_at(bin->b, rz_buf_size(bin->b) - 64, tmp, 64);
	return rz_mem_mem(tmp, 64, (const ut8 *)s, strlen(s)) != NULL;
}

static inline int needle(ELFOBJ *bin, const char *s) {
	if (bin->shstrtab) {
		ut32 len = bin->shstrtab_size;
		if (len > 4096) {
			len = 4096; // avoid slow loading .. can be buggy?
		}
		return rz_mem_mem((const ut8 *)bin->shstrtab, len,
			       (const ut8 *)s, strlen(s)) != NULL;
	}
	return 0;
}

// TODO: must return const char * all those strings must be const char os[LINUX] or so
char *Elf_(rz_bin_elf_get_osabi_name)(ELFOBJ *bin) {
	size_t i;
	size_t num = bin->ehdr.e_shnum;
	const char *section_name = NULL;
	switch (bin->ehdr.e_ident[EI_OSABI]) {
	case ELFOSABI_LINUX: return strdup("linux");
	case ELFOSABI_SOLARIS: return strdup("solaris");
	case ELFOSABI_FREEBSD: return strdup("freebsd");
	case ELFOSABI_HPUX: return strdup("hpux");
	}

	if (bin->shdr && bin->shstrtab) {
		for (i = 0; i < num; i++) {
			if (bin->shdr[i].sh_type == SHT_NOTE && bin->shdr[i].sh_name < bin->shstrtab_size) {
				section_name = &bin->shstrtab[bin->shdr[i].sh_name];
				if (!strcmp(section_name, ".note.openbsd.ident")) {
					return strdup("openbsd");
				}
				if (!strcmp(section_name, ".note.minix.ident")) {
					return strdup("minix");
				}
				if (!strcmp(section_name, ".note.netbsd.ident")) {
					return strdup("netbsd");
				}
				if (!strcmp(section_name, ".note.android.ident")) {
					return strdup("android");
				}
			}
		}
	}
	/* Hack to identify OS */
	if (needle(bin, "freebsd")) {
		return strdup("freebsd");
	}
	if (noodle(bin, "BEOS:APP_VERSION")) {
		return strdup("beos");
	}
	if (needle(bin, "GNU")) {
		return strdup("linux");
	}
	return strdup("linux");
}
