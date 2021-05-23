// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

struct flag_translation {
	ut64 flag;
	char *name;
};

static const struct flag_translation flag_translation_table[] = {
	{ SHF_WRITE, "write" },
	{ SHF_ALLOC, "alloc" },
	{ SHF_EXECINSTR, "execute" },
	{ SHF_MERGE, "merge" },
	{ SHF_STRINGS, "strings" },
	{ SHF_INFO_LINK, "info" },
	{ SHF_LINK_ORDER, "link_order" },
	{ SHF_OS_NONCONFORMING, "extra_os_processing_reqd" },
	{ SHF_GROUP, "group" },
	{ SHF_TLS, "TLS" },
	{ SHF_EXCLUDE, "exclude" },
	{ SHF_COMPRESSED, "compressed" }
};

/**
 * \brief Return a list of string representing flag options
 * \param elf flag
 * \return RzList of string representing flag options
 *
 * Compare the flag to common option such as SHF_WRITE, SHF_ALLOC, ect
 */
RZ_OWN RzList *Elf_(section_flag_to_rzlist)(ut64 flag) {
	RzList *flag_list = rz_list_new();
	if (!flag_list) {
		return NULL;
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(flag_translation_table); i++) {
		if (flag & flag_translation_table[i].flag) {
			rz_list_append(flag_list, flag_translation_table[i].name);
		}
	}

	return flag_list;
}
