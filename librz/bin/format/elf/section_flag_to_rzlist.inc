// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Return a list of string representing flag options
 * \param elf flag
 * \return RzList of string representing flag options
 *
 * Compare the flag to common option such as SHF_WRITE, SHF_ALLOC, ect
 */
RZ_OWN RzList *Elf_(section_flag_to_rzlist)(ut64 flag) {
	RzList *flag_list = rz_list_new();
	if (flag & SHF_WRITE) {
		rz_list_append(flag_list, "write");
	}
	if (flag & SHF_ALLOC) {
		rz_list_append(flag_list, "alloc");
	}
	if (flag & SHF_EXECINSTR) {
		rz_list_append(flag_list, "execute");
	}
	if (flag & SHF_MERGE) {
		rz_list_append(flag_list, "merge");
	}
	if (flag & SHF_STRINGS) {
		rz_list_append(flag_list, "strings");
	}
	if (flag & SHF_INFO_LINK) {
		rz_list_append(flag_list, "info");
	}
	if (flag & SHF_LINK_ORDER) {
		rz_list_append(flag_list, "link_order");
	}
	if (flag & SHF_OS_NONCONFORMING) {
		rz_list_append(flag_list, "extra_os_processing_reqd");
	}
	if (flag & SHF_GROUP) {
		rz_list_append(flag_list, "group");
	}
	if (flag & SHF_TLS) {
		rz_list_append(flag_list, "TLS");
	}
	if (flag & SHF_EXCLUDE) {
		rz_list_append(flag_list, "exclude");
	}
	if (flag & SHF_COMPRESSED) {
		rz_list_append(flag_list, "compressed");
	}
	return flag_list;
}
