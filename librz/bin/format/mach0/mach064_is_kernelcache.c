// SPDX-FileCopyrightText: 2019-2020 Francesco Tamagni <mrmacete@protonmail.ch>
// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "mach0_defines.h"

static bool is_kernelcache_buffer(RzBuffer *b) {
	ut64 length = rz_buf_size(b);
	if (length < sizeof(struct MACH0_(mach_header))) {
		return false;
	}
	ut32 cputype;
	if (!rz_buf_read_le32_at(b, 4, &cputype)) {
		return false;
	}
	if (cputype != CPU_TYPE_ARM64) {
		return false;
	}
	ut32 filetype;
	if (!rz_buf_read_le32_at(b, 12, &filetype)) {
		return false;
	}
	if (filetype == MH_FILESET) {
		return true;
	}
	ut32 flags;
	if (!rz_buf_read_le32_at(b, 24, &flags)) {
		return false;
	}
	if (!(flags & MH_PIE)) {
		return false;
	}
	ut32 ncmds;
	if (!rz_buf_read_le32_at(b, 16, &ncmds)) {
		return false;
	}
	bool has_unixthread = false;
	bool has_negative_vaddr = false;
	bool has_kext = false;

	ut32 cursor = sizeof(struct MACH0_(mach_header));
	for (size_t i = 0; i < ncmds && cursor < length; i++) {

		ut32 cmdtype;
		if (!rz_buf_read_le32_at(b, cursor, &cmdtype)) {
			return false;
		}

		ut32 cmdsize;
		if (!rz_buf_read_le32_at(b, cursor + 4, &cmdsize)) {
			return false;
		}

		switch (cmdtype) {
		case LC_KEXT:
			has_kext = true;
			break;
		case LC_UNIXTHREAD:
			has_unixthread = true;
			break;
		case LC_LOAD_DYLIB:
		case LC_LOAD_WEAK_DYLIB:
		case LC_LAZY_LOAD_DYLIB:
			return false;
		case LC_SEGMENT_64: {
			if (has_negative_vaddr) {
				break;
			}
			ut64 tmp;
			if (!rz_buf_read_le64_at(b, cursor + 24, &tmp)) {
				return false;
			}

			st64 vmaddr = convert_to_two_complement_64(tmp);
			if (vmaddr < 0) {
				has_negative_vaddr = true;
			}
		} break;
		}

		cursor += cmdsize;
	}

	return has_kext || (has_unixthread && has_negative_vaddr);
}
