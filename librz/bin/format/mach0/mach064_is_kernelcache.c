// SPDX-License-Identifier: LGPL-3.0-only
#include "mach0_defines.h"

static bool is_kernelcache_buffer(RzBuffer *b) {
	ut64 length = rz_buf_size(b);
	if (length < sizeof(struct MACH0_(mach_header))) {
		return false;
	}
	ut32 cputype = rz_buf_read_le32_at(b, 4);
	if (cputype != CPU_TYPE_ARM64) {
		return false;
	}
	ut32 filetype = rz_buf_read_le32_at(b, 12);
	if (filetype == MH_FILESET) {
		return true;
	}
	ut32 flags = rz_buf_read_le32_at(b, 24);
	if (!(flags & MH_PIE)) {
		return false;
	}

	int i, ncmds = rz_buf_read_le32_at(b, 16);
	bool has_unixthread = false;
	bool has_negative_vaddr = false;
	bool has_kext = false;

	ut32 cursor = sizeof(struct MACH0_(mach_header));
	for (i = 0; i < ncmds && cursor < length; i++) {

		ut32 cmdtype = rz_buf_read_le32_at(b, cursor);
		ut32 cmdsize = rz_buf_read_le32_at(b, cursor + 4);

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
			st64 vmaddr = rz_buf_read_le64_at(b, cursor + 24);
			if (vmaddr < 0) {
				has_negative_vaddr = true;
			}
		} break;
		}

		cursor += cmdsize;
	}

	return has_kext || (has_unixthread && has_negative_vaddr);
}
