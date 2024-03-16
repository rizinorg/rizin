// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static ut64 get_targets_map_base_from_segments(ELFOBJ *bin) {
	ut64 result = 0;

	RzBinElfSegment *segment;
	rz_bin_elf_foreach_segments(bin, segment) {
		if (segment->data.p_type != PT_LOAD) {
			continue;
		}

		result = RZ_MAX(result, segment->data.p_paddr + segment->data.p_memsz);
	}

	return result;
}

static ut64 get_targets_map_base_from_sections(ELFOBJ *bin) {
	ut64 result = 0;

	RzBinElfSection *section;
	rz_bin_elf_foreach_sections(bin, section) {
		if (section->rva == UT64_MAX) {
			continue;
		}
		result = RZ_MAX(result, section->rva + section->size);
	}

	return result;
}

static ut64 get_targets_map_base(ELFOBJ *bin) {
	if (Elf_(rz_bin_elf_has_segments)(bin)) {
		return get_targets_map_base_from_segments(bin);
	}

	return get_targets_map_base_from_sections(bin);
}

ut64 Elf_(rz_bin_elf_get_targets_map_base)(ELFOBJ *bin) {
	ut64 result = get_targets_map_base(bin);
	result += 0x8; // small additional shift to not overlap with symbols like _end
	return result + rz_num_align_delta(result, sizeof(Elf_(Addr)));
}
