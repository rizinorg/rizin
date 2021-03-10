// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

RZ_API void rz_core_visual_mark_reset(RzCore *core) {
	size_t i;
	for (i = 0; i < UT8_MAX; i++) {
		core->marks[i] = UT64_MAX;
	}
	core->marks_init = true;
}

RZ_API bool rz_core_visual_mark_dump(RzCore *core) {
	size_t i;
	if (!core->marks_init) {
		return false;
	}
	bool res = false;
	for (i = 0; i < UT8_MAX; i++) {
		if (core->marks[i] != UT64_MAX) {
			if (i > ASCII_MAX) {
				rz_cons_printf("fV %zu 0x%" PFMT64x "\n", i - ASCII_MAX - 1, core->marks[i]);
			} else {
				rz_cons_printf("fV %c 0x%" PFMT64x "\n", (char)i, core->marks[i]);
			}
			res = true;
		}
	}
	return res;
}

RZ_API void rz_core_visual_mark_set(RzCore *core, ut8 ch, ut64 addr) {
	if (!core->marks_init) {
		rz_core_visual_mark_reset(core);
	}
	core->marks[ch] = addr;
}

RZ_API void rz_core_visual_mark_del(RzCore *core, ut8 ch) {
	if (!core->marks_init) {
		return;
	}
	core->marks[ch] = UT64_MAX;
}

RZ_API void rz_core_visual_mark(RzCore *core, ut8 ch) {
	if (IS_DIGIT(ch)) {
		ch += ASCII_MAX + 1;
	}
	rz_core_visual_mark_set(core, ch, core->offset);
}

RZ_API void rz_core_visual_mark_seek(RzCore *core, ut8 ch) {
	if (core->marks_init && core->marks[ch] != UT64_MAX) {
		rz_core_seek(core, core->marks[ch], true);
	}
}
