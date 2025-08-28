// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

RZ_IPI void rz_core_visual_mark_reset(RzCore *core) {
	size_t i;
	for (i = 0; i < UT8_MAX; i++) {
		core->vmarks[i] = UT64_MAX;
	}
	core->vmarks_init = true;
}

RZ_IPI bool rz_core_visual_mark_dump(RzCore *core) {
	size_t i;
	if (!core->vmarks_init) {
		return false;
	}
	bool res = false;
	for (i = 0; i < UT8_MAX; i++) {
		if (core->vmarks[i] != UT64_MAX) {
			if (i > ASCII_MAX) {
				rz_cons_printf("fV %zu 0x%" PFMT64x "\n", i - ASCII_MAX - 1, core->vmarks[i]);
			} else {
				rz_cons_printf("fV %c 0x%" PFMT64x "\n", (char)i, core->vmarks[i]);
			}
			res = true;
		}
	}
	return res;
}

RZ_IPI void rz_core_visual_mark_set(RzCore *core, ut8 ch, ut64 addr) {
	if (!core->vmarks_init) {
		rz_core_visual_mark_reset(core);
	}
	core->vmarks[ch] = addr;
}

RZ_IPI void rz_core_visual_mark_del(RzCore *core, ut8 ch) {
	if (!core->vmarks_init) {
		return;
	}
	core->vmarks[ch] = UT64_MAX;
}

RZ_IPI void rz_core_visual_mark(RzCore *core, ut8 ch) {
	if (IS_DIGIT(ch)) {
		ch += ASCII_MAX + 1;
	}
	rz_core_visual_mark_set(core, ch, core->offset);
}

RZ_IPI void rz_core_visual_mark_seek(RzCore *core, ut8 ch) {
	if (core->vmarks_init && core->vmarks[ch] != UT64_MAX) {
		rz_core_seek(core, core->vmarks[ch], true);
	}
}
