// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_sign.h>

static void zign_unset_for(RzEvent *ev, int type, void *user, void *data) {
	RzSpaces *s = (RzSpaces *)ev->user;
	RzAnalysis *analysis = container_of(s, RzAnalysis, zign_spaces);
	RzSpaceEvent *se = (RzSpaceEvent *)data;
	rz_sign_space_unset_for(analysis, se->data.unset.space);
}

static void zign_count_for(RzEvent *ev, int type, void *user, void *data) {
	RzSpaces *s = (RzSpaces *)ev->user;
	RzAnalysis *analysis = container_of(s, RzAnalysis, zign_spaces);
	RzSpaceEvent *se = (RzSpaceEvent *)data;
	se->res = rz_sign_space_count_for(analysis, se->data.count.space);
}

static void zign_rename_for(RzEvent *ev, int type, void *user, void *data) {
	RzSpaces *s = (RzSpaces *)ev->user;
	RzAnalysis *analysis = container_of(s, RzAnalysis, zign_spaces);
	RzSpaceEvent *se = (RzSpaceEvent *)data;
	rz_sign_space_rename_for(analysis, se->data.rename.space,
		se->data.rename.oldname, se->data.rename.newname);
}


RZ_API void rz_sign_analysis_set_hooks(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_if_fail(analysis);

	rz_spaces_init(&analysis->zign_spaces, "zs");
	rz_event_hook(analysis->zign_spaces.event, RZ_SPACE_EVENT_UNSET, zign_unset_for, NULL);
	rz_event_hook(analysis->zign_spaces.event, RZ_SPACE_EVENT_COUNT, zign_count_for, NULL);
	rz_event_hook(analysis->zign_spaces.event, RZ_SPACE_EVENT_RENAME, zign_rename_for, NULL);
}
