/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include <rz_util/rz_serialize.h>
#include <rz_core.h>

#include "../util/serialize_helper.h"

/*
 * SDB Format:
 *
 * /
 *   /config => see config.c
 *   /flags => see flag.c
 *   /anal => see anal.c
 *   offset=<offset>
 *   blocksize=<blocksize>
 */

RZ_API void rz_serialize_core_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core) {
	rz_serialize_config_save (sdb_ns (db, "config", true), core->config);
	rz_serialize_flag_save (sdb_ns (db, "flags", true), core->flags);
	rz_serialize_anal_save (sdb_ns (db, "anal", true), core->anal);

	char buf[0x20];
	if (snprintf (buf, sizeof (buf), "0x%"PFMT64x, core->offset) < 0) {
		return;
	}
	sdb_set (db, "offset", buf, 0);

	if (snprintf (buf, sizeof (buf), "0x%"PFMT32x, core->blocksize) < 0) {
		return;
	}
	sdb_set (db, "blocksize", buf, 0);
}

RZ_API bool rz_serialize_core_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, RZ_NULLABLE RzSerializeResultInfo *res) {
	Sdb *subdb;

#define SUB(ns, call) SUB_DO(ns, call, return false;)

	SUB ("config", rz_serialize_config_load (subdb, core->config, res));
	SUB ("flags", rz_serialize_flag_load (subdb, core->flags, res));
	SUB ("anal", rz_serialize_anal_load (subdb, core->anal, res));

	const char *str = sdb_get (db, "offset", 0);
	if (!str || !*str) {
		SERIALIZE_ERR ("missing offset in core");
		return false;
	}
	core->offset = strtoull (str, NULL, 0);

	str = sdb_get (db, "blocksize", 0);
	if (!str || !*str) {
		SERIALIZE_ERR ("missing blocksize in core");
		return false;
	}
	ut64 bs = strtoull (str, NULL, 0);
	rz_core_block_size (core, (int)bs);

	// handled by config already:
	// cfglog, cmdrepeat, cmdtimes

	return true;
}
