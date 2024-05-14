// SPDX-FileCopyrightText: 2017 rkx1209 <rkx1209dev@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>
#include <rz_util/rz_json.h>

#define CMP_CNUM_REG(x, y)   ((x) >= ((RzDebugChangeReg *)y)->cnum ? 1 : -1)
#define CMP_CNUM_MEM(x, y)   ((x) >= ((RzDebugChangeMem *)y)->cnum ? 1 : -1)
#define CMP_CNUM_CHKPT(x, y) ((x) >= ((RzDebugCheckpoint *)y)->cnum ? 1 : -1)

RZ_API void rz_debug_session_free(RzDebugSession *session) {
	if (session) {
		rz_vector_free(session->checkpoints);
		ht_up_free(session->registers);
		ht_up_free(session->memory);
		RZ_FREE(session);
	}
}

static void rz_debug_checkpoint_fini(void *element, void *user) {
	RzDebugCheckpoint *checkpoint = element;
	size_t i;
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		rz_reg_arena_free(checkpoint->arena[i]);
	}
	rz_list_free(checkpoint->snaps);
}

RZ_API RzDebugSession *rz_debug_session_new(void) {
	RzDebugSession *session = RZ_NEW0(RzDebugSession);
	if (!session) {
		return NULL;
	}

	session->checkpoints = rz_vector_new(sizeof(RzDebugCheckpoint), rz_debug_checkpoint_fini, NULL);
	if (!session->checkpoints) {
		rz_debug_session_free(session);
		return NULL;
	}
	session->registers = ht_up_new(NULL, (HtUPFreeValue)rz_vector_free);
	if (!session->registers) {
		rz_debug_session_free(session);
		return NULL;
	}
	session->memory = ht_up_new(NULL, (HtUPFreeValue)rz_vector_free);
	if (!session->memory) {
		rz_debug_session_free(session);
		return NULL;
	}

	return session;
}

RZ_API bool rz_debug_add_checkpoint(RzDebug *dbg) {
	rz_return_val_if_fail(dbg->session, false);
	size_t i;
	RzDebugCheckpoint checkpoint = { 0 };

	// Save current registers arena iter
	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, 0);
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		RzRegArena *a = dbg->reg->regset[i].arena;
		RzRegArena *b = rz_reg_arena_new(a->size);
		rz_mem_copy(b->bytes, b->size, a->bytes, a->size);
		checkpoint.arena[i] = b;
	}

	// Save current memory maps
	checkpoint.snaps = rz_list_newf((RzListFree)rz_debug_snap_free);
	if (!checkpoint.snaps) {
		return false;
	}
	RzListIter *iter;
	RzDebugMap *map;
	rz_debug_map_sync(dbg);
	rz_list_foreach (dbg->maps, iter, map) {
		if ((map->perm & RZ_PERM_RW) == RZ_PERM_RW) {
			RzDebugSnap *snap = rz_debug_snap_map(dbg, map);
			if (snap) {
				rz_list_append(checkpoint.snaps, snap);
			}
		}
	}

	checkpoint.cnum = dbg->session->cnum;
	rz_vector_push(dbg->session->checkpoints, &checkpoint);

	// Add PC register change so we can check for breakpoints when continue [back]
	RzRegItem *ripc = rz_reg_get(dbg->reg, dbg->reg->name[RZ_REG_NAME_PC], RZ_REG_TYPE_GPR);
	ut64 data = rz_reg_get_value(dbg->reg, ripc);
	rz_debug_session_add_reg_change(dbg->session, ripc->arena, ripc->offset, data);

	return true;
}

static void _set_initial_registers(RzDebug *dbg) {
	size_t i;
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		RzRegArena *a = dbg->session->cur_chkpt->arena[i];
		RzRegArena *b = dbg->reg->regset[i].arena;
		if (a && b && a->bytes && b->bytes) {
			memcpy(b->bytes, a->bytes, a->size);
		}
	}
}

static void _set_register(RzDebug *dbg, RzRegItem *ri, ut32 cnum) {
	RzVector *vreg = ht_up_find(dbg->session->registers, ri->offset | (ri->arena << 16), NULL);
	if (!vreg) {
		return;
	}
	size_t index;
	rz_vector_upper_bound(vreg, cnum, index, CMP_CNUM_REG);
	if (index > 0 && index <= vreg->len) {
		RzDebugChangeReg *reg = rz_vector_index_ptr(vreg, index - 1);
		if (reg->cnum > dbg->session->cur_chkpt->cnum) {
			rz_reg_set_value(dbg->reg, ri, reg->data);
		}
	}
}

RZ_API void _restore_registers(RzDebug *dbg, ut32 cnum) {
	RzListIter *iter;
	RzRegItem *ri;
	_set_initial_registers(dbg);
	rz_list_foreach (dbg->reg->allregs, iter, ri) {
		_set_register(dbg, ri, cnum);
	}
}

static void _set_initial_memory(RzDebug *dbg) {
	RzListIter *iter;
	RzDebugSnap *snap;
	rz_list_foreach (dbg->session->cur_chkpt->snaps, iter, snap) {
		dbg->iob.write_at(dbg->iob.io, snap->addr, snap->data, snap->size);
	}
}

static bool _restore_memory_cb(void *user, const ut64 key, const void *value) {
	size_t index;
	RzDebug *dbg = user;
	RzVector *vmem = (RzVector *)value;

	rz_vector_upper_bound(vmem, dbg->session->cnum, index, CMP_CNUM_MEM);
	if (index > 0 && index <= vmem->len) {
		RzDebugChangeMem *mem = rz_vector_index_ptr(vmem, index - 1);
		if (mem->cnum > dbg->session->cur_chkpt->cnum) {
			dbg->iob.write_at(dbg->iob.io, key, &mem->data, 1);
		}
	}
	return true;
}

static void _restore_memory(RzDebug *dbg, ut32 cnum) {
	_set_initial_memory(dbg);
	ht_up_foreach(dbg->session->memory, _restore_memory_cb, dbg);
}

static RzDebugCheckpoint *_get_checkpoint_before(RzDebugSession *session, ut32 cnum) {
	RzDebugCheckpoint *checkpoint = NULL;
	size_t index;
	rz_vector_upper_bound(session->checkpoints, cnum, index, CMP_CNUM_CHKPT);
	if (index > 0 && index <= session->checkpoints->len) {
		checkpoint = rz_vector_index_ptr(session->checkpoints, index - 1);
	}
	return checkpoint;
}

RZ_API void rz_debug_session_restore_reg_mem(RzDebug *dbg, ut32 cnum) {
	// Set checkpoint for initial registers and memory
	dbg->session->cur_chkpt = _get_checkpoint_before(dbg->session, cnum);

	// Restore registers
	_restore_registers(dbg, cnum);
	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, true);

	// Restore memory
	_restore_memory(dbg, cnum);
}

RZ_API void rz_debug_session_list_memory(RzDebug *dbg) {
	RzHashSize dsize;
	RzListIter *iter;
	RzDebugMap *map;
	rz_debug_map_sync(dbg);
	rz_list_foreach (dbg->maps, iter, map) {
		if ((map->perm & RZ_PERM_RW) == RZ_PERM_RW) {
			RzDebugSnap *snap = rz_debug_snap_map(dbg, map);
			if (!snap) {
				return;
			}

			ut8 *hash = rz_debug_snap_get_hash(dbg, snap, &dsize);
			if (!hash) {
				rz_debug_snap_free(snap);
				return;
			}

			char *hexstr = rz_hex_bin2strdup(hash, dsize);
			if (!hexstr) {
				free(hash);
				rz_debug_snap_free(snap);
				return;
			}
			dbg->cb_printf("%s: %s\n", snap->name, hexstr);

			free(hexstr);
			free(hash);
			rz_debug_snap_free(snap);
		}
	}
}

RZ_API bool rz_debug_session_add_reg_change(RzDebugSession *session, int arena, ut64 offset, ut64 data) {
	RzVector *vreg = ht_up_find(session->registers, offset | (arena << 16), NULL);
	if (!vreg) {
		vreg = rz_vector_new(sizeof(RzDebugChangeReg), NULL, NULL);
		if (!vreg) {
			eprintf("Error: creating a register vector.\n");
			return false;
		}
		ht_up_insert(session->registers, offset | (arena << 16), vreg);
	}
	RzDebugChangeReg reg = { session->cnum, data };
	rz_vector_push(vreg, &reg);
	return true;
}

RZ_API bool rz_debug_session_add_mem_change(RzDebugSession *session, ut64 addr, ut8 data) {
	RzVector *vmem = ht_up_find(session->memory, addr, NULL);
	if (!vmem) {
		vmem = rz_vector_new(sizeof(RzDebugChangeMem), NULL, NULL);
		if (!vmem) {
			eprintf("Error: creating a memory vector.\n");
			return false;
		}
		ht_up_insert(session->memory, addr, vmem);
	}
	RzDebugChangeMem mem = { session->cnum, data };
	rz_vector_push(vmem, &mem);
	return true;
}

/* Save and Load Session */

// 0x<addr>=[<RzDebugChangeReg>]
static bool serialize_register_cb(void *db, const ut64 k, const void *v) {
	RzDebugChangeReg *reg;
	RzVector *vreg = (RzVector *)v;
	char tmpbuf[32];
	PJ *j = pj_new();
	if (!j) {
		return false;
	}
	pj_a(j);

	rz_vector_foreach (vreg, reg) {
		pj_o(j);
		pj_kN(j, "cnum", reg->cnum);
		pj_kn(j, "data", reg->data);
		pj_end(j);
	}

	pj_end(j);
	sdb_set(db, rz_strf(tmpbuf, "0x%" PFMT64x, k), pj_string(j));
	pj_free(j);
	return true;
}

static void serialize_registers(Sdb *db, HtUP *registers) {
	ht_up_foreach(registers, serialize_register_cb, db);
}

// 0x<addr>={"size":<size_t>, "a":[<RzDebugChangeMem>]}},
static bool serialize_memory_cb(void *db, const ut64 k, const void *v) {
	RzDebugChangeMem *mem;
	RzVector *vmem = (RzVector *)v;
	char tmpbuf[32];
	PJ *j = pj_new();
	if (!j) {
		return false;
	}
	pj_a(j);

	rz_vector_foreach (vmem, mem) {
		pj_o(j);
		pj_kN(j, "cnum", mem->cnum);
		pj_kn(j, "data", mem->data);
		pj_end(j);
	}

	pj_end(j);
	sdb_set(db, rz_strf(tmpbuf, "0x%" PFMT64x, k), pj_string(j));
	pj_free(j);
	return true;
}

static void serialize_memory(Sdb *db, HtUP *memory) {
	ht_up_foreach(memory, serialize_memory_cb, db);
}

static void serialize_checkpoints(Sdb *db, RzVector /*<RzDebugCheckpoint>*/ *checkpoints) {
	size_t i;
	RzDebugCheckpoint *chkpt;
	RzDebugSnap *snap;
	RzListIter *iter;
	char tmpbuf[32];

	rz_vector_foreach (checkpoints, chkpt) {
		// 0x<cnum>={
		//   registers:{"<RzRegisterType>":<RzRegArena>, ...},
		//   snaps:{"size":<size_t>, "a":[<RzDebugSnap>]}
		// }
		PJ *j = pj_new();
		if (!j) {
			return;
		}
		pj_o(j);

		// Serialize RzRegArena to "registers"
		// {"size":<int>, "bytes":"<base64>"}
		pj_ka(j, "registers");
		for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
			RzRegArena *arena = chkpt->arena[i];
			if (arena->bytes) {
				pj_o(j);
				pj_kn(j, "arena", i);
				char *ebytes = sdb_encode((const void *)arena->bytes, arena->size);
				pj_ks(j, "bytes", ebytes);
				free(ebytes);
				pj_kn(j, "size", arena->size);
				pj_end(j);
			}
		}
		pj_end(j);

		// Serialize RzDebugSnap to "snaps"
		// {"name":<str>, "addr":<ut64>, "addr_end":<ut64>, "size":<ut64>,
		//  "data":"<base64>", "perm":<int>, "user":<int>, "shared":<bool>}
		pj_ka(j, "snaps");
		rz_list_foreach (chkpt->snaps, iter, snap) {
			pj_o(j);
			pj_ks(j, "name", snap->name);
			pj_kn(j, "addr", snap->addr);
			pj_kn(j, "addr_end", snap->addr_end);
			pj_kn(j, "size", snap->size);
			char *edata = sdb_encode((const void *)snap->data, snap->size);
			if (!edata) {
				pj_free(j);
				return;
			}
			pj_ks(j, "data", edata);
			free(edata);
			pj_kn(j, "perm", snap->perm);
			pj_kn(j, "user", snap->user);
			pj_kb(j, "shared", snap->shared);
			pj_end(j);
		}
		pj_end(j);

		pj_end(j);
		sdb_set(db, rz_strf(tmpbuf, "0x%x", chkpt->cnum), pj_string(j));
		pj_free(j);
	}
}

/*
 * SDB Format:
 *
 * /
 *   maxcnum=<maxcnum>
 *
 *   /registers
 *     0x<addr>={"size":<size_t>, "a":[<RzDebugChangeReg>]}
 *
 *   /memory
 *     0x<addr>={"size":<size_t>, "a":[<RzDebugChangeMem>]}
 *
 *   /checkpoints
 *     0x<cnum>={
 *       registers:{"<RzRegisterType>":<RzRegArena>, ...},
 *       snaps:{"size":<size_t>, "a":[<RzDebugSnap>]}
 *     }
 *
 * RzDebugChangeReg JSON:
 * {"cnum":<int>, "data":<ut64>}
 *
 * RzDebugChangeMem JSON:
 * {"cnum":<int>, "data":<ut8>}
 *
 * RzRegArena JSON:
 * {"size":<int>, "bytes":"<base64>"}
 *
 * RzDebugSnap JSON:
 * {"name":<str>, "addr":<ut64>, "addr_end":<ut64>, "size":<ut64>,
 *  "data":"<base64>", "perm":<int>, "user":<int>, "shared":<bool>}
 *
 * Notes:
 * - This mostly follows rz-db-style serialization
 */
RZ_API void rz_debug_session_serialize(RzDebugSession *session, Sdb *db) {
	sdb_num_set(db, "maxcnum", session->maxcnum);
	serialize_registers(sdb_ns(db, "registers", true), session->registers);
	serialize_memory(sdb_ns(db, "memory", true), session->memory);
	serialize_checkpoints(sdb_ns(db, "checkpoints", true), session->checkpoints);
}

static bool session_sdb_save(Sdb *db, const char *path) {
	char *filename;
	if (!rz_file_is_directory(path)) {
		eprintf("Error: %s is not a directory\n", path);
		return false;
	}

	filename = rz_str_newf("%s%ssession.sdb", path, RZ_SYS_DIR);
	sdb_file(db, filename);
	if (!sdb_sync(db)) {
		eprintf("Failed to sync session to %s\n", filename);
		free(filename);
		sdb_close(db);
		return false;
	}
	free(filename);
	sdb_close(db);

	SdbListIter *it;
	SdbNs *ns;
	ls_foreach (db->ns, it, ns) {
		char *filename = rz_str_newf("%s%s%s.sdb", path, RZ_SYS_DIR, ns->name);
		sdb_file(ns->sdb, filename);
		if (!sdb_sync(ns->sdb)) {
			eprintf("Failed to sync %s to %s\n", ns->name, filename);
			free(filename);
			sdb_close(ns->sdb);
			return false;
		}
		free(filename);
		sdb_close(ns->sdb);
	}

	return true;
}

RZ_API bool rz_debug_session_save(RzDebugSession *session, const char *path) {
	Sdb *db = sdb_new0();
	if (!db) {
		return false;
	}
	rz_debug_session_serialize(session, db);

	if (!session_sdb_save(db, path)) {
		sdb_free(db);
		return false;
	}
	sdb_free(db);
	return true;
}

#define CHECK_TYPE(v, t) \
	if (!v || v->type != t) \
	continue

static bool deserialize_memory_cb(void *user, const SdbKv *kv) {
	RzJson *child;
	char *json_str = sdbkv_dup_value(kv);
	if (!json_str) {
		return true;
	}
	RzJson *reg_json = rz_json_parse(json_str);
	if (!reg_json || reg_json->type != RZ_JSON_ARRAY) {
		free(json_str);
		return true;
	}

	HtUP *memory = user;
	// Insert a new vector into `memory` HtUP at `addr`
	ut64 addr = sdb_atoi(sdbkv_key(kv));
	RzVector *vmem = rz_vector_new(sizeof(RzDebugChangeMem), NULL, NULL);
	if (!vmem) {
		eprintf("Error: failed to allocate RzVector vmem.\n");
		free(json_str);
		rz_json_free(reg_json);
		return false;
	}
	ht_up_insert(memory, addr, vmem);

	// Extract <RzDebugChangeMem>'s into the new vector
	for (child = reg_json->children.first; child; child = child->next) {
		if (child->type != RZ_JSON_OBJECT) {
			continue;
		}
		const RzJson *baby = rz_json_get(child, "cnum");
		CHECK_TYPE(baby, RZ_JSON_INTEGER);
		int cnum = baby->num.s_value;

		baby = rz_json_get(child, "data");
		CHECK_TYPE(baby, RZ_JSON_INTEGER);
		ut64 data = baby->num.u_value;

		RzDebugChangeMem mem = { cnum, data };
		rz_vector_push(vmem, &mem);
	}

	free(json_str);
	rz_json_free(reg_json);
	return true;
}

static void deserialize_memory(Sdb *db, HtUP *memory) {
	sdb_foreach(db, deserialize_memory_cb, memory);
}

static bool deserialize_registers_cb(void *user, const SdbKv *kv) {
	RzJson *child;
	char *json_str = sdbkv_dup_value(kv);
	if (!json_str) {
		return true;
	}
	RzJson *reg_json = rz_json_parse(json_str);
	if (!reg_json || reg_json->type != RZ_JSON_ARRAY) {
		free(json_str);
		return true;
	}

	// Insert a new vector into `registers` HtUP at `addr`
	HtUP *registers = user;
	RzVector *vreg = rz_vector_new(sizeof(RzDebugChangeReg), NULL, NULL);
	if (!vreg) {
		eprintf("Error: failed to allocate RzVector vreg.\n");
		rz_json_free(reg_json);
		free(json_str);
		return true;
	}
	ht_up_insert(registers, sdb_atoi(sdbkv_key(kv)), vreg);

	// Extract <RzDebugChangeReg>'s into the new vector
	for (child = reg_json->children.first; child; child = child->next) {
		if (child->type != RZ_JSON_OBJECT) {
			continue;
		}
		const RzJson *baby = rz_json_get(child, "cnum");
		CHECK_TYPE(baby, RZ_JSON_INTEGER);
		int cnum = baby->num.s_value;

		baby = rz_json_get(child, "data");
		CHECK_TYPE(baby, RZ_JSON_INTEGER);
		ut64 data = baby->num.u_value;

		RzDebugChangeReg reg = { cnum, data };
		rz_vector_push(vreg, &reg);
	}

	rz_json_free(reg_json);
	free(json_str);
	return true;
}

static void deserialize_registers(Sdb *db, HtUP *registers) {
	sdb_foreach(db, deserialize_registers_cb, registers);
}

static bool deserialize_checkpoints_cb(void *user, const SdbKv *kv) {
	const RzJson *child;
	char *json_str = sdbkv_dup_value(kv);
	if (!json_str) {
		return true;
	}
	RzJson *chkpt_json = rz_json_parse(json_str);
	if (!chkpt_json || chkpt_json->type != RZ_JSON_OBJECT) {
		free(json_str);
		return true;
	}

	RzVector *checkpoints = user;
	RzDebugCheckpoint checkpoint = { 0 };
	checkpoint.cnum = (int)sdb_atoi(sdbkv_key(kv));

	// Extract RzRegArena's from "registers"
	const RzJson *regs_json = rz_json_get(chkpt_json, "registers");
	if (!regs_json || regs_json->type != RZ_JSON_ARRAY) {
		free(json_str);
		rz_json_free(chkpt_json);
		return true;
	}
	for (child = regs_json->children.first; child; child = child->next) {
		const RzJson *baby;
		baby = rz_json_get(child, "arena");
		CHECK_TYPE(baby, RZ_JSON_INTEGER);
		int arena = baby->num.s_value;
		if (arena < RZ_REG_TYPE_GPR || arena >= RZ_REG_TYPE_LAST) {
			continue;
		}
		baby = rz_json_get(child, "size");
		CHECK_TYPE(baby, RZ_JSON_INTEGER);
		int size = baby->num.s_value;
		if (size < 0) {
			continue;
		}
		baby = rz_json_get(child, "bytes");
		CHECK_TYPE(baby, RZ_JSON_STRING);
		ut8 *bytes = sdb_decode(baby->str_value, NULL);

		RzRegArena *a = rz_reg_arena_new(size);
		if (!a) {
			free(bytes);
			continue;
		}
		memcpy(a->bytes, bytes, a->size);
		checkpoint.arena[arena] = a;
		free(bytes);
	}

	// Extract RzDebugSnap's from "snaps"
	checkpoint.snaps = rz_list_newf((RzListFree)rz_debug_snap_free);
	const RzJson *snaps_json = rz_json_get(chkpt_json, "snaps");
	if (!snaps_json || snaps_json->type != RZ_JSON_ARRAY) {
		goto end;
	}
	for (child = snaps_json->children.first; child; child = child->next) {
		const RzJson *namej = rz_json_get(child, "name");
		CHECK_TYPE(namej, RZ_JSON_STRING);
		const RzJson *dataj = rz_json_get(child, "data");
		CHECK_TYPE(dataj, RZ_JSON_STRING);
		const RzJson *sizej = rz_json_get(child, "size");
		CHECK_TYPE(sizej, RZ_JSON_INTEGER);
		const RzJson *addrj = rz_json_get(child, "addr");
		CHECK_TYPE(addrj, RZ_JSON_INTEGER);
		const RzJson *addr_endj = rz_json_get(child, "addr_end");
		CHECK_TYPE(addr_endj, RZ_JSON_INTEGER);
		const RzJson *permj = rz_json_get(child, "perm");
		CHECK_TYPE(permj, RZ_JSON_INTEGER);
		const RzJson *userj = rz_json_get(child, "user");
		CHECK_TYPE(userj, RZ_JSON_INTEGER);
		const RzJson *sharedj = rz_json_get(child, "shared");
		CHECK_TYPE(sharedj, RZ_JSON_BOOLEAN);

		RzDebugSnap *snap = RZ_NEW0(RzDebugSnap);
		if (!snap) {
			eprintf("Error: failed to allocate RzDebugSnap snap");
			continue;
		}
		snap->name = strdup(namej->str_value);
		snap->addr = addrj->num.u_value;
		snap->addr_end = addr_endj->num.u_value;
		snap->size = sizej->num.u_value;
		snap->data = sdb_decode(dataj->str_value, NULL);
		snap->perm = permj->num.s_value;
		snap->user = userj->num.s_value;
		snap->shared = sharedj->num.u_value;

		rz_list_append(checkpoint.snaps, snap);
	}
end:
	free(json_str);
	rz_json_free(chkpt_json);
	rz_vector_push(checkpoints, &checkpoint);
	return true;
}

static void deserialize_checkpoints(Sdb *db, RzVector /*<RzDebugCheckpoint>*/ *checkpoints) {
	sdb_foreach(db, deserialize_checkpoints_cb, checkpoints);
}

static bool session_sdb_load_ns(Sdb *db, const char *nspath, const char *filename) {
	Sdb *tmpdb = sdb_new0();
	if (sdb_open(tmpdb, filename) == -1) {
		eprintf("Error: failed to load %s into sdb\n", filename);
		sdb_free(tmpdb);
		return false;
	}
	Sdb *ns = sdb_ns_path(db, nspath, true);
	sdb_copy(tmpdb, ns);
	sdb_free(tmpdb);
	return true;
}

static Sdb *session_sdb_load(const char *path) {
	char *filename;
	Sdb *db = sdb_new0();
	if (!db) {
		return NULL;
	}

#define SDB_LOAD(fn, ns) \
	do { \
		filename = rz_str_newf("%s%s" fn ".sdb", path, RZ_SYS_DIR); \
		if (!session_sdb_load_ns(db, ns, filename)) { \
			free(filename); \
			goto error; \
		} \
		free(filename); \
	} while (0)

	SDB_LOAD("session", "");
	SDB_LOAD("registers", "registers");
	SDB_LOAD("memory", "memory");
	SDB_LOAD("checkpoints", "checkpoints");
	return db;
error:
	sdb_free(db);
	return NULL;
}

RZ_API void rz_debug_session_deserialize(RzDebugSession *session, Sdb *db) {
	Sdb *subdb;

	session->maxcnum = sdb_num_get(db, "maxcnum");

#define DESERIALIZE(ns, func) \
	do { \
		subdb = sdb_ns(db, ns, false); \
		if (!subdb) { \
			eprintf("Error: missing " ns " namespace\n"); \
			return; \
		} \
		func; \
	} while (0)

	DESERIALIZE("memory", deserialize_memory(subdb, session->memory));
	DESERIALIZE("registers", deserialize_registers(subdb, session->registers));
	DESERIALIZE("checkpoints", deserialize_checkpoints(subdb, session->checkpoints));
}

RZ_API bool rz_debug_session_load(RzDebug *dbg, const char *path) {
	Sdb *db = session_sdb_load(path);
	if (!db) {
		return false;
	}
	rz_debug_session_deserialize(dbg->session, db);
	// Restore debugger to the beginning of the session
	rz_debug_session_restore_reg_mem(dbg, 0);
	sdb_free(db);
	return true;
}
