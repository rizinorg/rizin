// SPDX-FileCopyrightText: 2020 Zi Fan <zifan.tan@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>
#include <rz_util.h>
#include <rz_reg.h>
#include "minunit.h"

Sdb *ref_db() {
	Sdb *db = sdb_new0();

	sdb_num_set(db, "maxcnum", 1);

	Sdb *registers_db = sdb_ns(db, "registers", true);
	sdb_set(registers_db, "0x100", "[{\"cnum\":0,\"data\":1094861636},{\"cnum\":1,\"data\":3735928559}]");

	Sdb *memory_sdb = sdb_ns(db, "memory", true);
	sdb_set(memory_sdb, "0x7ffffffff000", "[{\"cnum\":0,\"data\":170},{\"cnum\":1,\"data\":187}]");
	sdb_set(memory_sdb, "0x7ffffffff001", "[{\"cnum\":0,\"data\":0},{\"cnum\":1,\"data\":1}]");

	Sdb *checkpoints_sdb = sdb_ns(db, "checkpoints", true);
	sdb_set(checkpoints_sdb, "0x0", "{"
					"\"registers\":["
					"{\"arena\":0,\"bytes\":\"AAAAAAAAAAAAAAAAAAAAAA==\",\"size\":16},"
					"{\"arena\":1,\"bytes\":\"AQEBAQEBAQEBAQEBAQEBAQ==\",\"size\":16},"
					"{\"arena\":2,\"bytes\":\"AgICAgICAgICAgICAgICAg==\",\"size\":16},"
					"{\"arena\":3,\"bytes\":\"AwMDAwMDAwMDAwMDAwMDAw==\",\"size\":16},"
					"{\"arena\":4,\"bytes\":\"BAQEBAQEBAQEBAQEBAQEBA==\",\"size\":16},"
					"{\"arena\":5,\"bytes\":\"BQUFBQUFBQUFBQUFBQUFBQ==\",\"size\":16},"
					"{\"arena\":6,\"bytes\":\"BgYGBgYGBgYGBgYGBgYGBg==\",\"size\":16},"
					"{\"arena\":7,\"bytes\":\"BwcHBwcHBwcHBwcHBwcHBw==\",\"size\":16},"
					"{\"arena\":8,\"bytes\":\"CAgICAgICAgICAgICAgICA==\",\"size\":16},"
					"{\"arena\":9,\"bytes\":\"CQkJCQkJCQkJCQkJCQkJCQ==\",\"size\":16},"
					"{\"arena\":10,\"bytes\":\"CgoKCgoKCgoKCgoKCgoKCg==\",\"size\":16},"
					"{\"arena\":11,\"bytes\":\"CwsLCwsLCwsLCwsLCwsLCw==\",\"size\":16},"
					"{\"arena\":12,\"bytes\":\"DAwMDAwMDAwMDAwMDAwMDA==\",\"size\":16}"
					"],"
					"\"snaps\":["
					"{\"name\":\"[stack]\",\"addr\":8796092882944,\"addr_end\":8796092883200,\"size\":256,\"data\":\"8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8A==\",\"perm\":7,\"user\":0,\"shared\":true}"
					"]"
					"}");

	return db;
}

RzDebugSession *ref_session() {
	size_t i;
	RzDebugSession *s = rz_debug_session_new();

	// Registers & Memory
	rz_debug_session_add_reg_change(s, 0, 0x100, 0x41424344);
	rz_debug_session_add_mem_change(s, 0x7ffffffff000, 0xaa);
	rz_debug_session_add_mem_change(s, 0x7ffffffff001, 0x00);
	s->maxcnum++;
	s->cnum++;

	rz_debug_session_add_reg_change(s, 0, 0x100, 0xdeadbeef);
	rz_debug_session_add_mem_change(s, 0x7ffffffff000, 0xbb);
	rz_debug_session_add_mem_change(s, 0x7ffffffff001, 0x01);

	// Checkpoints
	RzDebugCheckpoint checkpoint = { 0 };
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		RzRegArena *a = rz_reg_arena_new(0x10);
		memset(a->bytes, i, a->size);
		checkpoint.arena[i] = a;
	}
	checkpoint.snaps = rz_list_newf((RzListFree)rz_debug_snap_free);
	RzDebugSnap *snap = RZ_NEW0(RzDebugSnap);
	snap->name = strdup("[stack]");
	snap->addr = 0x7fffffde000;
	snap->addr_end = 0x7fffffde100;
	snap->size = 0x100;
	snap->perm = 7;
	snap->user = 0;
	snap->shared = true;
	snap->data = malloc(snap->size);
	memset(snap->data, 0xf0, snap->size);
	rz_list_append(checkpoint.snaps, snap);
	rz_vector_push(s->checkpoints, &checkpoint);

	return s;
}

static void diff_cb(const SdbDiff *diff, void *user) {
	char buf[2048];
	if (sdb_diff_format(buf, sizeof(buf), diff) < 0) {
		return;
	}
	printf("%s\n", buf);
}

static bool test_session_save(void) {
	Sdb *expected = ref_db();
	Sdb *actual = sdb_new0();
	RzDebugSession *s = ref_session();
	rz_debug_session_serialize(s, actual);

	mu_assert("save", sdb_diff(expected, actual, diff_cb, NULL));

	sdb_free(actual);
	sdb_free(expected);
	rz_debug_session_free(s);
	mu_end;
}

static bool compare_registers_cb(void *user, const ut64 key, const void *value) {
	RzDebugChangeReg *actual_reg, *expected_reg;
	HtUP *ref = user;
	RzVector *actual_vreg = (RzVector *)value;

	RzVector *expected_vreg = ht_up_find(ref, key, NULL);
	mu_assert("vreg not found", expected_vreg);
	mu_assert_eq(actual_vreg->len, expected_vreg->len, "vreg length");

	size_t i;
	rz_vector_enumerate (actual_vreg, actual_reg, i) {
		expected_reg = rz_vector_index_ptr(expected_vreg, i);
		mu_assert_eq(actual_reg->cnum, expected_reg->cnum, "cnum");
		mu_assert_eq(actual_reg->data, expected_reg->data, "data");
	}
	return true;
}

static bool compare_memory_cb(void *user, const ut64 key, const void *value) {
	RzDebugChangeMem *actual_mem, *expected_mem;
	HtUP *ref = user;
	RzVector *actual_vmem = (RzVector *)value;

	RzVector *expected_vmem = ht_up_find(ref, key, NULL);
	mu_assert("vmem not found", expected_vmem);
	mu_assert_eq(actual_vmem->len, expected_vmem->len, "vmem length");

	size_t i;
	rz_vector_enumerate (actual_vmem, actual_mem, i) {
		expected_mem = rz_vector_index_ptr(expected_vmem, i);
		mu_assert_eq(actual_mem->cnum, expected_mem->cnum, "cnum");
		mu_assert_eq(actual_mem->data, expected_mem->data, "data");
	}
	return true;
}

static bool arena_eq(RzRegArena *actual, RzRegArena *expected) {
	mu_assert("arena null", actual && expected);
	mu_assert_eq(actual->size, expected->size, "arena size");
	mu_assert_memeq(actual->bytes, expected->bytes, expected->size, "arena bytes");
	return true;
}

static bool snap_eq(RzDebugSnap *actual, RzDebugSnap *expected) {
	mu_assert("snap null", actual && expected);
	mu_assert_streq(actual->name, expected->name, "snap name");
	mu_assert_eq(actual->addr, expected->addr, "snap addr");
	mu_assert_eq(actual->addr_end, expected->addr_end, "snap addr_end");
	mu_assert_eq(actual->size, expected->size, "snap size");
	mu_assert_eq(actual->perm, expected->perm, "snap perm");
	mu_assert_eq(actual->user, expected->user, "snap user");
	mu_assert_eq(actual->shared, expected->shared, "snap shared");
	mu_assert_memeq(actual->data, expected->data, expected->size, "snap data");
	return true;
}

static bool test_session_load(void) {
	RzDebugSession *ref = ref_session();
	RzDebugSession *s = rz_debug_session_new();
	Sdb *db = ref_db();
	rz_debug_session_deserialize(s, db);

	mu_assert_eq(s->maxcnum, ref->maxcnum, "maxcnum");
	// Registers
	ht_up_foreach(s->registers, compare_registers_cb, ref->registers);
	// Memory
	ht_up_foreach(s->memory, compare_memory_cb, ref->memory);
	// Checkpoints
	size_t i, chkpt_idx;
	RzDebugCheckpoint *chkpt, *ref_chkpt;
	mu_assert_eq(s->checkpoints->len, ref->checkpoints->len, "checkpoints length");
	rz_vector_enumerate (s->checkpoints, chkpt, chkpt_idx) {
		ref_chkpt = rz_vector_index_ptr(ref->checkpoints, chkpt_idx);
		// Registers
		for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
			arena_eq(chkpt->arena[i], ref_chkpt->arena[i]);
		}
		// Snaps
		RzListIter *actual_snaps_iter = rz_list_iterator(chkpt->snaps);
		RzListIter *expected_snaps_iter = rz_list_iterator(ref_chkpt->snaps);
		while (actual_snaps_iter && expected_snaps_iter) {
			RzDebugSnap *actual_snap = rz_list_iter_get(actual_snaps_iter);
			RzDebugSnap *expected_snap = rz_list_iter_get(expected_snaps_iter);
			snap_eq(actual_snap, expected_snap);
		}
	}

	sdb_free(db);
	rz_debug_session_free(s);
	rz_debug_session_free(ref);
	mu_end;
}

int all_tests() {
	mu_run_test(test_session_save);
	mu_run_test(test_session_load);
	return tests_passed != tests_run;
}

mu_main(all_tests)
