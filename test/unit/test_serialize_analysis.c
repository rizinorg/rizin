// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_util/rz_path.h>
#include "test_config.h"
#include "minunit.h"
#include "test_sdb.h"

#include "test_analysis_block_invars.inl"

bool test_analysis_switch_op_save() {
	RzAnalysisSwitchOp *op = rz_analysis_switch_op_new(1337, 42, 45, 46);

	PJ *j = pj_new();
	rz_serialize_analysis_switch_op_save(j, op);
	mu_assert_streq(pj_string(j), "{\"addr\":1337,\"min\":42,\"max\":45,\"def\":46,\"cases\":[]}", "empty switch");
	pj_free(j);

	rz_analysis_switch_op_add_case(op, 1339, 42, 0xdead);
	rz_analysis_switch_op_add_case(op, 1340, 43, 0xbeef);
	j = pj_new();
	rz_serialize_analysis_switch_op_save(j, op);
	mu_assert_streq(pj_string(j), "{\"addr\":1337,\"min\":42,\"max\":45,\"def\":46,\"cases\":[{\"addr\":1339,\"jump\":57005,\"value\":42},{\"addr\":1340,\"jump\":48879,\"value\":43}]}", "full switch");
	pj_free(j);

	rz_analysis_switch_op_free(op);
	mu_end;
}

bool test_analysis_switch_op_load() {
	char *str = strdup("{\"addr\":1337,\"min\":42,\"max\":45,\"def\":46,\"cases\":[]}");
	RzJson *json = rz_json_parse(str);
	RzAnalysisSwitchOp *sop = rz_serialize_analysis_switch_op_load(json);
	rz_json_free(json);
	free(str);
	mu_assert_notnull(sop, "sop");
	mu_assert_eq(sop->addr, 1337, "addr");
	mu_assert_eq(sop->min_val, 42, "min val");
	mu_assert_eq(sop->max_val, 45, "max val");
	mu_assert_eq(sop->def_val, 46, "def val");
	mu_assert_true(rz_list_empty(sop->cases), "no cases");
	rz_analysis_switch_op_free(sop);

	str = strdup("{\"addr\":1337,\"min\":42,\"max\":45,\"def\":46,\"cases\":[{\"addr\":1339,\"jump\":57005,\"value\":42},{\"addr\":1340,\"jump\":48879,\"value\":43}]}");
	json = rz_json_parse(str);
	sop = rz_serialize_analysis_switch_op_load(json);
	rz_json_free(json);
	free(str);
	mu_assert_notnull(sop, "sop");
	mu_assert_eq(sop->addr, 1337, "addr");
	mu_assert_eq(sop->min_val, 42, "min val");
	mu_assert_eq(sop->max_val, 45, "max val");
	mu_assert_eq(sop->def_val, 46, "def val");
	mu_assert_eq(rz_list_length(sop->cases), 2, "cases count");
	RzAnalysisCaseOp *cop = rz_list_get_n(sop->cases, 0);
	mu_assert_eq(cop->addr, 1339, "addr");
	mu_assert_eq(cop->jump, 0xdead, "jump");
	mu_assert_eq(cop->value, 42, "value");
	cop = rz_list_get_n(sop->cases, 1);
	mu_assert_eq(cop->addr, 1340, "addr");
	mu_assert_eq(cop->jump, 0xbeef, "jump");
	mu_assert_eq(cop->value, 43, "value");
	rz_analysis_switch_op_free(sop);

	mu_end;
}

Sdb *blocks_ref_db() {
	Sdb *db = sdb_new0();
	sdb_set(db, "0x539", "{\"size\":42}", 0);
	sdb_set(db, "0x4d2", "{\"size\":32,\"jump\":4883,\"fail\":16915,\"traced\":true,\"colorize\":16711680,\"switch_op\":{\"addr\":49232,\"min\":3,\"max\":5,\"def\":7,\"cases\":[]},\"ninstr\":3,\"op_pos\":[4,7],\"sp_delta\":[8,-8,16],\"sp\":256,\"cmpval\":262254561,\"cmpreg\":\"rax\"}", 0);
	return db;
}

bool test_analysis_block_save() {
	RzAnalysis *analysis = rz_analysis_new();

	rz_analysis_create_block(analysis, 1337, 42);

	RzAnalysisBlock *block = rz_analysis_create_block(analysis, 1234, 32);
	block->jump = 0x1313;
	block->fail = 0x4213;
	block->traced = true;
	block->colorize = 0xff0000;
	block->switch_op = rz_analysis_switch_op_new(49232, 3, 5, 7);
	block->ninstr = 3;
	mu_assert("enough size for op_pos test", block->op_pos_size >= 2); // if this fails, just change the test
	block->op_pos[0] = 4;
	block->op_pos[1] = 7;
	block->sp_entry = -0x100;
	rz_analysis_block_set_op_sp_delta(block, 0, -8);
	rz_analysis_block_set_op_sp_delta(block, 1, 8);
	rz_analysis_block_set_op_sp_delta(block, 2, -0x10);
	block->cmpval = 0xfa1afe1;
	block->cmpreg = "rax";

	Sdb *db = sdb_new0();
	rz_serialize_analysis_blocks_save(db, analysis);

	Sdb *expected = blocks_ref_db();
	assert_sdb_eq(db, expected, "analysis blocks save");
	sdb_free(db);
	sdb_free(expected);
	rz_analysis_free(analysis);
	mu_end;
}

bool test_analysis_block_load() {
	RzAnalysis *analysis = rz_analysis_new();

	Sdb *db = blocks_ref_db();
	bool succ = rz_serialize_analysis_blocks_load(db, analysis, NULL);
	mu_assert("load success", succ);

	RzAnalysisBlock *a = NULL;
	RzAnalysisBlock *b = NULL;
	size_t count = 0;

	RBIter iter;
	RzAnalysisBlock *block;
	rz_rbtree_foreach (analysis->bb_tree, iter, block, RzAnalysisBlock, _rb) {
		count++;
		if (block->addr == 1337) {
			a = block;
		} else if (block->addr == 1234) {
			b = block;
		}
	}
	mu_assert_eq(count, 2, "loaded blocks count");

	mu_assert_notnull(a, "block a");
	mu_assert_eq(a->size, 42, "size");
	mu_assert_eq(a->jump, UT64_MAX, "jump");
	mu_assert_eq(a->fail, UT64_MAX, "fail");
	mu_assert("traced", !a->traced);
	mu_assert_eq(a->colorize, 0, "colorize");
	mu_assert_null(a->switch_op, "switch op");
	mu_assert_eq(a->ninstr, 0, "ninstr");
	mu_assert_eq(a->sp_entry, RZ_STACK_ADDR_INVALID, "sp_entry");
	mu_assert_eq(a->cmpval, UT64_MAX, "cmpval");
	mu_assert_null(a->cmpreg, "cmpreg");

	mu_assert_notnull(b, "block b");
	mu_assert_eq(b->size, 32, "size");
	mu_assert_eq(b->jump, 0x1313, "jump");
	mu_assert_eq(b->fail, 0x4213, "fail");
	mu_assert("traced", b->traced);
	mu_assert_eq(b->colorize, 0xff0000, "colorize");
	mu_assert_notnull(b->switch_op, "switch op");
	mu_assert_eq(b->switch_op->addr, 49232, "switch op addr"); // switch_op is covered in detail by its own tests
	mu_assert_eq(b->ninstr, 3, "ninstr");
	mu_assert("op_pos_size", b->op_pos_size >= b->ninstr - 1);
	mu_assert_eq(b->op_pos[0], 4, "op_pos[0]");
	mu_assert_eq(b->op_pos[1], 7, "op_pos[1]");
	mu_assert_eq(b->sp_entry, -0x100, "sp_entry");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(b, 0), -8, "sp delta");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(b, 1), 8, "sp delta");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(b, 2), -0x10, "sp delta");
	mu_assert_eq(b->cmpval, 0xfa1afe1, "cmpval");
	mu_assert_ptreq(b->cmpreg, rz_str_constpool_get(&analysis->constpool, "rax"), "cmpreg from pool");

	rz_analysis_free(analysis);
	analysis = rz_analysis_new();
	// This could lead to a buffer overflow if unchecked:
	sdb_set(db, "0x539", "{\"size\":42,\"ninstr\":4,\"op_pos\":[4,7]}", 0);
	succ = rz_serialize_analysis_blocks_load(db, analysis, NULL);
	mu_assert("reject invalid op_pos array length", !succ);

	assert_block_invariants(analysis);
	// assert_block_leaks would fail here because loading blocks "leaks" them on purpose to be added to functions later.
	// (this just means there are blocks associated with no function)
	// so all cool and good here!

	sdb_free(db);
	rz_analysis_free(analysis);
	mu_end;
}

Sdb *functions_ref_db() {
	Sdb *db = sdb_new0();
	sdb_set(db, "0x4d2", "{\"name\":\"effekt\",\"type\":1,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"pure\":true,\"bbs\":[1337]}", 0);
	sdb_set(db, "0xbeef", "{\"name\":\"eskapist\",\"bits\":32,\"type\":16,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"bbs\":[]}", 0);
	sdb_set(db, "0x539", "{\"name\":\"hirsch\",\"bits\":16,\"type\":0,\"cc\":\"fancycall\",\"stack\":42,\"maxstack\":123,\"ninstr\":13,\"bp_frame\":true,\"bp_off\":4,\"bbs\":[1337,1234],\"imports\":[\"earth\",\"rise\"],\"labels\":{\"beach\":1400,\"another\":1450,\"year\":1440}}", 0);
	sdb_set(db, "0xdead", "{\"name\":\"agnosie\",\"bits\":32,\"type\":8,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"bbs\":[]}", 0);
	sdb_set(db, "0xc0ffee", "{\"name\":\"lifnej\",\"bits\":32,\"type\":32,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"bbs\":[]}", 0);
	sdb_set(db, "0x1092", "{\"name\":\"hiberno\",\"bits\":32,\"type\":2,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bbs\":[]}", 0);
	sdb_set(db, "0x67932", "{\"name\":\"anamnesis\",\"bits\":32,\"type\":4,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"noreturn\":true,\"bbs\":[]}", 0);
	sdb_set(db, "0x31337", "{\"name\":\"aldebaran\",\"bits\":32,\"type\":-1,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"bbs\":[]}", 0);
	return db;
}

bool test_analysis_function_save() {
	RzAnalysis *analysis = rz_analysis_new();

	RzAnalysisBlock *ba = rz_analysis_create_block(analysis, 1337, 42);
	RzAnalysisBlock *bb = rz_analysis_create_block(analysis, 1234, 32);

	RzAnalysisFunction *f = rz_analysis_create_function(analysis, "hirsch", 1337, RZ_ANALYSIS_FCN_TYPE_NULL);
	rz_analysis_function_add_block(f, ba);
	rz_analysis_function_add_block(f, bb);
	f->bits = 16;
	f->cc = rz_str_constpool_get(&analysis->constpool, "fancycall");
	f->stack = 42;
	f->maxstack = 123;
	f->bp_off = 4;
	f->ninstr = 13;
	f->imports = rz_list_newf(free);
	rz_list_push(f->imports, strdup("earth"));
	rz_list_push(f->imports, strdup("rise"));
	rz_analysis_function_set_label(f, "beach", 1400);
	rz_analysis_function_set_label(f, "another", 1450);
	rz_analysis_function_set_label(f, "year", 1440);

	f = rz_analysis_create_function(analysis, "effekt", 1234, RZ_ANALYSIS_FCN_TYPE_FCN);
	rz_analysis_function_add_block(f, ba);
	f->is_pure = true;
	f->bits = 0;

	f = rz_analysis_create_function(analysis, "hiberno", 4242, RZ_ANALYSIS_FCN_TYPE_LOC);
	f->bp_frame = false;

	f = rz_analysis_create_function(analysis, "anamnesis", 424242, RZ_ANALYSIS_FCN_TYPE_SYM);
	f->is_noreturn = true;

	rz_analysis_create_function(analysis, "agnosie", 0xdead, RZ_ANALYSIS_FCN_TYPE_IMP);
	rz_analysis_create_function(analysis, "eskapist", 0xbeef, RZ_ANALYSIS_FCN_TYPE_INT);
	rz_analysis_create_function(analysis, "lifnej", 0xc0ffee, RZ_ANALYSIS_FCN_TYPE_ROOT);
	rz_analysis_create_function(analysis, "aldebaran", 0x31337, RZ_ANALYSIS_FCN_TYPE_ANY);

	rz_analysis_block_unref(ba);
	rz_analysis_block_unref(bb);

	Sdb *db = sdb_new0();
	rz_serialize_analysis_functions_save(db, analysis);

	Sdb *expected = functions_ref_db();
	assert_sdb_eq(db, expected, "functions save");
	sdb_free(db);
	sdb_free(expected);
	rz_analysis_free(analysis);
	mu_end;
}

bool test_analysis_function_load() {
	RzAnalysis *analysis = rz_analysis_new();

	Sdb *db = functions_ref_db();

	RzAnalysisBlock *ba = rz_analysis_create_block(analysis, 1337, 42);
	RzAnalysisBlock *bb = rz_analysis_create_block(analysis, 1234, 32);

	bool succ = rz_serialize_analysis_functions_load(db, analysis, NULL);
	mu_assert("load success", succ);

	mu_assert_eq(ba->ref, 3, "ba refs");
	mu_assert_eq(bb->ref, 2, "bb refs");
	rz_analysis_block_unref(ba);
	rz_analysis_block_unref(bb);

	mu_assert_eq(rz_pvector_len(analysis->fcns), 8, "loaded fcn count");

	RzAnalysisFunction *f = rz_analysis_get_function_at(analysis, 1337);
	mu_assert_notnull(f, "function");
	mu_assert_streq(f->name, "hirsch", "name");
	mu_assert_eq(f->type, RZ_ANALYSIS_FCN_TYPE_NULL, "type");
	mu_assert_eq(rz_pvector_len(f->bbs), 2, "bbs count");
	mu_assert("bb", rz_pvector_contains(f->bbs, ba));
	mu_assert("bb", rz_pvector_contains(f->bbs, bb));
	mu_assert_eq(f->bits, 16, "bits");
	mu_assert_ptreq(f->cc, rz_str_constpool_get(&analysis->constpool, "fancycall"), "cc");
	mu_assert_eq(f->stack, 42, "stack");
	mu_assert_eq(f->maxstack, 123, "maxstack");
	mu_assert_eq(f->ninstr, 13, "ninstr");
	mu_assert("pure", !f->is_pure);
	mu_assert("noreturn", !f->is_noreturn);
	mu_assert("bp_frame", f->bp_frame);
	mu_assert_eq(f->bp_off, 4, "bp off");
	mu_assert_notnull(f->imports, "imports");
	mu_assert_eq(rz_list_length(f->imports), 2, "imports count");
	mu_assert_streq(rz_list_get_n(f->imports, 0), "earth", "import");
	mu_assert_streq(rz_list_get_n(f->imports, 1), "rise", "import");
	mu_assert_eq(f->labels->count, 3, "labels count");
	mu_assert_eq(rz_analysis_function_get_label(f, "beach"), 1400, "label");
	mu_assert_eq(rz_analysis_function_get_label(f, "another"), 1450, "label");
	mu_assert_eq(rz_analysis_function_get_label(f, "year"), 1440, "label");

	f = rz_analysis_get_function_at(analysis, 1234);
	mu_assert_notnull(f, "function");
	mu_assert_streq(f->name, "effekt", "name");
	mu_assert_eq(f->type, RZ_ANALYSIS_FCN_TYPE_FCN, "type");
	mu_assert_eq(rz_pvector_len(f->bbs), 1, "bbs count");
	mu_assert("bb", rz_pvector_contains(f->bbs, ba));
	mu_assert_eq(f->bits, 0, "bits");
	mu_assert_null(f->cc, "cc");
	mu_assert_eq(f->stack, 0, "stack");
	mu_assert_eq(f->maxstack, 0, "maxstack");
	mu_assert_eq(f->ninstr, 0, "ninstr");
	mu_assert("pure", f->is_pure);
	mu_assert("noreturn", !f->is_noreturn);
	mu_assert("bp_frame", f->bp_frame);
	mu_assert_eq(f->bp_off, 0, "bp off");
	mu_assert_null(f->imports, "imports");
	mu_assert_eq(f->labels->count, 0, "labels count");

	f = rz_analysis_get_function_at(analysis, 4242);
	mu_assert_notnull(f, "function");
	mu_assert_streq(f->name, "hiberno", "name");
	mu_assert_eq(f->type, RZ_ANALYSIS_FCN_TYPE_LOC, "type");
	mu_assert_eq(rz_pvector_len(f->bbs), 0, "bbs count");
	mu_assert_eq(f->bits, 32, "bits");
	mu_assert_null(f->cc, "cc");
	mu_assert_eq(f->stack, 0, "stack");
	mu_assert_eq(f->maxstack, 0, "maxstack");
	mu_assert_eq(f->ninstr, 0, "ninstr");
	mu_assert("pure", !f->is_pure);
	mu_assert("noreturn", !f->is_noreturn);
	mu_assert("bp_frame", !f->bp_frame);
	mu_assert_null(f->imports, "imports");
	mu_assert_eq(f->labels->count, 0, "labels count");

	f = rz_analysis_get_function_at(analysis, 424242);
	mu_assert_notnull(f, "function");
	mu_assert_streq(f->name, "anamnesis", "name");
	mu_assert_eq(f->type, RZ_ANALYSIS_FCN_TYPE_SYM, "type");
	mu_assert_eq(rz_pvector_len(f->bbs), 0, "bbs count");
	mu_assert_eq(f->bits, 32, "bits");
	mu_assert_null(f->cc, "cc");
	mu_assert_eq(f->stack, 0, "stack");
	mu_assert_eq(f->maxstack, 0, "maxstack");
	mu_assert_eq(f->ninstr, 0, "ninstr");
	mu_assert("pure", !f->is_pure);
	mu_assert("noreturn", f->is_noreturn);
	mu_assert("bp_frame", f->bp_frame);
	mu_assert_null(f->imports, "imports");
	mu_assert_eq(f->labels->count, 0, "labels count");

	f = rz_analysis_get_function_at(analysis, 0xdead);
	mu_assert_notnull(f, "function");
	mu_assert_streq(f->name, "agnosie", "name");
	mu_assert_eq(f->type, RZ_ANALYSIS_FCN_TYPE_IMP, "type");
	mu_assert_eq(f->labels->count, 0, "labels count");

	f = rz_analysis_get_function_at(analysis, 0xbeef);
	mu_assert_notnull(f, "function");
	mu_assert_streq(f->name, "eskapist", "name");
	mu_assert_eq(f->type, RZ_ANALYSIS_FCN_TYPE_INT, "type");
	mu_assert_eq(f->labels->count, 0, "labels count");

	f = rz_analysis_get_function_at(analysis, 0xc0ffee);
	mu_assert_notnull(f, "function");
	mu_assert_streq(f->name, "lifnej", "name");
	mu_assert_eq(f->type, RZ_ANALYSIS_FCN_TYPE_ROOT, "type");
	mu_assert_eq(f->labels->count, 0, "labels count");

	f = rz_analysis_get_function_at(analysis, 0x31337);
	mu_assert_notnull(f, "function");
	mu_assert_streq(f->name, "aldebaran", "name");
	mu_assert_eq(f->type, RZ_ANALYSIS_FCN_TYPE_ANY, "type");
	mu_assert_eq(f->labels->count, 0, "labels count");

	assert_block_invariants(analysis);
	assert_block_leaks(analysis);

	sdb_free(db);
	rz_analysis_free(analysis);
	mu_end;
}

static Sdb *noreturn_ref_db() {
	Sdb *db = sdb_new0();
	sdb_bool_set(db, "addr.8000500.noreturn", true, 0);
	sdb_bool_set(db, "addr.8000555.noreturn", true, 0);
	sdb_bool_set(db, "addr.8000610.noreturn", true, 0);
	sdb_bool_set(db, "addr.8000632.noreturn", true, 0);
	return db;
}

bool test_analysis_function_noreturn_save() {
	RzAnalysis *analysis = rz_analysis_new();

	rz_analysis_noreturn_add(analysis, NULL, 0x800800);
	bool has = sdb_bool_get(analysis->sdb_noret, "addr.800800.noreturn", 0);
	mu_assert_true(has, "noreturn add error");
	rz_analysis_noreturn_drop(analysis, "0x800800");
	bool hasnt = sdb_bool_get(analysis->sdb_noret, "addr.800800.noreturn", 0);
	mu_assert_false(hasnt, "noreturn drop error");

	rz_analysis_noreturn_add(analysis, NULL, 0x8000500);
	rz_analysis_noreturn_add(analysis, NULL, 0x8000555);
	rz_analysis_noreturn_add(analysis, NULL, 0x8000610);
	rz_analysis_noreturn_add(analysis, NULL, 0x8000632);
	Sdb *db = sdb_new0();
	rz_serialize_analysis_function_noreturn_save(db, analysis);

	Sdb *expected = noreturn_ref_db();
	assert_sdb_eq(db, expected, "function noreturn save");
	sdb_free(db);
	sdb_free(expected);
	rz_analysis_free(analysis);
	mu_end;
}

bool test_analysis_function_noreturn_load() {
	RzAnalysis *analysis = rz_analysis_new();
	Sdb *db = noreturn_ref_db();
	bool succ = rz_serialize_analysis_function_noreturn_load(db, analysis, NULL);
	sdb_free(db);
	mu_assert("load success", succ);

	bool has = sdb_bool_get(analysis->sdb_noret, "addr.8000500.noreturn", 0);
	has &= sdb_bool_get(analysis->sdb_noret, "addr.8000555.noreturn", 0);
	has &= sdb_bool_get(analysis->sdb_noret, "addr.8000610.noreturn", 0);
	has &= sdb_bool_get(analysis->sdb_noret, "addr.8000632.noreturn", 0);
	mu_assert_true(has, "noreturn load error");

	bool hasnt = sdb_bool_get(analysis->sdb_noret, "addr.800800.noreturn", 0);
	mu_assert_false(hasnt, "noreturn should not exist");

	rz_analysis_free(analysis);
	mu_end;
}

Sdb *vars_ref_db() {
	Sdb *db = sdb_new0();
	sdb_set(db, "0x539",
		"{\"name\":\"hirsch\",\"bits\":64,\"type\":0,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"bbs\":[],"
		"\"vars\":["
		"{\"name\":\"arg_rax\",\"type\":\"int64_t\",\"storage\":{\"type\":\"reg\",\"reg\":\"rax\"},\"accs\":[{\"off\":3,\"type\":\"r\",\"reg\":\"rax\"},{\"off\":13,\"type\":\"rw\",\"sp\":-13,\"reg\":\"rbx\"},{\"off\":23,\"type\":\"w\",\"sp\":123,\"reg\":\"rcx\"}],\"constrs\":[0,42,1,84,2,126,3,168,4,210,5,252,6,294,7,336,8,378,9,420,10,462,11,504,12,546,13,588,14,630,15,672]},"
		"{\"name\":\"var_0h\",\"type\":\"const char *\",\"storage\":{\"type\":\"stack\",\"stack\":0},\"accs\":[{\"off\":3,\"type\":\"w\",\"sp\":321,\"reg\":\"rsp\"}]},"
		"{\"name\":\"var_10h\",\"type\":\"struct something\",\"storage\":{\"type\":\"stack\",\"stack\":-16}},"
		"{\"name\":\"arg_8h\",\"type\":\"uint64_t\",\"storage\":{\"type\":\"stack\",\"stack\":8},\"cmt\":\"I have no idea what this var does\"},"
		"{\"name\":\"arg_18h\",\"type\":\"struct something\",\"storage\":{\"type\":\"composite\",\"composite\":[{\"offset_in_bits\":0,\"size_in_bits\":32,\"storage\":{\"type\":\"reg\",\"reg\":\"rax\"}},{\"offset_in_bits\":32,\"size_in_bits\":32,\"storage\":{\"type\":\"reg\",\"reg\":\"rbx\"}}]}}"
		"]}",
		0);
	return db;
}

static RzAnalysisVarStorage *composite_stor(RzAnalysisVarStorage *stor) {
	rz_analysis_var_storage_init_composite(stor);
	RzAnalysisVarStoragePiece p1 = {
		.offset_in_bits = 0,
		.size_in_bits = 32,
		.storage = RZ_NEW0(RzAnalysisVarStorage)
	};
	p1.storage->type = RZ_ANALYSIS_VAR_STORAGE_REG;
	p1.storage->reg = strdup("rax");
	RzAnalysisVarStoragePiece p2 = {
		.offset_in_bits = 32,
		.size_in_bits = 32,
		.storage = RZ_NEW0(RzAnalysisVarStorage)
	};
	p2.storage->type = RZ_ANALYSIS_VAR_STORAGE_REG;
	p2.storage->reg = strdup("rbx");
	rz_vector_push(stor->composite, &p1);
	rz_vector_push(stor->composite, &p2);
	return stor;
}

bool test_analysis_var_save() {
	RzAnalysis *analysis = rz_analysis_new();
	rz_analysis_use(analysis, "x86");
	rz_analysis_set_bits(analysis, 64);
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(analysis->typedb, types_dir, "x86", 64, "linux");

	RzAnalysisFunction *f = rz_analysis_create_function(analysis, "hirsch", 1337, RZ_ANALYSIS_FCN_TYPE_NULL);

	RzType *t_int64_t = rz_type_identifier_of_base_type_str(analysis->typedb, "int64_t");
	mu_assert_notnull(t_int64_t, "has int64_t type");
	RzType *t_uint64_t = rz_type_identifier_of_base_type_str(analysis->typedb, "uint64_t");
	mu_assert_notnull(t_uint64_t, "has uint64_t type");
	RzType *t_const_char_ptr = rz_type_pointer_of_base_type_str(analysis->typedb, "char", false);
	mu_assert_notnull(t_const_char_ptr, "has char* type");
	t_const_char_ptr->pointer.type->identifier.is_const = true;
	RzBaseType *bt_struct_something = rz_type_base_type_new(RZ_BASE_TYPE_KIND_STRUCT);
	mu_assert_notnull(bt_struct_something, "create struct something base type");
	bt_struct_something->name = strdup("something");
	rz_type_db_save_base_type(analysis->typedb, bt_struct_something);
	RzType *t_struct_something = rz_type_identifier_of_base_type(analysis->typedb, bt_struct_something, false);
	mu_assert_notnull(t_struct_something, "create struct something type");
	t_struct_something->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_STRUCT;

	RzAnalysisVarStorage stor;
	rz_analysis_var_storage_init_reg(&stor, "rax");
	RzAnalysisVar *v = rz_analysis_function_set_var(f, &stor, t_int64_t, 0, "arg_rax");
	rz_analysis_var_set_access(v, "rax", 1340, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, 0);
	rz_analysis_var_set_access(v, "rbx", 1350, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ | RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE, -13);
	rz_analysis_var_set_access(v, "rcx", 1360, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE, 123);

	ut64 val = 0;
	RzTypeCond cond;
	for (cond = RZ_TYPE_COND_AL; cond <= RZ_TYPE_COND_LS; cond++) {
		val += 42;
		RzTypeConstraint constr = {
			.cond = cond,
			.val = val
		};
		rz_analysis_var_add_constraint(v, &constr);
	}

	rz_analysis_var_storage_init_stack(&stor, 0);
	v = rz_analysis_function_set_var(f, &stor, t_const_char_ptr, 0, "var_0h");
	rz_analysis_var_set_access(v, "rsp", 1340, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE, 321);

	rz_analysis_var_storage_init_stack(&stor, -0x10);
	rz_analysis_function_set_var(f, &stor, t_struct_something, 0, "var_10h");
	rz_analysis_var_storage_init_stack(&stor, 8);
	v = rz_analysis_function_set_var(f, &stor, t_uint64_t, 0, "arg_8h");
	v->comment = strdup("I have no idea what this var does");

	RzAnalysisVarStorage compos = { 0 };
	composite_stor(&compos);
	rz_analysis_function_set_var(f, &compos, t_struct_something, 0, "arg_18h");

	Sdb *db = sdb_new0();
	rz_serialize_analysis_functions_save(db, analysis);

	Sdb *expected = vars_ref_db();
	assert_sdb_json_eq(db, expected, "functions save");
	sdb_free(db);
	sdb_free(expected);

	rz_analysis_free(analysis);
	mu_end;
}

bool test_analysis_var_load() {
	RzAnalysis *analysis = rz_analysis_new();
	rz_analysis_use(analysis, "x86");
	rz_analysis_set_bits(analysis, 64);
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(analysis->typedb, types_dir, "x86", 64, "linux");

	Sdb *db = vars_ref_db();

	bool succ = rz_serialize_analysis_functions_load(db, analysis, NULL);
	mu_assert("load success", succ);
	RzAnalysisFunction *f = rz_analysis_get_function_at(analysis, 1337);
	mu_assert_notnull(f, "function");

	mu_assert_eq(rz_pvector_len(&f->vars), 5, "vars count");

	RzType *t_int64_t = rz_type_identifier_of_base_type_str(analysis->typedb, "int64_t");
	mu_assert_notnull(t_int64_t, "has int64_t type");
	RzType *t_uint64_t = rz_type_identifier_of_base_type_str(analysis->typedb, "uint64_t");
	mu_assert_notnull(t_uint64_t, "has uint64_t type");
	RzType *t_const_char_ptr = rz_type_pointer_of_base_type_str(analysis->typedb, "char", true);
	mu_assert_notnull(t_const_char_ptr, "has \"const char *\" type");

	RzAnalysisVar *v = rz_analysis_function_get_reg_var_at(f, "rax");
	mu_assert_notnull(v, "var");
	mu_assert_eq(v->storage.type, RZ_ANALYSIS_VAR_STORAGE_REG, "var storage");
	mu_assert_streq(v->storage.reg, "rax", "var regname");
	mu_assert_streq(v->name, "arg_rax", "var name");
	mu_assert_true(rz_type_atomic_str_eq(analysis->typedb, v->type, "int64_t"), "var type");

	mu_assert_eq(v->accesses.len, 3, "accesses count");
	bool found[3] = { false, false, false };
	RzAnalysisVarAccess *acc;
	rz_vector_foreach(&v->accesses, acc) {
		if (acc->offset == 3 && acc->type == RZ_ANALYSIS_VAR_ACCESS_TYPE_READ && acc->reg_addend == 0 && !strcmp(acc->reg, "rax")) {
			found[0] = true;
		} else if (acc->offset == 13 && acc->type == (RZ_ANALYSIS_VAR_ACCESS_TYPE_READ | RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE) && acc->reg_addend == -13 && !strcmp(acc->reg, "rbx")) {
			found[1] = true;
		} else if (acc->offset == 23 && acc->type == RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE && acc->reg_addend == 123 && !strcmp(acc->reg, "rcx")) {
			found[2] = true;
		}
	}
	mu_assert("var accesses", found[0] && found[1] && found[2]);
	RzPVector *used = rz_analysis_function_get_vars_used_at(f, 1340);
	mu_assert("var used", rz_pvector_contains(used, v));

	mu_assert_eq(v->constraints.len, RZ_TYPE_COND_LS + 1, "constraints count");
	ut64 val = 0;
	RzTypeCond cond;
	for (cond = RZ_TYPE_COND_AL; cond <= RZ_TYPE_COND_LS; cond++) {
		val += 42;
		RzTypeConstraint *constr = rz_vector_index_ptr(&v->constraints, (size_t)(cond - RZ_TYPE_COND_AL));
		mu_assert_eq(constr->cond, cond, "constraint cond");
		mu_assert_eq(constr->val, val, "constraint val");
	}

	v = rz_analysis_function_get_stack_var_at(f, 0);
	mu_assert_notnull(v, "var");
	mu_assert_eq(v->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage");
	mu_assert_eq(v->storage.stack_off, 0, "var stack_off");
	mu_assert_streq(v->name, "var_0h", "var name");
	mu_assert_eq(v->type->kind, RZ_TYPE_KIND_POINTER, "var type");
	mu_assert_notnull(v->type->pointer.type, "var type");
	mu_assert_eq(v->type->pointer.type->kind, RZ_TYPE_KIND_IDENTIFIER, "var type");
	mu_assert_true(v->type->pointer.type->identifier.is_const, "var type");
	mu_assert_true(rz_type_atomic_str_eq(analysis->typedb, v->type->pointer.type, "char"), "var type");
	mu_assert_eq(v->accesses.len, 1, "accesses count");
	acc = rz_vector_index_ptr(&v->accesses, 0);
	mu_assert_eq(acc->offset, 3, "access offset");
	mu_assert_eq(acc->type, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE, "access type");
	mu_assert_eq(acc->reg_addend, 321, "access reg_addend");
	mu_assert_streq(acc->reg, "rsp", "access reg");
	mu_assert("var used", rz_pvector_contains(used, v)); // used at the same var as the reg one

	v = rz_analysis_function_get_stack_var_at(f, -0x10);
	mu_assert_notnull(v, "var");
	mu_assert_eq(v->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage");
	mu_assert_eq(v->storage.stack_off, -0x10, "var stack_off");
	mu_assert_streq(v->name, "var_10h", "var name");
	mu_assert_eq(v->type->kind, RZ_TYPE_KIND_IDENTIFIER, "var type");
	mu_assert_eq(v->type->identifier.kind, RZ_TYPE_IDENTIFIER_KIND_STRUCT, "var type");
	mu_assert_streq(v->type->identifier.name, "something", "var type");
	mu_assert_eq(v->accesses.len, 0, "accesses count");

	v = rz_analysis_function_get_stack_var_at(f, 8);
	mu_assert_notnull(v, "var");
	mu_assert_eq(v->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage");
	mu_assert_eq(v->storage.stack_off, 8, "var stack_off");
	mu_assert_streq(v->name, "arg_8h", "var name");
	mu_assert_true(rz_type_atomic_str_eq(analysis->typedb, v->type, "uint64_t"), "var type");
	mu_assert_eq(v->accesses.len, 0, "accesses count");
	mu_assert_streq(v->comment, "I have no idea what this var does", "var comment");

	RzAnalysisVarStorage compos = { 0 };
	composite_stor(&compos);
	v = rz_analysis_function_get_var_at(f, &compos);
	mu_assert_notnull(v, "var");
	mu_assert_eq(v->storage.type, RZ_ANALYSIS_VAR_STORAGE_COMPOSITE, "var storage");
	mu_assert_streq(v->name, "arg_18h", "var name");
	rz_analysis_var_storage_fini(&compos);

	sdb_free(db);
	rz_analysis_free(analysis);
	mu_end;
}

Sdb *xrefs_ref_db() {
	Sdb *db = sdb_new0();
	sdb_set(db, "0x29a", "[{\"to\":333,\"type\":\"s\"}]", 0);
	sdb_set(db, "0x1337", "[{\"to\":4242},{\"to\":4243,\"type\":\"c\"}]", 0);
	sdb_set(db, "0x2a", "[{\"to\":4321,\"type\":\"d\"}]", 0);
	sdb_set(db, "0x4d2", "[{\"to\":4243,\"type\":\"C\"}]", 0);
	return db;
}

bool test_analysis_xrefs_save() {
	RzAnalysis *analysis = rz_analysis_new();

	rz_analysis_xrefs_set(analysis, 0x1337, 4242, RZ_ANALYSIS_XREF_TYPE_NULL);
	rz_analysis_xrefs_set(analysis, 0x1337, 4243, RZ_ANALYSIS_XREF_TYPE_CODE);
	rz_analysis_xrefs_set(analysis, 1234, 4243, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 42, 4321, RZ_ANALYSIS_XREF_TYPE_DATA);
	rz_analysis_xrefs_set(analysis, 666, 333, RZ_ANALYSIS_XREF_TYPE_STRING);

	Sdb *db = sdb_new0();
	rz_serialize_analysis_xrefs_save(db, analysis);

	Sdb *expected = xrefs_ref_db();
	assert_sdb_eq(db, expected, "xrefs save");
	sdb_free(db);
	sdb_free(expected);
	rz_analysis_free(analysis);
	mu_end;
}

bool test_analysis_xrefs_load() {
	RzAnalysis *analysis = rz_analysis_new();

	Sdb *db = xrefs_ref_db();

	bool succ = rz_serialize_analysis_xrefs_load(db, analysis, NULL);
	mu_assert("load success", succ);
	mu_assert_eq(rz_analysis_xrefs_count(analysis), 5, "xrefs count");

	RzList *xrefs = rz_analysis_xrefs_get_from(analysis, 0x1337);
	mu_assert_eq(rz_list_length(xrefs), 2, "xrefs from count");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 0))->from, 0x1337, "xref from");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 0))->to, 4242, "xref to");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 0))->type, RZ_ANALYSIS_XREF_TYPE_NULL, "xref type");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 1))->from, 0x1337, "xref from");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 1))->to, 4243, "xref to");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 1))->type, RZ_ANALYSIS_XREF_TYPE_CODE, "xref type");
	rz_list_free(xrefs);

	xrefs = rz_analysis_xrefs_get_from(analysis, 1234);
	mu_assert_eq(rz_list_length(xrefs), 1, "xrefs from count");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 0))->from, 1234, "xref from");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 0))->to, 4243, "xref to");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 0))->type, RZ_ANALYSIS_XREF_TYPE_CALL, "xref type");
	rz_list_free(xrefs);

	xrefs = rz_analysis_xrefs_get_from(analysis, 42);
	mu_assert_eq(rz_list_length(xrefs), 1, "xrefs from count");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 0))->from, 42, "xref from");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 0))->to, 4321, "xref to");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 0))->type, RZ_ANALYSIS_XREF_TYPE_DATA, "xref type");
	rz_list_free(xrefs);

	xrefs = rz_analysis_xrefs_get_from(analysis, 666);
	mu_assert_eq(rz_list_length(xrefs), 1, "xrefs from count");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 0))->from, 666, "xref from");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 0))->to, 333, "xref to");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 0))->type, RZ_ANALYSIS_XREF_TYPE_STRING, "xref type");
	rz_list_free(xrefs);

	xrefs = rz_analysis_xrefs_get_to(analysis, 4243);
	mu_assert_eq(rz_list_length(xrefs), 2, "xrefs to count");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 0))->from, 1234, "xref from");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 0))->to, 4243, "xref to");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 0))->type, RZ_ANALYSIS_XREF_TYPE_CALL, "xref type");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 1))->from, 0x1337, "xref from");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 1))->to, 4243, "xref to");
	mu_assert_eq(((RzAnalysisXRef *)rz_list_get_n(xrefs, 1))->type, RZ_ANALYSIS_XREF_TYPE_CODE, "xref type");
	rz_list_free(xrefs);

	sdb_free(db);
	rz_analysis_free(analysis);
	mu_end;
}

Sdb *meta_ref_db() {
	Sdb *db = sdb_new0();
	Sdb *spaces_db = sdb_ns(db, "spaces", true);
	sdb_set(spaces_db, "name", "CS", 0);
	sdb_set(spaces_db, "spacestack", "[\"*\"]", 0);
	sdb_set(sdb_ns(spaces_db, "spaces", true), "myspace", "s", 0);
	sdb_set(db, "0x20a0", "[{\"size\":32,\"type\":\"s\",\"subtype\":78,\"str\":\"utf32be\"}]", 0);
	sdb_set(db, "0x20c0", "[{\"size\":32,\"type\":\"s\",\"subtype\":103,\"str\":\"guess\"}]", 0);
	sdb_set(db, "0x1337",
		"[{\"size\":16,\"type\":\"d\"},"
		"{\"size\":17,\"type\":\"c\"},"
		"{\"size\":18,\"type\":\"s\",\"subtype\":56,\"str\":\"some string\"},"
		"{\"size\":19,\"type\":\"f\"},"
		"{\"size\":20,\"type\":\"m\"},"
		"{\"size\":21,\"type\":\"h\"},"
		"{\"type\":\"C\",\"str\":\"some comment here\"},"
		"{\"size\":23,\"type\":\"H\"},"
		"{\"size\":24,\"type\":\"t\"},"
		"{\"type\":\"C\",\"str\":\"comment in space\",\"space\":\"myspace\"}]",
		0);
	sdb_set(db, "0x2000", "[{\"size\":32,\"type\":\"s\",\"subtype\":98,\"str\":\"8bit\"}]", 0);
	sdb_set(db, "0x2040", "[{\"size\":32,\"type\":\"s\",\"subtype\":117,\"str\":\"utf16le\"}]", 0);
	sdb_set(db, "0x2080", "[{\"size\":32,\"type\":\"s\",\"subtype\":110,\"str\":\"utf16be\"}]", 0);
	sdb_set(db, "0x2020", "[{\"size\":32,\"type\":\"s\",\"subtype\":56,\"str\":\"utf8\"}]", 0);
	sdb_set(db, "0x2060", "[{\"size\":32,\"type\":\"s\",\"subtype\":85,\"str\":\"utf32le\"}]", 0);
	return db;
}

bool test_analysis_meta_save() {
	RzAnalysis *analysis = rz_analysis_new();

	rz_meta_set(analysis, RZ_META_TYPE_DATA, 0x1337, 0x10, NULL);
	rz_meta_set(analysis, RZ_META_TYPE_CODE, 0x1337, 0x11, NULL);
	rz_meta_set(analysis, RZ_META_TYPE_STRING, 0x1337, 0x12, "some string");
	rz_meta_set(analysis, RZ_META_TYPE_FORMAT, 0x1337, 0x13, NULL);
	rz_meta_set(analysis, RZ_META_TYPE_MAGIC, 0x1337, 0x14, NULL);
	rz_meta_set(analysis, RZ_META_TYPE_HIDE, 0x1337, 0x15, NULL);
	rz_meta_set(analysis, RZ_META_TYPE_COMMENT, 0x1337, 1, "some comment here");
	rz_meta_set(analysis, RZ_META_TYPE_HIGHLIGHT, 0x1337, 0x17, NULL);
	rz_meta_set(analysis, RZ_META_TYPE_VARTYPE, 0x1337, 0x18, NULL);

	rz_meta_set_with_subtype(analysis, RZ_META_TYPE_STRING, RZ_STRING_ENC_8BIT, 0x2000, 0x20, "8bit");
	rz_meta_set_with_subtype(analysis, RZ_META_TYPE_STRING, RZ_STRING_ENC_UTF8, 0x2020, 0x20, "utf8");
	rz_meta_set_with_subtype(analysis, RZ_META_TYPE_STRING, RZ_STRING_ENC_UTF16LE, 0x2040, 0x20, "utf16le");
	rz_meta_set_with_subtype(analysis, RZ_META_TYPE_STRING, RZ_STRING_ENC_UTF32LE, 0x2060, 0x20, "utf32le");
	rz_meta_set_with_subtype(analysis, RZ_META_TYPE_STRING, RZ_STRING_ENC_UTF16BE, 0x2080, 0x20, "utf16be");
	rz_meta_set_with_subtype(analysis, RZ_META_TYPE_STRING, RZ_STRING_ENC_UTF32BE, 0x20a0, 0x20, "utf32be");
	rz_meta_set_with_subtype(analysis, RZ_META_TYPE_STRING, RZ_STRING_ENC_GUESS, 0x20c0, 0x20, "guess");

	rz_spaces_push(&analysis->meta_spaces, "myspace");
	rz_meta_set(analysis, RZ_META_TYPE_COMMENT, 0x1337, 1, "comment in space");
	rz_spaces_pop(&analysis->meta_spaces);

	Sdb *db = sdb_new0();
	rz_serialize_analysis_meta_save(db, analysis);

	Sdb *expected = meta_ref_db();
	assert_sdb_eq(db, expected, "meta save");
	sdb_free(db);
	sdb_free(expected);
	rz_analysis_free(analysis);
	mu_end;
}

bool test_analysis_meta_load() {
	RzAnalysis *analysis = rz_analysis_new();

	Sdb *db = meta_ref_db();

	bool succ = rz_serialize_analysis_meta_load(db, analysis, NULL);
	mu_assert("load success", succ);

	size_t count = 0;
	RzAnalysisMetaItem *meta;
	RzIntervalTreeIter it;
	rz_interval_tree_foreach (&analysis->meta, it, meta) {
		(void)meta;
		count++;
	}
	mu_assert_eq(count, 17, "meta count");

	ut64 size;
	meta = rz_meta_get_at(analysis, 0x1337, RZ_META_TYPE_DATA, &size);
	mu_assert_notnull(meta, "meta item");
	mu_assert_eq(size, 0x10, "meta item size");
	mu_assert_eq(meta->subtype, 0, "meta item subtype");
	mu_assert_null(meta->str, "meta item string");
	meta = rz_meta_get_at(analysis, 0x1337, RZ_META_TYPE_CODE, &size);
	mu_assert_notnull(meta, "meta item");
	mu_assert_eq(size, 0x11, "meta item size");
	mu_assert_eq(meta->subtype, 0, "meta item subtype");
	mu_assert_null(meta->str, "meta item string");
	meta = rz_meta_get_at(analysis, 0x1337, RZ_META_TYPE_STRING, &size);
	mu_assert_notnull(meta, "meta item");
	mu_assert_eq(size, 0x12, "meta item size");
	mu_assert_eq(meta->subtype, 56, "meta item subtype");
	mu_assert_streq(meta->str, "some string", "meta item string");
	meta = rz_meta_get_at(analysis, 0x1337, RZ_META_TYPE_FORMAT, &size);
	mu_assert_notnull(meta, "meta item");
	mu_assert_eq(size, 0x13, "meta item size");
	mu_assert_eq(meta->subtype, 0, "meta item subtype");
	mu_assert_null(meta->str, "meta item string");
	meta = rz_meta_get_at(analysis, 0x1337, RZ_META_TYPE_MAGIC, &size);
	mu_assert_notnull(meta, "meta item");
	mu_assert_eq(size, 0x14, "meta item size");
	mu_assert_eq(meta->subtype, 0, "meta item subtype");
	mu_assert_null(meta->str, "meta item string");
	meta = rz_meta_get_at(analysis, 0x1337, RZ_META_TYPE_HIDE, &size);
	mu_assert_notnull(meta, "meta item");
	mu_assert_eq(size, 0x15, "meta item size");
	mu_assert_eq(meta->subtype, 0, "meta item subtype");
	mu_assert_null(meta->str, "meta item string");
	meta = rz_meta_get_at(analysis, 0x1337, RZ_META_TYPE_COMMENT, &size);
	mu_assert_notnull(meta, "meta item");
	mu_assert_eq(size, 1, "meta item size");
	mu_assert_eq(meta->subtype, 0, "meta item subtype");
	mu_assert_streq(meta->str, "some comment here", "meta item string");
	meta = rz_meta_get_at(analysis, 0x1337, RZ_META_TYPE_HIGHLIGHT, &size);
	mu_assert_notnull(meta, "meta item");
	mu_assert_eq(size, 0x17, "meta item size");
	mu_assert_eq(meta->subtype, 0, "meta item subtype");
	mu_assert_null(meta->str, "meta item string");
	meta = rz_meta_get_at(analysis, 0x1337, RZ_META_TYPE_VARTYPE, &size);
	mu_assert_notnull(meta, "meta item");
	mu_assert_eq(size, 0x18, "meta item size");
	mu_assert_eq(meta->subtype, 0, "meta item subtype");
	mu_assert_null(meta->str, "meta item string");

	rz_spaces_push(&analysis->meta_spaces, "myspace");
	meta = rz_meta_get_at(analysis, 0x1337, RZ_META_TYPE_COMMENT, &size);
	mu_assert_notnull(meta, "meta item");
	mu_assert_eq(size, 1, "meta item size");
	mu_assert_eq(meta->subtype, 0, "meta item subtype");
	mu_assert_streq(meta->str, "comment in space", "meta item string");
	rz_spaces_pop(&analysis->meta_spaces);

	meta = rz_meta_get_at(analysis, 0x2000, RZ_META_TYPE_STRING, &size);
	mu_assert_notnull(meta, "meta item");
	mu_assert_eq(size, 0x20, "meta item size");
	mu_assert_eq(meta->subtype, RZ_STRING_ENC_8BIT, "meta item subtype");
	mu_assert_streq(meta->str, "8bit", "meta item string");
	meta = rz_meta_get_at(analysis, 0x2020, RZ_META_TYPE_STRING, &size);
	mu_assert_notnull(meta, "meta item");
	mu_assert_eq(size, 0x20, "meta item size");
	mu_assert_eq(meta->subtype, RZ_STRING_ENC_UTF8, "meta item subtype");
	mu_assert_streq(meta->str, "utf8", "meta item string");
	meta = rz_meta_get_at(analysis, 0x2040, RZ_META_TYPE_STRING, &size);
	mu_assert_notnull(meta, "meta item");
	mu_assert_eq(size, 0x20, "meta item size");
	mu_assert_eq(meta->subtype, RZ_STRING_ENC_UTF16LE, "meta item subtype");
	mu_assert_streq(meta->str, "utf16le", "meta item string");
	meta = rz_meta_get_at(analysis, 0x2060, RZ_META_TYPE_STRING, &size);
	mu_assert_notnull(meta, "meta item");
	mu_assert_eq(size, 0x20, "meta item size");
	mu_assert_eq(meta->subtype, RZ_STRING_ENC_UTF32LE, "meta item subtype");
	mu_assert_streq(meta->str, "utf32le", "meta item string");
	meta = rz_meta_get_at(analysis, 0x2080, RZ_META_TYPE_STRING, &size);
	mu_assert_notnull(meta, "meta item");
	mu_assert_eq(size, 0x20, "meta item size");
	mu_assert_eq(meta->subtype, RZ_STRING_ENC_UTF16BE, "meta item subtype");
	mu_assert_streq(meta->str, "utf16be", "meta item string");
	meta = rz_meta_get_at(analysis, 0x20a0, RZ_META_TYPE_STRING, &size);
	mu_assert_notnull(meta, "meta item");
	mu_assert_eq(size, 0x20, "meta item size");
	mu_assert_eq(meta->subtype, RZ_STRING_ENC_UTF32BE, "meta item subtype");
	mu_assert_streq(meta->str, "utf32be", "meta item string");
	meta = rz_meta_get_at(analysis, 0x20c0, RZ_META_TYPE_STRING, &size);
	mu_assert_notnull(meta, "meta item");
	mu_assert_eq(size, 0x20, "meta item size");
	mu_assert_eq(meta->subtype, RZ_STRING_ENC_GUESS, "meta item subtype");
	mu_assert_streq(meta->str, "guess", "meta item string");

	sdb_free(db);
	rz_analysis_free(analysis);
	mu_end;
}

Sdb *hints_ref_db() {
	Sdb *db = sdb_new0();
	sdb_set(db, "0x1000", "{\"optype\":-2147483648}", 0);
	sdb_set(db, "0x1001", "{\"optype\":1073741824}", 0);
	sdb_set(db, "0x1002", "{\"optype\":536870912}", 0);
	sdb_set(db, "0x1003", "{\"optype\":268435456}", 0);
	sdb_set(db, "0x1004", "{\"optype\":134217728}", 0);
	sdb_set(db, "0x1005", "{\"optype\":0}", 0);
	sdb_set(db, "0x1006", "{\"optype\":1}", 0);
	sdb_set(db, "0x1007", "{\"optype\":2}", 0);
	sdb_set(db, "0x1008", "{\"optype\":268435458}", 0);
	sdb_set(db, "0x1009", "{\"optype\":134217730}", 0);
	sdb_set(db, "0x100a", "{\"optype\":402653186}", 0);
	sdb_set(db, "0x100b", "{\"optype\":-2147483647}", 0);
	sdb_set(db, "0x100c", "{\"optype\":-1879048191}", 0);
	sdb_set(db, "0x100d", "{\"optype\":536870913}", 0);
	sdb_set(db, "0x100e", "{\"optype\":-1610612735}", 0);
	sdb_set(db, "0x100f", "{\"optype\":-2147483646}", 0);
	sdb_set(db, "0x1010", "{\"optype\":3}", 0);
	sdb_set(db, "0x1011", "{\"optype\":4}", 0);
	sdb_set(db, "0x1012", "{\"optype\":268435460}", 0);
	sdb_set(db, "0x1013", "{\"optype\":134217732}", 0);
	sdb_set(db, "0x1014", "{\"optype\":402653188}", 0);
	sdb_set(db, "0x1015", "{\"optype\":-2147483645}", 0);
	sdb_set(db, "0x1016", "{\"optype\":-2147483644}", 0);
	sdb_set(db, "0x1017", "{\"optype\":5}", 0);
	sdb_set(db, "0x1018", "{\"optype\":-2147483643}", 0);
	sdb_set(db, "0x1019", "{\"optype\":6}", 0);
	sdb_set(db, "0x101a", "{\"optype\":7}", 0);
	sdb_set(db, "0x101b", "{\"optype\":8}", 0);
	sdb_set(db, "0x101c", "{\"optype\":9}", 0);
	sdb_set(db, "0x101d", "{\"optype\":-2147483639}", 0);
	sdb_set(db, "0x101e", "{\"optype\":10}", 0);
	sdb_set(db, "0x101f", "{\"optype\":11}", 0);
	sdb_set(db, "0x1020", "{\"optype\":-2147483637}", 0);
	sdb_set(db, "0x1021", "{\"optype\":12}", 0);
	sdb_set(db, "0x1022", "{\"optype\":268435468}", 0);
	sdb_set(db, "0x1023", "{\"optype\":13}", 0);
	sdb_set(db, "0x1024", "{\"optype\":14}", 0);
	sdb_set(db, "0x1025", "{\"optype\":15}", 0);
	sdb_set(db, "0x1026", "{\"optype\":16}", 0);
	sdb_set(db, "0x1027", "{\"optype\":17}", 0);
	sdb_set(db, "0x1028", "{\"optype\":18}", 0);
	sdb_set(db, "0x1029", "{\"optype\":19}", 0);
	sdb_set(db, "0x102a", "{\"optype\":20}", 0);
	sdb_set(db, "0x102b", "{\"optype\":21}", 0);
	sdb_set(db, "0x102c", "{\"optype\":22}", 0);
	sdb_set(db, "0x102d", "{\"optype\":23}", 0);
	sdb_set(db, "0x102e", "{\"optype\":24}", 0);
	sdb_set(db, "0x102f", "{\"optype\":25}", 0);
	sdb_set(db, "0x1030", "{\"optype\":26}", 0);
	sdb_set(db, "0x1031", "{\"optype\":27}", 0);
	sdb_set(db, "0x1032", "{\"optype\":28}", 0);
	sdb_set(db, "0x1033", "{\"optype\":29}", 0);
	sdb_set(db, "0x1034", "{\"optype\":30}", 0);
	sdb_set(db, "0x1035", "{\"optype\":31}", 0);
	sdb_set(db, "0x1036", "{\"optype\":32}", 0);
	sdb_set(db, "0x1037", "{\"optype\":33}", 0);
	sdb_set(db, "0x1038", "{\"optype\":34}", 0);
	sdb_set(db, "0x1039", "{\"optype\":35}", 0);
	sdb_set(db, "0x103a", "{\"optype\":36}", 0);
	sdb_set(db, "0x103b", "{\"optype\":37}", 0);
	sdb_set(db, "0x103c", "{\"optype\":38}", 0);
	sdb_set(db, "0x103d", "{\"optype\":39}", 0);
	sdb_set(db, "0x103e", "{\"optype\":40}", 0);
	sdb_set(db, "0x103f", "{\"optype\":41}", 0);
	sdb_set(db, "0x1040", "{\"optype\":42}", 0);
	sdb_set(db, "0x1041", "{\"optype\":43}", 0);
	sdb_set(db, "0x1042", "{\"optype\":44}", 0);
	sdb_set(db, "0x1043", "{\"optype\":45}", 0);
	sdb_set(db, "0x1044", "{\"optype\":46}", 0);
	sdb_set(db, "0x1045", "{\"optype\":47}", 0);
	sdb_set(db, "0x100", "{\"arch\":\"arm\",\"bits\":16}", 0);
	sdb_set(db, "0x120", "{\"arch\":null}", 0);
	sdb_set(db, "0x130", "{\"bits\":0}", 0);
	sdb_set(db, "0x200", "{\"immbase\":10}", 0);
	sdb_set(db, "0x210", "{\"jump\":1337,\"fail\":1234}", 0);
	sdb_set(db, "0x220", "{\"syntax\":\"intel\"}", 0);
	sdb_set(db, "0x230", "{\"frame\":48}", 0);
	sdb_set(db, "0x240", "{\"ptr\":4321}", 0);
	sdb_set(db, "0x250", "{\"nword\":3}", 0);
	sdb_set(db, "0x260", "{\"ret\":666}", 0);
	sdb_set(db, "0x270", "{\"newbits\":32}", 0);
	sdb_set(db, "0x280", "{\"size\":7}", 0);
	sdb_set(db, "0x290", "{\"opcode\":\"mov\"}", 0);
	sdb_set(db, "0x2a0", "{\"toff\":\"sometype\"}", 0);
	sdb_set(db, "0x2b0", "{\"esil\":\"13,29,+\"}", 0);
	sdb_set(db, "0x2c0", "{\"high\":true}", 0);
	sdb_set(db, "0x2d0", "{\"val\":54323}", 0);
	return db;
}

// All of these optypes need to be correctly loaded from potentially older projects
// So changing anything here will require a migration pass!
static int all_optypes[] = {
	RZ_ANALYSIS_OP_TYPE_COND, RZ_ANALYSIS_OP_TYPE_REP, RZ_ANALYSIS_OP_TYPE_MEM, RZ_ANALYSIS_OP_TYPE_REG, RZ_ANALYSIS_OP_TYPE_IND,
	RZ_ANALYSIS_OP_TYPE_NULL, RZ_ANALYSIS_OP_TYPE_JMP, RZ_ANALYSIS_OP_TYPE_UJMP, RZ_ANALYSIS_OP_TYPE_RJMP, RZ_ANALYSIS_OP_TYPE_IJMP,
	RZ_ANALYSIS_OP_TYPE_IRJMP, RZ_ANALYSIS_OP_TYPE_CJMP, RZ_ANALYSIS_OP_TYPE_RCJMP, RZ_ANALYSIS_OP_TYPE_MJMP, RZ_ANALYSIS_OP_TYPE_MCJMP,
	RZ_ANALYSIS_OP_TYPE_UCJMP, RZ_ANALYSIS_OP_TYPE_CALL, RZ_ANALYSIS_OP_TYPE_UCALL, RZ_ANALYSIS_OP_TYPE_RCALL, RZ_ANALYSIS_OP_TYPE_ICALL,
	RZ_ANALYSIS_OP_TYPE_IRCALL, RZ_ANALYSIS_OP_TYPE_CCALL, RZ_ANALYSIS_OP_TYPE_UCCALL, RZ_ANALYSIS_OP_TYPE_RET, RZ_ANALYSIS_OP_TYPE_CRET,
	RZ_ANALYSIS_OP_TYPE_ILL, RZ_ANALYSIS_OP_TYPE_UNK, RZ_ANALYSIS_OP_TYPE_NOP, RZ_ANALYSIS_OP_TYPE_MOV, RZ_ANALYSIS_OP_TYPE_CMOV,
	RZ_ANALYSIS_OP_TYPE_TRAP, RZ_ANALYSIS_OP_TYPE_SWI, RZ_ANALYSIS_OP_TYPE_CSWI, RZ_ANALYSIS_OP_TYPE_UPUSH, RZ_ANALYSIS_OP_TYPE_RPUSH,
	RZ_ANALYSIS_OP_TYPE_PUSH, RZ_ANALYSIS_OP_TYPE_POP, RZ_ANALYSIS_OP_TYPE_CMP, RZ_ANALYSIS_OP_TYPE_ACMP, RZ_ANALYSIS_OP_TYPE_ADD,
	RZ_ANALYSIS_OP_TYPE_SUB, RZ_ANALYSIS_OP_TYPE_IO, RZ_ANALYSIS_OP_TYPE_MUL, RZ_ANALYSIS_OP_TYPE_DIV, RZ_ANALYSIS_OP_TYPE_SHR,
	RZ_ANALYSIS_OP_TYPE_SHL, RZ_ANALYSIS_OP_TYPE_SAL, RZ_ANALYSIS_OP_TYPE_SAR, RZ_ANALYSIS_OP_TYPE_OR, RZ_ANALYSIS_OP_TYPE_AND,
	RZ_ANALYSIS_OP_TYPE_XOR, RZ_ANALYSIS_OP_TYPE_NOR, RZ_ANALYSIS_OP_TYPE_NOT, RZ_ANALYSIS_OP_TYPE_STORE, RZ_ANALYSIS_OP_TYPE_LOAD,
	RZ_ANALYSIS_OP_TYPE_LEA, RZ_ANALYSIS_OP_TYPE_LEAVE, RZ_ANALYSIS_OP_TYPE_ROR, RZ_ANALYSIS_OP_TYPE_ROL, RZ_ANALYSIS_OP_TYPE_XCHG,
	RZ_ANALYSIS_OP_TYPE_MOD, RZ_ANALYSIS_OP_TYPE_SWITCH, RZ_ANALYSIS_OP_TYPE_CASE, RZ_ANALYSIS_OP_TYPE_LENGTH, RZ_ANALYSIS_OP_TYPE_CAST,
	RZ_ANALYSIS_OP_TYPE_NEW, RZ_ANALYSIS_OP_TYPE_ABS, RZ_ANALYSIS_OP_TYPE_CPL, RZ_ANALYSIS_OP_TYPE_CRYPTO, RZ_ANALYSIS_OP_TYPE_SYNC
};

#define ALL_OPTYPES_COUNT (sizeof(all_optypes) / sizeof(int))

bool test_analysis_hints_save() {
	RzAnalysis *analysis = rz_analysis_new();

	rz_analysis_hint_set_arch(analysis, 0x100, "arm");
	rz_analysis_hint_set_bits(analysis, 0x100, 16);
	rz_analysis_hint_set_arch(analysis, 0x120, NULL);
	rz_analysis_hint_set_bits(analysis, 0x130, 0);

	rz_analysis_hint_set_immbase(analysis, 0x200, 10);
	rz_analysis_hint_set_jump(analysis, 0x210, 1337);
	rz_analysis_hint_set_fail(analysis, 0x210, 1234);
	rz_analysis_hint_set_stackframe(analysis, 0x230, 0x30);
	rz_analysis_hint_set_pointer(analysis, 0x240, 4321);
	rz_analysis_hint_set_nword(analysis, 0x250, 3);
	rz_analysis_hint_set_ret(analysis, 0x260, 666);
	rz_analysis_hint_set_newbits(analysis, 0x270, 32);
	rz_analysis_hint_set_size(analysis, 0x280, 7);
	rz_analysis_hint_set_syntax(analysis, 0x220, "intel");
	rz_analysis_hint_set_opcode(analysis, 0x290, "mov");
	rz_analysis_hint_set_offset(analysis, 0x2a0, "sometype");
	rz_analysis_hint_set_esil(analysis, 0x2b0, "13,29,+");
	rz_analysis_hint_set_high(analysis, 0x2c0);
	rz_analysis_hint_set_val(analysis, 0x2d0, 54323);

	size_t i;
	for (i = 0; i < ALL_OPTYPES_COUNT; i++) {
		rz_analysis_hint_set_type(analysis, 0x1000 + i, all_optypes[i]);
	}

	Sdb *db = sdb_new0();
	rz_serialize_analysis_hints_save(db, analysis);

	Sdb *expected = hints_ref_db();
	assert_sdb_eq(db, expected, "hints save");
	sdb_free(db);
	sdb_free(expected);
	rz_analysis_free(analysis);
	mu_end;
}

static bool addr_hints_count_cb(ut64 addr, const RzVector /*<const RzAnalysisAddrHintRecord>*/ *records, void *user) {
	(*(size_t *)user) += records->len;
	return true;
}

static bool arch_hints_count_cb(ut64 addr, RZ_NULLABLE const char *arch, void *user) {
	(*(size_t *)user)++;
	return true;
}

static bool bits_hints_count_cb(ut64 addr, int bits, void *user) {
	(*(size_t *)user)++;
	return true;
}

bool test_analysis_hints_load() {
	RzAnalysis *analysis = rz_analysis_new();

	Sdb *db = hints_ref_db();

	bool succ = rz_serialize_analysis_hints_load(db, analysis, NULL);
	mu_assert("load success", succ);

	size_t count = 0;
	rz_analysis_addr_hints_foreach(analysis, addr_hints_count_cb, &count);
	rz_analysis_arch_hints_foreach(analysis, arch_hints_count_cb, &count);
	rz_analysis_bits_hints_foreach(analysis, bits_hints_count_cb, &count);
	mu_assert_eq(count, 19 + ALL_OPTYPES_COUNT, "hints count");

	ut64 addr;
	const char *arch = rz_analysis_hint_arch_at(analysis, 0x100, &addr);
	mu_assert_streq(arch, "arm", "arch hint");
	mu_assert_eq(addr, 0x100, "arch hint addr");
	int bits = rz_analysis_hint_bits_at(analysis, 0x100, &addr);
	mu_assert_eq(bits, 16, "bits hint");
	mu_assert_eq(addr, 0x100, "bits hint addr");
	arch = rz_analysis_hint_arch_at(analysis, 0x120, &addr);
	mu_assert_null(arch, "arch hint");
	mu_assert_eq(addr, 0x120, "arch hint addr");
	bits = rz_analysis_hint_bits_at(analysis, 0x100, &addr);
	mu_assert_eq(bits, 16, "bits hint");
	mu_assert_eq(addr, 0x100, "bits hint addr");

#define assert_addr_hint(addr, tp, check) \
	do { \
		const RzVector /*<const RzAnalysisAddrHintRecord>*/ *hints = rz_analysis_addr_hints_at(analysis, addr); \
		const RzAnalysisAddrHintRecord *record; \
		bool found = false; \
		rz_vector_foreach(hints, record) { \
			if (record->type == RZ_ANALYSIS_ADDR_HINT_TYPE_##tp) { \
				check; \
				found = true; \
				break; \
			} \
		} \
		mu_assert("addr hint", found); \
	} while (0)

	assert_addr_hint(0x200, IMMBASE, mu_assert_eq(record->immbase, 10, "immbase hint"));
	assert_addr_hint(0x210, JUMP, mu_assert_eq(record->jump, 1337, "jump hint"));
	assert_addr_hint(0x210, FAIL, mu_assert_eq(record->fail, 1234, "fail hint"));
	assert_addr_hint(0x230, STACKFRAME, mu_assert_eq(record->stackframe, 0x30, "stackframe hint"));
	assert_addr_hint(0x240, PTR, mu_assert_eq(record->ptr, 4321, "ptr hint"));
	assert_addr_hint(0x250, NWORD, mu_assert_eq(record->nword, 3, "nword hint"));
	assert_addr_hint(0x260, RET, mu_assert_eq(record->retval, 666, "ret hint"));
	assert_addr_hint(0x270, NEW_BITS, mu_assert_eq(record->newbits, 32, "newbits hint"));
	assert_addr_hint(0x280, SIZE, mu_assert_eq(record->size, 7, "size hint"));
	assert_addr_hint(0x220, SYNTAX, mu_assert_streq(record->syntax, "intel", "syntax hint"));
	assert_addr_hint(0x290, OPCODE, mu_assert_streq(record->opcode, "mov", "opcode hint"));
	assert_addr_hint(0x2a0, TYPE_OFFSET, mu_assert_streq(record->type_offset, "sometype", "type offset hint"));
	assert_addr_hint(0x2b0, ESIL, mu_assert_streq(record->esil, "13,29,+", "esil hint"));
	assert_addr_hint(0x2c0, HIGH, );
	assert_addr_hint(0x2d0, VAL, mu_assert_eq(record->val, 54323, "val hint"));

	size_t i;
	for (i = 0; i < ALL_OPTYPES_COUNT; i++) {
		assert_addr_hint(0x1000 + i, OPTYPE, mu_assert_eq(record->optype, all_optypes[i], "optype hint"));
	}

	sdb_free(db);
	rz_analysis_free(analysis);
	mu_end;
}

Sdb *classes_ref_db() {
	Sdb *db = sdb_new0();
	sdb_set(db, "Aeropause", "c", 0);
	sdb_set(db, "Bright", "c", 0);
	Sdb *attrs_db = sdb_ns(db, "attrs", true);
	sdb_set(attrs_db, "attrtypes.Bright", "base", 0);
	sdb_set(attrs_db, "attr.Aeropause.vtable.0", "0x1000,4,80", 0);
	sdb_set(attrs_db, "attrtypes.Aeropause", "method,vtable", 0);
	sdb_set(attrs_db, "attr.Aeropause.method", "some_meth,some_other_meth", 0);
	sdb_set(attrs_db, "attr.Bright.base", "0", 0);
	sdb_set(attrs_db, "attr.Aeropause.vtable", "0", 0);
	sdb_set(attrs_db, "attr.Bright.base.0", "Aeropause,8", 0);
	sdb_set(attrs_db, "attr.Aeropause.method.some_meth", "4919,42,0,some_meth", 0);
	sdb_set(attrs_db, "attr.Aeropause.method.some_other_meth", "4660,32,0,some_other_meth", 0);
	return db;
}

bool test_analysis_classes_save() {
	RzAnalysis *analysis = rz_analysis_new();

	rz_analysis_class_create(analysis, "Aeropause");
	RzAnalysisMethod crystal = {
		.name = strdup("some_meth"),
		.addr = 0x1337,
		.vtable_offset = 42,
		.method_type = RZ_ANALYSIS_CLASS_METHOD_DEFAULT,
		.real_name = strdup("some_meth")
	};
	rz_analysis_class_method_set(analysis, "Aeropause", &crystal);
	rz_analysis_class_method_fini(&crystal);

	RzAnalysisMethod meth = {
		.name = strdup("some_other_meth"),
		.addr = 0x1234,
		.vtable_offset = 0x20,
		.method_type = RZ_ANALYSIS_CLASS_METHOD_DEFAULT,
		.real_name = strdup("some_other_meth")
	};
	rz_analysis_class_method_set(analysis, "Aeropause", &meth);
	rz_analysis_class_method_fini(&meth);

	rz_analysis_class_create(analysis, "Bright");
	RzAnalysisBaseClass base = {
		.id = NULL,
		.offset = 8,
		.class_name = strdup("Aeropause")
	};
	rz_analysis_class_base_set(analysis, "Bright", &base);
	rz_analysis_class_base_fini(&base);

	RzAnalysisVTable vt = {
		.id = NULL,
		.offset = 4,
		.addr = 0x1000,
		.size = 0x50
	};
	rz_analysis_class_vtable_set(analysis, "Aeropause", &vt);
	rz_analysis_class_vtable_fini(&vt);

	Sdb *db = sdb_new0();
	rz_serialize_analysis_classes_save(db, analysis);

	Sdb *expected = classes_ref_db();
	assert_sdb_eq(db, expected, "classes save");
	sdb_free(db);
	sdb_free(expected);
	rz_analysis_free(analysis);
	mu_end;
}

bool test_analysis_classes_load() {
	RzAnalysis *analysis = rz_analysis_new();
	Sdb *db = classes_ref_db();
	bool succ = rz_serialize_analysis_classes_load(db, analysis, NULL);
	sdb_free(db);
	mu_assert("load success", succ);

	SdbList *classes = rz_analysis_class_get_all(analysis, true);
	mu_assert_eq(classes->length, 2, "classes count");
	SdbListIter *iter = ls_head(classes);
	SdbKv *kv = ls_iter_get(iter);
	mu_assert_streq(sdbkv_key(kv), "Aeropause", "class");
	kv = ls_iter_get(iter);
	mu_assert_streq(sdbkv_key(kv), "Bright", "class");
	ls_free(classes);

	RzVector *vals = rz_analysis_class_method_get_all(analysis, "Aeropause");
	mu_assert_eq(vals->len, 2, "method count");
	RzAnalysisMethod *meth = rz_vector_index_ptr(vals, 0);
	mu_assert_streq(meth->name, "some_meth", "method name");
	mu_assert_eq(meth->addr, 0x1337, "method addr");
	mu_assert_eq(meth->vtable_offset, 42, "method vtable offset");
	meth = rz_vector_index_ptr(vals, 1);
	mu_assert_streq(meth->name, "some_other_meth", "method name");
	mu_assert_eq(meth->addr, 0x1234, "method addr");
	mu_assert_eq(meth->vtable_offset, 0x20, "method vtable offset");
	rz_vector_free(vals);

	vals = rz_analysis_class_base_get_all(analysis, "Aeropause");
	mu_assert_eq(vals->len, 0, "base count");
	rz_vector_free(vals);

	vals = rz_analysis_class_vtable_get_all(analysis, "Aeropause");
	mu_assert_eq(vals->len, 1, "vtable count");
	RzAnalysisVTable *vt = rz_vector_index_ptr(vals, 0);
	mu_assert_eq(vt->offset, 4, "vtable offset");
	mu_assert_eq(vt->addr, 0x1000, "vtable addr");
	mu_assert_eq(vt->size, 0x50, "vtable size");
	rz_vector_free(vals);

	vals = rz_analysis_class_method_get_all(analysis, "Bright");
	mu_assert_eq(vals->len, 0, "method count");
	rz_vector_free(vals);

	vals = rz_analysis_class_base_get_all(analysis, "Bright");
	mu_assert_eq(vals->len, 1, "base count");
	RzAnalysisBaseClass *base = rz_vector_index_ptr(vals, 0);
	mu_assert_eq(base->offset, 8, "base class offset");
	mu_assert_streq(base->class_name, "Aeropause", "base class name");
	rz_vector_free(vals);

	vals = rz_analysis_class_vtable_get_all(analysis, "Bright");
	mu_assert_eq(vals->len, 0, "vtable count");
	rz_vector_free(vals);

	rz_analysis_free(analysis);
	mu_end;
}

static Sdb *cc_ref_db() {
	Sdb *db = sdb_new0();
	sdb_set(db, "cc.sectarian.ret", "rax", 0);
	sdb_set(db, "cc.sectarian.self", "rsi", 0);
	sdb_set(db, "cc.sectarian.error", "rdi", 0);
	sdb_set(db, "cc.sectarian.arg1", "rcx", 0);
	sdb_set(db, "cc.sectarian.arg0", "rdx", 0);
	sdb_set(db, "cc.sectarian.argn", "stack", 0);
	sdb_set(db, "cc.sectarian.maxargs", "2", 0);
	sdb_set(db, "sectarian", "cc", 0);
	return db;
}

bool test_analysis_cc_save() {
	RzAnalysis *analysis = rz_analysis_new();

	rz_analysis_cc_set(analysis, "rax sectarian(rdx, rcx, stack)");
	rz_analysis_cc_set_self(analysis, "sectarian", "rsi");
	rz_analysis_cc_set_error(analysis, "sectarian", "rdi");

	Sdb *db = sdb_new0();
	rz_serialize_analysis_cc_save(db, analysis);

	Sdb *expected = cc_ref_db();
	assert_sdb_eq(db, expected, "cc save");
	sdb_free(db);
	sdb_free(expected);
	rz_analysis_free(analysis);
	mu_end;
}

bool test_analysis_cc_load() {
	RzAnalysis *analysis = rz_analysis_new();
	Sdb *db = cc_ref_db();
	bool succ = rz_serialize_analysis_cc_load(db, analysis, NULL);
	sdb_free(db);
	mu_assert("load success", succ);

	char *v = rz_analysis_cc_get(analysis, "sectarian");
	mu_assert_streq(v, "rax rsi.sectarian (rdx, rcx, stack) rdi;", "get cc");
	free(v);
	const char *vv = rz_analysis_cc_self(analysis, "sectarian");
	mu_assert_streq(vv, "rsi", "get self");
	vv = rz_analysis_cc_error(analysis, "sectarian");
	mu_assert_streq(vv, "rdi", "get error");

	rz_analysis_free(analysis);
	mu_end;
}

Sdb *analysis_ref_db() {
	Sdb *db = sdb_new0();

	Sdb *blocks = sdb_ns(db, "blocks", true);
	sdb_set(blocks, "0x4d2", "{\"size\":32}", 0);
	sdb_set(blocks, "0x539", "{\"size\":42}", 0);

	Sdb *functions = sdb_ns(db, "functions", true);
	sdb_set(functions, "0x4d2", "{\"name\":\"effekt\",\"bits\":32,\"type\":1,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"bbs\":[1337]}", 0);
	sdb_set(functions, "0x539", "{\"name\":\"hirsch\",\"bits\":32,\"type\":0,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"bbs\":[1337,1234]}", 0);

	Sdb *noret = sdb_ns(db, "noreturn", true);
	sdb_bool_set(noret, "addr.800800.noreturn", true, 0);

	Sdb *xrefs = sdb_ns(db, "xrefs", true);
	sdb_set(xrefs, "0x42", "[{\"to\":1337,\"type\":\"C\"}]", 0);
	sdb_set(xrefs, "0x539", "[{\"to\":12648430,\"type\":\"d\"}]", 0);

	Sdb *meta = sdb_ns(db, "meta", true);
	Sdb *meta_spaces = sdb_ns(meta, "spaces", true);
	sdb_ns(meta_spaces, "spaces", true);
	sdb_set(meta_spaces, "spacestack", "[\"*\"]", 0);
	sdb_set(meta_spaces, "name", "CS", 0);
	sdb_set(meta, "0x1337", "[{\"type\":\"C\",\"subtype\":56,\"str\":\"some comment\"}]", 0);

	Sdb *hints = sdb_ns(db, "hints", true);
	sdb_set(hints, "0x10e1", "{\"arch\":\"arm\"}", 0);

	Sdb *classes = sdb_ns(db, "classes", true);
	sdb_set(classes, "Aeropause", "c", 0);
	Sdb *class_attrs = sdb_ns(classes, "attrs", true);
	sdb_set(class_attrs, "attrtypes.Aeropause", "method", 0);
	sdb_set(class_attrs, "attr.Aeropause.method", "some_meth", 0);
	sdb_set(class_attrs, "attr.Aeropause.method.some_meth", "4919,42,0,some_meth", 0);

	Sdb *imports = sdb_ns(db, "imports", true);
	sdb_set(imports, "pigs", "i", 0);
	sdb_set(imports, "dogs", "i", 0);
	sdb_set(imports, "sheep", "i", 0);

	Sdb *cc = sdb_ns(db, "cc", true);
	sdb_set(cc, "cc.sectarian.ret", "rax", 0);
	sdb_set(cc, "cc.sectarian.arg1", "rcx", 0);
	sdb_set(cc, "cc.sectarian.arg0", "rdx", 0);
	sdb_set(cc, "cc.sectarian.argn", "stack", 0);
	sdb_set(cc, "cc.sectarian.maxargs", "2", 0);
	sdb_set(cc, "sectarian", "cc", 0);

	sdb_ns(db, "types", true);
	sdb_ns(db, "callables", true);
	sdb_ns(db, "typelinks", true);
	sdb_ns(db, "vars", true);

	return db;
}

bool test_analysis_save() {
	RzAnalysis *analysis = rz_analysis_new();

	RzAnalysisBlock *ba = rz_analysis_create_block(analysis, 1337, 42);
	RzAnalysisBlock *bb = rz_analysis_create_block(analysis, 1234, 32);

	RzAnalysisFunction *f = rz_analysis_create_function(analysis, "hirsch", 1337, RZ_ANALYSIS_FCN_TYPE_NULL);
	rz_analysis_function_add_block(f, ba);
	rz_analysis_function_add_block(f, bb);

	f = rz_analysis_create_function(analysis, "effekt", 1234, RZ_ANALYSIS_FCN_TYPE_FCN);
	rz_analysis_function_add_block(f, ba);

	rz_analysis_block_unref(ba);
	rz_analysis_block_unref(bb);

	rz_analysis_noreturn_add(analysis, NULL, 0x800800);

	rz_analysis_xrefs_set(analysis, 0x42, 1337, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 1337, 0xc0ffee, RZ_ANALYSIS_XREF_TYPE_DATA);

	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, 0x1337, "some comment");

	rz_analysis_hint_set_arch(analysis, 4321, "arm");

	rz_analysis_class_create(analysis, "Aeropause");
	RzAnalysisMethod crystal = {
		.name = strdup("some_meth"),
		.addr = 0x1337,
		.vtable_offset = 42,
		.method_type = RZ_ANALYSIS_CLASS_METHOD_DEFAULT,
		.real_name = strdup("some_meth")
	};
	rz_analysis_class_method_set(analysis, "Aeropause", &crystal);
	rz_analysis_class_method_fini(&crystal);

	rz_analysis_add_import(analysis, "pigs");
	rz_analysis_add_import(analysis, "dogs");
	rz_analysis_add_import(analysis, "sheep");

	rz_analysis_cc_set(analysis, "rax sectarian(rdx, rcx, stack)");

	Sdb *db = sdb_new0();
	rz_serialize_analysis_save(db, analysis);

	// Remove `types` namespace first
	sdb_ns_unset(db, "types", NULL);
	sdb_ns(db, "types", true);
	sdb_ns(db, "callables", true);
	sdb_ns(db, "typelinks", true);

	Sdb *expected = analysis_ref_db();
	assert_sdb_eq(db, expected, "analysis save");
	sdb_free(db);
	sdb_free(expected);
	rz_analysis_free(analysis);
	mu_end;
}

bool test_analysis_load() {
	RzAnalysis *analysis = rz_analysis_new();

	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(analysis->typedb, types_dir, "x86", 64, "linux");

	Sdb *db = analysis_ref_db();
	bool succ = rz_serialize_analysis_load(db, analysis, NULL);
	sdb_free(db);
	mu_assert("load success", succ);

	// all tested in detail by dedicated tests, we only check here
	// if the things are loaded at all when loading a whole analysis.
	size_t blocks_count = 0;
	RBIter iter;
	RzAnalysisBlock *block;
	rz_rbtree_foreach (analysis->bb_tree, iter, block, RzAnalysisBlock, _rb) {
		(void)block;
		blocks_count++;
	}

	mu_assert_eq(blocks_count, 2, "blocks loaded");
	mu_assert_eq(rz_pvector_len(analysis->fcns), 2, "functions loaded");
	mu_assert_eq(rz_analysis_xrefs_count(analysis), 2, "xrefs loaded");

	const char *cmt = rz_meta_get_string(analysis, RZ_META_TYPE_COMMENT, 0x1337);
	mu_assert_streq(cmt, "some comment", "meta");

	const char *hint = rz_analysis_hint_arch_at(analysis, 4321, NULL);
	mu_assert_streq(hint, "arm", "hint");

	SdbList *classes = rz_analysis_class_get_all(analysis, true);
	mu_assert_eq(classes->length, 1, "classes count");
	SdbListIter *siter = ls_head(classes);
	SdbKv *kv = ls_iter_get(siter);
	mu_assert_streq(sdbkv_key(kv), "Aeropause", "class");
	ls_free(classes);
	RzVector *vals = rz_analysis_class_method_get_all(analysis, "Aeropause");
	mu_assert_eq(vals->len, 1, "method count");
	RzAnalysisMethod *meth = rz_vector_index_ptr(vals, 0);
	mu_assert_streq(meth->name, "some_meth", "method name");
	rz_vector_free(vals);

	mu_assert_eq(rz_list_length(analysis->imports), 3, "imports count");
	mu_assert_notnull(rz_list_find(analysis->imports, "pigs", (RzListComparator)strcmp, NULL), "import");
	mu_assert_notnull(rz_list_find(analysis->imports, "dogs", (RzListComparator)strcmp, NULL), "import");
	mu_assert_notnull(rz_list_find(analysis->imports, "sheep", (RzListComparator)strcmp, NULL), "import");

	char *cc = rz_analysis_cc_get(analysis, "sectarian");
	mu_assert_streq(cc, "rax sectarian (rdx, rcx, stack);", "get cc");
	free(cc);

	rz_analysis_free(analysis);
	mu_end;
}

int all_tests() {
	mu_run_test(test_analysis_switch_op_save);
	mu_run_test(test_analysis_switch_op_load);
	mu_run_test(test_analysis_block_save);
	mu_run_test(test_analysis_block_load);
	mu_run_test(test_analysis_function_save);
	mu_run_test(test_analysis_function_load);
	mu_run_test(test_analysis_function_noreturn_save);
	mu_run_test(test_analysis_function_noreturn_load);
	mu_run_test(test_analysis_var_save);
	mu_run_test(test_analysis_var_load);
	mu_run_test(test_analysis_xrefs_save);
	mu_run_test(test_analysis_xrefs_load);
	mu_run_test(test_analysis_meta_save);
	mu_run_test(test_analysis_meta_load);
	mu_run_test(test_analysis_hints_save);
	mu_run_test(test_analysis_hints_load);
	mu_run_test(test_analysis_classes_save);
	mu_run_test(test_analysis_classes_load);
	mu_run_test(test_analysis_cc_save);
	mu_run_test(test_analysis_cc_load);
	mu_run_test(test_analysis_save);
	mu_run_test(test_analysis_load);
	return tests_passed != tests_run;
}

mu_main(all_tests)
