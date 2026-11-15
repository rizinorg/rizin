// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_bin.h>
#include <rz_bin_stabs.h>
#include <rz_type.h>
#include "../unit/minunit.h"

static RzBinStabsEntry *entry_at(RzBinStabs *s, size_t i) {
	return (RzBinStabsEntry *)rz_vector_index_ptr(&s->entries, i);
}

static RzBinStabsSymbol *find_sym(RzBinStabsDebugInfo *di, const char *name) {
	void **it;
	rz_pvector_foreach (&di->symbols, it) {
		RzBinStabsSymbol *s = *it;
		if (RZ_STR_EQ(s->name, name)) {
			return s;
		}
	}
	return NULL;
}

bool test_stabs(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);
	RzBinOptions opt = { 0 };
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/stabs/stabs_hello", &opt);
	mu_assert_notnull(bf, "couldn't open file");

	RzBinStabs *stabs = rz_bin_stabs_parse(bf);
	mu_assert_notnull(stabs, "stabs should be parsed");

	// record parsing
	mu_assert_eq(rz_vector_len(&stabs->entries), 24, "stab entry count");

	// the first record is the compilation unit header
	RzBinStabsEntry *hdr = entry_at(stabs, 0);
	mu_assert_eq(hdr->type, RZ_BIN_STABS_N_UNDF, "header type");

	// source file
	RzBinStabsEntry *so = entry_at(stabs, 1);
	mu_assert_eq(so->type, RZ_BIN_STABS_N_SO, "N_SO type");
	mu_assert_streq(so->string, "stabs_hello.c", "N_SO string");
	mu_assert_eq(so->value, 0x401136, "N_SO value");

	// function "add"
	RzBinStabsEntry *fun_add = entry_at(stabs, 3);
	mu_assert_eq(fun_add->type, RZ_BIN_STABS_N_FUN, "N_FUN add type");
	mu_assert_true(rz_str_startswith(fun_add->string, "add:"), "N_FUN add name");
	mu_assert_eq(fun_add->value, 0x401136, "N_FUN add value");

	// function "main"
	RzBinStabsEntry *fun_main = entry_at(stabs, 14);
	mu_assert_eq(fun_main->type, RZ_BIN_STABS_N_FUN, "N_FUN main type");
	mu_assert_true(rz_str_startswith(fun_main->string, "main:"), "N_FUN main name");
	mu_assert_eq(fun_main->value, 0x401154, "N_FUN main value");

	// nine source line records overall
	size_t sline = 0;
	RzBinStabsEntry *e;
	rz_vector_foreach (&stabs->entries, e) {
		if (e->type == RZ_BIN_STABS_N_SLINE) {
			sline++;
		}
	}
	mu_assert_eq(sline, 9, "N_SLINE count");

	// line info: N_SLINE offsets are relative to the enclosing function, the
	// builder must resolve them to absolute addresses and keep them sorted
	RzBinSourceLineInfo *li = rz_bin_stabs_source_line_info(stabs);
	mu_assert_notnull(li, "line info should be built");
	mu_assert_eq(li->samples_count, 10, "line samples count");

	const ut64 addrs[] = { 0x401136, 0x401144, 0x40114f, 0x401152, 0x401154,
		0x401160, 0x401172, 0x40118b, 0x401190, 0x401192 };
	const ut32 lines[] = { 6, 7, 8, 9, 11, 12, 13, 14, 15, 0 };
	for (size_t i = 0; i < 10; i++) {
		mu_assert_eq(li->samples[i].address, addrs[i], "sample address");
		mu_assert_eq(li->samples[i].line, lines[i], "sample line");
	}
	// every covered sample points at the source file
	mu_assert_streq(li->samples[0].file, "stabs_hello.c", "sample file");
	// the trailing sample closes the range, like DW_LNE_end_sequence
	mu_assert_true(rz_bin_source_line_sample_is_closing(&li->samples[9]), "closing sample");

	rz_bin_source_line_info_free(li);
	rz_bin_stabs_free(stabs);
	rz_io_free(io);
	rz_bin_free(bin);
	mu_end;
}

bool test_stabs_extraction(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);
	RzBinOptions opt = { 0 };
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/stabs/stabs_syms", &opt);
	mu_assert_notnull(bf, "couldn't open file");

	RzBinStabs *stabs = rz_bin_stabs_parse(bf);
	mu_assert_notnull(stabs, "stabs should be parsed");

	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "typedb should be created");

	RzBinStabsDebugInfo *di = rz_bin_stabs_debug_info(stabs, typedb);
	mu_assert_notnull(di, "debug info should be extracted");

	// 3 globals/statics + 3 functions + 4 parameters + 4 locals
	mu_assert_eq(rz_pvector_len(&di->symbols), 14, "recovered symbol count");

	// global and static variables, with their resolved types
	RzBinStabsSymbol *g_counter = find_sym(di, "g_counter");
	mu_assert_notnull(g_counter, "g_counter recovered");
	mu_assert_eq(g_counter->kind, RZ_BIN_STABS_SYMBOL_GLOBAL, "g_counter is a global");
	mu_assert_eq(g_counter->type->kind, RZ_TYPE_KIND_IDENTIFIER, "g_counter type is an identifier");
	mu_assert_streq(g_counter->type->identifier.name, "int", "g_counter is an int");

	RzBinStabsSymbol *s_buffer = find_sym(di, "s_buffer");
	mu_assert_notnull(s_buffer, "s_buffer recovered");
	mu_assert_eq(s_buffer->kind, RZ_BIN_STABS_SYMBOL_STATIC, "s_buffer is a static");
	mu_assert_eq(s_buffer->value, 0x404040, "s_buffer has its own address");
	mu_assert_eq(s_buffer->type->kind, RZ_TYPE_KIND_ARRAY, "s_buffer is an array");
	mu_assert_eq(s_buffer->type->array.count, 16, "s_buffer holds 16 elements");

	RzBinStabsSymbol *g_origin = find_sym(di, "g_origin");
	mu_assert_notnull(g_origin, "g_origin recovered");
	mu_assert_eq(g_origin->kind, RZ_BIN_STABS_SYMBOL_GLOBAL, "g_origin is a global");
	mu_assert_streq(g_origin->type->identifier.name, "point", "g_origin is a struct point");
	mu_assert_eq(g_origin->type->identifier.kind, RZ_TYPE_IDENTIFIER_KIND_STRUCT, "g_origin identifier is a struct");

	// functions, with return types and addresses
	RzBinStabsSymbol *add = find_sym(di, "add");
	mu_assert_notnull(add, "add recovered");
	mu_assert_eq(add->kind, RZ_BIN_STABS_SYMBOL_FUNCTION, "add is a function");
	mu_assert_eq(add->value, 0x401136, "add address");
	mu_assert_streq(add->type->identifier.name, "int", "add returns an int");

	RzBinStabsSymbol *scale = find_sym(di, "scale");
	mu_assert_notnull(scale, "scale recovered");
	mu_assert_eq(scale->value, 0x401154, "scale address");
	mu_assert_streq(scale->type->identifier.name, "long", "scale returns a long");

	// parameters, linked back to their enclosing function
	RzBinStabsSymbol *a = find_sym(di, "a");
	mu_assert_notnull(a, "parameter a recovered");
	mu_assert_eq(a->kind, RZ_BIN_STABS_SYMBOL_PARAMETER, "a is a parameter");
	mu_assert_eq(a->function, 0x401136, "a belongs to add");
	mu_assert_streq(a->type->identifier.name, "int", "a is an int");

	RzBinStabsSymbol *p = find_sym(di, "p");
	mu_assert_notnull(p, "parameter p recovered");
	mu_assert_eq(p->kind, RZ_BIN_STABS_SYMBOL_PARAMETER, "p is a parameter");
	mu_assert_eq(p->function, 0x401154, "p belongs to scale");
	mu_assert_eq(p->type->kind, RZ_TYPE_KIND_POINTER, "p is a pointer");
	mu_assert_streq(p->type->pointer.type->identifier.name, "point", "p points to point");

	// local variables, linked back to their enclosing function
	RzBinStabsSymbol *sum = find_sym(di, "sum");
	mu_assert_notnull(sum, "local sum recovered");
	mu_assert_eq(sum->kind, RZ_BIN_STABS_SYMBOL_LOCAL, "sum is a local");
	mu_assert_eq(sum->function, 0x401136, "sum belongs to add");

	RzBinStabsSymbol *c = find_sym(di, "c");
	mu_assert_notnull(c, "local c recovered");
	mu_assert_eq(c->kind, RZ_BIN_STABS_SYMBOL_LOCAL, "c is a local");
	mu_assert_eq(c->function, 0x40118a, "c belongs to main");
	mu_assert_streq(c->type->identifier.name, "color", "c is an enum color");

	// types registered into the type database: struct, enum and typedef
	RzBaseType *point = rz_type_db_get_base_type(typedb, "point");
	mu_assert_notnull(point, "struct point registered");
	mu_assert_eq(point->kind, RZ_BASE_TYPE_KIND_STRUCT, "point is a struct");
	mu_assert_eq(rz_vector_len(&point->struct_data.members), 2, "point has two members");
	RzTypeStructMember *m0 = rz_vector_index_ptr(&point->struct_data.members, 0);
	mu_assert_streq(m0->name, "x", "first member is x");
	mu_assert_eq(m0->offset, 0, "x is at offset 0");
	RzTypeStructMember *m1 = rz_vector_index_ptr(&point->struct_data.members, 1);
	mu_assert_streq(m1->name, "y", "second member is y");
	mu_assert_eq(m1->offset, 4, "y is at offset 4");

	RzBaseType *color = rz_type_db_get_base_type(typedb, "color");
	mu_assert_notnull(color, "enum color registered");
	mu_assert_eq(color->kind, RZ_BASE_TYPE_KIND_ENUM, "color is an enum");
	mu_assert_eq(rz_vector_len(&color->enum_data.cases), 3, "color has three cases");
	RzTypeEnumCase *case0 = rz_vector_index_ptr(&color->enum_data.cases, 0);
	mu_assert_streq(case0->name, "RED", "first case is RED");
	mu_assert_eq(case0->val, 0, "RED is 0");
	RzTypeEnumCase *case2 = rz_vector_index_ptr(&color->enum_data.cases, 2);
	mu_assert_streq(case2->name, "BLUE", "third case is BLUE");
	mu_assert_eq(case2->val, 2, "BLUE is 2");

	RzBaseType *uint_t = rz_type_db_get_base_type(typedb, "uint_t");
	mu_assert_notnull(uint_t, "typedef uint_t registered");
	mu_assert_eq(uint_t->kind, RZ_BASE_TYPE_KIND_TYPEDEF, "uint_t is a typedef");

	rz_bin_stabs_debug_info_free(di);
	rz_type_db_free(typedb);
	rz_bin_stabs_free(stabs);
	rz_io_free(io);
	rz_bin_free(bin);
	mu_end;
}

bool test_stabs_truncated_descriptor(void) {
	// Regression: a struct member whose type descriptor is empty at the end of
	// the string used to advance the cursor past the NUL terminator, causing a
	// heap buffer over-read. The truncated type must instead resolve to void.
	RzBinStabs stabs = { 0 };
	rz_vector_init(&stabs.entries, sizeof(RzBinStabsEntry), NULL, NULL);
	RzBinStabsEntry e = { 0 };
	e.type = RZ_BIN_STABS_N_LSYM;
	e.string = "trunc:T(1,2)=s4a:"; // member "a" with its type missing at end-of-string
	e.strx = 1;
	rz_vector_push(&stabs.entries, &e);

	RzTypeDB *typedb = rz_type_db_new();
	RzBinStabsDebugInfo *di = rz_bin_stabs_debug_info(&stabs, typedb);
	mu_assert_notnull(di, "debug info built for a truncated descriptor");

	RzBaseType *bt = rz_type_db_get_base_type(typedb, "trunc");
	mu_assert_notnull(bt, "truncated struct still registered");
	mu_assert_eq(bt->kind, RZ_BASE_TYPE_KIND_STRUCT, "trunc is a struct");
	mu_assert_eq(rz_vector_len(&bt->struct_data.members), 1, "the single member is parsed");
	RzTypeStructMember *m = rz_vector_index_ptr(&bt->struct_data.members, 0);
	mu_assert_streq(m->name, "a", "member name is recovered");

	rz_bin_stabs_debug_info_free(di);
	rz_type_db_free(typedb);
	rz_vector_fini(&stabs.entries);

	// A global whose type definition is missing right after '=' must likewise
	// resolve to void without reading past the end of the string.
	RzBinStabs s2 = { 0 };
	rz_vector_init(&s2.entries, sizeof(RzBinStabsEntry), NULL, NULL);
	RzBinStabsEntry e2 = { 0 };
	e2.type = RZ_BIN_STABS_N_GSYM;
	e2.string = "g:G(1,2)="; // nothing follows the '='
	e2.strx = 1;
	rz_vector_push(&s2.entries, &e2);

	RzTypeDB *db2 = rz_type_db_new();
	RzBinStabsDebugInfo *di2 = rz_bin_stabs_debug_info(&s2, db2);
	mu_assert_notnull(di2, "debug info built for an empty descriptor");
	RzBinStabsSymbol *g = find_sym(di2, "g");
	mu_assert_notnull(g, "global with an empty descriptor is recovered");
	mu_assert_notnull(g->type, "global has a type");
	mu_assert_eq(g->type->kind, RZ_TYPE_KIND_IDENTIFIER, "empty descriptor resolves to an identifier");

	rz_bin_stabs_debug_info_free(di2);
	rz_type_db_free(db2);
	rz_vector_fini(&s2.entries);

	mu_end;
}

bool all_tests() {
	mu_run_test(test_stabs);
	mu_run_test(test_stabs_extraction);
	mu_run_test(test_stabs_truncated_descriptor);
	return tests_passed != tests_run;
}

mu_main(all_tests)
