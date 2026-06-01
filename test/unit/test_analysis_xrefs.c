// SPDX-FileCopyrightText: 2020 xvilka
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include "minunit.h"

static int count_iter(RzIterator *iter) {
	int count = 0;
	RzAnalysisXRef **xrefp;
	rz_iterator_foreach(iter, xrefp) {
		count++;
	}
	return count;
}

static bool test_rz_analysis_xrefs_count() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	mu_assert_eq(rz_analysis_xrefs_count(analysis), 0, "xrefs count");

	rz_analysis_xrefs_set(analysis, 0x1337, 42, RZ_ANALYSIS_XREF_TYPE_NULL);
	rz_analysis_xrefs_set(analysis, 0x1337, 43, RZ_ANALYSIS_XREF_TYPE_CODE);
	rz_analysis_xrefs_set(analysis, 1234, 43, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 12345, 43, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 4321, 4242, RZ_ANALYSIS_XREF_TYPE_CALL);

	mu_assert_eq(rz_analysis_xrefs_count(analysis), 5, "xrefs count");

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_rz_analysis_xrefs_count_type() {
	RzAnalysis *analysis = rz_analysis_new(NULL);
	mu_assert_eq(rz_analysis_xrefs_count_type(analysis,
			     RZ_ANALYSIS_XREF_TYPE_CALL),
		0, "call count empty");
	mu_assert_eq(rz_analysis_xrefs_count_type(analysis,
			     RZ_ANALYSIS_XREF_TYPE_CODE),
		0, "code count empty");

	rz_analysis_xrefs_set(analysis, 0x100, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 0x100, 0x300, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 0x100, 0x400, RZ_ANALYSIS_XREF_TYPE_CODE);
	rz_analysis_xrefs_set(analysis, 0x100, 0x500, RZ_ANALYSIS_XREF_TYPE_DATA);
	rz_analysis_xrefs_set(analysis, 0x100, 0x600, RZ_ANALYSIS_XREF_TYPE_STRING);

	mu_assert_eq(rz_analysis_xrefs_count(analysis), 5, "total count");
	mu_assert_eq(rz_analysis_xrefs_count_type(analysis,
			     RZ_ANALYSIS_XREF_TYPE_CALL),
		2, "call count");
	mu_assert_eq(rz_analysis_xrefs_count_type(analysis,
			     RZ_ANALYSIS_XREF_TYPE_CODE),
		1, "code count");
	mu_assert_eq(rz_analysis_xrefs_count_type(analysis,
			     RZ_ANALYSIS_XREF_TYPE_DATA),
		1, "data count");
	mu_assert_eq(rz_analysis_xrefs_count_type(analysis,
			     RZ_ANALYSIS_XREF_TYPE_STRING),
		1, "string count");

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_rz_analysis_xrefs_get_all_of_type() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	RzIterator *empty = rz_analysis_xrefs_get_all_of_type(
		analysis, RZ_ANALYSIS_XREF_TYPE_CALL);
	mu_assert_null(empty, "no xrefs of type when empty");

	rz_analysis_xrefs_set(analysis, 0x100, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 0x300, 0x400, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 0x100, 0x500, RZ_ANALYSIS_XREF_TYPE_CODE);

	RzIterator *calls = rz_analysis_xrefs_get_all_of_type(
		analysis, RZ_ANALYSIS_XREF_TYPE_CALL);
	mu_assert_notnull(calls, "call xrefs iter");
	mu_assert_eq(count_iter(calls), 2, "call xrefs count");
	rz_iterator_free(calls);

	RzIterator *codes = rz_analysis_xrefs_get_all_of_type(
		analysis, RZ_ANALYSIS_XREF_TYPE_CODE);
	mu_assert_notnull(codes, "code xrefs iter");
	mu_assert_eq(count_iter(codes), 1, "code xrefs count");
	rz_iterator_free(codes);

	RzIterator *data = rz_analysis_xrefs_get_all_of_type(
		analysis, RZ_ANALYSIS_XREF_TYPE_DATA);
	mu_assert_null(data, "no data xrefs");

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_rz_analysis_xrefs_get_to_type() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	rz_analysis_xrefs_set(analysis, 0x100, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 0x300, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 0x400, 0x200, RZ_ANALYSIS_XREF_TYPE_DATA);

	RzIterator *call_to = rz_analysis_xrefs_get_to_type(
		analysis, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	mu_assert_notnull(call_to, "call xrefs to addr");
	mu_assert_eq(count_iter(call_to), 2, "call xrefs to count");
	rz_iterator_free(call_to);

	RzIterator *data_to = rz_analysis_xrefs_get_to_type(
		analysis, 0x200, RZ_ANALYSIS_XREF_TYPE_DATA);
	mu_assert_notnull(data_to, "data xrefs to addr");
	mu_assert_eq(count_iter(data_to), 1, "data xrefs to count");
	rz_iterator_free(data_to);

	RzIterator *none = rz_analysis_xrefs_get_to_type(
		analysis, 0x200, RZ_ANALYSIS_XREF_TYPE_STRING);
	mu_assert_null(none, "no string xrefs to addr");

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_rz_analysis_xrefs_get_from_type() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	rz_analysis_xrefs_set(analysis, 0x100, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 0x100, 0x300, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 0x100, 0x400, RZ_ANALYSIS_XREF_TYPE_DATA);

	RzIterator *call_from = rz_analysis_xrefs_get_from_type(
		analysis, 0x100, RZ_ANALYSIS_XREF_TYPE_CALL);
	mu_assert_notnull(call_from, "call xrefs from addr");
	mu_assert_eq(count_iter(call_from), 2, "call xrefs from count");
	rz_iterator_free(call_from);

	RzIterator *data_from = rz_analysis_xrefs_get_from_type(
		analysis, 0x100, RZ_ANALYSIS_XREF_TYPE_DATA);
	mu_assert_notnull(data_from, "data xrefs from addr");
	mu_assert_eq(count_iter(data_from), 1, "data xrefs from count");
	rz_iterator_free(data_from);

	RzIterator *none = rz_analysis_xrefs_get_from_type(
		analysis, 0x100, RZ_ANALYSIS_XREF_TYPE_STRING);
	mu_assert_null(none, "no string xrefs from addr");

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_rz_analysis_xrefs_deln_updates_type_index() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	rz_analysis_xrefs_set(analysis, 0x100, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 0x100, 0x300, RZ_ANALYSIS_XREF_TYPE_CALL);
	mu_assert_eq(rz_analysis_xrefs_count_type(
			     analysis, RZ_ANALYSIS_XREF_TYPE_CALL),
		2, "before del");

	rz_analysis_xrefs_deln(analysis, 0x100, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	mu_assert_eq(rz_analysis_xrefs_count_type(
			     analysis, RZ_ANALYSIS_XREF_TYPE_CALL),
		1, "after del");

	RzIterator *calls = rz_analysis_xrefs_get_all_of_type(
		analysis, RZ_ANALYSIS_XREF_TYPE_CALL);
	mu_assert_notnull(calls, "remaining call xrefs");
	mu_assert_eq(count_iter(calls), 1, "remaining count");
	rz_iterator_free(calls);

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_rz_analysis_xrefs_init_resets_type_index() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	rz_analysis_xrefs_set(analysis, 0x100, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	mu_assert_eq(rz_analysis_xrefs_count(analysis), 1, "before init");
	mu_assert_eq(rz_analysis_xrefs_count_type(
			     analysis, RZ_ANALYSIS_XREF_TYPE_CALL),
		1, "type count before init");

	rz_analysis_xrefs_init(analysis);
	mu_assert_eq(rz_analysis_xrefs_count(analysis), 0, "after init");
	mu_assert_eq(rz_analysis_xrefs_count_type(
			     analysis, RZ_ANALYSIS_XREF_TYPE_CALL),
		0, "type count after init");

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_rz_analysis_xrefs_get_to() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	RzList *empty = rz_analysis_xrefs_get_to(analysis, 0x100);
	mu_assert_null(empty, "no xrefs when empty");

	rz_analysis_xrefs_set(analysis, 0x100, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 0x300, 0x200, RZ_ANALYSIS_XREF_TYPE_DATA);

	RzList *to = rz_analysis_xrefs_get_to(analysis, 0x200);
	mu_assert_notnull(to, "xrefs to addr");
	mu_assert_eq(rz_list_length(to), 2, "xrefs to count");
	rz_list_free(to);

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_rz_analysis_xrefs_get_from() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	rz_analysis_xrefs_set(analysis, 0x100, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 0x100, 0x300, RZ_ANALYSIS_XREF_TYPE_DATA);

	RzList *from = rz_analysis_xrefs_get_from(analysis, 0x100);
	mu_assert_notnull(from, "xrefs from addr");
	mu_assert_eq(rz_list_length(from), 2, "xrefs from count");
	rz_list_free(from);

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_rz_analysis_xrefs_list() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	rz_analysis_xrefs_set(analysis, 0x100, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 0x300, 0x400, RZ_ANALYSIS_XREF_TYPE_DATA);
	rz_analysis_xrefs_set(analysis, 0x500, 0x600, RZ_ANALYSIS_XREF_TYPE_CODE);

	RzList *all = rz_analysis_xrefs_list(analysis);
	mu_assert_notnull(all, "all xrefs list");
	mu_assert_eq(rz_list_length(all), 3, "all xrefs count");
	rz_list_free(all);

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_rz_analysis_xref_del() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	rz_analysis_xrefs_set(analysis, 0x100, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	mu_assert_eq(rz_analysis_xrefs_count(analysis), 1, "before del");

	rz_analysis_xref_del(analysis, 0x100, 0x200);
	mu_assert_eq(rz_analysis_xrefs_count(analysis), 0, "after del");
	mu_assert_eq(rz_analysis_xrefs_count_type(
			     analysis, RZ_ANALYSIS_XREF_TYPE_CALL),
		0, "type count after del");

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_rz_analysis_xrefs_set_no_self_ref() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	bool res = rz_analysis_xrefs_set(
		analysis, 0x100, 0x100, RZ_ANALYSIS_XREF_TYPE_CALL);
	mu_assert_false(res, "self-ref rejected");
	mu_assert_eq(rz_analysis_xrefs_count(analysis), 0, "no xref added");

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_rz_analysis_xrefs_set_update() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	rz_analysis_xrefs_set(analysis, 0x100, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	mu_assert_eq(rz_analysis_xrefs_count(analysis), 1, "count after first set");

	rz_analysis_xrefs_set(analysis, 0x100, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	mu_assert_eq(rz_analysis_xrefs_count(analysis), 1, "count stays 1 after update");

	RzIterator *calls = rz_analysis_xrefs_get_all_of_type(
		analysis, RZ_ANALYSIS_XREF_TYPE_CALL);
	mu_assert_notnull(calls, "call xrefs after update");
	mu_assert_eq(count_iter(calls), 1, "call xrefs after update count");
	rz_iterator_free(calls);

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_rz_analysis_xrefs_deln_nonexistent() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	rz_analysis_xrefs_set(analysis, 0x100, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_deln(analysis, 0x999, 0x888, RZ_ANALYSIS_XREF_TYPE_CALL);
	mu_assert_eq(rz_analysis_xrefs_count(analysis), 1, "del nonexistent addr");

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_rz_analysis_xref_del_mixed_types() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	rz_analysis_xrefs_set(analysis, 0x100, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 0x100, 0x200, RZ_ANALYSIS_XREF_TYPE_DATA);
	mu_assert_eq(rz_analysis_xrefs_count(analysis), 1, "same pair replaces");
	mu_assert_eq(rz_analysis_xrefs_count_type(
			     analysis, RZ_ANALYSIS_XREF_TYPE_CALL),
		0, "call type cleaned");
	mu_assert_eq(rz_analysis_xrefs_count_type(
			     analysis, RZ_ANALYSIS_XREF_TYPE_DATA),
		1, "data type set");

	RzIterator *data = rz_analysis_xrefs_get_all_of_type(
		analysis, RZ_ANALYSIS_XREF_TYPE_DATA);
	mu_assert_notnull(data, "data xrefs after replace");
	mu_assert_eq(count_iter(data), 1, "data xrefs count");
	rz_iterator_free(data);

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_rz_analysis_xrefs_get_to_range() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	rz_analysis_xrefs_set(analysis, 0x100, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 0x200, 0x300, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 0x300, 0x400, RZ_ANALYSIS_XREF_TYPE_DATA);
	rz_analysis_xrefs_set(analysis, 0x400, 0x100, RZ_ANALYSIS_XREF_TYPE_CALL);

	RzIterator *to_range = rz_analysis_xrefs_get_to_range(
		analysis, 0x200, 0x400);
	mu_assert_notnull(to_range, "to range iter");
	mu_assert_eq(count_iter(to_range), 3, "to range count");
	rz_iterator_free(to_range);

	RzIterator *single = rz_analysis_xrefs_get_to_range(
		analysis, 0x200, 0x200);
	mu_assert_notnull(single, "to range single iter");
	mu_assert_eq(count_iter(single), 1, "to range single count");
	rz_iterator_free(single);

	RzIterator *none = rz_analysis_xrefs_get_to_range(
		analysis, 0x500, 0x600);
	mu_assert_notnull(none, "to range empty iter");
	mu_assert_eq(count_iter(none), 0, "to range no match");
	rz_iterator_free(none);

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_rz_analysis_xrefs_get_from_range() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	rz_analysis_xrefs_set(analysis, 0x100, 0x200, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 0x200, 0x300, RZ_ANALYSIS_XREF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 0x300, 0x400, RZ_ANALYSIS_XREF_TYPE_DATA);
	rz_analysis_xrefs_set(analysis, 0x400, 0x100, RZ_ANALYSIS_XREF_TYPE_CALL);

	RzIterator *from_range = rz_analysis_xrefs_get_from_range(
		analysis, 0x100, 0x300);
	mu_assert_notnull(from_range, "from range iter");
	mu_assert_eq(count_iter(from_range), 3, "from range count");
	rz_iterator_free(from_range);

	RzIterator *single = rz_analysis_xrefs_get_from_range(
		analysis, 0x400, 0x400);
	mu_assert_notnull(single, "from range single iter");
	mu_assert_eq(count_iter(single), 1, "from range single count");
	rz_iterator_free(single);

	RzIterator *none = rz_analysis_xrefs_get_from_range(
		analysis, 0x500, 0x600);
	mu_assert_notnull(none, "from range empty iter");
	mu_assert_eq(count_iter(none), 0, "from range no match");
	rz_iterator_free(none);

	rz_analysis_free(analysis);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_analysis_xrefs_count);
	mu_run_test(test_rz_analysis_xrefs_count_type);
	mu_run_test(test_rz_analysis_xrefs_get_all_of_type);
	mu_run_test(test_rz_analysis_xrefs_get_to_type);
	mu_run_test(test_rz_analysis_xrefs_get_from_type);
	mu_run_test(test_rz_analysis_xrefs_deln_updates_type_index);
	mu_run_test(test_rz_analysis_xrefs_init_resets_type_index);
	mu_run_test(test_rz_analysis_xrefs_get_to);
	mu_run_test(test_rz_analysis_xrefs_get_from);
	mu_run_test(test_rz_analysis_xrefs_list);
	mu_run_test(test_rz_analysis_xref_del);
	mu_run_test(test_rz_analysis_xrefs_set_no_self_ref);
	mu_run_test(test_rz_analysis_xrefs_set_update);
	mu_run_test(test_rz_analysis_xrefs_deln_nonexistent);
	mu_run_test(test_rz_analysis_xref_del_mixed_types);
	mu_run_test(test_rz_analysis_xrefs_get_to_range);
	mu_run_test(test_rz_analysis_xrefs_get_from_range);
	return tests_passed != tests_run;
}

mu_main(all_tests)
