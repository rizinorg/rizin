// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "minunit.h"

bool test_core_seek(void) {
	RzCore *core = rz_core_new();
	mu_assert_eq(core->offset, 0, "seek starts at 0");
	rz_core_seek(core, 0x100, false);
	mu_assert_eq(core->offset, 0x100, "seek moved to 0x100");
	rz_core_seek(core, 0x200, false);
	mu_assert_eq(core->offset, 0x200, "seek moved to 0x200");
	rz_core_seek(core, 0x500, false);
	mu_assert_eq(core->offset, 0x500, "seek moved to 0x500");
	rz_core_seek_base(core, "23", false);
	mu_assert_eq(core->offset, 0x523, "seek_base moved to 0x523");
	rz_core_seek_delta(core, -0x23, false);
	mu_assert_eq(core->offset, 0x500, "seek_delta moved back to 0x500");
	rz_core_seek_delta(core, 0x100, false);
	mu_assert_eq(core->offset, 0x600, "seek_delta moved to 0x600");
	rz_core_seek(core, 0x1234567, false);
	rz_core_seek_align(core, 0x100, false);
	mu_assert_eq(core->offset, 0x1234500, "seek_align (0x100) moved from 0x1234567 to 0x1234500");
	rz_core_seek_align(core, 0x10000, false);
	mu_assert_eq(core->offset, 0x1230000, "seek_align (0x10000) moved from 0x1234500 to 0x1230000");
	rz_core_free(core);
	mu_end;
}

bool test_core_seek_prev_next(void) {
	RzCore *core = rz_core_new();
	rz_flag_set(core->flags, "flag1", 0x100, 1);
	rz_flag_set(core->flags, "flag2", 0x200, 1);
	rz_flag_set(core->flags, "flag3", 0x333, 1);
	rz_flag_set(core->flags, "flag4", 0x444, 1);
	rz_core_seek_next(core, "flag", true);
	mu_assert_eq(core->offset, 0x100, "seek_next flag goes to 0x100");
	rz_core_seek_next(core, "flag", true);
	mu_assert_eq(core->offset, 0x200, "seek_next flag goes to 0x200");
	rz_core_seek_next(core, "flag", true);
	rz_core_seek_next(core, "flag", true);
	mu_assert_eq(core->offset, 0x444, "seek_next flag goes to 0x444");
	rz_core_seek_next(core, "flag", true);
	mu_assert_eq(core->offset, 0x444, "seek_next flag remains at last flag");
	rz_core_seek_prev(core, "flag", true);
	mu_assert_eq(core->offset, 0x333, "seek_prev flag goes to 0x333");
	rz_core_seek_prev(core, "flag", true);
	rz_core_seek_prev(core, "flag", true);
	mu_assert_eq(core->offset, 0x100, "seek_prev flag goes to 0x100");
	rz_core_seek_prev(core, "flag", true);
	mu_assert_eq(core->offset, 0x100, "seek_prev flag remains at first flag");
	rz_core_free(core);
	mu_end;
}

bool test_core_seek_list(void) {
	RzCore *core = rz_core_new();
	rz_core_seek_and_save(core, 0x100, false);
	rz_core_seek_and_save(core, 0x200, false);
	rz_core_seek_and_save(core, 0x300, false);
	RzList *l = rz_core_seek_list(core);
	mu_assert_notnull(l, "seek list shall be returned");
	mu_assert_eq(rz_list_length(l), 4, "seek list contain 4 elements (current pos included)");
	RzCoreSeekItem *csu = (RzCoreSeekItem *)rz_list_get_n(l, 0);
	mu_assert_eq(csu->offset, 0, "1st is 0 seek");
	mu_assert_false(csu->is_current, "1st is NOT current seek");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 1);
	mu_assert_eq(csu->offset, 0x100, "2nd is 0x100 seek");
	mu_assert_false(csu->is_current, "2nd is NOT current seek");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 2);
	mu_assert_eq(csu->offset, 0x200, "3rd is 0x200 seek");
	mu_assert_false(csu->is_current, "3rd is NOT current seek");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 3);
	mu_assert_eq(csu->offset, 0x300, "4th is 0x300 seek");
	mu_assert_true(csu->is_current, "4th is current seek");
	rz_list_free(l);
	rz_core_free(core);
	mu_end;
}

bool test_core_seek_list_undo(void) {
	RzCore *core = rz_core_new();
	rz_core_seek_and_save(core, 0x100, false);
	rz_core_seek_and_save(core, 0x200, false);
	rz_core_seek_and_save(core, 0x300, false);
	rz_core_seek_undo(core);
	RzList *l = rz_core_seek_list(core);
	mu_assert_notnull(l, "seek list shall be returned");
	mu_assert_eq(rz_list_length(l), 4, "seek list contain 4 elements (current pos included)");
	RzCoreSeekItem *csu = (RzCoreSeekItem *)rz_list_get_n(l, 0);
	mu_assert_eq(csu->offset, 0, "1st is 0 seek");
	mu_assert_false(csu->is_current, "1st is NOT current seek");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 1);
	mu_assert_eq(csu->offset, 0x100, "2nd is 0x100 seek");
	mu_assert_false(csu->is_current, "2nd is NOT current seek");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 2);
	mu_assert_eq(csu->offset, 0x200, "3rd is 0x200 seek");
	mu_assert_true(csu->is_current, "3rd is current seek");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 3);
	mu_assert_eq(csu->offset, 0x300, "4th is 0x300 seek");
	mu_assert_false(csu->is_current, "4th is NOT current seek");
	rz_list_free(l);

	rz_core_seek_undo(core);
	rz_core_seek_undo(core);
	rz_core_seek_undo(core);
	rz_core_seek_undo(core);

	l = rz_core_seek_list(core);
	mu_assert_notnull(l, "seek list shall be returned");
	mu_assert_eq(rz_list_length(l), 4, "seek list contain 4 elements (current pos included)");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 0);
	mu_assert_eq(csu->offset, 0, "1st is 0 seek");
	mu_assert_true(csu->is_current, "1st is current seek");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 1);
	mu_assert_eq(csu->offset, 0x100, "2nd is 0x100 seek");
	mu_assert_false(csu->is_current, "2nd is NOT current seek");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 2);
	mu_assert_eq(csu->offset, 0x200, "3rd is 0x200 seek");
	mu_assert_false(csu->is_current, "3rd is NOT current seek");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 3);
	mu_assert_eq(csu->offset, 0x300, "4th is 0x300 seek");
	mu_assert_false(csu->is_current, "4th is NOT current seek");
	rz_list_free(l);

	rz_core_seek_and_save(core, 0x100, false);
	l = rz_core_seek_list(core);
	mu_assert_notnull(l, "seek list shall be returned");
	mu_assert_eq(rz_list_length(l), 2, "seek list contain 2 elements (current pos included) because seek deletes redos");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 0);
	mu_assert_eq(csu->offset, 0, "1st is 0 seek");
	mu_assert_false(csu->is_current, "1st is NOT current seek");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 1);
	mu_assert_eq(csu->offset, 0x100, "2nd is 0x100 seek");
	mu_assert_true(csu->is_current, "2nd is current seek");
	rz_list_free(l);

	rz_core_seek_and_save(core, 0x100, false);
	l = rz_core_seek_list(core);
	mu_assert_eq(rz_list_length(l), 2, "still 2 elements because 0x100 is already current seek");
	rz_list_free(l);

	rz_core_seek_and_save(core, 0, false);
	l = rz_core_seek_list(core);
	mu_assert_eq(rz_list_length(l), 3, "history should be 0 - 0x100 - 0");
	rz_list_free(l);

	rz_core_free(core);
	mu_end;
}

bool test_core_seek_undo_redo(void) {
	RzCore *core = rz_core_new();
	bool r = rz_core_seek_undo(core);
	mu_assert_false(r, "Cannot undo when no seek");
	r = rz_core_seek_redo(core);
	mu_assert_false(r, "Cannot redo when no undo has been done");

	rz_core_seek_and_save(core, 0x100, false);

	r = rz_core_seek_redo(core);
	mu_assert_false(r, "Cannot redo when no undo has been done");

	rz_core_seek_and_save(core, 0x200, false);
	rz_core_seek_and_save(core, 0x300, false);

	r = rz_core_seek_undo(core);
	mu_assert_true(r, "Undo seek 1 was done");
	mu_assert_eq(core->offset, 0x200, "first undo goes to 0x200");
	r = rz_core_seek_undo(core);
	mu_assert_true(r, "Undo seek 2 was done");
	mu_assert_eq(core->offset, 0x100, "second undo goes to 0x100");
	r = rz_core_seek_undo(core);
	mu_assert_true(r, "Undo seek 3 was done");
	mu_assert_eq(core->offset, 0, "third undo goes to 0");
	r = rz_core_seek_undo(core);
	mu_assert_false(r, "Undo seek 4 cannot be done because all undos have been done");

	r = rz_core_seek_redo(core);
	mu_assert_true(r, "Redo seek 1 was done");
	mu_assert_eq(core->offset, 0x100, "redo seek 1 goes to 0x100");
	r = rz_core_seek_redo(core);
	mu_assert_true(r, "Redo seek 2 was done");
	mu_assert_eq(core->offset, 0x200, "redo seek 2 goes to 0x200");
	r = rz_core_seek_redo(core);
	mu_assert_true(r, "Redo seek 3 was done");
	mu_assert_eq(core->offset, 0x300, "redo seek 3 goes to 0x300");
	r = rz_core_seek_redo(core);
	mu_assert_false(r, "Redo seek 4 cannot be done because all redos have been done");

	rz_core_seek_undo(core);
	rz_core_seek_undo(core);
	rz_core_seek_undo(core);
	rz_core_seek_and_save(core, 0x1000, true);
	r = rz_core_seek_redo(core);
	mu_assert_false(r, "Redo are deleted after a seek");

	rz_core_free(core);
	mu_end;
}

bool test_core_seek_dupped(void) {
	RzList *l;
	RzCoreSeekItem *csu;
	RzCore *core = rz_core_new();
	rz_core_seek_and_save(core, 0x100, false);
	rz_core_seek_and_save(core, 0x200, false);
	rz_core_seek_and_save(core, 0x300, false);

	l = rz_core_seek_list(core);
	mu_assert_eq(rz_list_length(l), 4, "4 elements in the list");
	rz_list_free(l);

	rz_core_seek_and_save(core, 0x300, false);
	rz_core_seek_and_save(core, 0x300, false);
	l = rz_core_seek_list(core);
	mu_assert_eq(rz_list_length(l), 4, "4 elements still in the list (no dup in last entry)");
	rz_list_free(l);

	rz_core_seek(core, 0x400, false);
	l = rz_core_seek_list(core);
	mu_assert_eq(rz_list_length(l), 4, "4 elements still in the list (silent seek done)");
	rz_list_free(l);

	rz_core_seek_and_save(core, 0x500, false);
	l = rz_core_seek_list(core);
	mu_assert_eq(rz_list_length(l), 5, "5 elements in history after save_and_seek 0x500");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 0);
	mu_assert_eq(csu->offset, 0, "1st is 0 seek");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 1);
	mu_assert_eq(csu->offset, 0x100, "2nd is 0x100 seek");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 2);
	mu_assert_eq(csu->offset, 0x200, "3rd is 0x200 seek");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 3);
	mu_assert_eq(csu->offset, 0x400, "4th is 0x400 seek (0x300 was not saved because we moved away from it withhout saving)");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 4);
	mu_assert_eq(csu->offset, 0x500, "5th is 0x500 seek");
	mu_assert_true(csu->is_current, "5th is current");
	rz_list_free(l);

	rz_core_seek(core, 0x400, false);
	rz_core_seek_mark(core);
	rz_core_seek_and_save(core, 0x600, false);
	l = rz_core_seek_list(core);
	mu_assert_eq(rz_list_length(l), 5, "no other element in history because 0x400 is already last element in history");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 3);
	mu_assert_eq(csu->offset, 0x400, "4th is still 0x400 seek");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 4);
	mu_assert_eq(csu->offset, 0x600, "5th is 0x600 seek");
	mu_assert_true(csu->is_current, "5th is current");
	rz_list_free(l);

	rz_core_free(core);
	mu_end;
}

bool test_core_seek_marksave(void) {
	RzCoreSeekItem *csu = NULL;
	RzList *l = NULL;
	RzCore *core = rz_core_new();
	rz_core_seek_and_save(core, 0x100, false);

	rz_core_seek_save(core);
	l = rz_core_seek_list(core);
	mu_assert_eq(rz_list_length(l), 2, "only 0 and 0x100 (current) are in list, save did not work because no mark");
	rz_list_free(l);

	rz_core_seek_mark(core);
	rz_core_seek_save(core);
	l = rz_core_seek_list(core);
	mu_assert_eq(rz_list_length(l), 2, "only 0 and 0x100 (current) are in list, we did not move from mark");
	rz_list_free(l);

	rz_core_seek_mark(core);
	rz_core_seek(core, 0x200, false);
	rz_core_seek(core, 0x300, false);
	rz_core_seek_and_save(core, 0x400, false);
	l = rz_core_seek_list(core);
	mu_assert_eq(rz_list_length(l), 3, "0, 0x100, 0x400 (current) are in list");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 0);
	mu_assert_eq(csu->offset, 0x0, "1st is 0 seek");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 1);
	mu_assert_eq(csu->offset, 0x100, "2nd is 0x100 seek");
	csu = (RzCoreSeekItem *)rz_list_get_n(l, 2);
	mu_assert_eq(csu->offset, 0x400, "3rd is 0x400 seek");
	mu_assert_true(csu->is_current, "3rd is current");
	rz_list_free(l);

	rz_core_seek_save(core);
	l = rz_core_seek_list(core);
	mu_assert_eq(rz_list_length(l), 3, "save did not work, because no mark after saving");
	rz_list_free(l);

	rz_core_free(core);
	mu_end;
}

int all_tests() {
	mu_run_test(test_core_seek);
	mu_run_test(test_core_seek_prev_next);
	mu_run_test(test_core_seek_list);
	mu_run_test(test_core_seek_list_undo);
	mu_run_test(test_core_seek_undo_redo);
	mu_run_test(test_core_seek_dupped);
	mu_run_test(test_core_seek_marksave);
	return tests_passed != tests_run;
}

mu_main(all_tests)