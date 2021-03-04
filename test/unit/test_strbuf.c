// SPDX-FileCopyrightText: 2019 radare <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

bool test_rz_strbuf_slice(void) {
	RzStrBuf *sa = rz_strbuf_new("foo,bar,cow");
	rz_strbuf_slice(sa, 2, 4); // should be from/to instead of from/len ?
	char *a = rz_strbuf_drain(sa);
	mu_assert_streq(a, "o,ba", "slicing fails");
	free(a);

	mu_end;
}

bool test_rz_strbuf_append(void) {
	RzStrBuf *sa = rz_strbuf_new("foo");
	rz_strbuf_append(sa, "bar");
	rz_strbuf_prepend(sa, "pre");
	char *a = rz_strbuf_drain(sa);
	mu_assert_streq(a, "prefoobar", "append+prepend");
	free(a);

	mu_end;
}

bool test_rz_strbuf_strong_string(void) {
	// small string
	RzStrBuf *sa = rz_strbuf_new("");
	rz_strbuf_set(sa, "food");
	mu_assert_eq(rz_strbuf_length(sa), 4, "rz_strbuf_set:food");
	mu_assert_eq(sa->len, 4, "len of string");
	// ptrlen not used here
	rz_strbuf_free(sa);

	sa = rz_strbuf_new("");
	rz_strbuf_set(sa, "food");
	char *drained = rz_strbuf_drain(sa);
	mu_assert_streq(drained, "food", "drained string");
	free(drained);

	// long string
	sa = rz_strbuf_new("");
	rz_strbuf_set(sa, "VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER");
	mu_assert_eq(rz_strbuf_length(sa), 46, "length from api");
	mu_assert_eq(sa->len, 46, "len of string");
	mu_assert_eq(sa->ptrlen, 47, "ptrlen of string");
	rz_strbuf_free(sa);

	sa = rz_strbuf_new("");
	rz_strbuf_set(sa, "VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER");
	drained = rz_strbuf_drain(sa);
	mu_assert_streq(drained, "VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", "drained string");
	free(drained);

	mu_end;
}

bool test_rz_strbuf_strong_binary(void) {
	RzStrBuf *sa = rz_strbuf_new("");
	bool res = rz_strbuf_setbin(sa, (const ut8 *)"food", 4);
	mu_assert("setbin success", res);
	mu_assert_memeq((const ut8 *)rz_strbuf_get(sa), (const ut8 *)"food", 4, "small binary data");
	mu_assert_eq(sa->len, 4, "len of binary data");
	rz_strbuf_free(sa);

	sa = rz_strbuf_new("");
	rz_strbuf_setbin(sa, (const ut8 *)"food", 4);
	char *drained = rz_strbuf_drain(sa);
	mu_assert_memeq((const ut8 *)drained, (const ut8 *)"food", 4, "drained binary data");
	free(drained);

	sa = rz_strbuf_new("");
	res = rz_strbuf_setbin(sa, (const ut8 *)"VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", 46);
	mu_assert("setbin success", res);
	mu_assert_memeq((const ut8 *)rz_strbuf_get(sa), (const ut8 *)"VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", 46, "big binary data");
	mu_assert_eq(sa->len, 46, "len of binary data");
	mu_assert_eq(sa->ptrlen, 47, "ptrlen of binary data");
	rz_strbuf_free(sa);

	sa = rz_strbuf_new("");
	rz_strbuf_setbin(sa, (const ut8 *)"VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", 46);
	drained = rz_strbuf_drain(sa);
	mu_assert_memeq((const ut8 *)drained, (const ut8 *)"VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", 46, "drained binary data");
	free(drained);

	mu_end;
}

bool test_rz_strbuf_weak_string(void) {
	// small string
	char *myptr = "food";
	RzStrBuf *sa = rz_strbuf_new("");
	rz_strbuf_setptr(sa, myptr, -1);
	mu_assert_eq(rz_strbuf_length(sa), 4, "length from api");
	mu_assert_eq(sa->len, 4, "len of string");
	mu_assert_eq(sa->ptrlen, 5, "len of string + 0");
	mu_assert_ptreq(rz_strbuf_get(sa), myptr, "weak ptr");
	rz_strbuf_free(sa);

	sa = rz_strbuf_new("");
	rz_strbuf_setptr(sa, myptr, -1);
	char *drained = rz_strbuf_drain(sa);
	mu_assert_memeq((const ut8 *)drained, (const ut8 *)"food", 4, "drained weak string");
	free(drained);

	// long string
	myptr = "VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER";
	sa = rz_strbuf_new("");
	rz_strbuf_setptr(sa, myptr, -1);
	mu_assert_eq(rz_strbuf_length(sa), 46, "length from api");
	mu_assert_eq(sa->len, 46, "len of string");
	mu_assert_eq(sa->ptrlen, 47, "len of string + 0");
	mu_assert_ptreq(rz_strbuf_get(sa), myptr, "weak ptr");
	rz_strbuf_free(sa);

	sa = rz_strbuf_new("");
	rz_strbuf_setptr(sa, myptr, -1);
	drained = rz_strbuf_drain(sa);
	mu_assert_memeq((const ut8 *)drained, (const ut8 *)"VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", 46, "drained weak string");
	free(drained);

	mu_end;
}

bool test_rz_strbuf_weak_binary(void) {
	char *myptr = "food";
	RzStrBuf *sa = rz_strbuf_new("");
	bool res = rz_strbuf_setptr(sa, myptr, 4);
	mu_assert("setbin success", res);
	mu_assert_ptreq(rz_strbuf_get(sa), myptr, "weak ptr");
	mu_assert_eq(sa->len, 4, "len of binary data");
	mu_assert_eq(sa->ptrlen, 4, "ptrlen of binary data");
	rz_strbuf_free(sa);

	sa = rz_strbuf_new("");
	rz_strbuf_setptr(sa, myptr, 4);
	char *drained = rz_strbuf_drain(sa);
	mu_assert_memeq((const ut8 *)drained, (const ut8 *)"food", 4, "drained binary data");
	free(drained);

	myptr = "VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER";
	sa = rz_strbuf_new("");
	res = rz_strbuf_setptr(sa, myptr, 46);
	mu_assert("setbin success", res);
	mu_assert_ptreq(rz_strbuf_get(sa), myptr, "weak ptr");
	mu_assert_eq(sa->len, 46, "len of binary data");
	mu_assert_eq(sa->ptrlen, 46, "ptrlen of binary data");
	rz_strbuf_free(sa);

	sa = rz_strbuf_new("");
	rz_strbuf_setptr(sa, myptr, 46);
	drained = rz_strbuf_drain(sa);
	mu_assert_memeq((const ut8 *)drained, (const ut8 *)"VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", 46, "drained binary data");
	free(drained);

	mu_end;
}

bool test_rz_strbuf_setbin(void) {
	RzStrBuf *sa = rz_strbuf_new("");
	rz_strbuf_setbin(sa, (const ut8 *)"inbuffffffff", 5);
	mu_assert_streq(rz_strbuf_get(sa), "inbuf", "setbin str with size");
	mu_assert_eq(rz_strbuf_length(sa), 5, "len from api");

	ut8 *buf = malloc(46); // alloc this on the heap to help valgrind and asan detect overflows
	memcpy(buf, "VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", 46);
	rz_strbuf_setbin(sa, buf, 46);
	mu_assert_memeq((const ut8 *)rz_strbuf_get(sa), buf, 46, "long binary");
	free(buf);
	mu_assert_eq(rz_strbuf_get(sa)[46], 0, "still null terminated");
	mu_assert_eq(rz_strbuf_length(sa), 46, "len from api");
	mu_assert_eq(sa->ptrlen, 46 + 1, "ptrlen");

	// reallocation
	buf = malloc(46 * 2);
	memcpy(buf, "VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFERVERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", 46 * 2);
	rz_strbuf_setbin(sa, buf, 46 * 2);
	mu_assert_memeq((const ut8 *)rz_strbuf_get(sa), buf, 46 * 2, "long binary");
	free(buf);
	mu_assert_eq(rz_strbuf_get(sa)[46 * 2], 0, "still null terminated");
	mu_assert_eq(rz_strbuf_length(sa), 46 * 2, "len from api");
	mu_assert_eq(sa->ptrlen, 46 * 2 + 1, "ptrlen");

	rz_strbuf_free(sa);
	mu_end;
}

bool test_rz_strbuf_set(void) {
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	const char *s = rz_strbuf_set(&sb, "I have packed only the essentials");
	mu_assert_notnull(s, "set return notnull");
	mu_assert_ptreq(s, rz_strbuf_get(&sb), "set return");
	mu_assert_streq(rz_strbuf_get(&sb), "I have packed only the essentials", "set");
	rz_strbuf_fini(&sb);
	mu_end;
}

bool test_rz_strbuf_setf(void) {
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	const char *s = rz_strbuf_setf(&sb, "One %s for hydration", "water");
	mu_assert_notnull(s, "setf return notnull");
	mu_assert_ptreq(s, rz_strbuf_get(&sb), "setf return");
	mu_assert_streq(rz_strbuf_get(&sb), "One water for hydration", "setf");
	rz_strbuf_fini(&sb);
	mu_end;
}

bool test_rz_strbuf_initf(void) {
	RzStrBuf sb;
	const char *s = rz_strbuf_initf(&sb, "hmmst, %s was that audial occurence? %d", "wat", 42);
	mu_assert_notnull(s, "initf return notnull");
	mu_assert_ptreq(s, rz_strbuf_get(&sb), "initf return");
	mu_assert_streq(rz_strbuf_get(&sb), "hmmst, wat was that audial occurence? 42", "initf");
	rz_strbuf_fini(&sb);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_strbuf_append);
	mu_run_test(test_rz_strbuf_strong_string);
	mu_run_test(test_rz_strbuf_strong_binary);
	mu_run_test(test_rz_strbuf_weak_string);
	mu_run_test(test_rz_strbuf_weak_binary);
	mu_run_test(test_rz_strbuf_slice);
	mu_run_test(test_rz_strbuf_setbin);
	mu_run_test(test_rz_strbuf_set);
	mu_run_test(test_rz_strbuf_setf);
	mu_run_test(test_rz_strbuf_initf);
	return tests_passed != tests_run;
}

mu_main(all_tests)