// SPDX-FileCopyrightText: 2015 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2015 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

typedef void (*RzAnalysisEsilPin)(RzAnalysis *a);

#if 0
// TODO: those hardcoded functions should go
/* default pins from libc */
static void pin_strlen(RzAnalysis *a) {
	// get a0 register
	// read memory and interpret it as a string
	// set a0 to the result of strlen;
	eprintf ("esilpin: strlen\n");
}

static void pin_write(RzAnalysis *a) {
	// get a0 register for fd
	// get a1 register for data
	// get a2 register for len
	// read len bytes from data and print them to screen + fd
	// set a0 to the result of write;
	eprintf ("esilpin: write\n");
}
#endif

/* pin api */

#define DB a->sdb_pins

RZ_API void rz_analysis_pin_init(RzAnalysis *a) {
	sdb_free(DB);
	DB = sdb_new0();
	//	sdb_ptr_set (DB, "strlen", pin_strlen, 0);
	//	sdb_ptr_set (DB, "write", pin_write, 0);
}

RZ_API void rz_analysis_pin_fini(RzAnalysis *a) {
	if (sdb_free(DB)) {
		DB = NULL;
	}
}

RZ_API void rz_analysis_pin(RzAnalysis *a, ut64 addr, const char *name) {
	char buf[64];
	const char *key = sdb_itoa(addr, buf, 16);
	sdb_set(DB, key, name, 0);
}

RZ_API void rz_analysis_pin_unset(RzAnalysis *a, ut64 addr) {
	char buf[64];
	const char *key = sdb_itoa(addr, buf, 16);
	sdb_unset(DB, key, 0);
}

RZ_API const char *rz_analysis_pin_call(RzAnalysis *a, ut64 addr) {
	char buf[64];
	const char *key = sdb_itoa(addr, buf, 16);
	if (key) {
		return sdb_const_get(DB, key, NULL);
#if 0
		const char *name;
		if (name) {
			RzAnalysisEsilPin fcnptr = (RzAnalysisEsilPin)
				sdb_ptr_get (DB, name, NULL);
			if (fcnptr) {
				fcnptr (a);
				return true;
			}
		}
#endif
	}
	return NULL;
}

static bool cb_list(void *user, const char *k, const char *v) {
	RzAnalysis *a = (RzAnalysis *)user;
	if (*k == '0') {
		// bind
		a->cb_printf("%s = %s\n", k, v);
	} else {
		// ptr
		a->cb_printf("PIN %s\n", k);
	}
	return true;
}

RZ_API void rz_analysis_pin_list(RzAnalysis *a) {
	sdb_foreach(DB, cb_list, a);
}
