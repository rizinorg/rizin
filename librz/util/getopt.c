// SPDX-FileCopyrightText: 1987, 1993, 1994 The Regents of the University of California
// SPDX-FileCopyrightText: 2019-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

/*
 * Copyright (c) 1987, 1993, 1994
 * The Regents of the University of California.  All rights reserved.
 * $Id: getopt.c,v 1.2 1998/01/21 22:27:05 billm Exp $ *
 */

#include "rz_util/rz_log.h"
#include "rz_util/rz_str.h"
#include <rz_util.h>

#define BADCH  (int)'?'
#define BADARG (int)':'
#define EMSG   ""

static bool longopt_has_values(const RzGetoptLong *desc) {
	return !rz_pvector_empty(desc->values);
}

static bool longopt_value_allowed(const RzGetoptLong *desc, const char *value) {
	if (!value || !*value) {
		return false;
	}
	void **it;
	rz_pvector_foreach (desc->values, it) {
		if (RZ_STR_EQ(*it, value)) {
			return true;
		}
	}
	return false;
}

static int rz_getopt_long_next(RzGetopt *opt, const char *arg) {
	const char *name = arg + 2;
	const RzGetoptLong *desc = NULL;

	RzGetoptLong *it;
	rz_vector_foreach (opt->longopts, it) {
		if (RZ_STR_EQ(name, it->name)) {
			desc = it;
			break;
		}
	}
	if (!desc) {
		opt->opt = '-';
		opt->ind++;
		if (opt->err && *opt->ostr != ':') {
			RZ_LOG_ERROR("%s: illegal option -- %s\n", opt->argv[0], name);
		}
		return BADCH;
	}

	const bool has_values = longopt_has_values(desc);
	if (!has_values) {
		opt->arg = NULL;
		opt->ind++;
		return desc->val;
	}

	const char *value = NULL;
	bool consume_value = false;
	if (opt->ind + 1 < opt->argc) {
		value = opt->argv[opt->ind + 1];
		consume_value = true;
	} else {
		value = desc->default_value;
	}

	if (!longopt_value_allowed(desc, value)) {
		opt->opt = '-';
		opt->ind += consume_value && !rz_str_startswith(value, "--") ? 2 : 1;
		if (opt->err && *opt->ostr != ':') {
			RZ_LOG_ERROR("%s: invalid argument '%s' for option -- %s\n", opt->argv[0], value ? value : "", desc->name);
		}
		return BADCH;
	}

	opt->arg = value;
	opt->ind += consume_value ? 2 : 1;
	return desc->val;
}

RZ_API void rz_getopt_init_long(RzGetopt *opt, int argc, const char **argv, const char *ostr, const RzVector *longopts) {
	memset(opt, 0, sizeof(RzGetopt));
	opt->err = 1;
	opt->ind = 1;
	opt->opt = 0;
	opt->reset = 0;
	opt->arg = NULL;
	opt->place = EMSG;
	opt->argc = argc;
	opt->argv = argv;
	opt->ostr = ostr;
	opt->longopts = longopts;
}

RZ_API void rz_getopt_init(RzGetopt *opt, int argc, const char **argv, const char *ostr) {
	rz_getopt_init_long(opt, argc, argv, ostr, NULL);
}

RZ_API int rz_getopt_next(RzGetopt *opt) {
	const char *oli; // option letter list index

	if (opt->reset || !*opt->place) { // update scanning pointer
		opt->reset = 0;
		if (opt->ind >= opt->argc) {
			opt->place = EMSG;
			return -1;
		}
		opt->place = opt->argv[opt->ind];
		if (!rz_str_startswith(opt->place, "-")) {
			opt->place = EMSG;
			return -1;
		}
		// found "--", either a long option or an error
		if (rz_str_startswith(opt->place, "--")) {
			// are long options enabled and more text exists after the "--" ?
			if (opt->longopts && strlen(opt->place) > 2) {
				int ret = rz_getopt_long_next(opt, opt->place);
				opt->place = EMSG;
				return ret;
			}
			// otherwise an error
			opt->ind++;
			opt->place = EMSG;
			return -1;
		}
		if (opt->place[1]) {
			opt->place++;
		}
	}
	/* option letter okay? */
	if ((opt->opt = (int)*opt->place++) == (int)':' || !(oli = strchr(opt->ostr, opt->opt))) {
		/*
		 * if the user didn't specify '-' as an option,
		 * assume it means -1.
		 */
		if (opt->opt == (int)'-') {
			opt->ind++;
			if (rz_getopt_next(opt) == -1) {
				opt->ind--;
				return -1;
			}

			return '-';
		}
		if (!*opt->place) {
			opt->ind++;
		}
		if (opt->err && *opt->ostr != ':') {
			RZ_LOG_ERROR("%s: illegal option -- %c\n", opt->argv[0], opt->opt);
		}
		return BADCH;
	}
	if (*++oli == ':') { /* need argument */
		if (*opt->place) { /* no white space */
			opt->arg = opt->place;
		} else if (opt->argc <= ++opt->ind) { /* no arg */
			opt->place = EMSG;
			if (*opt->ostr == ':') {
				return BADARG;
			}
			if (opt->err) {
				RZ_LOG_ERROR("%s: option requires an argument -- %c\n", opt->argv[0], opt->opt);
			}
			return BADCH;
		} else { /* white space */
			opt->arg = opt->argv[opt->ind];
		}
		opt->place = EMSG;
		opt->ind++;
	} else {
		opt->arg = NULL;
		if (!*opt->place) {
			opt->ind++;
		}
	}
	// dump back option letter
	return opt->opt;
}
