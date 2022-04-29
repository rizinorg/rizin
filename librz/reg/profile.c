// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_list.h>
#include <rz_util/rz_str.h>
#include <rz_reg.h>
#include <rz_util.h>
#include <rz_util/rz_assert.h>
#include <rz_lib.h>

/**
 * \brief Parses a register alias.
 *
 * The alias is of the form:
 * =<alias>  <reg name>
 *
 * \param reg 
 * \param tok
 * \param n
 * \return true 
 * \return false 
 */
static bool parse_alias(RZ_OUT RzReg *reg, char **tok, const int n) {
	rz_return_val_if_fail(reg && tok, false);
	if (n == 2) {
		int role = rz_reg_get_name_idx(tok[0] + 1);
		if (rz_reg_set_name(reg, role, tok[1])) {
			return true;
		}
		RZ_LOG_WARN("Invalid alias\n");
		return false;
	}
	RZ_LOG_WARN("Invalid syntax\n");
	return false;
}

// Sizes prepended with a dot are expressed in bits
// strtoul with base 0 allows the input to be in decimal/octal/hex format

static ut64 parse_size(char *s) {
	if (*s == '.') {
		return strtoul(s + 1, NULL, 0);
	} else {
		RZ_LOG_WARN("Could not parse size \"%s\".\n", s);
		return 0;
	}
}

/**
 * \brief Parses the offset of a register defintion.
 *
 * Offset is of the form: <byte>.<bit>
 * .<bit> is optional.
 *
 * \param s Size string.
 * \param item RzRegItem to store the size values.
 */
static void parse_offset(const char *s, RZ_OUT RzRegItem *item) {
	char *bit_offset = strchr(s, '.') + 1;
	if (bit_offset) {
		item->offset_bit = strtoul(bit_offset, NULL, 0);
	}
	item->offset = strtoul(s, NULL, 0);
}

/**
 * \brief Parses a register definition.
 *
 * \param reg Register struct which holds all register items.
 * \param def List of defintion string tokens.
 * \param n Number of columns in the register definition.
 * \return const char* NULL on success. 
 */
static bool parse_def(RZ_INOUT RzReg *reg, RZ_OWN RzList *def) {
	char *end;
	int type, type2;
	RzList *toks = rz_str_split_list(def, "\t", 0);

	char *p = strchr(tok[0], '@');
	if (p) {
		char *tok0 = strdup(tok[0]);
		char *at = tok0 + (p - tok[0]);
		*at++ = 0;
		type = rz_reg_type_by_name(tok0);
		type2 = rz_reg_type_by_name(at);
		free(tok0);
	} else {
		type2 = type = rz_reg_type_by_name(tok[0]);
		/* Hack to put flags in the same arena as gpr */
		if (type == RZ_REG_TYPE_FLG) {
			type2 = RZ_REG_TYPE_GPR;
		}
	}
	if (type < 0 || type2 < 0) {
		RZ_LOG_WARN("Invalid register type.\n");
		return false;
	}
#if 1
	if (rz_reg_get(reg, tok[1], RZ_REG_TYPE_ANY)) {
		RZ_LOG_WARN("Ignoring duplicated register definition '%s'.\n", tok[1]);
		return true;
	}
#endif

	RzRegItem *item = RZ_NEW0(RzRegItem);
	if (!item) {
		RZ_LOG_WARN("Unable to allocate memory.\n");
		return false;
	}

	item->type = type;
	item->name = strdup(tok[1]);
	// All the numeric arguments are strictly checked
	item->size = parse_size(tok[2], &end);
	if (*end != '\0' || !item->size) {
		rz_reg_item_free(item);
		RZ_LOG_WARN("Invalid size.\n");
		return false;
	}
	if (!strcmp(tok[3], "?")) {
		item->offset = -1;
	} else {
		item->offset = parse_size(tok[3], &end);
	}
	if (*end != '\0') {
		rz_reg_item_free(item);
		RZ_LOG_WARN("Invalid offset.\n");
		return false;
	}
	item->packed_size = parse_size(tok[4], &end);
	if (*end != '\0') {
		rz_reg_item_free(item);
		RZ_LOG_WARN("Invalid packed size.\n");
		return false;
	}

	// Dynamically update the list of supported bit sizes
	reg->bits |= item->size;

	// This is optional
	if (n == 6) {
		if (*tok[5] == '#') {
			// Remove # from the comment
			item->comment = strdup(tok[5] + 1);
		} else {
			item->flags = strdup(tok[5]);
		}
	}

	item->arena = type2;
	if (!reg->regset[type2].regs) {
		reg->regset[type2].regs = rz_list_newf((RzListFree)rz_reg_item_free);
	}
	rz_list_append(reg->regset[type2].regs, item);
	if (!reg->regset[type2].ht_regs) {
		reg->regset[type2].ht_regs = ht_pp_new0();
	}
	ht_pp_insert(reg->regset[type2].ht_regs, item->name, item);

	// Update the overall profile size
	if (item->offset + item->size > reg->size) {
		reg->size = item->offset + item->size;
	}
	// Update the overall type of registers into a regset
	reg->regset[type2].maskregstype |= ((int)1 << type);
	return true;
}

/**
 * \brief 
 *
 * A register definition string is of the following form:
 * "<type>  <name>  .<size>  <byte offset>(.<bit offset>)  <init val>  (# <comment>)\n"
 *
 * Elements in "()" are optional.
 * Separators are tab characters.
 *
 * type: Register type: gpr, fpr, ctr, flg etc.
 * name: Register name.
 * size: Register size in bits (decimal).
 * byte offset: Offset into register profile in bytes (decimal).
 * bit offset: Offset into the byte offset in bits (decimal).
 * init val: Value the register is initialized with (decimal).
 * comment: A comment about the register.
 *
 * \param reg
 * \param profile
 * \return RZ_API 
 */
RZ_API bool rz_reg_set_profile_string(RzReg *reg, const char *profile) {
	rz_return_val_if_fail(reg && profile, false);

	// Same profile, no need to change
	if (reg->reg_profile_str && !strcmp(reg->reg_profile_str, str)) {
		return true;
	}

	// we should reset all the arenas before setting the new reg profile
	rz_reg_arena_pop(reg);
	// Purge the old registers
	rz_reg_free_internal(reg, true);
	rz_reg_arena_shrink(reg);

	// Cache the profile string
	reg->reg_profile_str = strdup(str);

	RzList *def_lines = rz_str_split_lines(str, "\n", NULL);
	rz_return_val_if_fail(def_lines, false);

	st32 l = 0; // Line number
	const char *line;
	bool is_alias = false;
	RzListIter *it;
	rz_list_foreach(def_lines, it, line) {
		++l;
		RzList toks = rz_str_split_list(it->data, "\t", 0);
		ut32 toks_len = rz_list_length(toks);

		const char *first_tok = rz_list_get_top(toks); // First token the line.
		if (first_tok[0] == '#') { // Comment line
			continue;
		} else if (first_tok[0] == '=') { // Alias
			if (toks_len != 2) {
				RZ_LOG_WARN("Invalid number of %d columns in alias \"%s\" at line %d. 2 needed.", toks_len, l, line);
				continue;
			}
			is_alias = true;
		} else if (first_tok[0] == '\n') { // Empty line
			continue;
		} else {
			if (toks_len != 5 || toks_len != 6) {
				RZ_LOG_WARN("Invalid number of %d columns in definition \"%s\" at line %d. 5 or 6 needed.", toks_len, l, line);
				continue;
			}
		}
		bool success = is_alias
			? parse_alias(reg, toks)
			: parse_def(reg, toks);

		if (!success) {
			RZ_LOG_WARN("Parsing error in \"%s\" at line %d of register profile.\n", line, l);
			rz_reg_free_internal(reg, false);
			rz_list_free(toks);
			rz_list_free(def_lines);
			return false;
		}
	}
	rz_list_free(toks);
	rz_list_free(def_lines);

	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		RzRegSet *rs = &reg->regset[i];
		if (rs && rs->arena) {
			reg->size += rs->arena->size;
		}
	}

	// TODO Remove? byte size and bit size is now separated.
	// reg->size >>= 3; // bits to bytes (divide by 8)
	rz_reg_fit_arena(reg);
	// dup the last arena to allow regdiffing
	rz_reg_arena_push(reg);
	rz_reg_reindex(reg);
	// reset arenas
	return true;
}

RZ_API bool rz_reg_set_profile(RzReg *reg, const char *profile) {
	rz_return_val_if_fail(reg && profile, false);
	char *base, *file;
	char *str = rz_file_slurp(profile, NULL);
	if (!str) {
		base = rz_sys_getenv(RZ_LIB_ENV);
		if (base) {
			file = rz_str_append(base, profile);
			str = rz_file_slurp(file, NULL);
			free(file);
		}
	}
	if (!str) {
		eprintf("rz_reg_set_profile: Cannot find '%s'\n", profile);
		return false;
	}
	bool ret = rz_reg_set_profile_string(reg, str);
	free(str);
	return ret;
}

static char *gdb_to_rz_profile(const char *gdb) {
	rz_return_val_if_fail(gdb, NULL);
	RzStrBuf *sb = rz_strbuf_new("");
	if (!sb) {
		return NULL;
	}
	char *ptr1, *gptr, *gptr1;
	char name[16], groups[128], type[16];
	const int all = 1, gpr = 2, save = 4, restore = 8, float_ = 16,
		  sse = 32, vector = 64, system = 128, mmx = 256;
	int number, rel, offset, size, type_bits, ret;
	// Every line is -
	// Name Number Rel Offset Size Type Groups
	const char *ptr = rz_str_trim_head_ro(gdb);

	// It's possible someone includes the heading line too. Skip it
	if (rz_str_startswith(ptr, "Name")) {
		if (!(ptr = strchr(ptr, '\n'))) {
			rz_strbuf_free(sb);
			return NULL;
		}
		ptr++;
	}
	for (;;) {
		// Skip whitespace at beginning of line and empty lines
		while (isspace((ut8)*ptr)) {
			ptr++;
		}
		if (!*ptr) {
			break;
		}
		if ((ptr1 = strchr(ptr, '\n'))) {
			*ptr1 = '\0';
		} else {
			eprintf("Could not parse line: %s (missing \\n)\n", ptr);
			rz_strbuf_free(sb);
			return false;
		}
		ret = sscanf(ptr, " %s %d %d %d %d %s %s", name, &number, &rel,
			&offset, &size, type, groups);
		// Groups is optional, others not
		if (ret < 6) {
			if (*ptr != '*') {
				eprintf("Could not parse line: %s\n", ptr);
				rz_strbuf_free(sb);
				return NULL;
			}
			ptr = ptr1 + 1;
			continue;
		}
		// If name is '', then skip
		if (rz_str_startswith(name, "''")) {
			if (!ptr1) {
				break;
			}
			ptr = ptr1 + 1;
			continue;
		}
		// If size is 0, skip
		if (size == 0) {
			if (!ptr1) {
				break;
			}
			ptr = ptr1 + 1;
			continue;
		}
		// Parse group
		gptr = groups;
		type_bits = 0;
		while (1) {
			if ((gptr1 = strchr(gptr, ','))) {
				*gptr1 = '\0';
			}
			if (rz_str_startswith(gptr, "general")) {
				type_bits |= gpr;
			} else if (rz_str_startswith(gptr, "all")) {
				type_bits |= all;
			} else if (rz_str_startswith(gptr, "save")) {
				type_bits |= save;
			} else if (rz_str_startswith(gptr, "restore")) {
				type_bits |= restore;
			} else if (rz_str_startswith(gptr, "float")) {
				type_bits |= float_;
			} else if (rz_str_startswith(gptr, "sse")) {
				type_bits |= sse;
			} else if (rz_str_startswith(gptr, "mmx")) {
				type_bits |= mmx;
			} else if (rz_str_startswith(gptr, "vector")) {
				type_bits |= vector;
			} else if (rz_str_startswith(gptr, "system")) {
				type_bits |= system;
			}
			if (!gptr1) {
				break;
			}
			gptr = gptr1 + 1;
		}
		// If type is not defined, skip
		if (!*type) {
			if (!ptr1) {
				break;
			}
			ptr = ptr1 + 1;
			continue;
		}
		// TODO: More mappings between gdb and rizin reg groups. For now, either fpu or gpr
		if (!(type_bits & sse) && !(type_bits & float_)) {
			type_bits |= gpr;
		}
		// Print line
		rz_strbuf_appendf(sb, "%s\t%s\t.%d\t%d\t0\n",
			// Ref: Comment above about more register type mappings
			((type_bits & mmx) || (type_bits & float_) || (type_bits & sse)) ? "fpu" : "gpr",
			name, size * 8, offset);
		// Go to next line
		if (!ptr1) {
			break;
		}
		ptr = ptr1 + 1;
		continue;
	}
	return rz_strbuf_drain(sb);
}

RZ_API char *rz_reg_parse_gdb_profile(const char *profile_file) {
	char *str = NULL;
	if (!(str = rz_file_slurp(profile_file, NULL))) {
		char *base = rz_sys_getenv(RZ_LIB_ENV);
		if (base) {
			char *file = rz_str_appendf(base, RZ_SYS_DIR "%s", profile_file);
			if (file) {
				str = rz_file_slurp(file, NULL);
				free(file);
			}
		}
	}
	if (str) {
		char *ret = gdb_to_rz_profile(str);
		free(str);
		return ret;
	}
	eprintf("rz_reg_parse_gdb_profile: Cannot find '%s'\n", profile_file);
	return NULL;
}

RZ_API char *rz_reg_profile_to_cc(RzReg *reg) {
	const char *r0 = rz_reg_get_name_by_type(reg, "R0");
	const char *a0 = rz_reg_get_name_by_type(reg, "A0");
	const char *a1 = rz_reg_get_name_by_type(reg, "A1");
	const char *a2 = rz_reg_get_name_by_type(reg, "A2");
	const char *a3 = rz_reg_get_name_by_type(reg, "A3");

	// it is mandatory to have at least =A0 defined in the reg profile
	// this will be enforced in reg/profile at parsing time
	rz_return_val_if_fail(a0, NULL);
	if (!r0) {
		r0 = a0;
	}
	if (a3 && a2 && a1) {
		return rz_str_newf("%s reg(%s, %s, %s, %s)", r0, a0, a1, a2, a3);
	}
	if (a2 && a1) {
		return rz_str_newf("%s reg(%s, %s, %s)", r0, a0, a1, a2);
	}
	if (a1) {
		return rz_str_newf("%s reg(%s, %s)", r0, a0, a1);
	}
	return rz_str_newf("%s reg(%s)", r0, a0);
}
