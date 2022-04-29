// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_list.h>
#include <rz_util/rz_log.h>
#include <rz_util/rz_str.h>
#include <rz_reg.h>
#include <rz_util.h>
#include <rz_util/rz_assert.h>
#include <rz_lib.h>

/**
 * \brief Parses a register alias.
 *
 * The alias is of the form:
 * "=<alias>  <reg name>"
 *
 * \param reg
 * \param tok
 * \return true
 * \return false
 */
static bool parse_alias(RZ_OUT RzReg *reg, RZ_BORROW RzList *tokens) {
	rz_return_val_if_fail(reg && tokens, false);
	const char *alias = rz_list_get_n(tokens, 0);
	const char *target = rz_list_get_n(tokens, 1);
	if (!alias) {
		RZ_LOG_WARN("Failed to get alias name from token.\n")
		return false;
	}
	RzRegisterId role = rz_reg_get_name_idx(alias + 1);
	if (rz_reg_set_name(reg, role, target)) {
		return true;
	}
	RZ_LOG_WARN("Invalid alias\n");
	return false;
}

static bool parse_type(RZ_OUT RzRegItem *item, const char *type_str) {
	rz_return_val_if_fail(item && type_str, false);
	char *s = strdup(type_str);

	char *at = strchr(s, '@');
	if (at) {
		// This register has a secondary type e.g. xmm@fpu
		item->second_type = rz_reg_type_by_name(at + 1);
		if (item->second_type < 0) {
			RZ_LOG_WARN("Illegal secondary type appreviation \"%s\"\n", s);
			free(s);
			return false;
		}
		s[at - s] = '\0';
		item->type = rz_reg_type_by_name(s);
	} else {
		item->type = rz_reg_type_by_name(s);
	}
	/* Hack to put flags in the same arena as gpr */
	if (item->type == RZ_REG_TYPE_FLG) {
		item->second_type = RZ_REG_TYPE_GPR;
	}
	if (item->type < 0) {
		RZ_LOG_WARN("Illegal type appreviation \"%s\"\n", s);
		free(s);
		return false;
	}
	free(s);
	return true;
}

// Sizes prepended with a dot are expressed in bits
// strtoul with base 0 allows the input to be in decimal/octal/hex format

static ut64 parse_size(char *s) {
	rz_return_val_if_fail(s, -1);
	if (s[0] == '.') {
		return strtoul(s + 1, NULL, 0);
	} else { // packed size.
		return strtoul(s, NULL, 0);
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
	rz_return_if_fail(s && item);
	if (s[0] == '?') {
		item->offset = -1;
	}
	item->offset = strtoul(s, NULL, 0) * 8;
	if (item->offset < 0) {
		return;
	}
	const char *bi = strchr(s, '.');
	if (!bi) {
		return;
	}
	ut8 bit_offset = strtoul(bi + 1, NULL, 0);
	if (bit_offset < 0) {
		RZ_LOG_WARN("Bit offset should not be negative.\n");
		item->offset = -1;
		return;
	}
	item->offset += bit_offset;
}

/**
 * \brief Parses a register definition.
 *
 * \param reg Register struct which holds all register items.
 * \param tokens List of defintion string tokens.
 * \return bool True on success, False otherwise.
 */
static bool parse_def(RZ_INOUT RzReg *reg, RZ_OWN RzList *tokens) {
	rz_return_val_if_fail(reg && tokens, false);

	const char *name = rz_list_get_n(tokens, 1);
	rz_return_val_if_fail(name, false);
	if (rz_reg_get(reg, name, RZ_REG_TYPE_ANY)) {
		RZ_LOG_WARN("Ignoring duplicated register definition '%s'.\n", name);
		return true;
	}

	RzRegItem *item = RZ_NEW0(RzRegItem);
	if (!item) {
		RZ_LOG_WARN("Unable to allocate memory.\n");
		return false;
	}
	item->name = strdup(name);

	if (!parse_type(item, rz_list_get_n(tokens, 0))) {
		RZ_LOG_WARN("Invalid register type.\n");
		goto reg_parse_error;
	}

	item->size = parse_size(rz_list_get_n(tokens, 2));
	if (item->size <= 0) {
		RZ_LOG_WARN("Invalid register size.\n");
		goto reg_parse_error;
	}

	parse_offset(rz_list_get_n(tokens, 3), item);
	if (item->offset < 0) {
		RZ_LOG_WARN("Invalid register offset.\n");
		goto reg_parse_error;
	}

	item->packed_size = parse_size(rz_list_get_n(tokens, 4));
	if (item->packed_size < 0) {
		RZ_LOG_WARN("Invalid register packed size.\n");
		goto reg_parse_error;
	}

	// Dynamically update the list of supported bit sizes
	reg->bits |= item->size;

	// Comments and flags are optional
	if (rz_list_length(tokens) == 6) {
		const char *comment_flag = rz_list_get_n(tokens, 5);
		rz_return_val_if_fail(comment_flag, false);
		if (comment_flag[0] == '#') {
			// Remove # from the comment
			item->comment = strdup(comment_flag + 1);
		} else {
			item->flags = strdup(comment_flag);
		}
	}

	item->arena = item->type;
	if (!reg->regset[item->type].regs) {
		reg->regset[item->type].regs = rz_list_newf((RzListFree)rz_reg_item_free);
	}
	rz_list_append(reg->regset[item->type].regs, item);
	if (!reg->regset[item->type].ht_regs) {
		reg->regset[item->type].ht_regs = ht_pp_new0();
	}
	ht_pp_insert(reg->regset[item->type].ht_regs, item->name, item);

	// Update the overall profile size
	if (item->offset + item->size > reg->size) {
		reg->size = item->offset + item->size;
	}
	// Update the overall type of registers into a regset
	reg->regset[item->type].maskregstype |= ((int)1 << item->second_type);

	return true;

reg_parse_error:
	rz_reg_item_free(item);
	return false;
}

/**
 * \brief Parses a register profile. Each line is either a register alias or a register definiton.
 *
 * A register alias string is of the following form:
 * "=<alias>  <name>\n"
 *
 * A register definition string is of the following form:
 * "<type>(@type2)  <name>  .<size>  <byte offset>(.<bit offset>)  <packed val>  (# <comment>)\n"
 *
 * Elements in "()" are optional.
 * Each "<...>" token is separated by a tab character.
 *
 * alias: Register alias (e.g. PC, A1 etc.)
 * type: Register type: gpr, fpr, ctr, flg etc.
 * type2: The second register type. This is the main type (e.g. fpu is main, xmm is secondary = xmm@fpu)
 * name: Register name.
 * size: Register size in bits.
 * byte offset: Offset into register profile in bytes.
 * bit offset: Offset into the byte offset in bits.
 * packed val: Packed size of the register in bytes.
 * comment: A comment about the register.
 *
 * \param reg
 * \param profile
 * \return bool
 */
RZ_API bool rz_reg_set_profile_string(RzReg *reg, const char *profile) {
	rz_return_val_if_fail(reg && profile, false);

	// Same profile, no need to change
	if (reg->reg_profile_str && !strcmp(reg->reg_profile_str, profile)) {
		return true;
	}

	// we should reset all the arenas before setting the new reg profile
	rz_reg_arena_pop(reg);
	// Purge the old registers
	rz_reg_free_internal(reg, true);
	rz_reg_arena_shrink(reg);

	// Cache the profile string
	reg->reg_profile_str = strdup(profile);

	RzList *def_lines = rz_str_split_duplist_n(profile, "\n", 0, true);
	rz_return_val_if_fail(def_lines, false);

	st32 l = 0; // Line number
	const char *line;
	bool is_alias = false;
	RzListIter *it;
	RzList *toks = NULL;
	rz_list_foreach (def_lines, it, line) {
		if (strcmp(line, "") == 0) {
			continue;
		}
		++l;
		toks = rz_str_split_duplist_n(line, "\t", 0, true);
		if (!toks) {
			continue;
		}
		ut32 toks_len = rz_list_length(toks);

		const char *first_tok = rz_list_get_n(toks, 0); // First token of the line.
		if (first_tok[0] == '#') { // Comment line
			continue;
		} else if (first_tok[0] == '=') { // Alias
			if (toks_len != 2) {
				RZ_LOG_WARN("Invalid number of %d columns in alias \"%s\" at line %d. 2 needed.\n", toks_len, line, l);
				continue;
			}
			is_alias = true;
		} else if (isalpha(first_tok[0])) {
			if (toks_len != 5 && toks_len != 6) {
				RZ_LOG_WARN("Invalid number of %d columns in definition \"%s\" at line %d. 5 or 6 needed.\n", toks_len, line, l);
				continue;
			}
		} else {
			RZ_LOG_WARN("Invalid line \"%s\" at register profiles line %d.\n", line, l);
			continue;
		}
		bool success = is_alias
			? parse_alias(reg, toks)
			: parse_def(reg, toks);
		if (!success) {
			RZ_LOG_WARN("Parsing error in \"%s\" at line %d.\n", line, l);
			rz_reg_free_internal(reg, false);
			rz_list_free(toks);
			rz_list_free(def_lines);
			return false;
		}
		is_alias = false;
		rz_list_free(toks);
	}
	rz_list_free(def_lines);

	reg->size = 0;
	for (ut32 i = 0; i < RZ_REG_TYPE_LAST; i++) {
		RzRegSet *rs = &reg->regset[i];
		if (rs && rs->arena) {
			reg->size += rs->arena->size;
		}
	}

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

	if (!a0) {
		RZ_LOG_WARN("It is mandatory to have at least one argument register defined in the register profile.\n");
		return NULL;
	}
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
