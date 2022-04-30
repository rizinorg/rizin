// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_list.h>
#include <rz_util/rz_log.h>
#include <rz_util/rz_str.h>
#include <rz_reg.h>
#include <rz_util.h>
#include <rz_util/rz_assert.h>
#include <rz_lib.h>
#include <string.h>

static void rz_reg_profile_def_free(RzRegProfileDef *def) {
	if (!def) {
		return;
	}
	if (def->name) {
		free(def->name);
	}
	if (def->comment) {
		free(def->comment);
	}
	if (def->flags) {
		free(def->flags);
	}
	free(def);
}

static void rz_reg_profile_alias_free(RzRegProfileAlias *alias) {
	if (!alias) {
		return;
	}
	if (alias->reg_name) {
		free(alias->reg_name);
	}
	if (alias->alias) {
		free(alias->alias);
	}
	free(alias);
}

/**
 * \brief Parses a register type string.
 *
 * The type string must be of the following form:
 *
 * <sub-type>@<main-type>
 *
 * "<sub-type>@" is optional.
 *
 * \param item Register item whichs types are set.
 * \param type_str The type string.
 * \return true On success.
 * \return false On failure.
 */
static bool parse_type(RZ_OUT RzRegProfileDef *def, const char *type_str) {
	rz_return_val_if_fail(def && type_str, false);
	char *s = strdup(type_str);

	char *at = strchr(s, '@');
	if (at) {
		// This register has a secondary type e.g. xmm@fpu
		def->sub_type = rz_reg_type_by_name(at + 1);
		if (def->sub_type < 0) {
			RZ_LOG_WARN("Illegal secondary type appreviation \"%s\"\n", s);
			free(s);
			return false;
		}
		s[at - s] = '\0';
		def->type = rz_reg_type_by_name(s);
	} else {
		def->type = rz_reg_type_by_name(s);
	}
	if (def->type < 0) {
		RZ_LOG_WARN("Illegal type appreviation \"%s\"\n", s);
		free(s);
		return false;
	}
	free(s);
	return true;
}

/**
 * \brief Parses the size of a register definition.
 * Sizes with . in fornt are in bits. Otherwise in bytes.
 *
 * \param s Size string.
 * \return ut32 The size as integer or UT64_MAX if it fails.
 */
static ut32 parse_size(char *s) {
	rz_return_val_if_fail(s, UT32_MAX);
	if (s[0] == '.') {
		return strtoul(s + 1, NULL, 0);
	} else { // packed size.
		return strtoul(s, NULL, 0);
	}
}

/**
 * \brief Parses the offset of a register defintion and sets the offset in \p def->offset.
 *
 * Offset is of the form: <byte>.<bit>
 * .<bit> is optional.
 *
 * \param s Offset string.
 * \param def The defintion item to store the offset into \p def->offset in bits.
 * \return false On failure (sets def->offset = UT32_MAX).
 * \return true On success.
 */
static bool parse_offset(const char *s, RZ_OUT RzRegProfileDef *def) {
	rz_return_val_if_fail(s && def, false);
	if (s[0] == '?') {
		def->offset = -1;
		return true;
	}
	def->offset = strtoul(s, NULL, 0) * 8;

	const char *bi = strchr(s, '.');
	if (!bi) {
		// No bit offset given.
		return true;
	}

	ut8 bit_offset = strtoul(bi + 1, NULL, 0);
	def->offset += bit_offset;
	return true;
}

/**
 * \brief Parses a register alias.
 *
 * The alias is of the form:
 * "=<alias>  <reg name>"
 *
 * \param reg The RzReg struct with the register profile.
 * \param tokens A list with both tokens of the alias string.
 * \return true On success.
 * \return false On Failure.
 */
static bool parse_alias(RZ_OUT RzReg *reg, RZ_BORROW RzList *tokens) {
	rz_return_val_if_fail(reg && tokens, false);
	RzRegProfileAlias *pa = RZ_NEW0(RzRegProfileAlias);
	if (!pa) {
		RZ_LOG_WARN("Unable to allocate memory.\n");
		return false;
	}

	const char *real_name = rz_list_get_n(tokens, 1);
	const char *alias = rz_list_get_n(tokens, 0);
	if (!alias) {
		RZ_LOG_WARN("Failed to get alias name from token.\n")
		return false;
	}

	RzRegisterId role = rz_reg_get_name_idx(alias + 1);
	if (!(role >= 0 && role < RZ_REG_NAME_LAST)) {
		RZ_LOG_WARN("Invalid alias\n");
		return false;
	}

	pa->alias = strdup(alias);
	pa->reg_name = strdup(real_name);
	pa->role = role;
	rz_list_append(reg->reg_profile->alias, pa);

	return true;
}

/**
 * \brief Parses a register definition.
 *
 * \param reg Register struct with the register profile.
 * \param tokens List of strings of a single register definition.
 * \return false On failure.
 * \return true On success.
 */
static bool parse_def(RZ_INOUT RzReg *reg, RZ_OWN RzList *tokens) {
	rz_return_val_if_fail(reg && tokens, false);

	const char *name = rz_list_get_n(tokens, 1);
	rz_return_val_if_fail(name, false);
	if (rz_reg_get(reg, name, RZ_REG_TYPE_ANY)) {
		RZ_LOG_WARN("Ignoring duplicated register definition '%s'.\n", name);
		return true;
	}

	RzRegProfileDef *def = RZ_NEW0(RzRegProfileDef);
	if (!def) {
		RZ_LOG_WARN("Unable to allocate memory.\n");
		return false;
	}
	def->name = strdup(name);

	if (!parse_type(def, rz_list_get_n(tokens, 0))) {
		RZ_LOG_WARN("Invalid register type.\n");
		goto reg_parse_error;
	}

	def->size = parse_size(rz_list_get_n(tokens, 2));
	if (def->size == UT32_MAX || def->size == 0) {
		RZ_LOG_WARN("Invalid register size.\n");
		goto reg_parse_error;
	}

	def->packed = parse_size(rz_list_get_n(tokens, 4));
	if (def->packed == UT32_MAX) {
		RZ_LOG_WARN("Invalid register packed size.\n");
		goto reg_parse_error;
	}

	if (!parse_offset(rz_list_get_n(tokens, 3), def)) {
		RZ_LOG_WARN("Invalid register offset.\n");
		goto reg_parse_error;
	}

	// Comments and flags are optional
	if (rz_list_length(tokens) == 6) {
		const char *comment_flag = rz_list_get_n(tokens, 5);
		rz_return_val_if_fail(comment_flag, false);
		if (comment_flag[0] == '#') {
			// Remove # from the comment
			def->comment = strdup(comment_flag + 1);
		} else {
			def->flags = strdup(comment_flag);
		}
	}

	rz_list_append(reg->reg_profile->defs, def);

	return true;

reg_parse_error:
	rz_reg_profile_def_free(def);
	return false;
}

/**
 * \brief Parses a register profile string. Each line is either a register alias or a register definiton.
 *
 * A register alias string is of the following form:
 * "=<alias>  <name>\n"
 *
 * A register definition string is of the following form:
 * "(<sub-type>@)main-type  <name>  .<size>  <byte offset>(.<bit offset>)  <packed>  (# <comment> OR <flags>)\n"
 *
 * Elements in "()" are optional.
 * Each "<...>" token is separated by a tab character.
 *
 * * alias: Register alias (e.g. PC, A1 etc.)
 * * name: Register name.
 * * size: Register size in bits.
 * * main-type: Register type: gpr, fpr, ctr, flg etc.
 * * sub-type: The second register type (e.g. xmm@fpu : xmm is sub-type of fpu)
 * * byte offset: Offset into register profile in bytes.
 * * bit offset: Offset into the byte offset in bits.
 * * packed: Packed size of the register in bytes.
 * * comment: A comment about the register.
 * * Flags this register holds.
 *
 * \param reg Register struct which holds all register items.
 * \param profile Register profile string.
 * \return false On failure.
 * \return true On success.
 */
static bool parse_reg_profile_str(RZ_BORROW RzReg *reg, const char *profile) {
	rz_return_val_if_fail(reg && profile, false);

	// Same profile, no need to change
	if (reg->reg_profile_str && !strcmp(reg->reg_profile_str, profile)) {
		return true;
	}
	// Cache the profile string
	reg->reg_profile_str = strdup(profile);
	reg->reg_profile = RZ_NEW0(RzRegProfile);
	reg->reg_profile->defs = rz_list_newf((RzListFree)rz_reg_profile_def_free);
	reg->reg_profile->alias = rz_list_newf((RzListFree)rz_reg_profile_alias_free);

	RzList *def_lines = rz_str_split_duplist_n(profile, "\n", 0, true);
	rz_return_val_if_fail(def_lines, false);

	st32 l = 0; // Line number
	const char *line;
	bool is_alias = false;
	RzListIter *it;
	RzList *toks = NULL;
	rz_list_foreach (def_lines, it, line) {
		++l;
		if (strcmp(line, "") == 0) {
			continue;
		}
		toks = rz_str_split_duplist_n(line, "\t", 0, true);
		if (!toks) {
			continue;
		}
		ut32 toks_len = rz_list_length(toks);

		const char *first_tok = rz_list_get_n(toks, 0);
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

	return true;
}

static void add_item_to_regset(RZ_BORROW RzReg *reg, RZ_BORROW RzRegItem *item) {
	rz_return_if_fail(reg && item);
	RzRegisterType t = item->type;

	if (!reg->regset[t].regs) {
		reg->regset[t].regs = rz_list_newf((RzListFree)rz_reg_item_free);
	}
	if (!reg->regset[t].ht_regs) {
		reg->regset[t].ht_regs = ht_pp_new0();
	}

	rz_list_append(reg->regset[t].regs, item);
	ht_pp_insert(reg->regset[t].ht_regs, item->name, item);

	// Update the overall type of registers into a regset
	reg->regset[t].maskregstype |= ((int)1 << item->type);
	reg->regset[t].maskregstype |= ((int)1 << item->sub_type);
}

RZ_API bool rz_reg_set_reg_profile(RZ_BORROW RzReg *reg) {
	rz_return_val_if_fail(reg && reg->reg_profile, false);
	rz_return_val_if_fail(reg->reg_profile->alias && reg->reg_profile->defs, false);

	RzListIter *it;
	RzRegProfileAlias *alias;
	rz_list_foreach (reg->reg_profile->alias, it, alias) {
		if (!rz_reg_set_name(reg, alias->role, alias->reg_name)) {
			RZ_LOG_WARN("Invalid alias gviven.\n");
			return false;
		}
	}
	RzRegProfileDef *def;
	rz_list_foreach (reg->reg_profile->defs, it, def) {
		RzRegItem *item = RZ_NEW0(RzRegItem);
		if (!item) {
			RZ_LOG_WARN("Unable to allocate memory.\n");
			return false;
		}

		item->name = strdup(def->name);

		item->arena = def->type;
		item->type = def->type;
		item->sub_type = def->sub_type;
		/* Hack to put flags in the same arena as gpr */
		if (def->type == RZ_REG_TYPE_FLG) {
			def->sub_type = RZ_REG_TYPE_GPR;
			item->sub_type = RZ_REG_TYPE_GPR;
		}
		item->size = def->size;
		item->offset = def->offset;
		// Update the overall profile size
		if (item->offset + item->size > reg->size) {
			reg->size = item->offset + item->size;
		}
		// Dynamically update the list of supported bit sizes
		reg->bits |= def->size;
		item->packed_size = def->packed;

		if (def->comment) {
			item->comment = strdup(def->comment);
		}
		if (def->flags) {
			item->flags = strdup(def->flags);
		}

		add_item_to_regset(reg, item);
	}

	return true;
}

/**
 * \brief Parses a register profile string and sets up all registers accordingly in \p reg.
 *
 * \param reg The RzReg struct which should hold the register data.
 * \param profile The register profile string.
 * \return false On failure;
 * \return true On success.
 */
RZ_API bool rz_reg_set_profile_string(RZ_BORROW RzReg *reg, const char *profile) {
	rz_return_val_if_fail(reg && profile, false);
	// we should reset all the arenas before setting the new reg profile
	rz_reg_arena_pop(reg);
	// Purge the old registers
	rz_reg_free_internal(reg, true);
	rz_reg_arena_shrink(reg);

	if (!parse_reg_profile_str(reg, profile)) {
		RZ_LOG_WARN("Could not parse register profile string.\n")
		return false;
	}

	if (!rz_reg_set_reg_profile(reg)) {
		RZ_LOG_WARN("Could not set reg profile.\n");
		return false;
	}

	reg->size = 0;
	for (ut32 i = 0; i < RZ_REG_TYPE_LAST; i++) {
		RzRegSet *rs = &reg->regset[i];
		if (rs && rs->arena) {
			reg->size += rs->arena->size; // Sums minimum arena size.
		}
	}

	rz_reg_fit_arena(reg);
	// dup the last arena to allow regdiffing
	rz_reg_arena_push(reg);
	rz_reg_reindex(reg);
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
