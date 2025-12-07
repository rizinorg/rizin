// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file caddr.c
 * \brief Unified API for describing addresses in human-readable formats
 *
 * This module provides a unified and reusable API for generating human-readable
 * descriptions of memory addresses. It supports various options like:
 * - Name+offset format (e.g., "main+0x10")
 * - Source file and line information from debug symbols
 * - Function context
 * - Flag-based naming
 * - Customizable output formatting
 *
 * The API is designed to be used by different parts of Rizin and Cutter,
 * providing consistent address representation across the codebase.
 */

#include <rz_core.h>
#include <rz_util/rz_assert.h>

/**
 * \brief Create a new RzAddrDescribeOptions with default values
 * \return Pointer to newly allocated options structure, NULL on failure
 */
RZ_API RZ_OWN RzAddrDescribeOptions *rz_core_addr_describe_options_new(void) {
	RzAddrDescribeOptions *opts = RZ_NEW0(RzAddrDescribeOptions);
	if (!opts) {
		return NULL;
	}
	// Set sensible defaults - use decimal to match existing Rizin behavior
	opts->show_offset = true;
	opts->prefer_function = true;
	opts->show_flag = true;
	opts->use_decimal = true;
	opts->show_color = false;
	opts->show_source_info = false;
	opts->use_realnames = false;
	opts->max_flag_delta = 0; // 0 = unlimited (new behavior); use -1 for legacy 8192 limit
	opts->use_spaces_around_delta = false; // No spaces by default (compact format)
	return opts;
}

/**
 * \brief Free an RzAddrDescribeOptions structure
 * \param opts The options to free
 */
RZ_API void rz_core_addr_describe_options_free(RZ_NULLABLE RzAddrDescribeOptions *opts) {
	free(opts);
}

/**
 * \brief Free an RzAddrDescription structure
 * \param desc The description to free
 */
RZ_API void rz_core_addr_description_free(RZ_NULLABLE RzAddrDescription *desc) {
	if (!desc) {
		return;
	}
	free(desc->name);
	free(desc->fcn_name);
	free(desc->flag_name);
	free(desc->source_file);
	free(desc);
}

/**
 * \brief Get address description based on flags
 *
 * Helper function to find a flag at or near the given address
 * and compute the delta.
 */
static void addr_describe_from_flags(RzCore *core, RzAddrDescription *desc, ut64 addr, const RzAddrDescribeOptions *opts) {
	rz_return_if_fail(core && desc && opts);

	if (!opts->show_flag) {
		return;
	}

	RzFlagItem *fi = rz_flag_get_at(core->flags, addr, true);
	if (!fi) {
		return;
	}

	st64 delta = (st64)(addr - fi->offset);

	// Check max_flag_delta limit if set
	// max_flag_delta < 0: use default 8192 limit
	// max_flag_delta == 0: unlimited
	// max_flag_delta > 0: use that value as limit
	if (opts->max_flag_delta < 0) {
		// Default limit for backward compatibility
		if (delta < 0 || delta >= 8192) {
			return;
		}
	} else if (opts->max_flag_delta > 0) {
		if (delta < 0 || delta >= opts->max_flag_delta) {
			return;
		}
	}

	const char *name = (opts->use_realnames && fi->realname) ? fi->realname : fi->name;

	desc->flag_name = rz_str_dup(name);
	desc->flag_offset = fi->offset;
	desc->flag_delta = delta;
}

/**
 * \brief Get address description based on function analysis
 *
 * Helper function to find a function containing the address
 * and compute the delta from the function start.
 */
static void addr_describe_from_function(RzCore *core, RzAddrDescription *desc, ut64 addr, const RzAddrDescribeOptions *opts) {
	rz_return_if_fail(core && desc && opts);

	if (!opts->prefer_function) {
		return;
	}

	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0);
	if (!fcn) {
		// Try to get function at address
		fcn = rz_analysis_get_function_at(core->analysis, addr);
	}

	if (!fcn) {
		return;
	}

	desc->fcn_name = rz_str_dup(fcn->name);
	desc->fcn_addr = fcn->addr;
	desc->fcn_delta = (st64)(addr - fcn->addr);
}

/**
 * \brief Get source line information for address
 *
 * Helper function to retrieve source file and line number
 * from debug information if available.
 */
static void addr_describe_from_source(RzCore *core, RzAddrDescription *desc, ut64 addr, const RzAddrDescribeOptions *opts) {
	rz_return_if_fail(core && desc && opts);

	if (!opts->show_source_info) {
		return;
	}

	RzBinFile *bf = rz_bin_cur(core->bin);
	if (!bf || !bf->o) {
		return;
	}

	RzBinSourceLineInfo *lines = bf->o->lines;
	if (!lines) {
		return;
	}

	const RzBinSourceLineSample *sample = rz_bin_source_line_info_get_first_at(lines, addr);
	if (!sample || rz_bin_source_line_sample_is_closing(sample)) {
		return;
	}

	if (sample->file) {
		desc->source_file = rz_str_dup(sample->file);
	}
	desc->source_line = sample->line;
	desc->source_column = sample->column;
}

/**
 * \brief Describe an address with human-readable information
 *
 * This is the main unified API for generating address descriptions.
 * It combines information from flags, functions, and debug symbols
 * to create a comprehensive description of an address.
 *
 * \param core The RzCore instance
 * \param addr The address to describe
 * \param opts Options controlling what information to include
 * \return Pointer to RzAddrDescription, or NULL on failure. Caller must free with rz_core_addr_description_free()
 */
RZ_API RZ_OWN RzAddrDescription *rz_core_addr_describe(RZ_NONNULL RzCore *core, ut64 addr, RZ_NULLABLE const RzAddrDescribeOptions *opts) {
	rz_return_val_if_fail(core, NULL);

	RzAddrDescribeOptions default_opts = {
		.show_offset = true,
		.prefer_function = true,
		.show_flag = true,
		.use_decimal = true,
		.show_color = false,
		.show_source_info = false,
		.use_realnames = false
	};

	if (!opts) {
		opts = &default_opts;
	}

	RzAddrDescription *desc = RZ_NEW0(RzAddrDescription);
	if (!desc) {
		return NULL;
	}

	desc->addr = addr;

	// Get function information first (higher priority)
	addr_describe_from_function(core, desc, addr, opts);

	// Get flag information
	addr_describe_from_flags(core, desc, addr, opts);

	// Get source line information if requested
	addr_describe_from_source(core, desc, addr, opts);

	return desc;
}

/**
 * \brief Format an address description as a string
 *
 * Generates a formatted string representation of an address description.
 * The format depends on what information is available and the options provided.
 *
 * Priority order for name+offset:
 * 1. Function name (if opts->prefer_function is true and function is found)
 * 2. Flag name (if flag is found)
 * 3. Plain address
 *
 * \param desc The address description to format
 * \param opts Options controlling the output format
 * \return Newly allocated formatted string, or NULL on failure. Caller must free.
 */
RZ_API RZ_OWN char *rz_core_addr_description_to_string(RZ_NONNULL const RzAddrDescription *desc, RZ_NULLABLE const RzAddrDescribeOptions *opts) {
	rz_return_val_if_fail(desc, NULL);

	RzAddrDescribeOptions default_opts = {
		.show_offset = true,
		.prefer_function = true,
		.show_flag = true,
		.use_decimal = true,
		.show_color = false,
		.show_source_info = false,
		.use_realnames = false
	};

	if (!opts) {
		opts = &default_opts;
	}

	RzStrBuf sb;
	rz_strbuf_init(&sb);

	const char *name = NULL;
	st64 delta = 0;
	bool has_name = false;

	// Priority: function > flag > plain address
	if (opts->prefer_function && desc->fcn_name) {
		name = desc->fcn_name;
		delta = desc->fcn_delta;
		has_name = true;
	} else if (opts->show_flag && desc->flag_name) {
		name = desc->flag_name;
		delta = desc->flag_delta;
		has_name = true;
	}

	if (has_name && name) {
		const char *plus_fmt = opts->use_spaces_around_delta ? " + " : "+";
		const char *minus_fmt = opts->use_spaces_around_delta ? " - " : "-";
		if (delta > 0) {
			if (opts->use_decimal) {
				rz_strbuf_appendf(&sb, "%s%s%" PFMT64d, name, plus_fmt, delta);
			} else {
				rz_strbuf_appendf(&sb, "%s%s0x%" PFMT64x, name, plus_fmt, (ut64)delta);
			}
		} else if (delta < 0) {
			if (opts->use_decimal) {
				rz_strbuf_appendf(&sb, "%s%s%" PFMT64d, name, minus_fmt, -delta);
			} else {
				rz_strbuf_appendf(&sb, "%s%s0x%" PFMT64x, name, minus_fmt, (ut64)(-delta));
			}
		} else {
			rz_strbuf_append(&sb, name);
		}
	} else if (opts->show_offset) {
		// No name found, always show the address in hex format for clarity
		rz_strbuf_appendf(&sb, "0x%" PFMT64x, desc->addr);
	}

	// Append source info if requested and available
	if (opts->show_source_info && desc->source_file) {
		if (desc->source_line > 0) {
			if (desc->source_column > 0) {
				rz_strbuf_appendf(&sb, " (%s:%" PFMT32u ":%" PFMT32u ")",
					desc->source_file, desc->source_line, desc->source_column);
			} else {
				rz_strbuf_appendf(&sb, " (%s:%" PFMT32u ")",
					desc->source_file, desc->source_line);
			}
		} else {
			rz_strbuf_appendf(&sb, " (%s)", desc->source_file);
		}
	}

	return rz_strbuf_drain_nofree(&sb);
}

/**
 * \brief Convenience function to get a name+offset string for an address
 *
 * This is a simplified wrapper that combines rz_core_addr_describe() and
 * rz_core_addr_description_to_string() for common use cases.
 *
 * \param core The RzCore instance
 * \param addr The address to describe
 * \param opts Options controlling the output format (NULL for defaults)
 * \return Newly allocated string, or NULL on failure. Caller must free.
 */
RZ_API RZ_OWN char *rz_core_addr_describe_string(RZ_NONNULL RzCore *core, ut64 addr, RZ_NULLABLE const RzAddrDescribeOptions *opts) {
	rz_return_val_if_fail(core, NULL);

	RzAddrDescription *desc = rz_core_addr_describe(core, addr, opts);
	if (!desc) {
		return NULL;
	}

	char *result = rz_core_addr_description_to_string(desc, opts);
	rz_core_addr_description_free(desc);
	return result;
}

/**
 * \brief Get name+offset string for an address (simple version)
 *
 * This is the simplest API for getting a human-readable address description.
 * It uses default options and is suitable for most use cases.
 *
 * \param core The RzCore instance
 * \param addr The address to describe
 * \return Newly allocated string in "name+offset" format, or hex address. Caller must free.
 */
RZ_API RZ_OWN char *rz_core_addr_get_name_delta(RZ_NONNULL RzCore *core, ut64 addr) {
	rz_return_val_if_fail(core, NULL);
	return rz_core_addr_describe_string(core, addr, NULL);
}

/**
 * \brief Describe an address with function context
 *
 * Similar to rz_core_addr_describe() but forces preference for function names.
 *
 * \param core The RzCore instance
 * \param addr The address to describe
 * \return Pointer to RzAddrDescription, or NULL on failure. Caller must free.
 */
RZ_API RZ_OWN RzAddrDescription *rz_core_addr_describe_with_function(RZ_NONNULL RzCore *core, ut64 addr) {
	rz_return_val_if_fail(core, NULL);

	RzAddrDescribeOptions opts = {
		.show_offset = true,
		.prefer_function = true,
		.show_flag = true,
		.use_decimal = true,
		.show_color = false,
		.show_source_info = false,
		.use_realnames = false
	};

	return rz_core_addr_describe(core, addr, &opts);
}

/**
 * \brief Describe an address with source line information
 *
 * Similar to rz_core_addr_describe() but includes source file/line info.
 *
 * \param core The RzCore instance
 * \param addr The address to describe
 * \return Pointer to RzAddrDescription, or NULL on failure. Caller must free.
 */
RZ_API RZ_OWN RzAddrDescription *rz_core_addr_describe_with_source(RZ_NONNULL RzCore *core, ut64 addr) {
	rz_return_val_if_fail(core, NULL);

	RzAddrDescribeOptions opts = {
		.show_offset = true,
		.prefer_function = true,
		.show_flag = true,
		.use_decimal = true,
		.show_color = false,
		.show_source_info = true,
		.use_realnames = false
	};

	return rz_core_addr_describe(core, addr, &opts);
}

/**
 * \brief Format an address for display in the disassembly offset column
 *
 * This function generates the address string used in disassembly output,
 * supporting relative offsets (asm.reloff), segmented addresses, and
 * decimal/hex formatting.
 *
 * \param core The RzCore instance
 * \param addr The address to format
 * \param opts Display options
 * \return Newly allocated formatted string. Caller must free.
 */
RZ_API RZ_OWN char *rz_core_addr_format_for_display(RZ_NONNULL RzCore *core, ut64 addr, RZ_NULLABLE const RzAddrDescribeOptions *opts) {
	rz_return_val_if_fail(core, NULL);

	RzAddrDescribeOptions default_opts = {
		.show_offset = true,
		.prefer_function = false,
		.show_flag = false,
		.use_decimal = true,
		.show_color = false,
		.show_source_info = false,
		.use_realnames = false
	};

	if (!opts) {
		opts = &default_opts;
	}

	RzStrBuf sb;
	rz_strbuf_init(&sb);

	if (opts->use_decimal) {
		rz_strbuf_appendf(&sb, "%" PFMT64u, addr);
	} else {
		if (core->print && core->print->wide_offsets) {
			rz_strbuf_appendf(&sb, "0x%016" PFMT64x, addr);
		} else {
			rz_strbuf_appendf(&sb, "0x%08" PFMT64x, addr);
		}
	}

	return rz_strbuf_drain_nofree(&sb);
}

/**
 * \brief Get a detailed address description for JSON output
 *
 * Creates a PJ object with detailed address information suitable
 * for JSON output in commands.
 *
 * \param core The RzCore instance
 * \param pj The PrettyJSON instance to append to
 * \param addr The address to describe
 * \param opts Options controlling what information to include
 */
RZ_API void rz_core_addr_describe_pj(RZ_NONNULL RzCore *core, RZ_NONNULL PJ *pj, ut64 addr, RZ_NULLABLE const RzAddrDescribeOptions *opts) {
	rz_return_if_fail(core && pj);

	RzAddrDescription *desc = rz_core_addr_describe(core, addr, opts);
	if (!desc) {
		pj_o(pj);
		pj_kn(pj, "addr", addr);
		pj_end(pj);
		return;
	}

	pj_o(pj);
	pj_kn(pj, "addr", desc->addr);

	if (desc->fcn_name) {
		pj_ks(pj, "fcn_name", desc->fcn_name);
		pj_kn(pj, "fcn_addr", desc->fcn_addr);
		pj_kN(pj, "fcn_delta", desc->fcn_delta);
	}

	if (desc->flag_name) {
		pj_ks(pj, "flag_name", desc->flag_name);
		pj_kn(pj, "flag_offset", desc->flag_offset);
		pj_kN(pj, "flag_delta", desc->flag_delta);
	}

	if (desc->source_file) {
		pj_ks(pj, "source_file", desc->source_file);
		if (desc->source_line > 0) {
			pj_ki(pj, "source_line", desc->source_line);
		}
		if (desc->source_column > 0) {
			pj_ki(pj, "source_column", desc->source_column);
		}
	}

	// Generate a combined name+delta string
	char *name_delta = rz_core_addr_description_to_string(desc, opts);
	if (name_delta) {
		pj_ks(pj, "name_delta", name_delta);
		free(name_delta);
	}

	pj_end(pj);
	rz_core_addr_description_free(desc);
}

/**
 * \brief Get relative offset info for an address (for asm.reloff functionality)
 *
 * This function retrieves the function or flag name and delta for an address,
 * which is useful for displaying relative offsets in disassembly.
 *
 * \param core The RzCore instance
 * \param addr The address to describe
 * \param prefer_function If true, prefer function names over flags
 * \param use_flags If true and no function is found, use flag names
 * \param[out] out_name Pointer to store the name (must be freed by caller)
 * \param[out] out_delta Pointer to store the delta from the name's address
 * \return true if a name was found, false otherwise
 */
RZ_API bool rz_core_addr_get_reloff_info(RZ_NONNULL RzCore *core, ut64 addr,
	bool prefer_function, bool use_flags,
	RZ_OUT RZ_NULLABLE char **out_name, RZ_OUT RZ_NULLABLE st64 *out_delta) {
	rz_return_val_if_fail(core, false);

	if (out_name) {
		*out_name = NULL;
	}
	if (out_delta) {
		*out_delta = 0;
	}

	RzAddrDescribeOptions opts = {
		.show_offset = false,
		.prefer_function = prefer_function,
		.show_flag = use_flags,
		.use_decimal = true,
		.show_color = false,
		.show_source_info = false,
		.use_realnames = false
	};

	RzAddrDescription *desc = rz_core_addr_describe(core, addr, &opts);
	if (!desc) {
		return false;
	}

	bool found = false;

	// Priority: function > flag
	if (prefer_function && desc->fcn_name) {
		if (out_name) {
			*out_name = rz_str_dup(desc->fcn_name);
		}
		if (out_delta) {
			*out_delta = desc->fcn_delta;
		}
		found = true;
	} else if (use_flags && desc->flag_name) {
		if (out_name) {
			*out_name = rz_str_dup(desc->flag_name);
		}
		if (out_delta) {
			*out_delta = desc->flag_delta;
		}
		found = true;
	}

	rz_core_addr_description_free(desc);
	return found;
}

/**
 * \brief Get function-relative offset string for an address
 *
 * Returns a string like "main+0x10" if the address is within a function,
 * or NULL if not.
 *
 * \param core The RzCore instance
 * \param addr The address to describe
 * \return Newly allocated string or NULL. Caller must free.
 */
RZ_API RZ_OWN char *rz_core_addr_get_function_offset(RZ_NONNULL RzCore *core, ut64 addr) {
	rz_return_val_if_fail(core, NULL);

	RzAddrDescribeOptions opts = {
		.show_offset = false,
		.prefer_function = true,
		.show_flag = false,
		.use_decimal = true,
		.show_color = false,
		.show_source_info = false,
		.use_realnames = false
	};

	RzAddrDescription *desc = rz_core_addr_describe(core, addr, &opts);
	if (!desc || !desc->fcn_name) {
		rz_core_addr_description_free(desc);
		return NULL;
	}

	char *result = rz_core_addr_description_to_string(desc, &opts);
	rz_core_addr_description_free(desc);
	return result;
}

/**
 * \brief Get flag-relative offset string for an address
 *
 * Returns a string like "sym.func+0x10" if a flag exists at or before the address,
 * or NULL if not.
 *
 * \param core The RzCore instance
 * \param addr The address to describe
 * \return Newly allocated string or NULL. Caller must free.
 */
RZ_API RZ_OWN char *rz_core_addr_get_flag_offset(RZ_NONNULL RzCore *core, ut64 addr) {
	rz_return_val_if_fail(core, NULL);

	RzAddrDescribeOptions opts = {
		.show_offset = false,
		.prefer_function = false,
		.show_flag = true,
		.use_decimal = true,
		.show_color = false,
		.show_source_info = false,
		.use_realnames = false,
		.max_flag_delta = -1 // Use default 8192 limit for backward compatibility
	};

	RzAddrDescription *desc = rz_core_addr_describe(core, addr, &opts);
	if (!desc || !desc->flag_name) {
		rz_core_addr_description_free(desc);
		return NULL;
	}

	char *result = rz_core_addr_description_to_string(desc, &opts);
	rz_core_addr_description_free(desc);
	return result;
}

/**
 * \brief Get flag-relative offset string for an address with spaces around delta
 *
 * Returns a string like "sym.func + 0x10" if a flag exists at or before the address,
 * or NULL if not. Uses spaces around +/- for readability (used for prompts).
 *
 * \param core The RzCore instance
 * \param addr The address to describe
 * \return Newly allocated string or NULL. Caller must free.
 */
RZ_API RZ_OWN char *rz_core_addr_get_flag_offset_prompt(RZ_NONNULL RzCore *core, ut64 addr) {
	rz_return_val_if_fail(core, NULL);

	RzAddrDescribeOptions opts = {
		.show_offset = false,
		.prefer_function = false,
		.show_flag = true,
		.use_decimal = true,
		.show_color = false,
		.show_source_info = false,
		.use_realnames = false,
		.max_flag_delta = 0, // No limit for prompt - show all flags
		.use_spaces_around_delta = true // Use spaces for prompt display
	};

	RzAddrDescription *desc = rz_core_addr_describe(core, addr, &opts);
	if (!desc || !desc->flag_name) {
		rz_core_addr_description_free(desc);
		return NULL;
	}

	char *result = rz_core_addr_description_to_string(desc, &opts);
	rz_core_addr_description_free(desc);
	return result;
}
