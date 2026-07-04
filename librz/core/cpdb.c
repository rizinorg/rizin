// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_pdb.h>
#include "../bin/pdb/pdb.h"

static void pdb_types_print_standard(const RzTypeDB *db, const RzPdb *pdb, const RzList /*<RzBaseType *>*/ *types) {
	rz_return_if_fail(pdb && db && types);
	if (!types) {
		RZ_LOG_ERROR("core: there is nothing to print!\n");
	}
	RzListIter *it;
	RzBaseType *type;
	RzStrBuf *buf = rz_strbuf_new(NULL);
	rz_list_foreach (types, it, type) {
		char *pretty = rz_type_db_base_type_as_pretty_string(db, type, RZ_TYPE_PRINT_MULTILINE | RZ_TYPE_PRINT_END_NEWLINE, 1);
		rz_strbuf_append(buf, pretty);
		free(pretty);
	}
	rz_cons_print(rz_strbuf_get(buf));
	rz_strbuf_free(buf);
}

static void pdb_types_print_json(const RzTypeDB *db, const RzPdb *pdb, const RzList /*<RzBaseType *>*/ *types, PJ *pj) {
	rz_return_if_fail(db && pdb && types && pj);
	RzListIter *it;
	RzBaseType *type;
	pj_o(pj);
	pj_ka(pj, "types");
	rz_list_foreach (types, it, type) {
		switch (type->kind) {
		case RZ_BASE_TYPE_KIND_STRUCT: {
			pj_o(pj);
			pj_ks(pj, "type", "structure");
			pj_ks(pj, "name", type->name);
			pj_kn(pj, "size", type->size);
			pj_ka(pj, "members");
			RzTypeStructMember *memb;
			rz_vector_foreach (&type->struct_data.members, memb) {
				pj_o(pj);
				char *typ = rz_type_as_string(db, memb->type);
				pj_ks(pj, "member_type", typ);
				RZ_FREE(typ);
				pj_ks(pj, "member_name", memb->name);
				pj_kn(pj, "offset", memb->offset);
				pj_end(pj);
			}
			pj_end(pj);
			pj_end(pj);
			break;
		}
		case RZ_BASE_TYPE_KIND_UNION: {
			pj_o(pj);
			pj_ks(pj, "type", "union");
			pj_ks(pj, "name", type->name);
			pj_kn(pj, "size", type->size);
			pj_ka(pj, "members");
			RzTypeUnionMember *memb;
			rz_vector_foreach (&type->union_data.members, memb) {
				pj_o(pj);
				char *typ = rz_type_as_string(db, memb->type);
				pj_ks(pj, "member_type", typ);
				RZ_FREE(typ);
				pj_ks(pj, "member_name", memb->name);
				pj_kn(pj, "offset", memb->offset);
				pj_end(pj);
			}
			pj_end(pj);
			pj_end(pj);
			break;
		}
		case RZ_BASE_TYPE_KIND_ENUM: {
			pj_o(pj);
			pj_ks(pj, "type", "enum");
			pj_ks(pj, "name", type->name);
			char *typ = rz_type_as_string(db, type->type);
			pj_ks(pj, "base_type", typ);
			RZ_FREE(typ);
			pj_ka(pj, "cases");
			RzTypeEnumCase *cas;
			rz_vector_foreach (&type->enum_data.cases, cas) {
				pj_o(pj);
				pj_ks(pj, "enum_name", cas->name);
				pj_kn(pj, "enum_val", cas->val);
				pj_end(pj);
			}
			pj_end(pj);
			pj_end(pj);
			break;
		}
		default:
			break;
		}
	}
	pj_end(pj);
	pj_end(pj);
}

static void rz_core_bin_pdb_types_print(const RzTypeDB *db, const RzPdb *pdb, const RzCmdStateOutput *state) {
	rz_return_if_fail(db && pdb && state);
	RzPdbTpiStream *stream = pdb->s_tpi;
	if (!stream) {
		RZ_LOG_ERROR("core: there is no tpi stream in current pdb\n");
		return;
	}
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		pdb_types_print_standard(db, pdb, stream->print_type);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pdb_types_print_json(db, pdb, stream->print_type, state->d.pj);
		break;
	default:
		return;
	}
}

typedef struct {
	RzStrBuf *buf;
	const ut64 baddr;
	RzCmdStateOutput *state;
} PDBDumpContext;

static bool symbol_dump(RzPdb *pdb, const PDBSymbol *symbol, void *u) {
	PDBDumpContext *ctx = u;
	PJ *pj = ctx->state->d.pj;
	if (symbol->kind == PDB_Public) {
		const PDBSPublic *public = symbol->data;
		PeImageSectionHeader *sctn_header = pdb_section_hdr_by_index(pdb->s_pe, public->offset.section_index);
		if (!sctn_header) {
			return true;
		}
		ut64 addr = rz_bin_pdb_to_rva(pdb, &public->offset);
		if (addr == UT64_MAX) {
			return true;
		}
		if (ctx->baddr != UT64_MAX) {
			addr += ctx->baddr;
		}

		char *name = rz_demangler_msvc(public->name, RZ_DEMANGLER_FLAG_BASE);
		name = (name) ? name : rz_str_dup(public->name);

		switch (ctx->state->mode) {
		case RZ_OUTPUT_MODE_JSON: // JSON
			pj_o(pj);
			pj_kn(pj, "address", addr);
			pj_kN(pj, "symtype", symbol->raw_kind);
			pj_ks(pj, "section_name", sctn_header->name);
			pj_ks(pj, "gdata_name", name);
			pj_end(pj);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			rz_strbuf_appendf(ctx->buf, "0x%08" PFMT64x "  %d  %.*s  %s\n",
				addr,
				symbol->raw_kind, PDB_SIZEOF_SECTION_NAME, sctn_header->name, name);
			break;
		default:
			break;
		}
		free(name);
	}
	return true;
}

/**
 * \brief Return the PDB global vars string
 *
 * \param pdb PDB instance
 * \param baddr image base addr
 * \param state The RzCmdStateOutput instance
 * \return char *
 */
RZ_API char *rz_core_bin_pdb_gvars_as_string(
	RZ_NONNULL RzPdb *pdb, const ut64 baddr, RzCmdStateOutput *state) {
	rz_return_val_if_fail(pdb && state, NULL);
	RzStrBuf *buf = rz_strbuf_new(NULL);
	if (!buf) {
		return NULL;
	}
	PJ *pj = state->d.pj;
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_o(pj);
		pj_ka(pj, "gvars");
	}
	if (!pdb->s_pe) {
		rz_strbuf_free(buf);
		return NULL;
	}
	PDBDumpContext ctx = {
		.buf = buf,
		.baddr = baddr,
		.state = state,
	};
	rz_pdb_all_symbols_foreach(pdb, symbol_dump, &ctx);
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		pj_end(pj);
		// We will need this for Windows Heap.
		rz_strbuf_append(buf, pj_string(pj));
	}
	return rz_strbuf_drain(buf);
}

static void rz_core_bin_pdb_gvars_print(RzPdb *pdb, const ut64 baddr, RzCmdStateOutput *state) {
	rz_return_if_fail(pdb && state);
	char *str = rz_core_bin_pdb_gvars_as_string(pdb, baddr, state);
	// We don't need to print the output of JSON because the RzCmdStateOutput will handle it.
	if (state->mode == RZ_OUTPUT_MODE_STANDARD) {
		rz_cons_print(str);
	}
	free(str);
}

typedef struct {
	RzCore *core;
	const ut64 baddr;
	const char *file;
} PDBLoadContext;

static bool symbol_load(RzPdb *pdb, const PDBSymbol *symbol, void *u) {
	if (!symbol) {
		return true;
	}
	PDBLoadContext *ctx = u;
	const RzDemanglerFlag dflags = rz_demangler_get_flags(ctx->core->bin->demangler);
	if (symbol->kind == PDB_Public) {
		const PDBSPublic *public = symbol->data;
		if (RZ_STR_ISEMPTY(public->name)) {
			return true;
		}

		char *name = rz_demangler_msvc(public->name, dflags);
		name = (name) ? name : rz_str_dup(public->name);
		char *filtered_name = rz_name_filter2(name, true);
		char *fname = rz_str_newf("pdb.%s.%s", ctx->file, filtered_name);

		ut64 addr = rz_bin_pdb_to_rva(pdb, &public->offset);
		if (addr == UT64_MAX) {
			free(filtered_name);
			free(fname);
			free(name);
			return true;
		}
		if (ctx->baddr != UT64_MAX) {
			addr += ctx->baddr;
		}

		RzFlagItem *item = rz_flag_set(ctx->core->flags, fname, addr, 0);
		if (item) {
			rz_flag_item_set_realname(ctx->core->flags, item, name);
		}
		free(filtered_name);
		free(fname);
		free(name);
	} else if (symbol->kind == PDB_Data) {
		const PDBSData *data = symbol->data;
		if (RZ_STR_ISEMPTY(data->name)) {
			return true;
		}
		ut64 addr = rz_bin_pdb_to_rva(pdb, &data->offset);
		if (addr == UT64_MAX) {
			return true;
		}
		if (ctx->baddr != UT64_MAX) {
			addr += ctx->baddr;
		}

		RzAnalysisVarGlobal *existing_glob = NULL;
		if ((existing_glob = rz_analysis_var_global_get_byaddr_in(ctx->core->analysis, addr))) {
			RZ_LOG_INFO("global variable %s at 0x%" PFMT64x " already exists.\n", existing_glob->name, existing_glob->addr);
			return true;
		}
		if ((existing_glob = rz_analysis_var_global_get_byname(ctx->core->analysis, data->name))) {
			RZ_LOG_INFO("global variable %s at 0x%" PFMT64x " already exists.\n", existing_glob->name, existing_glob->addr);
			return true;
		}
		RzPdbTpiType *t = rz_bin_pdb_get_type_by_index(pdb->s_tpi, data->type_index);
		if (!t) {
			return true;
		}
		RzTypeDB *typedb = rz_analysis_get_type_db(ctx->core->analysis);
		RzType *rt = rz_type_db_pdb_parse(typedb, pdb->s_tpi, t);
		if (!rt) {
			return true;
		}
		rz_analysis_var_global_create(ctx->core->analysis, data->name, rt, addr);
	}
	return true;
}

/**
 * \brief Second-pass callback that turns PDB public function symbols into
 * analyzed functions.
 *
 * The PDB explicitly marks public symbols that are functions (cvpsfFunction).
 * Some of these (e.g. virtual methods only reached through a vtable) are never
 * discovered by call-following code analysis, so without this they would be
 * present only as a flag and never show up as a function. This mirrors how
 * \ref rz_core_analysis_all turns FUNC bin symbols into functions: it triggers
 * analysis at the address and lets the already-set PDB flag name the function.
 *
 * This must run after all symbol flags have been set (see \ref pdb_symbols_load)
 * so that functions reached by direct calls from here are also named correctly.
 */
static bool symbol_make_function(RzPdb *pdb, const PDBSymbol *symbol, void *u) {
	if (!symbol || symbol->kind != PDB_Public) {
		return true;
	}
	const PDBSPublic *public = symbol->data;
	if (!public || !public->function || RZ_STR_ISEMPTY(public->name)) {
		return true;
	}
	PDBLoadContext *ctx = u;
	RzCore *core = ctx->core;
	ut64 addr = rz_bin_pdb_to_rva(pdb, &public->offset);
	if (addr == UT64_MAX) {
		return true;
	}
	if (ctx->baddr != UT64_MAX) {
		addr += ctx->baddr;
	}
	// Only create functions where executable code is actually mapped. This also
	// keeps the symbol info (flags, types, globals) usable when no backing
	// binary is loaded, since in that case no function will be created.
	if (!rz_io_is_valid_offset(core->io, addr, RZ_PERM_X)) {
		return true;
	}
	if (rz_analysis_get_function_at(core->analysis, addr)) {
		return true;
	}
	int depth = rz_config_get_i(core->config, "analysis.depth");
	rz_core_analysis_fcn(core, addr, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, depth);
	return true;
}

static void pdb_symbols_load(
	RzCore *core, RzPdb *pdb, const char *pdbfile) {
	rz_return_if_fail(core && pdb);
	if (!(pdb->s_pe && pdb->s_gdata)) {
		return;
	}
	ut64 baddr = rz_bin_get_baddr(core->bin);
	if (!baddr || baddr == UT64_MAX) {
		baddr = rz_config_get_i(core->config, "bin.baddr");
		RZ_LOG_WARN("core: cannot find base address, flags will probably be misplaced\n");
	}
	char *file = rz_str_replace(rz_str_dup(pdbfile), ".pdb", "", 0);
	rz_flag_space_push(core->flags, RZ_FLAGS_FS_SYMBOLS);

	PDBLoadContext ctx = {
		.core = core,
		.baddr = baddr,
		.file = file,
	};
	rz_pdb_all_symbols_foreach(pdb, symbol_load, &ctx);

	rz_flag_space_pop(core->flags);

	// Create functions for public function symbols in a separate pass, after
	// every symbol flag has been set, so each function (and any function it
	// directly calls) is named from its PDB flag.
	rz_pdb_all_symbols_foreach(pdb, symbol_make_function, &ctx);

	free(file);
}

/**
 * \brief Parse PDB file info and integrate with typedb
 *
 * \param core RzCore instance
 * \param file Path of PDB file
 * \return bool
 */
RZ_API RzPdb *rz_core_pdb_load_info(RZ_NONNULL RzCore *core, RZ_NONNULL const char *file) {
	rz_return_val_if_fail(core && file, NULL);
	RzPdb *pdb = rz_bin_pdb_parse_from_file(file);
	if (!pdb) {
		return NULL;
	}

	// Save compound types into types database
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	rz_type_db_pdb_load(typedb, pdb);
	pdb_symbols_load(core, pdb, rz_file_basename(file));
	return pdb;
}

static void pdb_modules_print(RZ_NONNULL RzPdb *pdb, RZ_NONNULL RzCmdStateOutput *state) {
	if (!(pdb->s_dbi && pdb->s_dbi->modules)) {
		return;
	}
	PJ *j = state->d.pj;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		pj_o(j);
		pj_ka(j, "modules");
		break;
	case RZ_OUTPUT_MODE_STANDARD: {
		rz_cons_println("modules:");
		break;
	}
	default: rz_warn_if_reached();
	}
	void **it;
	rz_pvector_foreach (pdb->s_dbi->modules, it) {
		PDB_DBIModule *module = *it;
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON: {
			pj_o(j);
			pj_ks(j, "module_name", module->module_name);
			pj_ks(j, "object_file_name", module->object_file_name);
			pj_end(j);
			break;
		}
		case RZ_OUTPUT_MODE_STANDARD: {
			rz_cons_println(module->module_name);
			break;
		}
		default: rz_warn_if_reached();
		}
	}
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(j);
		pj_end(j);
	}
}

/**
 * \brief Print parsed PDB file info
 *
 * \param db RzTypeDB
 * \param pdb instance of PDB
 * \param state Output State
 * \return void
 */
RZ_API void rz_core_pdb_info_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzTypeDB *db, RZ_NONNULL RzPdb *pdb, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_if_fail(db && pdb && state);

	ut64 baddr = rz_config_get_i(core->config, "bin.baddr");
	if (core->bin->cur && core->bin->cur->o && core->bin->cur->o->opts.baseaddr) {
		baddr = core->bin->cur->o->opts.baseaddr;
	} else {
		RZ_LOG_WARN("core: cannot find base address, flags will probably be misplaced\n");
	}

	rz_cmd_state_output_array_start(state);
	pdb_modules_print(pdb, state);
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	rz_core_bin_pdb_types_print(typedb, pdb, state);
	rz_core_bin_pdb_gvars_print(pdb, baddr, state);
	rz_cmd_state_output_array_end(state);
}
