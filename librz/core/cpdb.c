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
		rz_strbuf_append(buf, rz_type_db_base_type_as_pretty_string(db, type, RZ_TYPE_PRINT_MULTILINE | RZ_TYPE_PRINT_END_NEWLINE, 1));
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
			rz_vector_foreach(&type->struct_data.members, memb) {
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
			rz_vector_foreach(&type->union_data.members, memb) {
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
			rz_vector_foreach(&type->enum_data.cases, cas) {
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

static void symbol_dump(PDBSymbol *symbol, RzStrBuf *buf, RZ_NONNULL const RzPdb *pdb, const ut64 img_base, PJ *pj, const RzOutputMode mode) {
	if (symbol->kind == PDB_Public) {
		PDBSPublic *public = symbol->data;
		PeImageSectionHeader *sctn_header = pdb_section_hdr_by_index(pdb->s_pe, public->offset.section_index);
		if (!sctn_header) {
			return;
		}
		ut64 addr = rz_bin_pdb_to_rva(pdb, &public->offset);
		if (addr == UT64_MAX) {
			return;
		}
		if (img_base != UT64_MAX) {
			addr += img_base;
		}

		char *name = rz_demangler_msvc(public->name, RZ_DEMANGLER_FLAG_BASE);
		name = (name) ? name : strdup(public->name);

		switch (mode) {
		case RZ_OUTPUT_MODE_JSON: // JSON
			pj_o(pj);
			pj_kn(pj, "address", addr);
			pj_kN(pj, "symtype", symbol->raw_kind);
			pj_ks(pj, "section_name", sctn_header->name);
			pj_ks(pj, "gdata_name", name);
			pj_end(pj);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			rz_strbuf_appendf(buf, "0x%08" PFMT64x "  %d  %.*s  %s\n",
				addr,
				symbol->raw_kind, PDB_SIZEOF_SECTION_NAME, sctn_header->name, name);
			break;
		default:
			break;
		}
		free(name);
	}
}

/**
 * \brief Return the PDB global vars string
 *
 * \param pdb PDB instance
 * \param img_base image base addr
 * \param pj JSON instance
 * \param mode RzOutputMode
 * \return char *
 */
RZ_API char *rz_core_bin_pdb_gvars_as_string(
	RZ_NONNULL const RzPdb *pdb, const ut64 img_base, PJ *pj, const RzOutputMode mode) {
	rz_return_val_if_fail(pdb, NULL);
	RzPdbGDataStream *gsym_data_stream = 0;
	RzPdbPeStream *pe_stream = 0;
	RzStrBuf *buf = rz_strbuf_new(NULL);
	if (!buf) {
		return NULL;
	}
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_o(pj);
		pj_ka(pj, "gvars");
	}
	gsym_data_stream = pdb->s_gdata;
	pe_stream = pdb->s_pe;
	if (!pe_stream) {
		rz_strbuf_free(buf);
		return NULL;
	}
	void **it;
	rz_pvector_foreach (gsym_data_stream->global_symbols, it) {
		symbol_dump(*it, buf, pdb, img_base, pj, mode);
	}
	if (pdb->module_infos) {
		void **modit;
		rz_pvector_foreach (pdb->module_infos, modit) {
			PDBModuleInfo *modi = *modit;
			rz_pvector_foreach (modi->symbols, it) {
				symbol_dump(*it, buf, pdb, img_base, pj, mode);
			}
		err:
			continue;
		}
	}
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		pj_end(pj);
		// We will need this for Windows Heap.
		rz_strbuf_append(buf, pj_string(pj));
	}
	char *str = strdup(rz_strbuf_get(buf));
	rz_strbuf_free(buf);
	return str;
}

static void rz_core_bin_pdb_gvars_print(const RzPdb *pdb, const ut64 img_base, const RzCmdStateOutput *state) {
	rz_return_if_fail(pdb && state);
	char *str = rz_core_bin_pdb_gvars_as_string(pdb, img_base, state->d.pj, state->mode);
	// We don't need to print the output of JSON because the RzCmdStateOutput will handle it.
	if (state->mode == RZ_OUTPUT_MODE_STANDARD) {
		rz_cons_print(str);
	}
	free(str);
}

static void symbol_process(PDBSymbol *symbol, const RzCore *core, const RzPdb *pdb, const ut64 img_base, char *file) {
	if (!symbol) {
		return;
	}
	const RzDemanglerFlag dflags = rz_demangler_get_flags(core->bin->demangler);
	if (symbol->kind == PDB_Public) {
		const PDBSPublic *public = symbol->data;

		char *name = rz_demangler_msvc(public->name, dflags);
		name = (name) ? name : strdup(public->name);
		char *filtered_name = rz_name_filter2(name, true);
		char *fname = rz_str_newf("pdb.%s.%s", file, filtered_name);

		ut64 addr = rz_bin_pdb_to_rva(pdb, &public->offset);
		if (addr == UT64_MAX) {
			return;
		}
		if (img_base != UT64_MAX) {
			addr += img_base;
		}

		RzFlagItem *item = rz_flag_set(core->flags, fname, addr, 0);
		if (item) {
			rz_flag_item_set_realname(item, name);
		}
		free(filtered_name);
		free(name);
	} else if (symbol->kind == PDB_Data) {
		const PDBSData *data = symbol->data;
		if (!data->global) {
			return;
		}
		ut64 addr = rz_bin_pdb_to_rva(pdb, &data->offset);
		if (addr == UT64_MAX) {
			return;
		}
		if (img_base != UT64_MAX) {
			addr += img_base;
		}

		RzPdbTpiType *t = rz_bin_pdb_get_type_by_index(pdb->s_tpi, data->type_index);
		if (!t) {
			return;
		}
		RzType *rt = rz_type_db_pdb_parse(core->analysis->typedb, pdb->s_tpi, t);
		if (!rt) {
			return;
		}
		rz_analysis_var_global_create(core->analysis, data->name, rt, addr);
	}
}

static void pdb_set_symbols(
	const RzCore *core, const RzPdb *pdb, const ut64 img_base, const char *pdbfile) {
	rz_return_if_fail(core && pdb);
	if (!(pdb->s_pe && pdb->s_gdata)) {
		return;
	}
	char *file = rz_str_replace(strdup(pdbfile), ".pdb", "", 0);
	rz_flag_space_push(core->flags, RZ_FLAGS_FS_SYMBOLS);

	void **it;
	rz_pvector_foreach (pdb->s_gdata->global_symbols, it) {
		symbol_process(*it, core, pdb, img_base, file);
	}

	if (pdb->module_infos) {
		void **modit;
		rz_pvector_foreach (pdb->module_infos, modit) {
			PDBModuleInfo *modi = *modit;
			rz_pvector_foreach (modi->symbols, it) {
				symbol_process(*it, core, pdb, img_base, file);
			}
		err:
			continue;
		}
	}
	rz_flag_space_pop(core->flags);
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

	ut64 baddr = rz_bin_get_baddr(core->bin);
	if (!baddr || baddr == UT64_MAX) {
		baddr = rz_config_get_i(core->config, "bin.baddr");
		RZ_LOG_WARN("core: cannot find base address, flags will probably be misplaced\n");
	}

	RzPdb *pdb = rz_bin_pdb_parse_from_file(file);
	if (!pdb) {
		return NULL;
	}

	// Save compound types into types database
	rz_type_db_pdb_load(core->analysis->typedb, pdb);
	pdb_set_symbols(core, pdb, baddr, rz_file_basename(file));
	return pdb;
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
	rz_core_bin_pdb_types_print(core->analysis->typedb, pdb, state);
	rz_core_bin_pdb_gvars_print(pdb, baddr, state);
	rz_cmd_state_output_array_end(state);
}
