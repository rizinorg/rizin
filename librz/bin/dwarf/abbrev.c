// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

/**
 * \brief Initialize a RzBinDwarfAbbrevDecl
 * \param abbrev the RzBinDwarfAbbrevDecl to initialize
 * \return 0 on success, otherwise a nonzero error code
 */
static int RzBinDwarfAbbrevDecl_init(RzBinDwarfAbbrevDecl *abbrev) {
	if (!abbrev) {
		return -EINVAL;
	}
	rz_vector_init(&abbrev->defs, sizeof(RzBinDwarfAttrSpec), NULL, NULL);
	return 0;
}

static int RzBinDwarfAbbrevDecl_fini(RzBinDwarfAbbrevDecl *abbrev) {
	if (!abbrev) {
		return -EINVAL;
	}
	rz_vector_fini(&abbrev->defs);
	return 0;
}

static void RzBinDwarfAbbrevTable_free(RzBinDwarfAbbrevTable *table) {
	if (!table) {
		return;
	}
	rz_vector_fini(&table->abbrevs);
	free(table);
}

static void RzBinDwarfAbbrevs_fini(RzBinDwarfAbbrev *abbrevs) {
	ht_up_free(abbrevs->by_offset);
	R_free(abbrevs->R);
}

static bool RzBinDwarfAbbrevs_init(RzBinDwarfAbbrev *abbrevs) {
	if (!abbrevs) {
		return false;
	}
	abbrevs->by_offset = ht_up_new(NULL, (HtUPFreeValue)RzBinDwarfAbbrevTable_free);
	if (!abbrevs->by_offset) {
		goto beach;
	}
	return true;
beach:
	RzBinDwarfAbbrevs_fini(abbrevs);
	return false;
}

RZ_API void rz_bin_dwarf_abbrev_free(RZ_OWN RZ_NULLABLE RzBinDwarfAbbrev *abbrevs) {
	if (!abbrevs) {
		return;
	}
	RzBinDwarfAbbrevs_fini(abbrevs);
	free(abbrevs);
}

static RzBinDwarfAbbrevTable *RzBinDwarfAbbrevTable_new(size_t offset) {
	RzBinDwarfAbbrevTable *table = RZ_NEW0(RzBinDwarfAbbrevTable);
	rz_vector_init(&table->abbrevs, sizeof(RzBinDwarfAbbrevDecl), (RzVectorFree)RzBinDwarfAbbrevDecl_fini, NULL);
	table->offset = offset;
	return table;
}

static bool RzBinDwarfAbbrevs_parse(RzBinDwarfAbbrev *abbrevs) {
	RzBinEndianReader *R = abbrevs->R;
	RET_FALSE_IF_FAIL(RzBinDwarfAbbrevs_init(abbrevs));
	RzBinDwarfAbbrevTable *tbl = RzBinDwarfAbbrevTable_new(R_tell(R));
	while (true) {
		ut64 offset = R_tell(R);
		if (!tbl) {
			tbl = RzBinDwarfAbbrevTable_new(offset);
		}

		RzBinDwarfAbbrevDecl decl = {
			.offset = offset,
			0,
		};

		ULE128_OR_GOTO(decl.code, ok);
		if (decl.code == 0) {
			ht_up_update(abbrevs->by_offset, tbl->offset, tbl);
			tbl = NULL;
			continue;
		}

		ULE128_OR_GOTO(decl.tag, err);
		U8_OR_GOTO(decl.has_children, err);
		if (!(decl.has_children == DW_CHILDREN_yes || decl.has_children == DW_CHILDREN_no)) {
			RZ_LOG_ERROR(".debug_abbrevs parse error: 0x%" PFMT64x "\t[%s] invalid DW_CHILDREN value: %d\n",
				R_tell(R), rz_bin_dwarf_tag(decl.tag), decl.has_children);
			goto err;
		}

		RzBinDwarfAbbrevDecl_init(&decl);
		RZ_LOG_DEBUG("0x%" PFMT64x ":\t[%" PFMT64u "] %s, has_children: %d\n",
			offset, decl.code, rz_bin_dwarf_tag(decl.tag), decl.has_children);

		do {
			RzBinDwarfAttrSpec def = { 0 };
			ULE128_OR_GOTO(def.at, err);
			if (def.at == 0) {
				ULE128_OR_GOTO(def.form, err);
				if (def.form == 0) {
					goto abbrev_ok;
				}
				RZ_LOG_ERROR("invalid name and form %" PFMT32d " %" PFMT32d "\n",
					def.at, def.form);
				goto err;
			}

			ULE128_OR_GOTO(def.form, err);

			/**
			 * http://www.dwarfstd.org/doc/DWARF5.pdf#page=225
			 *
			 * The attribute form DW_FORM_implicit_const is another special case. For
			 * attributes with this form, the attribute specification contains a third part, which is
			 * a signed LEB128 number. The value of this number is used as the value of the
			 * attribute, and no value is stored in the .debug_info section.
			 */
			if (def.form == DW_FORM_implicit_const) {
				SLE128_OR_GOTO(def.special, err);
			}
			RZ_LOG_DEBUG("0x%" PFMT64x ":\t\t%s [%s] special = %" PFMT64d "\n",
				R_tell(R), rz_bin_dwarf_attr(def.at), rz_bin_dwarf_form(def.form), def.special);
			rz_vector_push(&decl.defs, &def);
		} while (true);
	abbrev_ok:
		rz_vector_push(&tbl->abbrevs, &decl);
		abbrevs->count++;
	}
ok:
	ht_up_update(abbrevs->by_offset, tbl->offset, tbl);
	return abbrevs;
err:
	RzBinDwarfAbbrevTable_free(tbl);
	return false;
}

/**
 * \brief Parse .debug_abbrev section
 * \param buffer  Buffer to parse
 * \return RzBinDwarfAbbrevs object
 */
RZ_API RZ_OWN RzBinDwarfAbbrev *rz_bin_dwarf_abbrev_new(RZ_OWN RZ_NONNULL RzBinEndianReader *R) {
	rz_return_val_if_fail(R, NULL);
	RzBinDwarfAbbrev *abbrevs = RZ_NEW0(RzBinDwarfAbbrev);
	RET_FALSE_IF_FAIL(abbrevs);
	abbrevs->R = R;
	if (!RzBinDwarfAbbrevs_parse(abbrevs)) {
		rz_bin_dwarf_abbrev_free(abbrevs);
		return NULL;
	}
	return abbrevs;
}

/**
 * \brief Parse .debug_abbrev section
 * \param bf  Binfile to parse
 * \return RzBinDwarfAbbrevs object
 */
RZ_API RZ_OWN RzBinDwarfAbbrev *rz_bin_dwarf_abbrev_from_file(
	RZ_BORROW RZ_NONNULL RzBinFile *bf, bool is_dwo) {
	rz_return_val_if_fail(bf, NULL);
	RzBinEndianReader *r = RzBinEndianReader_from_file(bf, ".debug_abbrev", is_dwo);
	RET_NULL_IF_FAIL(r);
	return rz_bin_dwarf_abbrev_new(r);
}

/**
 * \brief Get the abbrev's decl count
 *
 * \param da RzBinDwarfAbbrevs object
 * \return Abbrev count
 */
RZ_API size_t rz_bin_dwarf_abbrev_count(RZ_BORROW RZ_NONNULL const RzBinDwarfAbbrev *da) {
	rz_return_val_if_fail(da, 0);
	return da->count;
}

/**
 * \brief Get the abbrev's decl by index
 *
 * \param da RzBinDwarfAbbrevs object
 * \param idx Index
 * \return Abbrev decl or NULL if not found
 */
RZ_API RZ_BORROW RzBinDwarfAbbrevDecl *rz_bin_dwarf_abbrev_get(RZ_BORROW RZ_NONNULL const RzBinDwarfAbbrevTable *tbl, size_t idx) {
	rz_return_val_if_fail(tbl, NULL);
	if (idx > rz_vector_len(&tbl->abbrevs)) {
		return NULL;
	}
	return rz_vector_index_ptr(&tbl->abbrevs, idx - 1);
}

/**
 * \brief Get the RzBinDwarfAttrDef count of the abbrev decl
 *
 * \param decl RzBinDwarfAbbrevDecl object
 * \return RzBinDwarfAttrDef count
 */
RZ_API size_t rz_bin_dwarf_abbrev_decl_count(RZ_BORROW RZ_NONNULL const RzBinDwarfAbbrevDecl *decl) {
	rz_return_val_if_fail(decl, 0);
	return rz_vector_len(&decl->defs);
}

static void abbrev_decl_dump(
	RZ_NONNULL RZ_BORROW RzBinDwarfAbbrevDecl *decl,
	RZ_NONNULL RZ_BORROW RzStrBuf *sb) {
	rz_return_if_fail(decl && sb);
	rz_strbuf_appendf(sb, "%" PFMT64d " ", decl->code);
	rz_strbuf_appendf(sb, "%s\t", rz_bin_dwarf_tag(decl->tag));
	rz_strbuf_appendf(sb, "%s ", rz_bin_dwarf_children(decl->has_children));
	rz_strbuf_appendf(sb, "(0x%" PFMT64x ")\n", decl->offset);

	RzBinDwarfAttrSpec *def = NULL;
	rz_vector_foreach (&decl->defs, def) {
		rz_strbuf_appendf(sb, "\t%s\t%s\n",
			rz_bin_dwarf_attr(def->at), rz_bin_dwarf_form(def->form));
	}
	rz_strbuf_append(sb, "\n");
}

static bool cb_abbrev_table_dump(void *user, ut64 k, const void *v) {
	if (!v) {
		return false;
	}
	RzStrBuf *sb = user;
	const RzBinDwarfAbbrevTable *table = v;
	if (!rz_vector_empty(&table->abbrevs)) {
		rz_strbuf_appendf(sb, "Abbrev table for offset: 0x%08zx\n", table->offset);
	}

	void *itdecl;
	rz_vector_foreach (&table->abbrevs, itdecl) {
		if (!itdecl) {
			continue;
		}
		abbrev_decl_dump(itdecl, sb);
	}
	return true;
}

RZ_API void rz_core_bin_dwarf_abbrevs_dump(
	RZ_NONNULL RZ_BORROW const RzBinDwarfAbbrev *abbrevs,
	RZ_NONNULL RZ_BORROW RzStrBuf *sb) {
	rz_return_if_fail(abbrevs && sb);
	if (abbrevs->by_offset->count > 0) {
		rz_strbuf_append(sb, ".debug_abbrevs content:\n");
	}
	ht_up_foreach(abbrevs->by_offset, cb_abbrev_table_dump, sb);
}
