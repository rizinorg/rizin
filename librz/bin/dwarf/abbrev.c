// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

static int RzBinDwarfAbbrevDecl_init(RzBinDwarfAbbrevDecl *abbrev) {
	if (!abbrev) {
		return -EINVAL;
	}
	rz_vector_init(&abbrev->defs, sizeof(RzBinDwarfAttrDef), NULL, NULL);
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

static void htup_RzBinDwarfAbbrevTable_free(HtUPKv *kv) {
	if (!kv) {
		return;
	}
	RzBinDwarfAbbrevTable_free(kv->value);
}

static void RzBinDwarfDebugAbbrevs_fini(RzBinDwarfDebugAbbrevs *abbrevs) {
	ht_up_free(abbrevs->tbl_by_offset);
}

static bool RzBinDwarfDebugAbbrevs_init(RzBinDwarfDebugAbbrevs *abbrevs) {
	if (!abbrevs) {
		return false;
	}
	abbrevs->tbl_by_offset = ht_up_new(NULL, htup_RzBinDwarfAbbrevTable_free, NULL);
	if (!abbrevs->tbl_by_offset) {
		goto beach;
	}
	return true;
beach:
	RzBinDwarfDebugAbbrevs_fini(abbrevs);
	return false;
}

RZ_API void rz_bin_dwarf_abbrev_free(RZ_OWN RZ_NULLABLE RzBinDwarfDebugAbbrevs *abbrevs) {
	if (!abbrevs) {
		return;
	}
	RzBinDwarfDebugAbbrevs_fini(abbrevs);
	free(abbrevs);
}

static RzBinDwarfAbbrevTable *RzBinDwarfAbbrevTable_new(size_t offset) {
	RzBinDwarfAbbrevTable *table = RZ_NEW0(RzBinDwarfAbbrevTable);
	rz_vector_init(&table->abbrevs, sizeof(RzBinDwarfAbbrevDecl), (RzVectorFree)RzBinDwarfAbbrevDecl_fini, NULL);
	table->offset = offset;
	return table;
}

static bool RzBinDwarfDebugAbbrevs_parse(RzBuffer *buffer, RzBinDwarfDebugAbbrevs *abbrevs) {
	RET_FALSE_IF_FAIL(RzBinDwarfDebugAbbrevs_init(abbrevs));
	RzBinDwarfAbbrevTable *tbl = RzBinDwarfAbbrevTable_new(rz_buf_tell(buffer));
	while (true) {
		ut64 offset = rz_buf_tell(buffer);
		if (!tbl) {
			tbl = RzBinDwarfAbbrevTable_new(offset);
		}

		RzBinDwarfAbbrevDecl decl = {
			.offset = offset,
			0,
		};

		ULE128_OR_GOTO(decl.code, ok);
		if (decl.code == 0) {
			ht_up_update(abbrevs->tbl_by_offset, tbl->offset, tbl);
			tbl = NULL;
			continue;
		}

		ULE128_OR_GOTO(decl.tag, err);
		U8_OR_GOTO(decl.has_children, err);
		if (!(decl.has_children == DW_CHILDREN_yes || decl.has_children == DW_CHILDREN_no)) {
			RZ_LOG_ERROR(".debug_abbrevs parse error: 0x%" PFMT64x "\t[%s] invalid DW_CHILDREN value: %d\n",
				rz_buf_tell(buffer), rz_bin_dwarf_tag(decl.tag), decl.has_children);
			goto err;
		}

		RzBinDwarfAbbrevDecl_init(&decl);
		RZ_LOG_DEBUG("0x%" PFMT64x ":\t[%" PFMT64u "] %s, has_children: %d\n",
			offset, decl.code, rz_bin_dwarf_tag(decl.tag), decl.has_children);

		do {
			RzBinDwarfAttrDef def = { 0 };
			ULE128_OR_GOTO(def.name, err);
			if (def.name == 0) {
				ULE128_OR_GOTO(def.form, err);
				if (def.form == 0) {
					goto abbrev_ok;
				}
				RZ_LOG_ERROR("invalid name and form %" PFMT32d " %" PFMT32d "\n",
					def.name, def.form);
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
				rz_buf_tell(buffer), rz_bin_dwarf_attr(def.name), rz_bin_dwarf_form(def.form), def.special);
			rz_vector_push(&decl.defs, &def);
		} while (true);
	abbrev_ok:
		rz_vector_push(&tbl->abbrevs, &decl);
		abbrevs->count++;
	}
ok:
	ht_up_update(abbrevs->tbl_by_offset, tbl->offset, tbl);
	return abbrevs;
err:
	RzBinDwarfAbbrevTable_free(tbl);
	return false;
}

/**
 * \brief Parse .debug_abbrev section
 * \param binfile  Binfile to parse
 * \return RzBinDwarfDebugAbbrevs object
 */
RZ_API RZ_OWN RzBinDwarfDebugAbbrevs *rz_bin_dwarf_abbrev_parse(RZ_BORROW RZ_NONNULL RzBinFile *binfile) {
	rz_return_val_if_fail(binfile, NULL);
	RzBinDwarfDebugAbbrevs *abbrevs = NULL;
	RzBuffer *buf = get_section_buf(binfile, "debug_abbrev");
	GOTO_IF_FAIL(buf, ok);
	abbrevs = RZ_NEW0(RzBinDwarfDebugAbbrevs);
	GOTO_IF_FAIL(abbrevs, err);
	abbrevs->tbl_by_offset = ht_up_new(NULL, htup_RzBinDwarfAbbrevTable_free, NULL);
	GOTO_IF_FAIL(abbrevs->tbl_by_offset, err);
	GOTO_IF_FAIL(RzBinDwarfDebugAbbrevs_parse(buf, abbrevs), err);
ok:
	rz_buf_free(buf);
	return abbrevs;
err:
	rz_bin_dwarf_abbrev_free(abbrevs);
	abbrevs = NULL;
	goto ok;
}

/**
 * \brief Get the RzBinDwarfAttrDef object by attribute's name
 *
 * \param abbrev RzBinDwarfDebugAbbrevDecl object
 * \param name DW_AT name
 * \return RzBinDwarfAttrDef object or NULL if not found
 */
RZ_API RZ_BORROW RzBinDwarfAttrDef *rz_bin_dwarf_abbrev_attr_by_name(RZ_BORROW RZ_NONNULL const RzBinDwarfAbbrevDecl *abbrev, enum DW_AT name) {
	rz_return_val_if_fail(abbrev, NULL);
	RzBinDwarfAttrDef *attr = NULL;
	rz_vector_foreach(&abbrev->defs, attr) {
		if (attr->name == name) {
			return attr;
		}
	}
	return NULL;
}

/**
 * \brief Get the RzBinDwarfAttrDef object by index
 *
 * \param decl RzBinDwarfAbbrevDecl object
 * \param idx Index
 * \return RzBinDwarfAttrDef object or NULL if not found
 */
RZ_API RzBinDwarfAttrDef *rz_bin_dwarf_abbrev_attr_by_index(RZ_NONNULL const RzBinDwarfAbbrevDecl *decl, size_t idx) {
	rz_return_val_if_fail(decl, NULL);
	return rz_vector_index_ptr(&decl->defs, idx);
}

/**
 * \brief Get the abbrev's decl count
 *
 * \param da RzBinDwarfDebugAbbrevs object
 * \return Abbrev count
 */
RZ_API size_t rz_bin_dwarf_abbrev_count(RZ_BORROW RZ_NONNULL const RzBinDwarfDebugAbbrevs *da) {
	rz_return_val_if_fail(da, 0);
	return da->count;
}

/**
 * \brief Get the abbrev's decl by index
 *
 * \param da RzBinDwarfDebugAbbrevs object
 * \param idx Index
 * \return Abbrev decl or NULL if not found
 */
RZ_API RZ_BORROW RzBinDwarfAbbrevDecl *rz_bin_dwarf_abbrev_get(RZ_BORROW RZ_NONNULL const RzBinDwarfAbbrevTable *tbl, size_t idx) {
	rz_return_val_if_fail(tbl, NULL);
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
