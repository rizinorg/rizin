// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

static int abbrev_decl_init(RzBinDwarfAbbrevDecl *abbrev) {
	if (!abbrev) {
		return -EINVAL;
	}
	rz_vector_init(&abbrev->defs, sizeof(RzBinDwarfAttrDef), NULL, NULL);
	return 0;
}

static int abbrev_decl_fini(RzBinDwarfAbbrevDecl *abbrev) {
	if (!abbrev) {
		return -EINVAL;
	}
	rz_vector_fini(&abbrev->defs);
	return 0;
}

static void kv_abbrev_free(HtUPKv *kv) {
	if (!kv) {
		return;
	}
	RzVector *v = kv->value;
	if (!v) {
		return;
	}
	rz_vector_fini(v);
}

static void abbrev_fini(RzBinDwarfDebugAbbrevs *abbrevs) {
	if (!abbrevs) {
		return;
	}
	ht_up_free(abbrevs->tbl);
}

static int abbrev_init(RzBinDwarfDebugAbbrevs *abbrevs) {
	if (!abbrevs) {
		return -EINVAL;
	}
	abbrevs->tbl = ht_up_new(NULL, kv_abbrev_free, NULL);
	if (!abbrevs->tbl) {
		goto beach;
	}
	return 0;
beach:
	abbrev_fini(abbrevs);
	return -EINVAL;
}

RZ_API void rz_bin_dwarf_abbrev_free(RzBinDwarfDebugAbbrevs *abbrevs) {
	if (!abbrevs) {
		return;
	}
	abbrev_fini(abbrevs);
	free(abbrevs);
}

static RzBinDwarfAbbrevTable *abbrev_table_new(size_t offset) {
	RzBinDwarfAbbrevTable *table = RZ_NEW0(RzBinDwarfAbbrevTable);
	rz_vector_init(&table->abbrevs, sizeof(RzBinDwarfAbbrevDecl), (RzVectorFree)abbrev_decl_fini, NULL);
	table->offset = offset;
	return table;
}

static void abbrev_table_free(RzBinDwarfAbbrevTable *table) {
	if (!table) {
		return;
	}
	rz_vector_fini(&table->abbrevs);
	free(table);
}

static void htup_abbrev_table_free(HtUPKv *kv) {
	if (!kv) {
		return;
	}
	abbrev_table_free(kv->value);
}

static bool abbrev_parse(RzBuffer *buffer, RzBinDwarfDebugAbbrevs *abbrevs) {
	abbrev_init(abbrevs);
	RzBinDwarfAbbrevTable *tbl = abbrev_table_new(rz_buf_tell(buffer));
	while (true) {
		ut64 offset = rz_buf_tell(buffer);
		if (!tbl) {
			tbl = abbrev_table_new(offset);
		}

		ut64 code = 0;
		ULE128_OR_GOTO(code, ok);
		if (code == 0) {
			ht_up_update(abbrevs->tbl, tbl->offset, tbl);
			tbl = NULL;
			continue;
		}

		ut64 tag;
		ULE128_OR_RET_FALSE(tag);
		ut8 has_children;
		U8_OR_RET_FALSE(has_children);
		if (!(has_children == DW_CHILDREN_yes || has_children == DW_CHILDREN_no)) {
			RZ_LOG_ERROR("0x%" PFMT64x ":\tinvalid DW_CHILDREN value: %d\n", rz_buf_tell(buffer), has_children);
			break;
		}

		RzBinDwarfAbbrevDecl decl = {
			.offset = offset,
			.code = code,
			.tag = tag,
			.has_children = has_children,
		};
		abbrev_decl_init(&decl);
		RZ_LOG_DEBUG("0x%" PFMT64x ":\t[%" PFMT64u "] %s, has_children: %d\n", offset, code, rz_bin_dwarf_tag(tag), has_children);

		do {
			ut64 name = 0;
			ULE128_OR_RET_FALSE(name);
			if (name == 0) {
				st64 form = 0;
				ULE128_OR_RET_FALSE(form);
				if (form == 0) {
					goto abbrev_ok;
				}
				RZ_LOG_ERROR("invalid name and form %" PFMT64d " %" PFMT64d "\n", name, form);
				goto err;
			}

			ut64 form = 0;
			ULE128_OR_RET_FALSE(form);

			/**
			 * http://www.dwarfstd.org/doc/DWARF5.pdf#page=225
			 *
			 * The attribute form DW_FORM_implicit_const is another special case. For
			 * attributes with this form, the attribute specification contains a third part, which is
			 * a signed LEB128 number. The value of this number is used as the value of the
			 * attribute, and no value is stored in the .debug_info section.
			 */
			st64 special = 0;
			if (form == DW_FORM_implicit_const) {
				SLE128_OR_RET_FALSE(special);
			}
			RzBinDwarfAttrDef def = {
				.name = name,
				.form = form,
				.special = special,
			};
			RZ_LOG_DEBUG("0x%" PFMT64x ":\t\t%s [%s] special = %" PFMT64d "\n", rz_buf_tell(buffer), rz_bin_dwarf_attr(name), rz_bin_dwarf_form(form), special);
			rz_vector_push(&decl.defs, &def);
		} while (true);
	abbrev_ok:
		rz_vector_push(&tbl->abbrevs, &decl);
		abbrevs->count++;
	}
ok:
	ht_up_update(abbrevs->tbl, tbl->offset, tbl);
	return abbrevs;
err:
	rz_bin_dwarf_abbrev_free(abbrevs);
	return NULL;
}

RZ_API RzBinDwarfDebugAbbrevs *rz_bin_dwarf_abbrev_parse(RzBinFile *binfile) {
	rz_return_val_if_fail(binfile, NULL);
	RzBinDwarfDebugAbbrevs *abbrevs = NULL;
	RzBuffer *buf = get_section_buf(binfile, "debug_abbrev");
	GOTO_IF_FAIL(buf, ok);
	abbrevs = RZ_NEW0(RzBinDwarfDebugAbbrevs);
	GOTO_IF_FAIL(abbrevs, err);
	abbrevs->tbl = ht_up_new(NULL, htup_abbrev_table_free, NULL);
	GOTO_IF_FAIL(abbrevs->tbl, err);
	GOTO_IF_FAIL(abbrev_parse(buf, abbrevs), err);
ok:
	rz_buf_free(buf);
	return abbrevs;
err:
	rz_bin_dwarf_abbrev_free(abbrevs);
	abbrevs = NULL;
	goto ok;
}

RZ_API RzBinDwarfAttrDef *rz_bin_dwarf_abbrev_get_attr(RZ_NONNULL const RzBinDwarfAbbrevDecl *abbrev, enum DW_AT name) {
	rz_return_val_if_fail(abbrev, NULL);
	RzBinDwarfAttrDef *attr = NULL;
	rz_vector_foreach(&abbrev->defs, attr) {
		if (attr->name == name) {
			return attr;
		}
	}
	return NULL;
}

RZ_API size_t rz_bin_dwarf_abbrev_count(RZ_NONNULL const RzBinDwarfDebugAbbrevs *da) {
	rz_return_val_if_fail(da, 0);
	return da->count;
}

RZ_API RzBinDwarfAbbrevDecl *rz_bin_dwarf_abbrev_get(RZ_NONNULL const RzBinDwarfAbbrevTable *tbl, size_t idx) {
	rz_return_val_if_fail(tbl, NULL);
	return rz_vector_index_ptr(&tbl->abbrevs, idx - 1);
}

RZ_API size_t rz_bin_dwarf_abbrev_decl_count(RZ_NONNULL const RzBinDwarfAbbrevDecl *decl) {
	rz_return_val_if_fail(decl, 0);
	return rz_vector_len(&decl->defs);
}

RZ_API RzBinDwarfAttrDef *rz_bin_dwarf_abbrev_attr_get(RZ_NONNULL const RzBinDwarfAbbrevDecl *decl, size_t idx) {
	rz_return_val_if_fail(decl, NULL);
	return rz_vector_index_ptr(&decl->defs, idx);
}
