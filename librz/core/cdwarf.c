// SPDX-FileCopyrightText: 2021 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

RZ_API RZ_OWN char *rz_core_bin_dwarf_abbrev_decl_to_string(
	RZ_NONNULL RZ_BORROW RzBinDwarfAbbrevDecl *decl) {
	rz_return_val_if_fail(decl, NULL);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		return NULL;
	}
	rz_strbuf_appendf(sb, "    %-4" PFMT64d " ", decl->code);
	const char *tagname = rz_bin_dwarf_tag(decl->tag);
	if (tagname) {
		rz_strbuf_appendf(sb, "  %-25s ", tagname);
	}
	rz_strbuf_appendf(sb, "[%s]", decl->has_children ? "has children" : "no children");
	rz_strbuf_appendf(sb, " (0x%" PFMT64x ")\n", decl->offset);

	RzBinDwarfAttrSpec *def = NULL;
	rz_vector_foreach(&decl->defs, def) {
		const char *attr_name = rz_bin_dwarf_attr(def->at);
		const char *attr_form_name = rz_bin_dwarf_form(def->form);
		if (attr_name && attr_form_name) {
			rz_strbuf_appendf(sb, "    %-30s %s\n", attr_name, attr_form_name);
		}
	}
	return rz_strbuf_drain(sb);
}

static bool abbrev_table_dump_cb(void *user, ut64 k, const void *v) {
	if (!v) {
		return false;
	}
	RzStrBuf *sb = user;
	const RzBinDwarfAbbrevTable *table = v;
	void *itdecl;
	rz_vector_foreach(&table->abbrevs, itdecl) {
		if (!itdecl) {
			return false;
		}
		RzBinDwarfAbbrevDecl *decl = itdecl;
		char *decl_str = rz_core_bin_dwarf_abbrev_decl_to_string(decl);
		if (decl_str) {
			rz_strbuf_append(sb, decl_str);
			free(decl_str);
		}
	}
	return true;
}

RZ_API RZ_OWN char *rz_core_bin_dwarf_abbrevs_to_string(
	RZ_NONNULL RZ_BORROW const RzBinDwarfAbbrev *abbrevs) {
	rz_return_val_if_fail(abbrevs, NULL);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		return NULL;
	}
	ht_up_foreach(abbrevs->tbl_by_offset, abbrev_table_dump_cb, sb);
	return rz_strbuf_drain(sb);
}

RZ_API RZ_OWN char *rz_core_bin_dwarf_attr_to_string(
	RZ_NONNULL RZ_BORROW const RzBinDwarfAttr *attr,
	RzBinDWARF *dw, ut64 stroffsets_base) {
	rz_return_val_if_fail(attr, NULL);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		return NULL;
	}
	switch (attr->form) {
	case DW_FORM_block:
	case DW_FORM_block1:
	case DW_FORM_block2:
	case DW_FORM_block4:
	case DW_FORM_exprloc:
		rz_strbuf_appendf(sb, "%" PFMT64u " byte block:", rz_bin_dwarf_attr_block(attr)->length);
		rz_bin_dwarf_block_dump(rz_bin_dwarf_attr_block(attr), sb);
		break;
	case DW_FORM_data1:
	case DW_FORM_data2:
	case DW_FORM_data4:
	case DW_FORM_data8:
	case DW_FORM_data16:
		rz_strbuf_appendf(sb, "%" PFMT64u "", rz_bin_dwarf_attr_udata(attr));
		if (attr->at == DW_AT_language) {
			rz_strbuf_appendf(sb, "   (%s)", rz_str_get_null(rz_bin_dwarf_lang(rz_bin_dwarf_attr_udata(attr))));
		}
		break;
	case DW_FORM_string:
		if (rz_bin_dwarf_attr_string(attr, dw, stroffsets_base)) {
			rz_strbuf_appendf(sb, "%s", rz_bin_dwarf_attr_string(attr, dw, stroffsets_base));
		} else {
			rz_strbuf_append(sb, "No string found");
		}
		break;
	case DW_FORM_flag:
		rz_strbuf_appendf(sb, "%u", rz_bin_dwarf_attr_flag(attr));
		break;
	case DW_FORM_sdata:
		rz_strbuf_appendf(sb, "%" PFMT64d "", rz_bin_dwarf_attr_sdata(attr));
		break;
	case DW_FORM_udata:
		rz_strbuf_appendf(sb, "%" PFMT64u "", rz_bin_dwarf_attr_udata(attr));
		break;
	case DW_FORM_ref_addr:
	case DW_FORM_ref1:
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8:
	case DW_FORM_ref_sig8:
	case DW_FORM_ref_udata:
	case DW_FORM_ref_sup4:
	case DW_FORM_ref_sup8:
	case DW_FORM_sec_offset:
		rz_strbuf_appendf(sb, "<0x%" PFMT64x ">", rz_bin_dwarf_attr_udata(attr));
		break;
	case DW_FORM_flag_present:
		rz_strbuf_append(sb, "1");
		break;
	case DW_FORM_strx:
	case DW_FORM_strx1:
	case DW_FORM_strx2:
	case DW_FORM_strx3:
	case DW_FORM_strx4:
	case DW_FORM_line_ptr:
	case DW_FORM_strp_sup:
	case DW_FORM_strp: {
		switch (attr->value.kind) {
		case RzBinDwarfAttr_String:
			rz_strbuf_appendf(sb, "%s", rz_bin_dwarf_attr_string(attr, dw, stroffsets_base));
			break;
		case RzBinDwarfAttr_StrOffsetIndex:
			rz_strbuf_appendf(sb, "(indirect string, index 0x%" PFMT64x "): %s",
				attr->value.u64, rz_bin_dwarf_attr_string(attr, dw, stroffsets_base));
			break;
		case RzBinDwarfAttr_StrRef:
			rz_strbuf_appendf(sb, "(indirect string, .debug_str+0x%" PFMT64x "): %s",
				attr->value.u64, rz_bin_dwarf_attr_string(attr, dw, stroffsets_base));
			break;
		case RzBinDwarfAttr_LineStrRef:
			rz_strbuf_appendf(sb, "(indirect string, .debug_line_str+0x%" PFMT64x "): %s",
				attr->value.u64, rz_bin_dwarf_attr_string(attr, dw, stroffsets_base));
			break;
		default:
			break;
		}
		break;
	}
	case DW_FORM_addr:
	case DW_FORM_addrx:
	case DW_FORM_addrx1:
	case DW_FORM_addrx2:
	case DW_FORM_addrx3:
	case DW_FORM_addrx4:
	case DW_FORM_loclistx:
	case DW_FORM_rnglistx:
		rz_strbuf_appendf(sb, "0x%" PFMT64x "", rz_bin_dwarf_attr_udata(attr));
		break;
	case DW_FORM_implicit_const:
		rz_strbuf_appendf(sb, "0x%" PFMT64d "", rz_bin_dwarf_attr_udata(attr));
		break;
	default:
		rz_strbuf_appendf(sb, "Unknown attr value form %s\n", rz_bin_dwarf_form(attr->form));
		break;
	};
	return rz_strbuf_drain(sb);
}

RZ_API RZ_OWN char *rz_core_bin_dwarf_debug_info_to_string(
	RZ_NONNULL RZ_BORROW const RzBinDwarfInfo *info,
	const RzBinDWARF *dw) {
	rz_return_val_if_fail(info, NULL);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		return NULL;
	}
	RzBinDwarfCompUnit *unit = NULL;
	rz_vector_foreach(&info->units, unit) {
		rz_strbuf_append(sb, "\n");
		rz_strbuf_appendf(sb, "  Compilation Unit @ offset 0x%" PFMT64x ":\n", unit->offset);
		rz_strbuf_appendf(sb, "   Length:        0x%" PFMT64x "\n", unit->hdr.length);
		rz_strbuf_appendf(sb, "   Version:       %d\n", unit->hdr.encoding.version);
		rz_strbuf_appendf(sb, "   Abbrev Offset: 0x%" PFMT64x "\n", unit->hdr.abbrev_offset);
		rz_strbuf_appendf(sb, "   Pointer Size:  %d\n", unit->hdr.encoding.address_size);
		const char *unit_type_name = rz_bin_dwarf_unit_type(unit->hdr.ut);
		if (unit_type_name) {
			rz_strbuf_appendf(sb, "   Unit Type:     %s\n", unit_type_name);
		}
		rz_strbuf_append(sb, "\n");

		RzBinDwarfDie *die = NULL;
		rz_vector_foreach(&unit->dies, die) {
			rz_strbuf_appendf(sb, "<0x%" PFMT64x ">: Abbrev Number: %-4" PFMT64u " ",
				die->offset, die->abbrev_code);

			const char *tag_name = rz_bin_dwarf_tag(die->tag);
			if (tag_name) {
				rz_strbuf_appendf(sb, "(%s)\n", tag_name);
			} else {
				rz_strbuf_append(sb, "(Unknown abbrev tag)\n");
			}

			if (!die->abbrev_code) {
				continue;
			}

			RzBinDwarfAttr *attr = NULL;
			rz_vector_foreach(&die->attrs, attr) {
				if (!attr->at) {
					continue;
				}
				const char *attr_name = rz_bin_dwarf_attr(attr->at);
				if (attr_name) {
					rz_strbuf_appendf(sb, "\t%s ", attr_name);
				} else {
					rz_strbuf_appendf(sb, "\tAT_UNKWN [0x%-3" PFMT32x "]\t ", attr->at);
				}
				rz_strbuf_appendf(sb, "[%s]\t: ", rz_str_get_null(rz_bin_dwarf_form(attr->form)));
				rz_strbuf_append(sb, rz_str_get_null(rz_core_bin_dwarf_attr_to_string(attr, (RzBinDWARF *)dw, unit->str_offsets_base)));
				rz_strbuf_append(sb, "\n");
			}
		}
	}
	return rz_strbuf_drain(sb);
}

typedef struct {
	RzBinDWARF *dw;
	RzStrBuf *sb;
} DumpContext;

static bool htup_loclists_cb(void *u, ut64 k, const void *v) {
	const RzBinDwarfLocList *loclist = v;
	DumpContext *ctx = u;
	if (!(loclist && ctx && ctx->sb && ctx->dw)) {
		return false;
	}
	RzStrBuf *sb = ctx->sb;
	rz_strbuf_appendf(sb, "0x%" PFMT64x "\n", loclist->offset);
	void **it;
	rz_pvector_foreach (&loclist->entries, it) {
		RzBinDwarfLocListEntry *entry = *it;
		rz_strbuf_appendf(sb, "\t(0x%" PFMT64x ", 0x%" PFMT64x ")\t", entry->range->begin, entry->range->end);
		if (entry->expression) {
			const RzBinDwarfEncoding *enc = ht_up_find(
				ctx->dw->info->location_encoding, k, NULL);
			if (!enc) {
				continue;
			}
			RzBinDWARFDumpOption dump_opt = {
				.loclist_sep = ",\t",
				.loclist_indent = "",
				.expr_sep = ", "
			};
			rz_bin_dwarf_expression_dump(
				enc, entry->expression, ctx->sb, &dump_opt);
		}
		rz_strbuf_append(sb, "\n");
	}
	return true;
}

RZ_API RZ_OWN char *rz_core_bin_dwarf_loc_to_string(
	RZ_NONNULL RZ_BORROW RzBinDwarfLocLists *loclists,
	RZ_NONNULL RZ_BORROW RzBinDWARF *dw) {
	rz_return_val_if_fail(dw && loclists && loclists->loclist_by_offset, NULL);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		return NULL;
	}
	rz_strbuf_appendf(sb, "\nContents of the .debug_loc|.debug_loclists section:\n");
	DumpContext ctx = {
		.dw = dw,
		.sb = sb,
	};
	ht_up_foreach(loclists->loclist_by_offset, htup_loclists_cb, &ctx);
	rz_strbuf_append(sb, "\n");
	return rz_strbuf_drain(sb);
}

RZ_API RZ_OWN char *rz_core_bin_dwarf_aranges_to_string(RZ_NONNULL RZ_BORROW RzBinDwarfARanges *aranges) {
	rz_return_val_if_fail(aranges, NULL);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		return NULL;
	}
	rz_strbuf_append(sb, "\nContents of the .debug_aranges section:\n");
	RzListIter *it;
	RzBinDwarfARangeSet *set;
	rz_list_foreach (aranges->list, it, set) {
		rz_strbuf_append(sb, "  Address Range Set\n");
		rz_strbuf_appendf(sb, "   Unit Length:           0x%" PFMT64x "\n", set->unit_length);
		rz_strbuf_appendf(sb, "   64bit:                 %s\n", rz_str_bool(set->is_64bit));
		rz_strbuf_appendf(sb, "   Version:               %u\n", (unsigned int)set->version);
		rz_strbuf_appendf(sb, "   Offset in .debug_info: 0x%" PFMT64x "\n", set->debug_info_offset);
		rz_strbuf_appendf(sb, "   Address Size:          %u\n", (unsigned int)set->address_size);
		rz_strbuf_appendf(sb, "   Segment Size:          %u\n", (unsigned int)set->segment_size);
		rz_strbuf_append(sb, "   Ranges:\n");
		rz_strbuf_append(sb, "    address            length\n");
		for (size_t i = 0; i < set->aranges_count; i++) {
			rz_strbuf_appendf(sb, "    0x%016" PFMT64x " 0x%016" PFMT64x "\n", set->aranges[i].addr, set->aranges[i].length);
		}
	}
	rz_strbuf_append(sb, "\n");
	return rz_strbuf_drain(sb);
}

/**
 * \param regs optional, the state after op has been executed. If not null, some meaningful results from this context will be shown.
 */
static void print_line_op(RzStrBuf *sb, RzBinDwarfLineOp *op, RzBinDwarfLineHdr *hdr) {
	switch (op->type) {
	case RZ_BIN_DWARF_LINE_OP_TYPE_STD:
		rz_strbuf_append(sb, rz_str_get_null(rz_bin_dwarf_lns(op->opcode)));
		switch (op->opcode) {
		case DW_LNS_advance_pc:
			rz_strbuf_appendf(sb, "\t%" PFMT64u, op->args.advance_pc);
			break;
		case DW_LNS_advance_line:
			rz_strbuf_appendf(sb, "\t%" PFMT64u, op->args.advance_line);
			break;
		case DW_LNS_set_file:
			rz_strbuf_appendf(sb, "\t%" PFMT64u, op->args.set_file);
			break;
		case DW_LNS_set_column:
			rz_strbuf_appendf(sb, "\t%" PFMT64u, op->args.set_column);
			break;
		case DW_LNS_fixed_advance_pc:
			rz_strbuf_appendf(sb, "\t%" PFMT64u, op->args.fixed_advance_pc);
			break;
		case DW_LNS_set_isa:
			rz_strbuf_appendf(sb, "\t%" PFMT64u, op->args.set_isa);
			break;
		case DW_LNS_copy:
		case DW_LNS_negate_stmt:
		case DW_LNS_set_basic_block:
		case DW_LNS_const_add_pc:
		case DW_LNS_set_prologue_end:
		case DW_LNS_set_epilogue_begin:
		default:
			break;
		}
		break;
	case RZ_BIN_DWARF_LINE_OP_TYPE_EXT:
		rz_strbuf_append(sb, rz_str_get_null(rz_bin_dwarf_lne(op->ext_opcode)));
		switch (op->opcode) {
		case DW_LNE_set_address:
			rz_strbuf_appendf(sb, "\t0x%" PFMT64x, op->args.set_address);
			break;
		case DW_LNE_define_file:
			rz_strbuf_appendf(sb, "\tfilename \"%s\", dir_index %" PFMT64u ", ",
				op->args.define_file.path_name,
				op->args.define_file.directory_index);
			break;
		case DW_LNE_set_discriminator:
			rz_strbuf_appendf(sb, "\t%" PFMT64u "\n", op->args.set_discriminator);
			break;
		case DW_LNE_end_sequence:
		default:
			break;
		}
		break;
	case RZ_BIN_DWARF_LINE_OP_TYPE_SPEC:
		rz_strbuf_appendf(sb, "Special opcode\t%u", op->opcode);
		break;
	default:
		rz_strbuf_appendf(sb, "Unknown opcode type %u, opcode: %x", (unsigned int)op->type, op->opcode);
		break;
	}
	rz_strbuf_append(sb, "\n");
}

RZ_API RZ_OWN char *rz_core_bin_dwarf_line_unit_to_string(
	RZ_NONNULL RZ_BORROW RzBinDwarfLineUnit *unit) {
	rz_return_val_if_fail(unit, NULL);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		return NULL;
	}
	RzBinDwarfLineHdr *hdr = &unit->hdr;
	rz_strbuf_appendf(sb, " Header information[0x%" PFMT64x "]\n", hdr->offset);
	rz_strbuf_appendf(sb, "  Length:                             %" PFMT64u "\n", hdr->unit_length);
	rz_strbuf_appendf(sb, "  DWARF Version:                      %d\n", hdr->encoding.version);
	rz_strbuf_appendf(sb, "  Header Length:                      %" PFMT64d "\n", hdr->header_length);
	rz_strbuf_appendf(sb, "  Minimum Instruction Length:         %d\n", hdr->min_inst_len);
	rz_strbuf_appendf(sb, "  Maximum Operations per Instruction: %d\n", hdr->max_ops_per_inst);
	rz_strbuf_appendf(sb, "  Initial value of 'is_stmt':         %d\n", hdr->default_is_stmt);
	rz_strbuf_appendf(sb, "  Line Base:                          %d\n", hdr->line_base);
	rz_strbuf_appendf(sb, "  Line Range:                         %d\n", hdr->line_range);
	rz_strbuf_appendf(sb, "  Opcode Base:                        %d\n\n", hdr->opcode_base);
	rz_strbuf_append(sb, " Opcodes:\n");
	for (size_t i = 1; i < hdr->opcode_base; i++) {
		rz_strbuf_appendf(sb, "standard_opcode_lengths[%s] = %d\n",
			rz_str_get_null(rz_bin_dwarf_lns(i)), hdr->std_opcode_lengths[i - 1]);
	}
	rz_strbuf_append(sb, "\n");
	if (rz_pvector_len(&hdr->directories) > 0) {
		rz_strbuf_appendf(sb, " The Directory Table:\n");
		for (size_t i = 0; i < rz_pvector_len(&hdr->directories); i++) {
			rz_strbuf_appendf(sb, "  %u     %s\n", (unsigned int)i + 1, (char *)rz_pvector_at(&hdr->directories, i));
		}
	}
	if (rz_vector_len(&hdr->file_names)) {
		rz_strbuf_append(sb, "\n");
		rz_strbuf_append(sb, " The File Name Table:\n");
		rz_strbuf_append(sb, "  Entry Dir     Time      Size       Name\n");
		for (size_t i = 0; i < rz_vector_len(&hdr->file_names); i++) {
			RzBinDwarfFileEntry *f = rz_vector_index_ptr(&hdr->file_names, i);
			rz_strbuf_appendf(sb, "  %u     %" PFMT64u "       %" PFMT64u "         %" PFMT64u "          %s\n",
				(unsigned int)i + 1, f->directory_index, f->timestamp, f->size, f->path_name);
		}
		rz_strbuf_append(sb, "\n");
	}
	rz_strbuf_append(sb, " Line Number Statements:\n");
	void *opsit;
	size_t i;
	rz_vector_enumerate(&unit->ops, opsit, i) {
		RzBinDwarfLineOp *op = opsit;
		rz_strbuf_append(sb, "  ");
		print_line_op(sb, op, &unit->hdr);
		if (op->type == RZ_BIN_DWARF_LINE_OP_TYPE_EXT && op->ext_opcode == DW_LNE_end_sequence && i + 1 < rz_vector_len(&unit->ops)) {
			// extra newline for nice sequence separation
			rz_strbuf_append(sb, "\n");
		}
	}
	return rz_strbuf_drain(sb);
}

RZ_API RZ_OWN char *rz_core_bin_dwarf_line_units_to_string(RZ_NONNULL RZ_BORROW RzBinDwarfLine *line) {
	rz_return_val_if_fail(line && line->reader, NULL);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		return NULL;
	}
	rz_strbuf_appendf(sb, "Raw dump of debug contents of section %s:\n\n", line->reader->section_name);
	RzListIter *it;
	RzBinDwarfLineUnit *unit;
	bool first = true;
	rz_list_foreach (line->units, it, unit) {
		if (first) {
			first = false;
		} else {
			rz_strbuf_append(sb, "\n");
		}
		char *s = rz_core_bin_dwarf_line_unit_to_string(unit);
		if (s) {
			rz_strbuf_append(sb, s);
			free(s);
		}
	}
	rz_strbuf_append(sb, "\n");
	return rz_strbuf_drain(sb);
}

static bool htup_rnglists_cb(void *u, ut64 k, const void *v) {
	const RzBinDwarfRngList *rnglist = v;
	RzStrBuf *sb = u;
	if (!(rnglist && sb)) {
		return false;
	}

	rz_strbuf_appendf(sb, "0x%" PFMT64x "\n", rnglist->offset);
	void **it;
	rz_pvector_foreach (&rnglist->entries, it) {
		RzBinDwarfRange *range = *it;
		rz_strbuf_appendf(sb, "\t(0x%" PFMT64x ", 0x%" PFMT64x ")\n", range->begin, range->end);
	}
	return true;
}

RZ_API RZ_OWN char *rz_core_bin_dwarf_rnglists_to_string(
	RZ_NONNULL RZ_BORROW RzBinDwarfRngLists *rnglists) {
	rz_warn_if_fail(rnglists && rnglists->rnglist_by_offset);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		return NULL;
	}
	rz_strbuf_appendf(sb, "\nContents of the .debug_rnglists|.debug_ranges section:\n");
	ht_up_foreach(rnglists->rnglist_by_offset, htup_rnglists_cb, sb);
	rz_strbuf_append(sb, "\n");
	return rz_strbuf_drain(sb);
}
