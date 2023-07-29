// SPDX-FileCopyrightText: 2021 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

#define my_printf(...) rz_strbuf_appendf(sb, __VA_ARGS__)
#define my_print(x)    rz_strbuf_append(sb, (x))
#define my_print_init \
	RzStrBuf *sb = rz_strbuf_new(NULL); \
	if (!sb) { \
		return NULL; \
	}
#define my_print_get rz_strbuf_drain(sb)

RZ_API char *rz_core_bin_dwarf_abbrev_decl_to_string(RzBinDwarfAbbrevDecl *decl) {
	if (!decl) {
		return NULL;
	}
	my_print_init;
	my_printf("    %-4" PFMT64d " ", decl->code);
	const char *tagname = rz_bin_dwarf_tag(decl->tag);
	if (tagname) {
		my_printf("  %-25s ", tagname);
	}
	my_printf("[%s]", decl->has_children ? "has children" : "no children");
	my_printf(" (0x%" PFMT64x ")\n", decl->offset);

	RzBinDwarfAttrDef *def = NULL;
	rz_vector_foreach(&decl->defs, def) {
		const char *attr_name = rz_bin_dwarf_attr(def->name);
		const char *attr_form_name = rz_bin_dwarf_form(def->form);
		if (attr_name && attr_form_name) {
			my_printf("    %-30s %s\n", attr_name, attr_form_name);
		}
	}
	return my_print_get;
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
			my_print(decl_str);
			free(decl_str);
		}
	}
	return true;
}

RZ_API char *rz_core_bin_dwarf_abbrevs_to_string(const RzBinDwarfDebugAbbrevs *abbrevs) {
	if (!abbrevs) {
		return NULL;
	}
	my_print_init;
	ht_up_foreach(abbrevs->tbl_by_offset, abbrev_table_dump_cb, sb);
	return my_print_get;
}

RZ_API char *rz_core_bin_dwarf_attr_to_string(const RzBinDwarfAttr *val) {
	rz_return_val_if_fail(val, NULL);
	my_print_init;
	switch (val->form) {
	case DW_FORM_block:
	case DW_FORM_block1:
	case DW_FORM_block2:
	case DW_FORM_block4:
	case DW_FORM_exprloc:
		my_printf("%" PFMT64u " byte block:", val->block.length);
		rz_bin_dwarf_block_dump(&val->block, sb);
		break;
	case DW_FORM_data1:
	case DW_FORM_data2:
	case DW_FORM_data4:
	case DW_FORM_data8:
	case DW_FORM_data16:
		my_printf("%" PFMT64u "", val->uconstant);
		if (val->name == DW_AT_language) {
			const char *lang_name = rz_bin_dwarf_lang(val->uconstant);
			if (lang_name) {
				my_printf("   (%s)", lang_name);
			}
		}
		break;
	case DW_FORM_string:
		if (val->string.content) {
			my_printf("%s", val->string.content);
		} else {
			my_print("No string found");
		}
		break;
	case DW_FORM_flag:
		my_printf("%u", val->flag);
		break;
	case DW_FORM_sdata:
		my_printf("%" PFMT64d "", val->sconstant);
		break;
	case DW_FORM_udata:
		my_printf("%" PFMT64u "", val->uconstant);
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
		my_printf("<0x%" PFMT64x ">", val->reference);
		break;
	case DW_FORM_flag_present:
		my_print("1");
		break;
	case DW_FORM_strx:
	case DW_FORM_strx1:
	case DW_FORM_strx2:
	case DW_FORM_strx3:
	case DW_FORM_strx4:
	case DW_FORM_line_ptr:
	case DW_FORM_strp_sup:
	case DW_FORM_strp:
		my_printf("(indirect string, offset: 0x%" PFMT64x "): %s",
			val->string.offset, val->string.content);
		break;
	case DW_FORM_addr:
	case DW_FORM_addrx:
	case DW_FORM_addrx1:
	case DW_FORM_addrx2:
	case DW_FORM_addrx3:
	case DW_FORM_addrx4:
	case DW_FORM_loclistx:
	case DW_FORM_rnglistx:
		my_printf("0x%" PFMT64x "", val->address);
		break;
	case DW_FORM_implicit_const:
		my_printf("0x%" PFMT64d "", val->uconstant);
		break;
	default:
		my_printf("Unknown attr value form %s\n", rz_bin_dwarf_form(val->form));
		break;
	};
	return my_print_get;
}

RZ_API char *rz_core_bin_dwarf_debug_info_to_string(const RzBinDwarfDebugInfo *info) {
	rz_return_val_if_fail(info, NULL);
	my_print_init;
	RzBinDwarfCompUnit *unit = NULL;
	rz_vector_foreach(&info->units, unit) {
		my_print("\n");
		my_printf("  Compilation Unit @ offset 0x%" PFMT64x ":\n", unit->offset);
		my_printf("   Length:        0x%" PFMT64x "\n", unit->hdr.length);
		my_printf("   Version:       %d\n", unit->hdr.encoding.version);
		my_printf("   Abbrev Offset: 0x%" PFMT64x "\n", unit->hdr.abbrev_offset);
		my_printf("   Pointer Size:  %d\n", unit->hdr.encoding.address_size);
		const char *unit_type_name = rz_bin_dwarf_unit_type(unit->hdr.unit_type);
		if (unit_type_name) {
			my_printf("   Unit Type:     %s\n", unit_type_name);
		}
		my_print("\n");

		RzBinDwarfDie *die = NULL;
		rz_vector_foreach(&unit->dies, die) {
			my_printf("<0x%" PFMT64x ">: Abbrev Number: %-4" PFMT64u " ", die->offset, die->abbrev_code);

			const char *tag_name = rz_bin_dwarf_tag(die->tag);
			if (tag_name) {
				my_printf("(%s)\n", tag_name);
			} else {
				my_print("(Unknown abbrev tag)\n");
			}

			if (!die->abbrev_code) {
				continue;
			}

			RzBinDwarfAttr *attr = NULL;
			rz_vector_foreach(&die->attrs, attr) {
				if (!attr->name) {
					continue;
				}
				const char *attr_name = rz_bin_dwarf_attr(attr->name);
				if (attr_name) {
					my_printf("     %-25s : ", attr_name);
				} else {
					my_printf("     AT_UNKWN [0x%-3" PFMT32x "]\t : ", attr->name);
				}
				my_print(rz_str_get_null(rz_core_bin_dwarf_attr_to_string(attr)));
				my_printf("\n");
			}
		}
	}
	return my_print_get;
}

typedef struct {
	RzBinDwarf *dw;
	RzStrBuf *sb;
} DumpContex;

bool htup_loclists_cb(void *u, ut64 k, const void *v) {
	const RzBinDwarfLocList *loclist = v;
	DumpContex *ctx = u;
	if (!(loclist && ctx && ctx->sb && ctx->dw)) {
		return false;
	}
	RzStrBuf *sb = ctx->sb;

	my_printf("0x%" PFMT64x "\n", loclist->offset);
	void **it;
	rz_pvector_foreach (&loclist->entries, it) {
		RzBinDwarfLocationListEntry *entry = *it;
		my_printf("\t(0x%" PFMT64x ", 0x%" PFMT64x ")\t[", entry->range->begin, entry->range->end);
		rz_bin_dwarf_expression_dump(&ctx->dw->encoding, entry->expression, ctx->sb, ",\t", "");
		my_print("]\n");
	}
	return true;
}

RZ_API char *rz_core_bin_dwarf_loc_to_string(RzBinDwarf *dw, RzBinDwarfLocListTable *loclists, int addr_size) {
	rz_return_val_if_fail(loclists && loclists->loclist_by_offset, NULL);
	my_print_init;
	my_printf("\nContents of the .debug_%s section:\n", loclists->debug_loc ? "loc" : "loclists");
	DumpContex ctx = {
		.dw = dw,
		.sb = sb,
	};
	ht_up_foreach(loclists->loclist_by_offset, htup_loclists_cb, &ctx);
	my_print("\n");
	return my_print_get;
}

RZ_API char *rz_core_bin_dwarf_aranges_to_string(RzList /*<RzBinDwarfARangeSet *>*/ *aranges) {
	rz_return_val_if_fail(aranges, NULL);
	my_print_init;
	my_print("\nContents of the .debug_aranges section:\n");
	RzListIter *it;
	RzBinDwarfARangeSet *set;
	rz_list_foreach (aranges, it, set) {
		my_print("  Address Range Set\n");
		my_printf("   Unit Length:           0x%" PFMT64x "\n", set->unit_length);
		my_printf("   64bit:                 %s\n", rz_str_bool(set->is_64bit));
		my_printf("   Version:               %u\n", (unsigned int)set->version);
		my_printf("   Offset in .debug_info: 0x%" PFMT64x "\n", set->debug_info_offset);
		my_printf("   Address Size:          %u\n", (unsigned int)set->address_size);
		my_printf("   Segment Size:          %u\n", (unsigned int)set->segment_size);
		my_print("   Ranges:\n");
		my_print("    address            length\n");
		for (size_t i = 0; i < set->aranges_count; i++) {
			my_printf("    0x%016" PFMT64x " 0x%016" PFMT64x "\n", set->aranges[i].addr, set->aranges[i].length);
		}
	}
	my_print("\n");
	return my_print_get;
}

/**
 * \param regs optional, the state after op has been executed. If not null, some meaningful results from this context will be shown.
 */
static void print_line_op(RzStrBuf *sb, RzBinDwarfLineOp *op, RzBinDwarfLineHeader *hdr) {
	switch (op->type) {
	case RZ_BIN_DWARF_LINE_OP_TYPE_STD:
		my_print(rz_str_get_null(rz_bin_dwarf_lns(op->opcode)));
		switch (op->opcode) {
		case DW_LNS_advance_pc:
			my_printf("\t%" PFMT64u, op->args.advance_pc);
			break;
		case DW_LNS_advance_line:
			my_printf("\t%" PFMT64u, op->args.advance_line);
			break;
		case DW_LNS_set_file:
			my_printf("\t%" PFMT64u, op->args.set_file);
			break;
		case DW_LNS_set_column:
			my_printf("\t%" PFMT64u, op->args.set_column);
			break;
		case DW_LNS_fixed_advance_pc:
			my_printf("\t%" PFMT64u, op->args.fixed_advance_pc);
			break;
		case DW_LNS_set_isa:
			my_printf("\t%" PFMT64u, op->args.set_isa);
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
		my_print(rz_str_get_null(rz_bin_dwarf_lne(op->ext_opcode)));
		switch (op->opcode) {
		case DW_LNE_set_address:
			my_printf("\t0x%" PFMT64x, op->args.set_address);
			break;
		case DW_LNE_define_file:
			my_printf("\tfilename \"%s\", dir_index %" PFMT64u ", ",
				op->args.define_file.path_name,
				op->args.define_file.directory_index);
			break;
		case DW_LNE_set_discriminator:
			my_printf("\t%" PFMT64u "\n", op->args.set_discriminator);
			break;
		case DW_LNE_end_sequence:
		default:
			break;
		}
		break;
	case RZ_BIN_DWARF_LINE_OP_TYPE_SPEC:
		my_printf("Special opcode\t%u", op->opcode);
		break;
	default:
		my_printf("Unknown opcode type %u, opcode: %x", (unsigned int)op->type, op->opcode);
		break;
	}
	my_print("\n");
}

RZ_API char *rz_core_bin_dwarf_line_unit_to_string(RzBinDwarfLineUnit *unit) {
	if (!unit) {
		return NULL;
	}
	my_print_init;
	RzBinDwarfLineHeader *hdr = &unit->header;
	my_printf(" Header information[0x%" PFMT64x "]\n", hdr->offset);
	my_printf("  Length:                             %" PFMT64u "\n", hdr->unit_length);
	my_printf("  DWARF Version:                      %d\n", hdr->version);
	my_printf("  Header Length:                      %" PFMT64d "\n", hdr->header_length);
	my_printf("  Minimum Instruction Length:         %d\n", hdr->min_inst_len);
	my_printf("  Maximum Operations per Instruction: %d\n", hdr->max_ops_per_inst);
	my_printf("  Initial value of 'is_stmt':         %d\n", hdr->default_is_stmt);
	my_printf("  Line Base:                          %d\n", hdr->line_base);
	my_printf("  Line Range:                         %d\n", hdr->line_range);
	my_printf("  Opcode Base:                        %d\n\n", hdr->opcode_base);
	my_print(" Opcodes:\n");
	for (size_t i = 1; i < hdr->opcode_base; i++) {
		my_printf("  Opcode %zu has %d arg\n", i, hdr->std_opcode_lengths[i - 1]);
	}
	my_print("\n");
	if (rz_pvector_len(&hdr->directories) > 0) {
		my_printf(" The Directory Table:\n");
		for (size_t i = 0; i < rz_pvector_len(&hdr->directories); i++) {
			my_printf("  %u     %s\n", (unsigned int)i + 1, (char *)rz_pvector_at(&hdr->directories, i));
		}
	}
	if (rz_vector_len(&hdr->file_names)) {
		my_print("\n");
		my_print(" The File Name Table:\n");
		my_print("  Entry Dir     Time      Size       Name\n");
		for (size_t i = 0; i < rz_vector_len(&hdr->file_names); i++) {
			RzBinDwarfFileEntry *f = rz_vector_index_ptr(&hdr->file_names, i);
			my_printf("  %u     %" PFMT64u "       %" PFMT64u "         %" PFMT64u "          %s\n",
				(unsigned int)i + 1, f->directory_index, f->timestamp, f->size, f->path_name);
		}
		my_print("\n");
	}
	my_print(" Line Number Statements:\n");
	void *opsit;
	size_t i;
	rz_vector_enumerate(&unit->ops, opsit, i) {
		RzBinDwarfLineOp *op = opsit;
		my_print("  ");
		print_line_op(sb, op, &unit->header);
		if (op->type == RZ_BIN_DWARF_LINE_OP_TYPE_EXT && op->ext_opcode == DW_LNE_end_sequence && i + 1 < rz_vector_len(&unit->ops)) {
			// extra newline for nice sequence separation
			my_print("\n");
		}
	}
	return my_print_get;
}

RZ_API char *rz_core_bin_dwarf_line_units_to_string(RzList /*<RzBinDwarfLineUnit *>*/ *lines) {
	rz_return_val_if_fail(lines, NULL);
	my_print_init;
	my_print("Raw dump of debug contents of section .debug_line:\n\n");
	RzListIter *it;
	RzBinDwarfLineUnit *unit;
	bool first = true;
	rz_list_foreach (lines, it, unit) {
		if (first) {
			first = false;
		} else {
			my_print("\n");
		}
		char *s = rz_core_bin_dwarf_line_unit_to_string(unit);
		if (s) {
			my_print(s);
			free(s);
		}
	}
	my_print("\n");
	return my_print_get;
}

bool htup_rnglists_cb(void *u, ut64 k, const void *v) {
	const RzBinDwarfRngList *rnglist = v;
	RzStrBuf *sb = u;
	if (!(rnglist && sb)) {
		return false;
	}

	my_printf("0x%" PFMT64x "\n", rnglist->offset);
	void **it;
	rz_pvector_foreach (&rnglist->entries, it) {
		RzBinDwarfRange *range = *it;
		my_printf("\t(0x%" PFMT64x ", 0x%" PFMT64x ")\n", range->begin, range->end);
	}
	return true;
}

RZ_API char *rz_core_bin_dwarf_rnglists_to_string(RzBinDwarfRngListTable *rnglists) {
	rz_warn_if_fail(rnglists && rnglists->rnglist_by_offset);
	my_print_init;
	my_printf("\nContents of the .debug_%s section:\n", rnglists->debug_ranges ? "ranges" : "rnglists");
	ht_up_foreach(rnglists->rnglist_by_offset, htup_rnglists_cb, sb);
	my_print("\n");
	return my_print_get;
}
