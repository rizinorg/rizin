#include <rz_core.h>

RZ_API void rz_core_bin_dwarf_print_abbrev_section(const RzBinDwarfDebugAbbrev *da) {
	size_t i, j;
	if (!da) {
		return;
	}
	for (i = 0; i < da->count; i++) {
		rz_cons_printf("   %-4" PFMT64d " ", da->decls[i].code);
		const char *tagname = rz_bin_dwarf_get_tag_name(da->decls[i].tag);
		if (tagname) {
			rz_cons_printf("  %-25s ", tagname);
		}
		rz_cons_printf("[%s]", da->decls[i].has_children ? "has children" : "no children");
		rz_cons_printf(" (0x%" PFMT64x ")\n", da->decls[i].offset);

		if (da->decls[i].defs) {
			for (j = 0; j < da->decls[i].count; j++) {
				const char *attr_name = rz_bin_dwarf_get_attr_name(da->decls[i].defs[j].attr_name);
				const char *attr_form_name = rz_bin_dwarf_get_attr_form_name(da->decls[i].defs[j].attr_form);
				if (attr_name && attr_form_name) {
					rz_cons_printf("    %-30s %-30s\n", attr_name, attr_form_name);
				}
			}
		}
	}
}

RZ_API void rz_core_bin_dwarf_print_attr_value(const RzBinDwarfAttrValue *val) {
	size_t i;
	rz_return_if_fail(val);

	switch (val->attr_form) {
	case DW_FORM_block:
	case DW_FORM_block1:
	case DW_FORM_block2:
	case DW_FORM_block4:
	case DW_FORM_exprloc:
		rz_cons_printf("%" PFMT64u " byte block:", val->block.length);
		for (i = 0; i < val->block.length; i++) {
			rz_cons_printf(" 0x%02x", val->block.data[i]);
		}
		break;
	case DW_FORM_data1:
	case DW_FORM_data2:
	case DW_FORM_data4:
	case DW_FORM_data8:
	case DW_FORM_data16:
		rz_cons_printf("%" PFMT64u "", val->uconstant);
		if (val->attr_name == DW_AT_language) {
			const char *lang_name = rz_bin_dwarf_get_lang_name(val->uconstant);
			if (lang_name) {
				rz_cons_printf("   (%s)", lang_name);
			}
		}
		break;
	case DW_FORM_string:
		if (val->string.content) {
			rz_cons_printf("%s", val->string.content);
		} else {
			rz_cons_print("No string found");
		}
		break;
	case DW_FORM_flag:
		rz_cons_printf("%u", val->flag);
		break;
	case DW_FORM_sdata:
		rz_cons_printf("%" PFMT64d "", val->sconstant);
		break;
	case DW_FORM_udata:
		rz_cons_printf("%" PFMT64u "", val->uconstant);
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
		rz_cons_printf("<0x%" PFMT64x ">", val->reference);
		break;
	case DW_FORM_flag_present:
		rz_cons_print("1");
		break;
	case DW_FORM_strx:
	case DW_FORM_strx1:
	case DW_FORM_strx2:
	case DW_FORM_strx3:
	case DW_FORM_strx4:
	case DW_FORM_line_ptr:
	case DW_FORM_strp_sup:
	case DW_FORM_strp:
		rz_cons_printf("(indirect string, offset: 0x%" PFMT64x "): %s",
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
		rz_cons_printf("0x%" PFMT64x "", val->address);
		break;
	case DW_FORM_implicit_const:
		rz_cons_printf("0x%" PFMT64d "", val->uconstant);
		break;
	default:
		rz_cons_printf("Unknown attr value form %" PFMT64d "\n", val->attr_form);
		break;
	};
}

RZ_API void rz_core_bin_dwarf_print_debug_info(const RzBinDwarfDebugInfo *inf) {
	size_t i, j, k;
	RzBinDwarfDie *dies;
	RzBinDwarfAttrValue *values;

	rz_return_if_fail(inf);

	for (i = 0; i < inf->count; i++) {
		rz_cons_print("\n");
		rz_cons_printf("  Compilation Unit @ offset 0x%" PFMT64x ":\n", inf->comp_units[i].offset);
		rz_cons_printf("   Length:        0x%" PFMT64x "\n", inf->comp_units[i].hdr.length);
		rz_cons_printf("   Version:       %d\n", inf->comp_units[i].hdr.version);
		rz_cons_printf("   Abbrev Offset: 0x%" PFMT64x "\n", inf->comp_units[i].hdr.abbrev_offset);
		rz_cons_printf("   Pointer Size:  %d\n", inf->comp_units[i].hdr.address_size);
		const char *unit_type_name = rz_bin_dwarf_get_unit_type_name(inf->comp_units[i].hdr.unit_type);
		if (unit_type_name) {
			rz_cons_printf("   Unit Type:     %s\n", unit_type_name);
		}
		rz_cons_print("\n");

		dies = inf->comp_units[i].dies;

		for (j = 0; j < inf->comp_units[i].count; j++) {
			rz_cons_printf("<0x%" PFMT64x ">: Abbrev Number: %-4" PFMT64u " ", dies[j].offset, dies[j].abbrev_code);

			const char *tag_name = rz_bin_dwarf_get_tag_name(dies[j].tag);
			if (tag_name) {
				rz_cons_printf("(%s)\n", tag_name);
			} else {
				rz_cons_print("(Unknown abbrev tag)\n");
			}

			if (!dies[j].abbrev_code) {
				continue;
			}
			values = dies[j].attr_values;

			for (k = 0; k < dies[j].count; k++) {
				if (!values[k].attr_name) {
					continue;
				}
				const char *attr_name = rz_bin_dwarf_get_attr_name(values[k].attr_name);
				if (attr_name) {
					rz_cons_printf("     %-25s : ", attr_name);
				} else {
					rz_cons_printf("     AT_UNKWN [0x%-3" PFMT64x "]\t : ", values[k].attr_name);
				}
				rz_core_bin_dwarf_print_attr_value(&values[k]);
				rz_cons_printf("\n");
			}
		}
	}
}

static int offset_comp(const void *a, const void *b) {
	const RzBinDwarfLocList *f = a;
	const RzBinDwarfLocList *s = b;
	ut64 first = f->offset;
	ut64 second = s->offset;
	if (first < second) {
		return -1;
	}
	if (first > second) {
		return 1;
	}
	return 0;
}

static bool sort_loclists(void *user, const ut64 key, const void *value) {
	RzBinDwarfLocList *loc_list = (RzBinDwarfLocList *)value;
	RzList *sort_list = user;
	rz_list_add_sorted(sort_list, loc_list, offset_comp);
	return true;
}

RZ_API void rz_core_bin_dwarf_print_loc(HtUP /*<offset, RzBinDwarfLocList*/ *loc_table, int addr_size) {
	rz_return_if_fail(loc_table);
	rz_cons_print("\nContents of the .debug_loc section:\n");
	RzList /*<RzBinDwarfLocList *>*/ *sort_list = rz_list_new();
	/* sort the table contents by offset and print sorted
	   a bit ugly, but I wanted to decouple the parsing and printing */
	ht_up_foreach(loc_table, sort_loclists, sort_list);
	RzListIter *i;
	RzBinDwarfLocList *loc_list;
	rz_list_foreach (sort_list, i, loc_list) {
		RzListIter *j;
		RzBinDwarfLocRange *range;
		ut64 base_offset = loc_list->offset;
		rz_list_foreach (loc_list->list, j, range) {
			rz_cons_printf("0x%" PFMT64x " 0x%" PFMT64x " 0x%" PFMT64x "\n", base_offset, range->start, range->end);
			base_offset += addr_size * 2;
			if (range->expression) {
				base_offset += 2 + range->expression->length; /* 2 bytes for expr length */
			}
		}
		rz_cons_printf("0x%" PFMT64x " <End of list>\n", base_offset);
	}
	rz_cons_print("\n");
	rz_list_free(sort_list);
}
