// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "omf51.h"
/**
 * \file omf51.c
 * \brief Conventions
 *
 * Record format
 * The OMF-Records have the basic format as shown in the example below:
 *
 * *****************************************
 * * RecType | RecLen | Content | CheckSum *
 * *****************************************
 *
 * The Record-Type field ’RecType’ is the first byte in each record and identifies the
 * record by an the 8 bit record number.
 * The Record-Length field ’RecLen’ contains the number of bytes in the record
 * exclusive the RecTyp and RecLen field. RecLen is a 16 Bit value.
 * The format of the Content field depends upon record type. The number of bytes
 * and there layout depends upon the record type.
 * The Checksum field is always the last field in each record and contains the check
 * sum, which is the 2’s complement of the sum (modulus 256) of all other bytes in
 * the record. Therefore, the sum of all bytes in a record modulus 256 equals zero.
 *
 * Index values
 * Many of the OMF51 records use some index to refer to other records. The high
 * order bit of the first (and possibly the only one) byte determines whether the index
 * occupies one or two bytes. If the bit is 0, then the index is a number in range 0 to
 * 0x7F, occupying one byte. If the bit is 1, then the index is a number in range 0x80
 * and 0x7FFF, occupying two bytes; the value is constructed as follows: the low order
 * 8 bits are in the second byte, and the high order 7 bites are in the first byte.
 * Throughout this document, names with the suffix ’Index’ specify an index of the form
 * just described, for example GroupIndex, SectionIndex, TypeIndex.
 *
 * Representation of Names (Name format)
 * A name is represented by the leading length of the name, which is a byte value
 * followed by the name itself, for example:
 *
 *  *********************
 *  * 4 | K | E | I | L *
 *  *********************
 *
 * A name may represent a null name, which is denoted by a value 0 with no other bytes
 * following the zero length name:
 *  *****
 *  * 0 *
 *  *****
 * Note that names represented in this manner never have a null terminator as is the
 * case with C language style strings.
 * Names are used in almost all symbolic debug records to specify symbolic names.
 * Null names may be used by BLKDEF records to specify unnamed do-blocks.
 *
 */

bool is_valid_omf51_type(const ut8 type) {
	const ut8 types[] = {
		OMF166_DEPLST, OMF_LINSYM,
		OMF_THEADR, OMF51_ENTRYPOINT,
		OMF_GRPDEF, OMF_COMMENT, OMF_LINNUM, OMF_PUBDEF,
		OMF_EXTDEF, OMF_ALIAS,
		OMF166_UNKNOWN0, OMF166_INCLUDES, OMF166_UNKNOWN2, OMF166_UNKNOWN3, OMF166_UNKNOWN4,
		0x84, 0xc0, 0xd0, 0x8e, 0x92, 0x98, 0xc8,
		0
	};
	for (int ct = 0; types[ct]; ct++) {
		if (types[ct] == type) {
			return true;
		}
	}
	RZ_LOG_ERROR("Invalid record type: 0x%02x\n", type);
	return false;
}

ut16 omf51_max_record_size(void) {
	return OMF51_RECORD_MAX_SIZE;
}

ut8 rz_bin_omf51_get_bits(RZ_NONNULL void *target_obj) {
	const rz_bin_omf51_obj *obj = (const rz_bin_omf51_obj *)target_obj;
	if (!obj) {
		rz_warn_if_reached();
	}
	return 8;
}

RzPVector /*<RzBinMap *>*/ *omf51_maps(RZ_NONNULL const void *target_obj) {
	const rz_bin_omf51_obj *obj = (const rz_bin_omf51_obj *)target_obj;

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	// const rz_bin_omf51_obj *obj = bf->o->bin_obj;
	RzBinMap *map = NULL;
	void **it;
	rz_pvector_foreach (obj->pe_vec, it) {
		const OMF_pes *pe = (OMF_pes *)*it;
		map = RZ_NEW0(RzBinMap);
		if (!map) {
			rz_pvector_free(ret);
			return NULL;
		}
		map->paddr = pe->paddr;
		map->vaddr = pe->offset;
		map->psize = pe->size;
		map->vsize = pe->size;
		map->perm = get_perm_by_type(pe->data_type);
		map->name = rz_str_dup(get_data_type51(pe->data_type));
		rz_pvector_push(ret, map);
	}
	return ret;
}

static int offset_cmp(const void *a, const void *b, void *user) {
	const OMF_symbol *sa = a;
	const OMF_symbol *sb = b;
	// first, sort by addr
	if (sa->offset < sb->offset) {
		return -1;
	}
	if (sa->offset > sb->offset) {
		return 1;
	}
	return strcmp(sa->name2, sb->name2);
}

RzPVector /*<RzBinSection *>*/ *omf51_symbols(RZ_NONNULL const void *target_obj) {
	const rz_bin_omf51_obj *obj = (const rz_bin_omf51_obj *)target_obj;

	if (!obj) {
		return NULL;
	}

	if (!rz_pvector_len(obj->symbols_vec)) {
		return NULL;
	}

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	rz_pvector_sort(obj->symbols_vec, offset_cmp, NULL);
	void **it;
	rz_pvector_foreach (obj->symbols_vec, it) {
		const OMF_symbol *p = (OMF_symbol *)*it;
		if (p->is_data)
			continue;
		const char *name = NULL;
		if (p->ti == 0x4B) {
			name = rz_str_newf("label.%s", p->name2);
		} else if (p->ti == 0x4D) {
			name = rz_str_newf("a166_NEAR.%s", p->name2);
		} else if (p->ti == 0x4E) {
			name = rz_str_newf("a166_FAR.%s", p->name2);
		} else if (p->ti == 0x53) {
			name = rz_str_newf("a166_INTNO.%s", p->name2);
		} else if (p->ti == 0x54) {
			name = rz_str_newf("a166_REGBANK.%s", p->name2);
		} else {
			name = rz_str_dup(p->name2);
		}

		RzBinSymbol *sym = rz_bin_symbol_new(name, p->offset, p->base + p->offset);
		RZ_FREE(name);
		sym->forwarder = "NONE";
		sym->size = (ut32)p->size;
		if (p->ti == 0x4D) {
			sym->bits = 16; ///< NEAR
		} else {
			sym->bits = 32;
		}

		switch (p->rec_type) {
		case OMF166_GLBDEF:
		case OMF166_PUBDEF:
			sym->bind = RZ_BIN_BIND_GLOBAL_STR;
			sym->type = RZ_BIN_TYPE_FUNC_STR;
			break;
		case OMF166_LOCSYM:
			sym->bind = RZ_BIN_BIND_LOCAL_STR;
			sym->type = RZ_BIN_TYPE_FUNC_STR;
			break;
		default:
			sym->bind = RZ_BIN_BIND_UNKNOWN_STR;
			sym->type = RZ_BIN_TYPE_UNKNOWN_STR;
			break;
		}
		rz_pvector_push(ret, sym);
	}
	rz_pvector_foreach (obj->pe_vec, it) {
		const OMF_pes *pe = (OMF_pes *)*it;
		if (pe->isVector) {
			const ut64 addr = (pe->SegmentNumber8 << 16) + pe->offset;
			char *sym_name = pe->offset == 0x00 ? rz_str_newf("int.RESET") : rz_str_newf("isr_vec_0x%" PFMT64x, addr & 0xff);
			RzBinSymbol *ptr = RZ_NEW0(RzBinSymbol);
			if (!ptr) {
				free(sym_name);
				return ret;
			}
			ptr->name = sym_name;
			ptr->paddr = addr;
			ptr->vaddr = addr;
			ptr->size = pe->size;
			ptr->ordinal = 0;
			ptr->bits = 16;
			ptr->bind = RZ_BIN_BIND_GLOBAL_STR;
			ptr->type = RZ_BIN_TYPE_FUNC_STR;
			rz_pvector_push(ret, ptr);
		}
	}
	return ret;
}

RzPVector /*<RzBinSection *>*/ *omf51_sections(RZ_NONNULL const void *target_obj) {
	const rz_bin_omf51_obj *obj = (const rz_bin_omf51_obj *)target_obj;

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}

	void **it;
	rz_pvector_foreach (obj->sections_vec, it) {
		const OMF_sections *section = (OMF_sections *)*it;

		RzBinSection *new = RZ_NEW0(RzBinSection);
		if (!new) {
			rz_pvector_free(ret);
			return NULL;
		}
		new->name = rz_str_newf("%s_%s", section->name51, "");
		new->size = section->Seclen;
		new->vsize = section->Seclen;
		new->vaddr = (section->SegmentNumber8 << 16) + section->offset;
		new->has_strings = section->Type != 2;
		new->is_data = section->Type != 2;
		new->is_segment = 0;
		new->perm = c166_get_perms_from_class(section->class_index);
		rz_pvector_push(ret, new);
	}
	return ret;
}

RzBinInfo *omf51_info(RZ_NONNULL const void *target_obj) {
	const rz_bin_omf51_obj *obj = (const rz_bin_omf51_obj *)target_obj;
	if (!obj) {
		return NULL;
	}

	RzBinInfo *ret;
	if (!((ret = RZ_NEW0(RzBinInfo)))) {
		return NULL;
	}

	// ret->type = get_memory_model(obj->modinfo);
	// ret->file = rz_str_dup(bf->file);
	ret->bclass = rz_str_dup("OMF (Object Module Format)");
	ret->rclass = rz_str_dup("OMF51");
	ret->compiler = rz_str_dup("keil");
	ret->os = rz_str_dup("8051");
	ret->machine = rz_str_dup("Palm8051");
	ret->arch = rz_str_dup("8051");
	ret->big_endian = false;
	ret->has_va = true;
	ret->bits = 8;
	ret->dbg_info = 0;
	ret->has_nx = false;
	return ret;
}

static bool load_omf166_lnames(const rz_bin_omf51_obj *obj, const OMF_record *record, const ut8 *buf, const size_t buf_size, ut64 global_ct) {
	ut32 tmp_size = 0;
	ut32 ct_name = 0;

	OMF_lnames *lname = NULL;
	if (!(record && buf) || record->size <= 3) {
		return false;
	}

	while ((int)tmp_size < (int)(record->size - 1)) {
		const int next = buf[3 + tmp_size] + 1;
		if (next < 1)
			break;
		tmp_size += next;
	}
	tmp_size = 0;
	while ((int)tmp_size < (int)(record->size - 1)) {
		// sometimes there is a name with a null size so we just skip it
		const ut8 cb = buf[3 + tmp_size];
		if (record->size + 3 < tmp_size + cb) {
			RZ_LOG_ERROR("Invalid Lnames record (bad size)\n");
			return false;
		}
		lname = RZ_NEW0(OMF_lnames);
		if (!lname) {
			return false;
		}
		if ((tmp_size + 4 + cb) < buf_size) {
			memcpy(lname->name, buf + 3 + tmp_size + 1, cb);
			lname->index = ct_name;
		}

		rz_pvector_push(obj->lnames_vec, lname);
		ct_name++;
		tmp_size += cb + 1;
	}
	return true;
}

static int load_omf_data(const rz_bin_omf51_obj *obj, const ut8 *buf, const size_t buf_size, const OMF_record *record) {
	if ((!(record->type & 1) && record->size < 4) || (record->size < 6)) {
		RZ_LOG_ERROR("Invalid Ledata record (bad size)\n");
		return false;
	}

	OMF_ledatas *lep = RZ_NEW0(OMF_ledatas);
	if (!lep) {
		return false;
	}
	size_t ct = 3;
	lep->seg_idx = omf_get_idx_offset(buf, buf_size - ct, &ct);
	if (lep->seg_idx & 0xff00) {
		if ((!(record->type & 1) && record->size < 5) || (record->size < 7)) {
			RZ_LOG_ERROR("Invalid Ledata record (bad size)\n");
			RZ_FREE(lep);
			return false;
		}
	}
	lep->offset = rz_read_le16_offset(buf, &ct);
	rz_pvector_push(obj->ledatas_vec, lep);
	return true;
}

static int load_omf_blkdef(const rz_bin_omf51_obj *obj, const ut8 *buf, const size_t buf_size, ut64 global_ct) {
	size_t ct = 3;
	OMF_blocks *block = RZ_NEW0(OMF_blocks);
	if (!block) {
		return false;
	}

	block->GroupIndex = omf_get_idx_offset(buf, buf_size - ct, &ct);
	block->SectionIndex = omf_get_idx_offset(buf, buf_size - ct, &ct);

	if (!block->GroupIndex && !block->SectionIndex) {
		block->FrameNumber = rz_read_le16_offset(buf, &ct);
	}

	block->n = rz_read_le8_offset(buf, &ct);
	rz_str_ncpy(block->name, (const char *)&buf[ct], block->n + 1);

	ct += block->n;
	block->BlockOffset16 = rz_read_le16_offset(buf, &ct);
	block->BlockLength16 = rz_read_le16_offset(buf, &ct);
	block->PInfoProcedure = (rz_read_le8_offset(buf, &ct) & 0x80);

	ct += 2; ///< RESERVED16
	block->TI = omf_get_idx_offset(buf, buf_size - ct, &ct);

	if (block->n > 0) {
		rz_pvector_push(obj->blocks_vec, block);
	} else {
		RZ_FREE(block);
	}
	return true;
}

static int load_88_data(const rz_bin_omf51_obj *obj, const ut8 *buf, const OMF_record *record, ut64 global_ct, const size_t buf_size) {
#ifdef RZ_DEBUG
	RZ_LOG_DEBUG("load_omf: 0x88        [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
		record->size, global_ct, global_ct, record->type, buf_size);
#endif

	if (!(obj && obj->coments_vec)) {
		return false;
	}

	size_t ct = 3;
	while (ct < record->size) {
		OMF_symbol *sym = RZ_NEW0(OMF_symbol);
		if (!sym) {
			return false;
		}
		sym->rec_type = record->type;

		const ut8 unk1 = rz_read_le8_offset(buf, &ct);
		const ut16 unk2 = rz_read_le16_offset(buf, &ct);
		const ut32 addr = rz_read_le32_offset(buf, &ct);
		const ut16 unk3 = rz_read_le16_offset(buf, &ct);
		const ut16 unk4 = rz_read_le16_offset(buf, &ct);
		(void)unk1;
		(void)unk2;
		(void)unk3;
		(void)unk4;

		const ut8 n = rz_read_le8_offset(buf, &ct);
		sym->n = n;
		if (ct + sym->n + 1 > buf_size) {
			RZ_LOG_ERROR("Invalid sym record (overflow)\n");
			RZ_FREE(sym);
			continue;
		}
		rz_mem_copy(sym->name2, MAX_NAME_LEN, buf + ct, sym->n);
#ifdef RZ_DEBUG
		RZ_LOG_DEBUG("unk1: %d, unk2: %d, unk3: 0x%04x, unk4: 0x%04x, addr: 0x%06x, n: %d, `%s`\n",
			unk1, unk2, unk3, unk4, addr, n, sym->name2);
#endif
		ct += sym->n;
		sym->offset = addr;
		rz_pvector_push(obj->symbols_vec, sym);
	}
	return true;
}

char *reg_type_name(const ut8 type) {
	switch (type) {
	case 0x00:
		return "sfr";
	case 0x01:
		return "sbit";
	case 0x80:
		return "0x80";
	case 0x81:
		return "0x81";
	case 0x0a:
		return "0x0a";
	default:
		printf("reg_type_name: 0x%02x\n", type);
		rz_warn_if_reached();
		return "unknown";
	}
}

bool reg_exist(RzPVector *v, const ut16 addr) {
	void **it;
	rz_pvector_foreach (v, it) {
		const OMF_regs *reg = (OMF_regs *)*it;
		if (reg->addr == addr) {
			return true;
		}
	}
	return false;
}

static int load_d0_data(const rz_bin_omf51_obj *obj, const ut8 *buf, const OMF_record *record, ut64 global_ct, const size_t buf_size) {
#ifdef RZ_DEBUG
	printf("load_omf: 0xd0          [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
		record->size, global_ct, global_ct, record->type, buf_size);
#endif

	if (!(obj && obj->regs_vec)) {
		return false;
	}

	size_t ct = 3;
	while (ct < record->size) {
		OMF_regs *reg = RZ_NEW0(OMF_regs);
		if (!reg) {
			return false;
		}
		reg->unk1 = rz_read_le16_offset(buf, &ct);
		reg->type = rz_read_le8_offset(buf, &ct);
		reg->addr = rz_read_le16_offset(buf, &ct);
		reg->unk4 = rz_read_le16_offset(buf, &ct);
		reg->unk5 = rz_read_le16_offset(buf, &ct);
		reg->unk6 = rz_read_le16_offset(buf, &ct);
		reg->n = rz_read_le8_offset(buf, &ct);
		if (ct + reg->n + 1 > buf_size) {
			RZ_LOG_ERROR("Invalid sym record (overflow)\n");
			RZ_FREE(reg);
			continue;
		}
		rz_mem_copy(reg->name, MAX_NAME_LEN, buf + ct, reg->n);
#ifdef RZ_DEBUG
		RZ_LOG_DEBUG("\t\tunk1: 0x%04x, type: %5s (0x%02x), addr: 0x%04x, unk4: 0x%04x, unk5: 0x%04x, unk6: 0x%04x, n: %d, `%s`\n",
			reg->unk1, reg_type_name(reg->type), reg->type, reg->addr, reg->unk4, reg->unk5, reg->unk6, reg->n, reg->name);
#endif
		ct += reg->n;
		if (!reg_exist(obj->regs_vec, reg->addr)) {
			rz_pvector_push(obj->regs_vec, reg);
		} else {
			RZ_FREE(reg);
		}
	}
	return true;
}

static int load_8e_data(const rz_bin_omf51_obj *obj, const ut8 *buf, const OMF_record *record, ut64 global_ct, const size_t buf_size) {
#ifdef RZ_DEBUG
	RZ_LOG_DEBUG("load_omf: 0x8e          [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")",
		record->size, global_ct, global_ct, record->type, buf_size);
#endif

	if (!(obj && obj->symbols_vec)) {
		return false;
	}

	size_t ct = 3;
	while (ct < record->size) {
		OMF_symbol *sym = RZ_NEW0(OMF_symbol);
		if (!sym) {
			return false;
		}
		sym->rec_type = record->type;
#ifdef RZ_DEBUG
		// RZ_LOG_DEBUG("unk1: %d, unk2: %d, unk3: 0x%04x, unk4: 0x%04x, addr: 0x%06x, n: %d, `%s`\n",
		// 	unk1, unk2, unk3, unk4, addr, n, sym->name2);
#endif
		const ut16 unk1 = rz_read_le16_offset(buf, &ct);
		sym->type51 = rz_read_le8_offset(buf, &ct);
		const ut16 unk2 = rz_read_le16_offset(buf, &ct);
		const ut16 unk3 = rz_read_le16_offset(buf, &ct);
		sym->offset = rz_read_le32_offset(buf, &ct);
		sym->n = rz_read_le8_offset(buf, &ct);
		(void)unk1;
		(void)unk2;
		(void)unk3;

		if (ct + sym->n + 1 > buf_size) {
			RZ_LOG_ERROR("Invalid sym record (overflow)\n");
			RZ_FREE(sym);
			continue;
		}
		rz_mem_copy(sym->name2, MAX_NAME_LEN, buf + ct, sym->n);
#ifdef RZ_DEBUG
		RZ_LOG_DEBUG("\t\tunk1: 0x%04x, type: %5s (0x%02x), unk2: 0x%04x, unk3: 0x%04x, addr: 0x%06x, n: %d, `%s`\n",
			unk1, reg_type_name(sym->type51), sym->type51, unk2, unk3,
			sym->offset, sym->n, sym->name2);
#endif
		ct += sym->n;
		rz_pvector_push(obj->symbols_vec, sym);
	}
	return true;
}

static int load_linsym_data(const rz_bin_omf51_obj *obj, const ut8 *buf, const OMF_record *record, ut64 global_ct, const size_t buf_size) {
	size_t ct = 3;
#ifdef RZ_DEBUG
	if (record->type == 0xc0) {
		RZ_LOG_DEBUG("load_omf: 0xc0          [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")",
			record->size, global_ct, global_ct, record->type, buf_size);
	} else if (record->type == 0xc4) {
		RZ_LOG_DEBUG("load_omf: 0xc4          [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")",
			record->size, global_ct, global_ct, record->type, buf_size);
	}
#endif

	while (ct < record->size) {
		const ut8 n = rz_read_le8_offset(buf, &ct);
		char name[MAX_NAME_LEN] = { 0 };
		rz_str_ncpy(name, (const char *)&buf[ct], n + 1);
#ifdef RZ_DEBUG
		RZ_LOG_DEBUG("\t\tn: %d, `%s`\n", n, name);
#endif
		ct += n;
	}
	return true;
}

static int load_c8_data(const rz_bin_omf51_obj *obj, const ut8 *buf, const OMF_record *record, ut64 global_ct, const size_t buf_size) {
#ifdef RZ_DEBUG
	size_t ct = 3;
	RZ_LOG_DEBUG("load_omf: 0xc8          [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ") ",
		record->size, global_ct, global_ct, record->type, buf_size);
#ifdef RZ_DEBUG1
	rz_print_bytes(NULL, buf + 3, record->size - 1, "0x%02x ");
	printf("\n");
#endif

	const ut16 unk1 = rz_read_le16_offset(buf, &ct);
	const ut16 unk2 = rz_read_le16_offset(buf, &ct);
	const ut16 unk3 = rz_read_le16_offset(buf, &ct);
	const ut8 unk4 = rz_read_le8_offset(buf, &ct);
	RZ_LOG_DEBUG("\t\tunk1: 0x%04x, unk2: 0x%04x, unk3: 0x%04x, unk4: 0x%02x\n", unk1, unk2, unk3, unk4);
#endif
	return true;
}

static int load_98_data(const rz_bin_omf51_obj *obj, const ut8 *buf, const OMF_record *record, ut64 global_ct, const size_t buf_size) {
#ifdef RZ_DEBUG
	RZ_LOG_DEBUG("load_omf: 0x98          [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")",
		record->size, global_ct, global_ct, record->type, buf_size);
	size_t ct = 3;
#ifdef RZ_DEBUG1
	rz_print_bytes(NULL, buf + 3, record->size - 1, "0x%02x ");
	printf("\n");
#endif

	const ut16 unk1 = rz_read_le16_offset(buf, &ct);
	const ut16 unk2 = rz_read_le16_offset(buf, &ct);

	const ut32 null1 = rz_read_le32_offset(buf, &ct);
	const ut32 null2 = rz_read_le32_offset(buf, &ct);
	const ut32 null3 = rz_read_le32_offset(buf, &ct);
	const ut32 null4 = rz_read_le32_offset(buf, &ct);
	const ut16 unk3 = rz_read_le16_offset(buf, &ct);
	const ut16 unk4 = rz_read_le16_offset(buf, &ct);
	RZ_LOG_DEBUG("\t\tunk1: 0x%04x, unk2: 0x%04x, [ 0x%04x 0x%04x 0x%04x 0x%04x ] unk3: 0x%04x, unk4: 0x%04x\n",
		unk1, unk2,
		null1, null2, null3, null4,
		unk3, unk4);
#endif
	return true;
}

static int load_theadr_data(const rz_bin_omf51_obj *obj, const ut8 *buf, const OMF_record *record, ut64 global_ct, const size_t buf_size) {
	if (!(obj && obj->coments_vec)) {
		return false;
	}
#ifdef RZ_DEBUG
	RZ_LOG_DEBUG("load_omf: %s        [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
		OMF166_THEADR ? "THEADR" : "LHEADR", record->size, global_ct, global_ct, record->type, buf_size);
#endif
	size_t ct = 3;
	ct += 1;
	while (ct < record->size) {
		const ut8 n = rz_read_le8_offset(buf, &ct);
		char name[MAX_NAME_LEN] = { 0 };
		rz_str_ncpy(name, (const char *)&buf[ct], n + 1);
#ifdef RZ_DEBUG
		RZ_LOG_DEBUG("\t\tOMF_THEADR -  n: %d, `%s`\n", n, name);
#endif
		ct += n;
	}
	return true;
}

static int load_84_data(const rz_bin_omf51_obj *obj, const ut8 *buf, const OMF_record *record, ut64 global_ct, const size_t buf_size) {
	if (!(obj && obj->sections_vec)) {
		return false;
	}

	size_t ct = 3;
	OMF_sections *section = RZ_NEW0(OMF_sections);
	if (!section) {
		return false;
	}

	while (ct < record->size) {
		const ut8 unk1 = rz_read_le8_offset(buf, &ct);
		const ut16 size = rz_read_le16_offset(buf, &ct);
		const ut32 addr = rz_read_le32_offset(buf, &ct);
		ct += 1;
		const ut16 size2 = rz_read_le16_offset(buf, &ct);
		const ut16 unk3 = rz_read_le16_offset(buf, &ct);
		section->Type = rz_read_le8_offset(buf, &ct);
		const ut8 unk4 = rz_read_le8_offset(buf, &ct);

		const ut8 n = rz_read_le8_offset(buf, &ct);
		section->offset = addr;
		section->Seclen = size2;
		section->n51 = n;
		rz_mem_copy(section->name51, MAX_NAME_LEN,
			(const char *)&buf[ct], n);
#ifdef RZ_DEBUG
		RZ_LOG_DEBUG("load_omf: 0x84          [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
			record->size, global_ct, global_ct, record->type, buf_size);
		// return load_omf51_global_sym_record(obj, record, buf, buf_size);
		RZ_LOG_DEBUG("\t\tunk1: %d, size: %d, type: 0x%02x, unk3: 0x%04x, unk4: 0x%02x, addr: 0x%06x, size2: %d (0x%04x), n: %d, `%s`\n",
			unk1, size, section->Type, unk3, unk4, addr, size2, size2, n, section->name51);
#endif
		(void)unk1;
		(void)unk3;
		(void)size;
		(void)unk4;
		ct += n;
	}

	rz_pvector_push(obj->sections_vec, section);
	return true;
}

static int load_9a_data(const rz_bin_omf51_obj *obj, const ut8 *buf, const OMF_record *record, ut64 global_ct, const size_t buf_size) {
	size_t ct = 3;
#ifdef RZ_DEBUG
	RZ_LOG_DEBUG("load_omf: OMF_GRPDEF    [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")",
		record->size, global_ct, global_ct, record->type, buf_size);
	const ut8 group_index = rz_read_le8_offset(buf, &ct);
	const ut8 unk2 = rz_read_le8_offset(buf, &ct);
	const ut8 unk3 = rz_read_le8_offset(buf, &ct);
	RZ_LOG_DEBUG("\t\tgroup_index: 0x%02x, unk2: 0x%02x, unk3: 0x%02x",
		group_index, unk2, unk3);
#endif
	OMF_groupdef *grp = RZ_NEW0(OMF_groupdef);
	if (!grp) {
		return false;
	}
	while (ct < record->size - 3) {
		const ut8 n = rz_read_le8_offset(buf, &ct);
		if (grp->name_n == 0) {
			grp->name_n = n;
			rz_mem_copy(grp->name, MAX_NAME_LEN,
				(const char *)&buf[ct], n);
		} else {
			grp->path_n = n;
			rz_mem_copy(grp->path, MAX_NAME_LEN,
				(const char *)&buf[ct], n);
		}
		ct += n;
	}
#ifdef RZ_DEBUG
	RZ_LOG_DEBUG("\t\tct: %lu (%d), n: %d, `%s%s`\n",
		ct, record->size, grp->name_n + grp->path_n, grp->path, grp->name);
#endif
	rz_pvector_push(obj->group_vec, grp);
	return true;
}

static int load_grpdef_data(const rz_bin_omf51_obj *obj, const ut8 *buf, const OMF_record *record, ut64 global_ct) {
	if (!obj) {
		return false;
	}

	/*
	 * Group Definition Record - Used to combine sections
	 *
	 * B1  | RecLen  | Seg | RESERVED8 |           CHANKS Data                  | Chks
	 * B1  | 0D 00   | C0  |   10      | FF 05   FF 0C   FF 0D   FF 0E   FF 18  | 33
	 * B1  | 05 00   | 40  |   06      | FF 0F                                  | F6
	 * B1  | 05 00   | C0  |   12      | FF 14                                  | 65
	 */
#ifdef RZ_DEBUG
	RZ_LOG_DEBUG("load_omf = GRPDEF  =  [%05d] (%" PFMT64u ") [0x%08" PFMT64x "] 0x%02x\n",
		record->size, global_ct, global_ct, record->type);
#endif
	return true;
}

static int load_omf51_pedata(const rz_bin_omf51_obj *obj, const ut8 *buf, const OMF_record *record, const ut64 global_ct, const size_t buf_size) {
#ifdef RZ_DEBUG
	RZ_LOG_DEBUG("load_omf: OMF51_PEDATA  [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")",
		record->size, global_ct, global_ct, record->type, buf_size);
#endif
	if (!(obj && obj->pe_vec)) {
		return false;
	}

	OMF_pes *pe = RZ_NEW0(OMF_pes);
	if (!pe) {
		return false;
	}

	size_t ct = 3;
#ifdef RZ_DEBUG1
	printf("PEDATA: ");
	rz_print_bytes(NULL, buf + ct, 10, "0x%02x ");
#endif
	pe->SegmentNumber8 = rz_read_le8_offset(buf, &ct);
	ct += 5; ///< Unknown bytes
	pe->offset = rz_read_le32_offset(buf, &ct);
	pe->size = pe->psize = record->size - 1 - (ct - 3);
	pe->paddr = global_ct + ct;
#ifdef RZ_DEBUG1
	rz_print_bytes(NULL, buf + ct, pe->size, "0x%02x ");
#endif
#ifdef RZ_DEBUG
	RZ_LOG_DEBUG("\t\tSegment: %d, offset: 0x%x, size: %d, addr: 0x%x\n",
		pe->SegmentNumber8, pe->offset, pe->size, pe->paddr);
#endif
	rz_pvector_push(obj->pe_vec, pe);
	return true;
}

static int load_omf_unk1(const rz_bin_omf51_obj *obj, const ut8 *buf, const size_t buf_size, const OMF_record *record, const ut64 global_ct) {
	/**
	 * 61    40 00    2C 03 9D 55 01 00
	 * 38    43 3A 5C 4B 65 69 6C ... 5C 47 65 74 6C 69 6E 65 2E 63
	 * C:\Keil_v5\c166\Examples\XC16x Devices\MEASURE\Getline.c
	 * CA
	 */
#if RZ_BUILD_DEBUG
	RZ_LOG_DEBUG("load_omf: INCLUDES 0x61 [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\t\t",
		record->size, global_ct, global_ct, record->type, buf_size);

	OMF_debug_includes *dip = RZ_NEW0(OMF_debug_includes);
	if (!dip) {
		return false;
	}
	size_t offset = 3;
	dip->timestamp = rz_read_le32_offset(buf, &offset);
	dip->index = rz_read_le16_offset(buf, &offset);
	dip->n = rz_read_le8_offset(buf, &offset);
	rz_str_ncpy(dip->name, (const char *)&buf[offset], dip->n + 1);

	char buffer[80];
	const time_t raw_time = (time_t)dip->timestamp;
	const struct tm *time_info = localtime(&raw_time); // Convert to local time structure
	strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", time_info);

	RZ_LOG_DEBUG("[%u] [ %s ] %u `%s`\n",
		dip->index, buffer, dip->timestamp, dip->name);
	rz_pvector_push(obj->includes_vec, dip);

#endif
	return true;
}

static int load_omf_unk2(const ut8 *buf, const size_t buf_size, const OMF_record *record, const ut64 global_ct) {
#if RZ_BUILD_DEBUG
	RZ_LOG_DEBUG("load_omf: UNKNOWN2 0x62 [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\t\t",
		record->size, global_ct, global_ct, record->type, buf_size);
	char name[255] = RZ_EMPTY;
	size_t offset = 3; // 7
	const ut16 index = rz_read_le16_offset(buf, &offset); // Scope ID / Parent Scope Index
	const ut16 flags = rz_read_le16_offset(buf, &offset); // Type/Flags / Level depth
	const ut8 n = rz_read_le8_offset(buf, &offset);
	rz_str_ncpy(name, (const char *)&buf[offset], n + 1);
	RZ_LOG_DEBUG("index: %d flags: 0x%04x  `%s`\n", index, flags, name);
#endif
	return true;
}

static int load_omf_unk3(const ut8 *buf, const size_t buf_size, const OMF_record *record, const ut64 global_ct) {
#if RZ_BUILD_DEBUG
	RZ_LOG_DEBUG("load_omf: UNKNOWN3 0x63 [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\t\t",
		record->size, global_ct, global_ct, record->type, buf_size);
	RZ_LOG_DEBUG("%02x \t%02x %02x \t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
		buf[0], buf[1], buf[2],
		buf[3], buf[4], buf[5], buf[6], buf[7],
		buf[8], buf[9], buf[10], buf[11], buf[12],
		buf[13], buf[14]);
#endif
	return true;
}

char *sym_operation_name(const ut8 type) {
	switch (type) {
	case 0x00:
		return "definition";
	case 0x01:
		return "condition";
	case 0x02:
		return "assignment";
	default:
		printf("sym_operation_name: 0x%02x\n", type);
		rz_warn_if_reached();
		return "references";
	}
}

static int load_omf_unk4(const ut8 *buf, const size_t buf_size, const OMF_record *record, const ut64 global_ct) {
#if RZ_BUILD_DEBUG
	RZ_LOG_DEBUG("load_omf: UNKNOWN4 0x64 [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\t\t",
		record->size, global_ct, global_ct, record->type, buf_size);
	size_t ct = 3;
	const ut16 count = rz_read_le16_offset(buf, &ct);
	if (count == 0 || count > UINT16_MAX) {
		return false;
	}

	RZ_LOG_DEBUG("count: %2d [%02x %02x]\t%02x %02x\n",
		count, buf[ct], buf[ct + 1], buf[ct + 2], buf[ct + 3]);
	ct += 2;

	for (ut16 i = 0; i < count; i++) {
		const ut8 b1 = rz_read_le8_offset(buf, &ct);
		const ut8 b2 = rz_read_le8_offset(buf, &ct);
		const ut8 b3 = rz_read_le8_offset(buf, &ct);
		const ut8 b4 = rz_read_le8_offset(buf, &ct);
		const ut16 line = rz_read_le16_offset(buf, &ct);

		RZ_LOG_DEBUG("\t\t%02x %02x %02x %02x  [line: %5d]   %02x %02x %10s (0x%02x) %02x %02x %02x %02x %02x %02x %02x\n",
			b1, b2, b3, b4, line,
			buf[ct], buf[ct + 1],
			sym_operation_name(buf[ct + 2]), buf[ct + 2],
			buf[ct + 3], buf[ct + 4], buf[ct + 5],
			buf[ct + 6], buf[ct + 7], buf[ct + 8], buf[ct + 9]);
		ct += 10;
	}
	RZ_LOG_DEBUG("\n");
#endif
	return true;
}

static int load_omf_secdef(rz_bin_omf51_obj *obj, const ut8 *buf, const OMF_record *record) {
	size_t ct = 3;
	OMF_sections *section = RZ_NEW0(OMF_sections);
	if (!section) {
		return false;
	}

	const ut8 SecTyp = rz_read_le8_offset(buf, &ct); // ct = 3
	section->Type = SecTyp >> 6; ///< 0:=BIT, 1:=DATA, 2:=CODE, 3:=CONST
	section->X = (SecTyp & 0x20) >> 5; ///< is set if the section is of type ’xhuge’ (length 0 ... 16M).
	section->H = (SecTyp & 0x10) >> 4; ///< is set if the section is of type ’huge’ (length 0 ... 64K).
	section->bitpos = SecTyp & 0x0F;
	section->SecAtr = rz_read_le8_offset(buf, &ct); // ct = 4
	section->SegmentNumber8 = rz_read_le8_offset(buf, &ct); // ct = 5
	ct++;
	section->offset = rz_read_le16_offset(buf, &ct); // ct = 7
	section->Seclen = record->type == OMF166_XSECDEF ? rz_read_le32_offset(buf, &ct) : rz_read_le16_offset(buf, &ct); // ct = 9
	section->isXSec = (record->type == OMF166_XSECDEF);

	/*
		0xC5 |   RecLen   | SecTyp | SecAtr |   base |      |           |   Seclen   |                 | ChkSum
		0xb0   0x0c 0x00     0x80     0x00      0xc0   0x00   0x8a 0x16   0x50 0x02     0x1b 0x02 0x01    0xf4
		0xb0   0x0c 0x00     0x50     0x00      0xc0   0x00   0x4c 0x1e   0x6f 0x00     0x1c 0x04 0x01    0x3a
	*/
	section->index = rz_read_le8_offset(buf, &ct) - 1;
	section->class_index = rz_read_le8_offset(buf, &ct) - 1;
	rz_pvector_push(obj->sections_vec, section);
	obj->SEC_INDEX++;
	return true;
}

/**
 * \brief The MODINF record loader
 *
 * \details The MODINF record provides module information such as memory model used in
 * translation. ModInf, which is a byte value, uses bits to represent the specific
 * information. The bits within the ModInf byte are as follows:
 * 7 6 5 4 3 2 1 0
 * *********************************
 * * D | F | x | m | m | m | C | M *
 * *********************************
 *   |   |   |               |   +----> [NON]SEGMENTED
 *   |   |   |   \----+---/  +--------> [NO]CASE
 *   |   |   |        +---------------> MEMORY MODEL
 *   |   |   +------------------------> MOD167
 *   |   +----------------------------> FLOAT-USED
 *   +--------------------------------> DOUBLE-USED
 * [Non]Segmented:
 *	If bit is set, then the segmented cpu mode was choosen for the module.
 * [No]Case:
 *	If bit is set, then names are to be considered case sensitive. This info is intended
 *	for the linker when combining object modules.
 * Memory Model:
 * The three bit model specifier gives the memory model choosen on translation:
 *	1: Tiny
 *	2: Small
 *	3: Compact
 *	4: Medium
 *	5: Large
 * Mod167:
 *	If bit is set, then the module is intended to be executed on an 80C167 CPU,
 *	otherwise the module is for a 80C166 CPU.
 * Float used:
 *	The module contains single precision float operations. This bit is intended for the
 *	 linker for automatic selection of libraries.
 * Double used:
 *	The module contains double precision float operations. This bit is intended for the
 *	linker for automatic selection of libraries.
 *
 * \param obj Plugin format data
 * \param buf Buffer for parsing
 * \param record Pointer to new record for filling data
 * \return True is success, false is something wrong
 */
static int load_omf_modinf(rz_bin_omf51_obj *obj, const ut8 *buf, const OMF_record *record) {
#if RZ_BUILD_DEBUG
	RZ_LOG_DEBUG("0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n", buf[0], buf[1], buf[2], buf[3], buf[4]);
#endif
	const ut16 ct = 3;
	if (!(record->type & 1) && record->size != 2) {
		RZ_LOG_ERROR("Invalid MODINF record (bad size)\n");
		return false;
	}
	obj->modinfo = rz_read_le8(buf + ct);
	return true;
}

static int load_linnum92_data(const rz_bin_omf51_obj *obj, const ut8 *buf, const OMF_record *record, ut64 global_ct, const size_t buf_size) {

#ifndef RZ_DEBUG
	RZ_LOG_DEBUG("load_omf: 0x92          [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
		record->size, global_ct, global_ct, record->type, buf_size);
#endif
	size_t ct = 3;
	const ut16 GroupIndex = omf_get_idx_offset(buf, buf_size - ct, &ct);
	const ut16 unk16 = rz_read_le16_offset(buf, &ct);

	while (ct < record->size) {
		OMF_linnums *linnum = RZ_NEW0(OMF_linnums);
		if (!linnum) {
			return false;
		}
		const ut8 unk8 = rz_read_le8_offset(buf, &ct);
		linnum->LineNumber = rz_read_le16_offset(buf, &ct);
		const ut8 unk8_2 = rz_read_le8_offset(buf, &ct);
		(void)unk8_2;
		const ut16 offset = rz_read_le16_offset(buf, &ct);
		const ut8 seg = rz_read_le8_offset(buf, &ct);
		linnum->address = ((ut64)seg << 16) | offset;
		const OMF_groupdef *group = rz_pvector_at(obj->group_vec, GroupIndex - 1);
		if (!group) {
			RZ_FREE(linnum);
			return false;
		}
		linnum->n = group->path_n + group->name_n + 1;
		char k[MAX_NAME_LEN] = RZ_EMPTY;
		rz_strf(k, "%s%s", group->path, group->name);
		rz_mem_copy(linnum->filename, MAX_NAME_LEN,
			k, linnum->n);
		if (unk16 != 0 || unk8 != 0) {
			printf("\t\tGroupIndex: 0x%02x, unk16: 0x%04x, unk8: 0x%02x, LineNumber: %d, address: 0x%06" PFMT64x ", `%s`\n",
				GroupIndex, unk16, unk8, linnum->LineNumber, linnum->address, k);
		}

		rz_pvector_push(obj->linnums_vec, linnum);
	}
	return true;
}

bool rz_bin_format_omf51_load_content(RZ_NONNULL void *target_obj, OMF_record *record, const ut8 *buf, const ut64 global_ct, const size_t buf_size) {
	// generic loader just copy data from buf to content
	rz_bin_omf51_obj *obj = (rz_bin_omf51_obj *)target_obj;
	if (!record->size) {
		RZ_LOG_ERROR("Invalid record (size to short)\n");
		return false;
	}

	switch (record->type) {
	case 0xc0:
	case OMF_LINSYM:
		return load_linsym_data(obj, buf, record, global_ct, buf_size);
	case OMF_NBKPAT:
		return load_c8_data(obj, buf, record, global_ct, buf_size);
	case OMF_SEGDEF:
		return load_98_data(obj, buf, record, global_ct, buf_size);
	case 0x84:
		return load_84_data(obj, buf, record, global_ct, buf_size);
	case OMF51_ENTRYPOINT: // DONE
		obj->base_addr = rz_read_at_le32(buf, 3);
#ifdef RZ_DEBUG
		RZ_LOG_DEBUG("load_omf: OMF51_ENTRYPOINT   [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n\t\t",
			record->size, global_ct, global_ct, record->type, buf_size);
		RZ_LOG_DEBUG("base_addr?: 0x%06" PFMT64x "\n\t\t", obj->base_addr);
#endif
#ifdef RZ_DEBUG1
		rz_print_bytes(NULL, buf + 3, record->size - 1, "0x%02x ");
		printf("\n");
#endif
		return true;
	case OMF166_LNAMES: {
		return load_omf166_lnames(obj, record, buf, buf_size, global_ct);
	}
	case OMF_PUBDEF:
#ifdef RZ_DEBUG
		RZ_LOG_DEBUG("load_omf: 0x90 (PUBDEF?)[%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\t\t",
			record->size, global_ct, global_ct, record->type, buf_size);
		rz_print_bytes(NULL, buf, record->size + 3, "0x%02x ");
#endif
		return true;
	case OMF_EXTDEF:
#ifdef RZ_DEBUG
		RZ_LOG_DEBUG("load_omf: OMF_EXTDEF    [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
			record->size, global_ct, global_ct, record->type, buf_size);
#endif
		return true;
	case OMF_ALIAS:
#ifdef RZ_DEBUG
		RZ_LOG_DEBUG("load_omf: OMF_ALIAS    [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
			record->size, global_ct, global_ct, record->type, buf_size);
#endif
		return true;
	case 0xd0: // DONE
		return load_d0_data(obj, buf, record, global_ct, buf_size);
	case 0x8e:
		return load_8e_data(obj, buf, record, global_ct, buf_size);
	case 0x92:
		return load_linnum92_data(obj, buf, record, global_ct, buf_size);
	case OMF166_BLKDEF: {
		return load_omf_blkdef(obj, buf, buf_size, global_ct);
	}
	case OMF_LHEADR:
	case OMF_THEADR:
		return load_theadr_data(obj, buf, record, global_ct, buf_size);
	case OMF166_MODINF: {
		return load_omf_modinf(obj, buf, record);
	}
	case OMF166_MODEND: {
#ifdef RZ_DEBUG
		RZ_LOG_DEBUG("load_omf = MODEND  =  [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
			record->size, global_ct, global_ct, record->type, buf_size);
#endif
		return true;
	}
	case OMF166_BLKEND: {
#ifdef RZ_DEBUG
		RZ_LOG_DEBUG("load_omf = BLKEND  =  [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
			record->size, global_ct, global_ct, record->type, buf_size);
#endif
		return true;
	}
	case OMF51_PEDATA: {
		return load_omf51_pedata(obj, buf, record, global_ct, buf_size);
	}
	case OMF166_REGDEF: {
		/**
		 *     Type | RecLen | Offset | Base | n  | NAME             | RegMask | RESERVED | Chks
		 *      E3    0F 00    00 00     FC    07   INTREGS            FF FF      00         F1
		 *      E3    18 00    00 20     FC    10   ?C_MAINREGISTERS   FF FF      00         1D
		 */
#ifdef RZ_DEBUG
		RZ_LOG_DEBUG("load_omf = REGDEF  =  [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
			record->size, global_ct, global_ct, record->type, buf_size);
#endif
		return true;
	}
	case 0x88: { // DONE
		return load_88_data(obj, buf, record, global_ct, buf_size);
	}
	case OMF_GRPDEF:
		return load_9a_data(obj, buf, record, global_ct, buf_size);
	case OMF166_GRPDEF: {
#ifdef RZ_DEBUG
		RZ_LOG_DEBUG("load_omf: OMF166_GRPDEF [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n\t\t",
			record->size, global_ct, global_ct, record->type, buf_size);
#endif
		return load_grpdef_data(obj, buf, record, global_ct);
	}
	case OMF166_DEPLST:
#ifdef RZ_DEBUG
		RZ_LOG_DEBUG("load_omf: OMF166_DEPLST [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
			record->size, global_ct, global_ct, record->type, buf_size);
		char *tmp = rz_str_newlen((const char *)&buf[6], record->size - 5);
		RZ_LOG_DEBUG("\t\t[%d] OMF166_DEPLST `%s`\n", record->size - 5, tmp);
		free(tmp);
#endif
		return true;
	case OMF166_LEDATA: {
		return load_omf_data(obj, buf, buf_size, record);
	}
	case OMF166_SECDEF:
	case OMF166_XSECDEF: {
		return load_omf_secdef(obj, buf, record);
	}
	case OMF166_UNKNOWN0: {
		/**
		 *	60    5E 00    00 02 03 00 95 00 00 00 0C 00 00
		 *	05  69 64 61 74 61						= idata
		 *	05  73 64 61 74 61						= sdata
		 *	05  62 64 61 74 61						= bdata
		 *	04  6E 65 61 72							= near
		 *	03  66 61 72							= far
		 *	0A  6E 65 61 72 20 63 6F 6E 73 74		= near const
		 *	09  66 61 72 20 63 6F 6E 73 74			= far const
		 *	04  68 75 67 65							= huge
		 *	0A  68 75 67 65 20 63 6F 6E 73 74		= huge const
		 *	05  78 68 75 67 65						= xhuge
		 *	0B  78 68 75 67 65 20 63 6F 6E 73 74	= xhuge const
		 *	DB
		 */
		size_t left = 14;
		while (record->size - 1 > left) {
			char name[255] = RZ_EMPTY;
			const ut8 n = rz_read_le8_offset(buf, &left);
			rz_str_ncpy(name, (const char *)&buf[left], n + 1);
			left += n;
		}
		return true;
	}
	case OMF166_INCLUDES: {
		return load_omf_unk1(obj, buf, buf_size, record, global_ct);
	}
	case OMF166_UNKNOWN2: {
		return load_omf_unk2(buf, buf_size, record, global_ct);
	}
	case OMF166_UNKNOWN3: {
		return load_omf_unk3(buf, buf_size, record, global_ct);
	}
	case OMF166_UNKNOWN4: {
		return load_omf_unk4(buf, buf_size, record, global_ct);
	}
	default: {
#ifdef RZ_DEBUG
		RZ_LOG_DEBUG
		printf("load_omf: [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
			record->size, global_ct, global_ct, record->type, buf_size);
#endif
		rz_warn_if_reached();
		break;
	}
	}
	record->content = RZ_NEWS0(char, record->size);
	if (!record->content) {
		return false;
	}
	((char *)record->content)[record->size - 1] = 0;
	return true;
}

const char *get_data_type51(ut8 data_type) {
	switch (data_type) {
	case 0: {
		return "BIT";
	}
	case 1: {
		return "DATA";
	}
	case 2: {
		return "CODE";
	}
	case 3: {
		return "CONST";
	}
	default: {
		rz_warn_if_reached();
		return NULL;
	}
	}
}

bool rz_bin_format_omf51_init_internal_storage(RZ_NONNULL void *target_obj) {
	rz_bin_omf51_obj *obj = (rz_bin_omf51_obj *)target_obj;
	new_pv_and_check(obj->sections_vec, free, false);
	new_pv_and_check(obj->symbols_vec, free, false);
	new_pv_and_check(obj->blocks_vec, free, false);
	new_pv_and_check(obj->pe_vec, free, false);
	new_pv_and_check(obj->lnames_vec, free, false);
	new_pv_and_check(obj->deplsts_vec, free, false);
	new_pv_and_check(obj->linnums_vec, omf_linnums_free, false);
	new_pv_and_check(obj->coments_vec, free, false);
	new_pv_and_check(obj->includes_vec, free, false);
	new_pv_and_check(obj->group_vec, free, false);
	new_pv_and_check(obj->regs_vec, free, false);
	new_pv_and_check(obj->ledatas_vec, free, false);
	return true;
}

static int block_cmp(const void *a, const void *b, void *user) {
	const OMF_blocks *sa = a;
	const OMF_blocks *sb = b;
	// first, sort by addr
	if (sa->BlockOffset16 < sb->BlockOffset16) {
		return -1;
	}
	if (sa->BlockOffset16 > sb->BlockOffset16) {
		return 1;
	}
	return 0;
}

static int find_symbol_by_paddr(const void *paddr, const void *sym, void *user) {
	const OMF_symbol *p = (OMF_symbol *)sym;
	const ut32 offset = p->base | p->offset;
	const ut32 addr = *(ut32 *)paddr;
	return (addr == offset);
}

bool rz_bin_format_omf51_post_init(RZ_NONNULL const void *target_obj) {
	const rz_bin_omf51_obj *obj = (const rz_bin_omf51_obj *)target_obj;
	const size_t bc = rz_pvector_len(obj->blocks_vec);
	if (bc > 0) {
		RzPVector *v = obj->blocks_vec;
		rz_pvector_sort(v, block_cmp, NULL);
		void **it;
		rz_pvector_foreach (v, it) {
			const OMF_blocks *block = (OMF_blocks *)*it;
			ut32 offset = (block->FrameNumber << 16) | block->BlockOffset16;
			void **iter = rz_pvector_find(obj->symbols_vec, &offset, find_symbol_by_paddr, NULL);
			if (!iter) {
				OMF_symbol *sym = RZ_NEW0(OMF_symbol);
				if (!sym) {
					break;
				}
				sym->is_data = false;
				sym->base = block->FrameNumber << 16;
				sym->n = block->n;

				rz_str_ncpy(sym->name2, (const char *)block->name, block->n + 1);
				sym->size = block->BlockLength16;
				sym->seg_idx = block->FrameNumber;
				sym->offset = offset & 0xFFFF;
				sym->ti = block->TI;
				sym->rec_type = OMF166_BLKDEF;
				rz_pvector_push(obj->symbols_vec, sym);
			} else {
				OMF_symbol *sym = (OMF_symbol *)*iter;
				sym->size = block->BlockLength16;
			}
		}
	}

	const size_t linc = rz_pvector_len(obj->linnums_vec);
	if (linc > 0) {
		RzPVector *v = obj->linnums_vec;
		rz_pvector_sort(v, omf_line_sample_cmp, NULL);
	}
	return true;
}

void rz_bin_free_all_omf51_obj(RZ_NONNULL void *target_obj) {
	if (!target_obj) {
		return;
	}
	rz_bin_omf51_obj *obj = (rz_bin_omf51_obj *)target_obj;

	PVEC_FREE(obj->sections_vec);
	PVEC_FREE(obj->symbols_vec);
	PVEC_FREE(obj->blocks_vec);
	PVEC_FREE(obj->pe_vec);
	PVEC_FREE(obj->lnames_vec);
	PVEC_FREE(obj->deplsts_vec);
	PVEC_FREE(obj->linnums_vec);
	PVEC_FREE(obj->coments_vec);
	PVEC_FREE(obj->includes_vec);
	PVEC_FREE(obj->group_vec);
	PVEC_FREE(obj->regs_vec);
	PVEC_FREE(obj->ledatas_vec);
	RZ_FREE(obj);
}

RzBinAddr *rz_bin_omf51_get_entry(RZ_NONNULL const void *target_obj) {
	const rz_bin_omf51_obj *obj = (const rz_bin_omf51_obj *)target_obj;
	if (!obj) {
		return NULL;
	}

	if (!rz_pvector_len(obj->symbols_vec)) {
		return NULL;
	}
	const RzPVector *v = obj->symbols_vec;
	void **it;
	rz_pvector_foreach (v, it) {
		const char *start_symbol_name = "main";
		const OMF_symbol *symbol = (OMF_symbol *)*it;
		if (!strcmp(symbol->name2, start_symbol_name)) {
			RzBinAddr *addr = RZ_NEW0(RzBinAddr);
			if (!addr) {
				return NULL;
			}
			addr->vaddr = symbol->base + symbol->offset;
			return addr;
		}
	}
	return NULL;
}

ut64 omf51_baddr(RZ_NONNULL const void *target_obj) {
	const rz_bin_omf51_obj *obj = (const rz_bin_omf51_obj *)target_obj;
	return obj->base_addr;
}
