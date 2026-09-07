// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "omf51.h"
#define RZ_DEBUG
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

static bool is_valid_omf51_type(const ut8 type) {
	const ut8 types[] = {
		OMF166_DEPLST, OMF_LINSYM,
		OMF_THEADR, OMF51_ENTRYPOINT,
		OMF_GRPDEF, OMF_COMENT, OMF_LINNUM, OMF_PUBDEF,
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

static ut16 omf166_get_idx(const ut8 *buf, const size_t buf_size) {
	if (buf_size < 2) {
		return 0;
	}
	const ut16 ret = rz_read_le8(buf);
	if (ret & 0x80) {
		return (ut16)(ret & 0x7f) * 0x100 + rz_read_at_le8(buf, 1);
	}
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
	size_t ct = 4;
	if ((!(record->type & 1) && record->size < 4) || (record->size < 6)) {
		RZ_LOG_ERROR("Invalid Ledata record (bad size)\n");
		return false;
	}

	OMF_ledatas *lep = RZ_NEW0(OMF_ledatas);
	if (!lep) {
		return false;
	}
	lep->seg_idx = omf166_get_idx(buf + 3, buf_size - 3);
	if (lep->seg_idx & 0xff00) {
		if ((!(record->type & 1) && record->size < 5) || (record->size < 7)) {
			RZ_LOG_ERROR("Invalid Ledata record (bad size)\n");
			RZ_FREE(lep);
			return false;
		}
		ct++;
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

	block->GroupIndex = omf166_get_idx(buf + ct, buf_size - ct);
	ct++;
	block->SectionIndex = omf166_get_idx(buf + ct, buf_size - ct);
	ct++;
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
	block->TI = omf166_get_idx(buf + ct, buf_size - ct);

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
		// sym->base = base;

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
		reg->name[reg->n] = '\0';
#ifdef RZ_DEBUG
		printf("\t\tunk1: 0x%04x, type: %5s (0x%02x), addr: 0x%04x, unk4: 0x%04x, unk5: 0x%04x, unk6: 0x%04x, n: %d, `%s`\n",
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
#endif
	printf("load_omf: 0x8e          [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")",
		record->size, global_ct, global_ct, record->type, buf_size);

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
		const ut8 unk1 = rz_read_le16_offset(buf, &ct);
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
		sym->name2[sym->n] = '\0';
#ifdef RZ_DEBUG
#endif
		printf("\t\tunk1: 0x%04x, type: %5s (0x%02x), unk2: 0x%04x, unk3: 0x%04x, addr: 0x%06x, n: %d, `%s`\n",
			unk1, reg_type_name(sym->type51), sym->type51, unk2, unk3,
			sym->offset, sym->n, sym->name2);
		ct += sym->n;
		// if (!reg_exist(obj->regs_vec, reg->addr)) {
		// 	rz_pvector_push(obj->regs_vec, reg);
		// } else {
		// 	RZ_FREE(reg);
		// }
		rz_pvector_push(obj->symbols_vec, sym);
	}
	return true;
}

static int load_linsym_data(const rz_bin_omf51_obj *obj, const ut8 *buf, const OMF_record *record, ut64 global_ct, const size_t buf_size) {
	size_t ct = 3;
	if (record->type == 0xc0) {
		printf("load_omf: 0xc0          [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")",
			record->size, global_ct, global_ct, record->type, buf_size);
	} else if (record->type == 0xc4) {
		printf("load_omf: 0xc4          [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")",
			record->size, global_ct, global_ct, record->type, buf_size);
	}

	while (ct < record->size) {
		const ut8 n = rz_read_le8_offset(buf, &ct);
		char name[MAX_NAME_LEN] = { 0 };
		rz_str_ncpy(name, (const char *)&buf[ct], n + 1);
		printf("\t\tn: %d, `%s`\n", n, name);
		ct += n;
	}
	return true;
}

static int load_c8_data(const rz_bin_omf51_obj *obj, const ut8 *buf, const OMF_record *record, ut64 global_ct, const size_t buf_size) {
	size_t ct = 3;

	printf("load_omf: 0xc8          [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ") ",
		record->size, global_ct, global_ct, record->type, buf_size);
#ifdef RZ_DEBUG1
	rz_print_bytes(NULL, buf + 3, record->size - 1, "0x%02x ");
	// printf("\n");
#endif

	const ut16 unk1 = rz_read_le16_offset(buf, &ct);
	const ut16 unk2 = rz_read_le16_offset(buf, &ct);
	const ut16 unk3 = rz_read_le16_offset(buf, &ct);
	const ut8 unk4 = rz_read_le8_offset(buf, &ct);
	printf("\t\tunk1: 0x%04x, unk2: 0x%04x, unk3: 0x%04x, unk4: 0x%02x\n", unk1, unk2, unk3, unk4);
	return true;
}

static int load_98_data(const rz_bin_omf51_obj *obj, const ut8 *buf, const OMF_record *record, ut64 global_ct, const size_t buf_size) {
	size_t ct = 3;

	printf("load_omf: 0x98          [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")",
		record->size, global_ct, global_ct, record->type, buf_size);
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
	// ct += 16;
	const ut16 unk3 = rz_read_le16_offset(buf, &ct);
	const ut16 unk4 = rz_read_le16_offset(buf, &ct);
	printf("\t\tunk1: 0x%04x, unk2: 0x%04x, [ 0x%04x 0x%04x 0x%04x 0x%04x ] unk3: 0x%04x, unk4: 0x%04x\n",
		unk1, unk2,
		null1, null2, null3, null4,
		unk3, unk4);
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
	if (!(obj && obj->coments_vec)) {
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
	// if (!(obj && obj->coments_vec)) {
	// 	return false;
	// }

	printf("load_omf: OMF_GRPDEF    [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")",
		record->size, global_ct, global_ct, record->type, buf_size);
	size_t ct = 3;
	const ut8 group_index = rz_read_le8_offset(buf, &ct);
	const ut8 unk2 = rz_read_le8_offset(buf, &ct);
	const ut8 unk3 = rz_read_le8_offset(buf, &ct);
	printf("\t\tgroup_index: 0x%02x, unk2: 0x%02x, unk3: 0x%02x",
		group_index, unk2, unk3);
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
	printf("\t\tct: %lu (%d), n: %d, `%s%s`\n",
		ct, record->size, grp->name_n + grp->path_n, grp->path, grp->name);
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
	printf("load_omf = GRPDEF  =  [%05d] (%" PFMT64u ") [0x%08" PFMT64x "] 0x%02x\n",
		record->size, global_ct, global_ct, record->type);
	return true;
}

static int load_omf51_pedata(const rz_bin_omf51_obj *obj, const ut8 *buf, const OMF_record *record, const ut64 global_ct, const size_t buf_size) {
#ifdef RZ_DEBUG
	printf("load_omf: OMF51_PEDATA  [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")",
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
	printf("\t\tSegment: %d, offset: 0x%x, size: %d, addr: 0x%x\n",
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
	printf("load_omf: INCLUDES 0x61 [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\t\t",
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

	printf("[%u] [ %s ] %u `%s`\n",
		dip->index, buffer, dip->timestamp, dip->name);
	rz_pvector_push(obj->includes_vec, dip);

#endif
	return true;
}

static int load_omf_unk2(const ut8 *buf, const size_t buf_size, const OMF_record *record, const ut64 global_ct) {
#if RZ_BUILD_DEBUG
	printf("load_omf: UNKNOWN2 0x62 [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\t\t",
		record->size, global_ct, global_ct, record->type, buf_size);
	char name[255] = RZ_EMPTY;
	size_t offset = 3; // 7
	const ut16 index = rz_read_le16_offset(buf, &offset); // Scope ID / Parent Scope Index
	const ut16 flags = rz_read_le16_offset(buf, &offset); // Type/Flags / Level depth
	const ut8 n = rz_read_le8_offset(buf, &offset);
	rz_str_ncpy(name, (const char *)&buf[offset], n + 1);
	printf("index: %d flags: 0x%04x  `%s`\n", index, flags, name);
#endif
	return true;
}

static int load_omf_unk3(const ut8 *buf, const size_t buf_size, const OMF_record *record, const ut64 global_ct) {
	printf("load_omf: UNKNOWN3 0x63 [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\t\t",
		record->size, global_ct, global_ct, record->type, buf_size);
#if RZ_BUILD_DEBUG
	// char name[255] = RZ_EMPTY;
	// size_t offset = 7;
	// const ut8 n = rz_read_le8_offset(buf, &offset);
	// rz_str_ncpy(name, (const char *)&buf[offset], n + 1); // cct = 12
	// printf("load_omf = UNKNOWN3  =  [%05d] [0x%08" PFMT64x "] 0x%02x (%10" PFMTSZu ")\t `%s`\n",
	// 	record->size, global_ct, record->type, buf_size, name);
	printf("%02x \t%02x %02x \t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
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
	printf("load_omf: UNKNOWN4 0x64 [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\t\t",
		record->size, global_ct, global_ct, record->type, buf_size);
	size_t ct = 3;
	const ut16 count = rz_read_le16_offset(buf, &ct);
	if (count == 0 || count > UINT16_MAX) {
		return false;
	}

	printf("count: %2d [%02x %02x]\t%02x %02x\n",
		count, buf[ct], buf[ct + 1], buf[ct + 2], buf[ct + 3]);
	ct += 2;

	for (ut16 i = 0; i < count; i++) {
		const ut8 b1 = rz_read_le8_offset(buf, &ct);
		const ut8 b2 = rz_read_le8_offset(buf, &ct);
		const ut8 b3 = rz_read_le8_offset(buf, &ct);
		const ut8 b4 = rz_read_le8_offset(buf, &ct);
		const ut16 line = rz_read_le16_offset(buf, &ct);

		printf("\t\t%02x %02x %02x %02x  [line: %5d]   %02x %02x %10s (0x%02x) %02x %02x %02x %02x %02x %02x %02x\n",
			b1, b2, b3, b4, line,
			buf[ct], buf[ct + 1],
			sym_operation_name(buf[ct + 2]), buf[ct + 2],
			buf[ct + 3], buf[ct + 4], buf[ct + 5],
			buf[ct + 6], buf[ct + 7], buf[ct + 8], buf[ct + 9]);
		ct += 10;
	}
	printf("\n");
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
	printf("0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n", buf[0], buf[1], buf[2], buf[3], buf[4]);
#if RZ_BUILD_DEBUG
#endif
	const ut16 ct = 3;
	if (!(record->type & 1) && record->size != 2) {
		RZ_LOG_ERROR("Invalid MODINF record (bad size)\n");
		return false;
	}
	obj->modinfo = rz_read_le8(buf + ct);
	return true;
}
/**
 * \brief Each compound type will force creation of a type record, which describes
 * the type of a variable or function.
 *
 * \details The layout of the type record is as shown:
 * ******************************************
 * * 0xF0 | RecLen | Type-Descriptor | Chks *
 * ******************************************
 * The NEWTYPE records are implictely numbered by sequenece, i.e. the first
 * record has number 0, the second number one and so on. The debug records
 * (LOCSYM, PUBDEF, ...) refer to a type record using an index, called TI
 * (TypeIndex) for short. The index uses the general format used within OMF166
 * and has a special interpretation.
 *
 * \param obj Plugin format data
 * \param buf Buffer for parsing
 * \return True is success, false is something wrong
 */
// static int load_omf_typnew(rz_bin_omf51_obj *obj, const ut8 *buf) {
// 	obj->TI_INDEX = obj->TI_INDEX | 0x80;
//
// 	OMF_type *newtype = RZ_NEW0(OMF_type);
// 	if (!newtype) {
// 		return false;
// 	}
// 	size_t cct = 3;
// 	newtype->index = obj->TI_INDEX;
// 	newtype->descr_type = rz_read_le8_offset(buf, &cct);
//
// 	switch (newtype->descr_type) {
// 	case COMPONENT_LIST_DESCRIPTOR: {
// 		newtype->is_data = true;
// 		/**
// 		 * \code
// 		 *  0x20 | NrOfComp16 | Components [*]  { TI16 | OFFS32 | REP8 | POS8 | n,’name’ }
// 		 * \endcode
// 		 */
// 		const ut16 raw_count = rz_read_le16_offset(buf, &cct);
// 		if (raw_count == 0 || raw_count > UINT16_MAX) {
// 			return false;
// 		}
// 		newtype->label = rz_str_dup("COMPONENT_LIST_DESCRIPTOR");
// 		newtype->descriptor.components.index = obj->TI_INDEX;
// 		newtype->descriptor.components.count = raw_count;
// 		newtype->descriptor.components.comp =
// 			RZ_NEWS0(OMF_component, newtype->descriptor.components.count);
// 		if (!newtype->descriptor.components.comp) {
// 			RZ_FREE(newtype->label);
// 			RZ_FREE(newtype);
// 			return false;
// 		}
//
// 		for (ut16 i = 0; i < newtype->descriptor.components.count; i++) {
// 			OMF_component *component = newtype->descriptor.components.comp + i;
// 			component->index = obj->TI_INDEX;
// 			component->ti = rz_read_le16_offset(buf, &cct);
// 			component->offset = rz_read_le16_offset(buf, &cct);
// 			cct += 2; ///< RESERVED16
// 			component->REP8 = rz_read_le8_offset(buf, &cct);
// 			component->POS8 = rz_read_le8_offset(buf, &cct);
// 			component->n = rz_read_le8_offset(buf, &cct);
// 			rz_str_ncpy(component->name, (const char *)&buf[cct], component->n + 1);
// 			cct += component->n;
// 		}
// 		break;
// 	}
// 	case POINTER_DESCRIPTOR: {
// 		newtype->label = rz_str_dup("POINTER_DESCRIPTOR");
// 		newtype->descriptor.pointer.size = rz_read_le8_offset(buf, &cct);
// 		newtype->descriptor.pointer.attrib = rz_read_le8_offset(buf, &cct);
// 		///< RESERVED16
// 		cct += 2;
// 		///< Specs bug (must be le16 by datasheet)
// 		newtype->descriptor.pointer.ti = rz_read_le8_offset(buf, &cct);
// 		break;
// 	}
// 	case ARRAY_DESCRIPTOR: {
// 		newtype->is_data = true;
// 		///< 0x22 | DIMS8 | ATTRIB8 | TI16 | DIMSZ32 [*]
// 		cct = 4;
// 		newtype->descriptor.array.dims = rz_read_le8_offset(buf, &cct);
// 		newtype->descriptor.array.attrib = rz_read_le8_offset(buf, &cct);
// 		newtype->descriptor.array.ti = rz_read_le16_offset(buf, &cct);
// 		newtype->descriptor.array.dimsz = rz_read_le32_offset(buf, &cct);
// 		char array_length[255] = RZ_EMPTY;
// 		if (newtype->descriptor.array.dimsz != 0xFFFFFFFF) {
// 			rz_strf(array_length, "%d", newtype->descriptor.array.dimsz);
// 		}
// 		newtype->label = rz_str_newf("%s array[%s]",
// 			name_of_ti(obj, newtype->descriptor.array.ti),
// 			array_length);
// 		break;
// 	}
// 	case FUNCTION_DESCRIPTOR: {
// 		///<  0x23 | ATTRIB8 | RTYPE-TI16 | PARMLIST-TI16
// 		///<  0x23   0x01       0x44 0x00    0x82 0x00 0x1f
// 		///<  0x23   0x01       0x4a 0x00    0x4a 0x00 0x51
// 		///<  0x23   0x01       0x44 0x00    0x4a 0x00 0x57
// 		cct = 4;
// 		newtype->descriptor.function.attrib = rz_read_le8_offset(buf, &cct);
// 		newtype->descriptor.function.rtype_ti = rz_read_le16_offset(buf, &cct);
// 		newtype->descriptor.function.parmlist_ti = rz_read_le16_offset(buf, &cct);
// 		newtype->label = rz_str_dup(newtype->descriptor.function.attrib ? "Near-Function" : "Far-Function");
// 		break;
// 	}
// 	case STRUCT_UNION_DESCRIPTOR: {
// 		///< 0x24 | ATTRIB8 | SIZE32 | MEMBER-TI16 | tagname
// 		cct = 4;
// 		newtype->descriptor.struct_union.is_struct = (rz_read_le8_offset(buf, &cct) == 1);
// 		newtype->descriptor.struct_union.size = rz_read_le32_offset(buf, &cct);
// 		newtype->descriptor.struct_union.member_ti = rz_read_le16_offset(buf, &cct);
// 		newtype->descriptor.struct_union.n = rz_read_le8_offset(buf, &cct);
//
// 		rz_str_ncpy(
// 			newtype->descriptor.struct_union.tagname,
// 			(const char *)&buf[cct],
// 			newtype->descriptor.struct_union.n + 1);
// 		newtype->label = rz_str_dup(newtype->descriptor.struct_union.tagname);
// 		break;
// 	}
// 	case BITFIELD_DESCRIPTOR: {
// 		newtype->label = rz_str_dup("BITFIELD_DESCRIPTOR");
// 		///< 0x25 | TI16 | OFFSET8 | WIDTH8
// 		break;
// 	}
// 	default: {
// 		rz_warn_if_reached();
// 		break;
// 	}
// 	}
//
// 	ht_up_insert(obj->ht_types, obj->TI_INDEX, newtype);
// 	obj->TI_INDEX++;
// 	return true;
// }

static int load_linnum92_data(const rz_bin_omf51_obj *obj, const ut8 *buf, const size_t buf_size, const OMF_record *record, ut64 global_ct) {
	OMF_linnums *linnum = NULL;
	size_t ct = 3;
#ifdef RZ_DEBUG
	RZ_LOG_DEBUG("load_omf: 0x92          [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
		record->size, global_ct, global_ct, record->type, buf_size);
#endif
	const ut8 GroupIndex = omf166_get_idx(buf + ct, buf_size - ct); // ct = 3
	ct++;
	const ut16 unk16 = rz_read_le16_offset(buf, &ct); // ct = 4

	while (ct < record->size) {
		linnum = RZ_NEW0(OMF_linnums);
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
		char k[512];
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

static int rz_bin_format_omf51_load_content(rz_bin_omf51_obj *obj, OMF_record *record, const ut8 *buf, const ut64 global_ct, const size_t buf_size) {
	// generic loader just copy data from buf to content
	if (!record->size) {
		RZ_LOG_ERROR("Invalid record (size to short)\n");
		return false;
	}

	switch (record->type) {
	case 0xc0:
		return load_linsym_data(obj, buf, record, global_ct, buf_size);
	case 0xc4:
		return load_linsym_data(obj, buf, record, global_ct, buf_size);
	case 0xc8:
		return load_c8_data(obj, buf, record, global_ct, buf_size);
	case 0x98:
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
	case 0x90:
		printf("load_omf: 0x90 (PUBDEF?)[%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\t\t",
			record->size, global_ct, global_ct, record->type, buf_size);
		rz_print_bytes(NULL, buf, record->size + 3, "0x%02x ");
		return true;
	case OMF_EXTDEF:
		printf("load_omf: OMF_EXTDEF    [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
			record->size, global_ct, global_ct, record->type, buf_size);
		return true;
	case OMF_ALIAS:
		printf("load_omf: OMF_ALIAS    [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
			record->size, global_ct, global_ct, record->type, buf_size);
		return true;
	// case OMF166_UNKNOWN0:
	// 	printf("load_omf: OMF166_UNKNOWN0    [%05d] [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
	// 		record->size, global_ct, record->type, buf_size);
	// 	return true;
	// case OMF166_INCLUDES:
	// 	printf("load_omf: OMF166_INCLUDES    [%05d] [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
	// 		record->size, global_ct, record->type, buf_size);
	// 	return true;
	// case OMF166_UNKNOWN2:
	// 	printf("load_omf: OMF166_UNKNOWN2    [%05d] [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
	// 		record->size, global_ct, record->type, buf_size);
	// 	return true;
	// case OMF166_UNKNOWN3:
	// 	printf("load_omf: OMF166_UNKNOWN3    [%05d] [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
	// 		record->size, global_ct, record->type, buf_size);
	// 	return true;
	// case OMF166_UNKNOWN4:
	// 	printf("load_omf: OMF166_UNKNOWN4    [%05d] [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
	// 		record->size, global_ct, record->type, buf_size);
	// 	return true;
	case 0xd0: // DONE
		return load_d0_data(obj, buf, record, global_ct, buf_size);
	case 0x8e:
		return load_8e_data(obj, buf, record, global_ct, buf_size);
	case 0x92:
		return load_linnum92_data(obj, buf, buf_size, record, global_ct);
	// case OMF166_GLBDEF:
	// case OMF166_LOCSYM:
	// case OMF166_PUBDEF:
	// case OMF166_DEBSYM: {
	// 	return load_omf166_global_sym_record(obj, record, buf, buf_size);
	// }
	case OMF166_BLKDEF: {
		return load_omf_blkdef(obj, buf, buf_size, global_ct);
	}
	// case OMF166_VECTAB:
	// case OMF166_PEDATA: {
	// 	return load_omf_pedata(obj, buf, record, global_ct);
	// }
	case OMF_LHEADR:
	case OMF_THEADR:
		return load_theadr_data(obj, buf, record, global_ct, buf_size);
	// case OMF166_LHEADR:
	// case OMF166_THEADR: {
	// 	char name[255] = RZ_EMPTY;
	// 	size_t offset = 3;
	// 	ut8 n = rz_read_le8_offset(buf, &offset);
	// 	rz_str_ncpy(name, (const char *)&buf[offset], n + 1);
	// 	printf("load_omf = %s  =  [0x%08" PFMT64x "] (%05d) `%s`\n",
	// 		record->type == OMF166_THEADR ? "THEADR" : "LHEADR",
	// 		global_ct,
	// 		record->size,
	// 		name);
	// 	return true;
	// }
	case OMF166_MODINF: {
		return load_omf_modinf(obj, buf, record);
	}
	case OMF166_MODEND: {
		printf("load_omf = MODEND  =  [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
			record->size, global_ct, global_ct, record->type, buf_size);
		return true;
	}
	case OMF166_BLKEND: {
		printf("load_omf = BLKEND  =  [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
			record->size, global_ct, global_ct, record->type, buf_size);
		return true;
	}
	case OMF51_PEDATA: { // DONE
		return load_omf51_pedata(obj, buf, record, global_ct, buf_size);
	}
	case OMF166_REGDEF: {
		/**
		 *     Type | RecLen | Offset | Base | n  | NAME             | RegMask | RESERVED | Chks
		 *      E3    0F 00    00 00     FC    07   INTREGS            FF FF      00         F1
		 *      E3    18 00    00 20     FC    10   ?C_MAINREGISTERS   FF FF      00         1D
		 */
		printf("load_omf = REGDEF  =  [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
			record->size, global_ct, global_ct, record->type, buf_size);
		return true;
	}
	case 0x88: { // DONE
		return load_88_data(obj, buf, record, global_ct, buf_size);
	}
	case OMF_GRPDEF:
		return load_9a_data(obj, buf, record, global_ct, buf_size);
	case OMF166_GRPDEF: {
		printf("load_omf: OMF166_GRPDEF [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n\t\t",
			record->size, global_ct, global_ct, record->type, buf_size);
		return load_grpdef_data(obj, buf, record, global_ct);
	}
	// case OMF166_DEPLST: {
	// 	return load_deplst_data(buf, record);
	// }
	case OMF166_DEPLST: // DONE
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

		// case OMF166_TYPNEW: {
		// 	return load_omf_typnew(obj, buf);
		// }

	case OMF166_SECDEF:
	case OMF166_XSECDEF: {
		return load_omf_secdef(obj, buf, record);
	}
	case OMF166_UNKNOWN0: {
		/*
			60    5E 00    00 02 03 00 95 00 00 00 0C 00 00
			05  69 64 61 74 61						= idata
			05  73 64 61 74 61						= sdata
			05  62 64 61 74 61						= bdata
			04  6E 65 61 72							= near
			03  66 61 72							= far
			0A  6E 65 61 72 20 63 6F 6E 73 74		= near const
			09  66 61 72 20 63 6F 6E 73 74			= far const
			04  68 75 67 65							= huge
			0A  68 75 67 65 20 63 6F 6E 73 74		= huge const
			05  78 68 75 67 65						= xhuge
			0B  78 68 75 67 65 20 63 6F 6E 73 74	= xhuge const
			DB
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
		printf("load_omf: [%05d] (%5" PFMT64u ") [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
			record->size, global_ct, global_ct, record->type, buf_size);
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

static OMF_record *rz_bin_format_omf51_load_record(rz_bin_omf51_obj *obj, const ut8 *buf, ut64 global_ct, size_t buf_size) {
	if (!is_valid_omf51_type(*buf) || !rz_bin_checksum_omf_ok(buf, buf_size)) {
		return NULL;
	}
	OMF_record *new = RZ_NEW0(OMF_record);
	if (!new) {
		return false;
	}
	size_t offset = 0;
	new->type = rz_read_le8_offset(buf, &offset);
	const ut16 raw_count = rz_read_le16_offset(buf, &offset);
	if (raw_count == 0 || raw_count > UINT16_MAX) {
		return false;
	}
	new->size = raw_count;

	// at least a record has a type, a size and a checksum
	if (new->size > (buf_size - offset) || buf_size < (offset + 1)) {
		RZ_LOG_ERROR("Invalid record (too short)\n");
		RZ_FREE(new);
		return NULL;
	}
	if (!rz_bin_format_omf51_load_content(obj, new, buf, global_ct, buf_size)) {
		RZ_FREE(new);
		return NULL;
	}
	new->checksum = buf[offset + new->size];
	return new;
}

static int line_sample_cmp(const void *a, const void *b, void *user) {
	const OMF_linnums *sa = a;
	const OMF_linnums *sb = b;
	// first, sort by addr
	if (sa->address < sb->address) {
		return -1;
	}
	if (sa->address > sb->address) {
		return 1;
	}
	// then sort by line
	if (sa->LineNumber < sb->LineNumber) {
		return -1;
	}
	if (sa->LineNumber > sb->LineNumber) {
		return 1;
	}
	// and eventually by file because this is the most expensive operation
	if (!strlen(sa->filename) && !strlen(sb->filename)) {
		return 0;
	}
	if (!strlen(sa->filename)) {
		return -1;
	}
	if (!strlen(sb->filename)) {
		return 1;
	}
	return strcmp(sa->filename, sb->filename);
}

static void omf166_linnums_free(void *it) {
	OMF_linnums *p = (OMF_linnums *)it;
	RZ_FREE(p);
}

// static void typnew_free(OMF_type *type) {
// 	if (!type) {
// 		return;
// 	}
// 	if (type->descr_type == FINAL_TYPE) {
// 		RZ_FREE(type->descriptor.final_types.label);
// 	}
// 	if (type->descr_type == FUNCTION_DESCRIPTOR) {
// 		rz_type_callable_free((RzCallable *)type->rz_type);
// 	}
// 	if (type->descr_type == COMPONENT_LIST_DESCRIPTOR) {
// 		RZ_FREE(type->descriptor.components.comp);
// 	}
// 	RZ_FREE(type->label);
// 	RZ_FREE(type);
// }

#define new_pv_and_check(vec, destructor) \
	if (!((vec) = rz_pvector_new((RzPVectorFree)(destructor)))) \
		return false;

static int rz_bin_format_omf51_init_internal_storage(rz_bin_omf51_obj *obj) {
	// obj->ht_types = ht_up_new(NULL, (HtUPFreeValue)typnew_free);
	// if (!obj->ht_types) {
	// 	return false;
	// }

	// const OMF_types final_types[] = {
	// 	{ 0x40, true, 0, "untyped" },
	// 	{ 0x41, true, 1, "bit" },
	// 	{ 0x42, true, 8, "char" },
	// 	{ 0x43, true, 8, "unsigned char" },
	// 	{ 0x44, true, 32, "int" },
	// 	{ 0x45, true, 32, "unsigned int" },
	// 	{ 0x46, true, 32, "long" },
	// 	{ 0x47, true, 32, "unsigned long" },
	// 	{ 0x48, true, 32, "float" }, ///< (32-Bit IEEE)
	// 	{ 0x49, true, 64, "double" }, ///< (64-Bit IEEE)
	// 	{ 0x4A, false, 0, "void" },
	// 	{ 0x4B, false, 0, "label" },
	// 	{ 0x4C, true, 4, "<a166 BITWORD>" },
	// 	{ 0x4D, false, 0, "<a166 NEAR>" },
	// 	{ 0x4E, false, 0, "<a166 FAR>" },
	// 	{ 0x4F, true, 3, "<a166 DATA3>" },
	// 	{ 0x50, true, 4, "<a166 DATA4>" },
	// 	{ 0x51, true, 8, "<a166 DATA8>" },
	// 	{ 0x52, true, 16, "<a166 DATA16>" },
	// 	{ 0x53, false, 0, "<a166 INTNO>" },
	// 	{ 0x54, false, 0, "<a166 REGBANK>" }
	// };
	// const int ft_count = RZ_ARRAY_SIZE(final_types);
	// for (ut8 i = 0; i < (ut8)ft_count; i++) {
	// 	OMF_type *newtype = RZ_NEW0(OMF_type);
	// 	if (!newtype) {
	// 		return false;
	// 	}
	// 	newtype->index = final_types[i].index;
	// 	newtype->descr_type = FINAL_TYPE;
	// 	newtype->is_data = final_types[i].is_data;
	// 	newtype->label = rz_str_dup(final_types[i].label);
	// 	newtype->descriptor.final_types.index = final_types[i].index;
	// 	newtype->descriptor.final_types.is_data = final_types[i].is_data;
	// 	newtype->descriptor.final_types.size = final_types[i].size;
	// 	newtype->descriptor.final_types.label = rz_str_dup(final_types[i].label);
	// 	if (!ht_up_insert(obj->ht_types, final_types[i].index, newtype)) {
	// 		eprintf("error insert `%s (0x%x)`\n", final_types[i].label, final_types[i].index);
	// 	}
	// }

	new_pv_and_check(obj->sections_vec, free);
	new_pv_and_check(obj->symbols_vec, free);
	new_pv_and_check(obj->blocks_vec, free);
	new_pv_and_check(obj->pe_vec, free);
	new_pv_and_check(obj->lnames_vec, free);
	new_pv_and_check(obj->deplsts_vec, free);
	new_pv_and_check(obj->linnums_vec, omf166_linnums_free);
	new_pv_and_check(obj->coments_vec, free);
	new_pv_and_check(obj->includes_vec, free);
	new_pv_and_check(obj->group_vec, free);
	new_pv_and_check(obj->regs_vec, free);
	new_pv_and_check(obj->ledatas_vec, free);
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

static int rz_bin_format_omf166_load_all_records(rz_bin_omf51_obj *obj, const ut8 *buf, const ut64 size) {
	if (!obj) {
		return false;
	}

	ut64 ct = 0;
	OMF_record *new_rec = NULL;

	rz_bin_format_omf51_init_internal_storage(obj);

	while (ct < size) {
		new_rec = rz_bin_format_omf51_load_record(obj, buf + ct, ct, size - ct);
		if (!new_rec) {
			return false;
		}
		ct += 3 + new_rec->size;
		free(new_rec);
	}

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
		rz_pvector_sort(v, line_sample_cmp, NULL);
	}
	return true;
}

#define PVEC_FREE(vec) \
	if (vec) { \
		rz_pvector_free(vec); \
	}

void rz_bin_format_omf51_free_all_records(rz_bin_omf51_obj *obj) {
	if (!obj) {
		return;
	}
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
}

rz_bin_omf51_obj *rz_bin_format_omf51_load(const ut8 *buf, ut64 size) {
	rz_bin_omf51_obj *ret = RZ_NEW0(rz_bin_omf51_obj);
	if (!ret) {
		return NULL;
	}

	if (!rz_bin_format_omf166_load_all_records(ret, buf, size)) {
		rz_bin_format_omf51_free_all_records(ret);
		return NULL;
	}
	return ret;
}

void rz_bin_format_omf51_fini(rz_bin_omf51_obj *obj) {
	rz_bin_format_omf51_free_all_records(obj);
	RZ_FREE(obj);
}

bool rz_bin_omf51_get_entry(const rz_bin_omf51_obj *obj, RzBinAddr *addr) {
	if (!obj) {
		return false;
	}

	if (!rz_pvector_len(obj->symbols_vec))
		return false;
	const RzPVector *v = obj->symbols_vec;
	void **it;
	rz_pvector_foreach (v, it) {
		const char *start_symbol_name = "main";
		const OMF_symbol *symbol = (OMF_symbol *)*it;
		if (!strcmp(symbol->name2, start_symbol_name)) {
			addr->vaddr = symbol->base + symbol->offset;
			return true;
		}
	}
	return false;
}
