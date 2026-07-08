// SPDX-FileCopyrightText: 2015 ampotos <mercie_i@epitech.eu>
// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "omf.h"

/**
 * \file omf166.c
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
 * Many of the OMF166 records use some index to refer to other records. The high
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

RZ_API ut8 memory_model_type(ut8 modinfo) {
	return (modinfo & 0x1C) >> 2;
}

RZ_API char *get_memory_model(ut8 modinfo) {
	const ut8 MEMORY_MODEL = memory_model_type(modinfo); ///< The three bit model specifier gives the memory model choosen on translation:
	switch (MEMORY_MODEL) {
	case OMF_MEMORY_MODEL_TINY: {
		return rz_str_dup("Tiny: program 64K or less");
	}
	case OMF_MEMORY_MODEL_SMALL: {
		return rz_str_dup("Small: 'near' functions and data");
	}
	case OMF_MEMORY_MODEL_COMPACT: {
		return rz_str_dup("Compact: 'far' data, 'near' funcs");
	}
	case OMF_MEMORY_MODEL_MEDIUM: {
		return rz_str_dup("Medium: 'near' data, 'far' funcs");
	}
	case OMF_MEMORY_MODEL_LARGE: {
		return rz_str_dup("Large: 'far' functions and data");
	}
	case OMF_MEMORY_MODEL_HCOMPACT: {
		return rz_str_dup("HCompact: 'huge' data, 'near' funcs");
	}
	case OMF_MEMORY_MODEL_HLARGE: {
		return rz_str_dup("HLarge: 'huge' data, 'far' funcs");
	}
	case OMF_MEMORY_MODEL_XLARGE: {
		return rz_str_dup("XLarge: 'xhuge' data, 'far' funcs");
	}
	default:
		RZ_LOG_ERROR("Unknown MEMORY_MODEL: 0x%02x.\n", MEMORY_MODEL);
		return rz_str_dup("Unknown MEMORY_MODEL");
	}
}

static bool is_data_ti(const rz_bin_omf166_obj *obj, const ut16 ti_index) {
	bool found = false;
	const OMF_type *type = ht_up_find(obj->ht_types, ti_index, &found);
#ifdef RZ_BUILD_DEBUG
	rz_warn_if_fail(found);
#endif
	return found ? type->is_data : false;
}

RZ_API const char *name_of_ti(const rz_bin_omf166_obj *obj, const ut16 ti_index) {
	if (ti_index == 0x00)
		return "void";
	bool found = false;
	const OMF_type *type = ht_up_find(obj->ht_types, ti_index, &found);
	if (!found)
		return NULL;

	switch (type->descr_type) {
	case FINAL_TYPE: {
		return type->label;
	}
	case COMPONENT_LIST_DESCRIPTOR: {
		return type->label ? type->label : "COMPONENT_LIST";
	}
	case POINTER_DESCRIPTOR: {
		const char *x = name_of_ti(obj, type->descriptor.pointer.ti);
		static char x2[255] = { 0 };
		if (type->descriptor.pointer.attrib == 1)
			rz_snprintf(x2, sizeof(buffer), "%s *", x); ///< "POINTER: 1 = Data pointer (PAGE:OFFSET)"
		if (type->descriptor.pointer.attrib == 2)
			rz_snprintf(x2, sizeof(buffer), "%s *", x); ///< "POINTER: 2 = Function pointer (SEG:OFFSET)"
		if (type->descriptor.pointer.attrib == 4)
			rz_snprintf(x2, sizeof(buffer), "%s *", x); ///< "POINTER: 4 = Huge pointer (linear 32-Bit)"
		if (type->descriptor.pointer.attrib == 8)
			rz_snprintf(x2, sizeof(buffer), "%s *", x); ///< "POINTER: 8 = Xhuge pointer (linear 32-Bit)"
		return x2;
	}
	case ARRAY_DESCRIPTOR: {
		return type->label ? type->label : "ARRAY";
	}
	case FUNCTION_DESCRIPTOR: {
		return type->descriptor.function.attrib ? "Near-Function" : "Far-Function";
	}
	case STRUCT_UNION_DESCRIPTOR: {
		return type->descriptor.struct_union.tagname;
	}
	case BITFIELD_DESCRIPTOR: {
		return "BITFIELD";
	}
	default: {
		rz_warn_if_reached();
		return NULL;
	}
	}
	rz_warn_if_reached();
	return NULL;
}

const char *name_of_iTyp(ut8 iTyp) {
	switch (iTyp) {
	case ITYP_OUTPUTFILE: {
		return "Outputfile";
	}
	case ITYP_INPUTFILE: {
		return "Inputfile";
	}
	case ITYP_INCLUDEFILE: {
		return "Includefile";
	}
	case ITYP_COMMANDFILE: {
		return "Commandfile";
	}
	case ITYP_OBJECT_INPUTFILE: {
		return "Object-Inputfile";
	}
	case ITYP_COMMANDLINE: {
		return "Commandline";
	}
	default: {
		rz_warn_if_reached();
		return "UNKNOWN";
	}
	}
}

const char *get_data_type(ut8 data_type) {
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

ut32 get_perm_by_type(ut8 data_type) {
	switch (data_type) {
	case 0: ///< BIT
	case 1: { ///< DATA
		return RZ_PERM_RW;
	}
	case 2: {
		return RZ_PERM_RX; ///< CODE
	}
	case 3: {
		return RZ_PERM_R; ///< CONST
	}
	default: {
		rz_warn_if_reached();
		return RZ_PERM_R;
	}
	}
}

ut32 c166_get_perms_from_class(const ut8 class_id) {
	switch (class_id) {
	case C166_CLASS_ICODE:
	case C166_CLASS_FCODE:
	case C166_CLASS_NCODE:
		return RZ_PERM_RW;
	case C166_CLASS_FCONST:
	case C166_CLASS_HCONST:
	case C166_CLASS_XCONST:
	case C166_CLASS_NCONST:
		return RZ_PERM_R;
	case C166_CLASS_SDATA:
	case C166_CLASS_SDATA0:
	case C166_CLASS_IDATA:
	case C166_CLASS_IDATA0:
	case C166_CLASS_FDATA:
	case C166_CLASS_FDATA0:
	case C166_CLASS_HDATA:
	case C166_CLASS_HDATA0:
	case C166_CLASS_XDATA:
	case C166_CLASS_XDATA0:
	case C166_CLASS_NDATA:
	case C166_CLASS_NDATA0:
	case C166_CLASS_BIT:
	case C166_CLASS_BIT0:
	case C166_CLASS_BDATA:
	case C166_CLASS_BDATA0:
	case C166_CLASS_EBDATA:
	case C166_CLASS_EBDATA0:
		return RZ_PERM_RW;
	default:
		return RZ_PERM_R;
	}
}

ut64 rz_bin_omf166_get_abs_addr(ut8 SegmentNumber8, ut16 Offset) {
	ut64 offset = 0;
	offset = (SegmentNumber8 << 16) | Offset;
	return offset;
}

static bool is_valid_omf166_type(ut8 type) {
	const ut8 types[] = {
		OMF166_RTXDEF, OMF166_DEPLST, OMF166_REGMSK, OMF166_TYPNEW,
		OMF166_BLKEND, OMF166_THEADR, OMF166_LHEADR, OMF166_COMMENT,
		OMF166_MODEND, OMF166_LINNUM, OMF166_LNAMES, OMF166_LIBLOC,
		OMF166_LIBNAMES, OMF166_LIBDICT, OMF166_LIBHDR, OMF166_PHEADR,
		OMF166_PECDEF, OMF166_SSKDEF, OMF166_MODINF, OMF166_TSKDEF,
		OMF166_REGDEF, OMF166_SECDEF, OMF166_TYPDEF, OMF166_GRPDEF,
		OMF166_PUBDEF, OMF166_GLBDEF, OMF166_EXTDEF, OMF166_LOCSYM,
		OMF166_BLKDEF, OMF166_DEBSYM, OMF166_LEDATA, OMF166_PEDATA,
		OMF166_VECTAB, OMF166_FIXUPP, OMF166_TSKEND, OMF166_XSECDEF,
		OMF166_UNKNOWN0, OMF166_INCLUDES, OMF166_UNKNOWN2, OMF166_UNKNOWN3,
		OMF166_UNKNOWN4, OMF166_UNKNOWN5,
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

bool rz_bin_checksum_omf166_ok(const ut8 *buf, size_t buf_size) {
	ut8 checksum = 0;

	if (buf_size < 3) {
		RZ_LOG_ERROR("Invalid record (too short)\n");
		return false;
	}
	ut16 size = rz_read_le16(buf + 1);
	if (buf_size < size + 3) {
		RZ_LOG_ERROR("Invalid record (too short)\n");
		return false;
	}
	// Some compiler set checksum to 0
	if (!buf[size + 2]) {
		return true;
	}
	size += 3;
	for (; size; size--) {
		if (buf_size < size) {
			RZ_LOG_ERROR("Invalid record (too short)\n");
			return false;
		}
		checksum += buf[size - 1];
	}
	if (checksum)
		RZ_LOG_ERROR("Invalid record checksum\n");
	return !checksum ? true : false;
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

static bool load_omf166_lnames(const rz_bin_omf166_obj *obj, const OMF_record *record, const ut8 *buf, const size_t buf_size, ut64 global_ct) {
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

static int load_omf166_global_sym_record(const rz_bin_omf166_obj *obj, const OMF_record *record, const ut8 *buf, const size_t buf_size) {
	OMF_symbol *sym = NULL;
	size_t ct = 3;
	ut32 base = 0;

	if (record->size <= 3) {
		return false;
	}
	if (record->type == OMF166_DEBSYM) {
		if ((buf[ct] == 0x02)) {
			ct++;
			base = rz_read_le8_offset(buf, &ct);
		} else {
			///< A DEBSYM record whose FRAMEINFO field is 0 is functionally
			///< equivalent to a LOCSYM record.
			ct++;
			base = rz_read_le32_offset(buf, &ct);
		}
	} else
		base = rz_read_le32_offset(buf, &ct);

	if (record->size <= ct) {
		RZ_LOG_ERROR("Invalid sym record (bad size)\n");
		return false;
	}

	while (record->size > ct) {
		sym = RZ_NEW0(OMF_symbol);
		if (!sym) {
			return false;
		}
		sym->rec_type = record->type;
		sym->base = base;
		sym->n = rz_read_le8_offset(buf, &ct);
		rz_str_ncpy(sym->name2, (const char *)&buf[ct], sym->n + 1);

		ct += sym->n;
		sym->offset = rz_read_le16_offset(buf, &ct);
		sym->REP8 = rz_read_le8_offset(buf, &ct);
		sym->V = sym->REP8 >> 7;
		sym->REP = (sym->REP8 & 0x70) >> 4;
		sym->bpos = sym->REP8 & 0x0F;
		sym->ti = omf166_get_idx(buf + ct, buf_size - ct);
		ct += (buf[ct] & 0x80) ? 2 : 1;

		sym->is_data = is_data_ti(obj, sym->ti);
		const ut8 rep = (sym->REP8 & 0x70) >> 4;

		switch (rep) {
		case REP_BIT:
		case REP_VAR:
		case REP_REGBANK:
		case REP_INTNO:
		case REP_CONST:
		case REP_REGVAR:
		case REP_AUTO:
			sym->is_data = true;
			break;
		default:
			sym->is_data = false;
			break;
		}
		rz_pvector_push(obj->symbols_vec, sym);
	}
	return true;
}

static int load_omf_data(const rz_bin_omf166_obj *obj, const ut8 *buf, const size_t buf_size, const OMF_record *record) {
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

static int load_omf_blkdef(const rz_bin_omf166_obj *obj, const ut8 *buf, const size_t buf_size, ut64 global_ct) {
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

static int load_comment_data(const rz_bin_omf166_obj *obj, const ut8 *buf, const OMF_record *record, ut64 global_ct) {
	if (!(obj && obj->coments_vec)) {
		return false;
	}

	OMF_coments *comment = RZ_NEW0(OMF_coments);
	if (!comment) {
		return false;
	}

	size_t ct = 3;
	const ut8 ComTyp_b2 = rz_read_le8_offset(buf, &ct);
	const ut8 ComTyp_b1 = rz_read_le8_offset(buf, &ct);
	comment->nopurge = (ComTyp_b1 & 0x80) >> 7;
	comment->is_filename = (ComTyp_b2 == 0x4b);
	comment->n = record->size + 3 - ct;
	rz_str_ncpy(comment->text,
		(const char *)&buf[ct], comment->n);
	rz_pvector_push(obj->coments_vec, comment);
	return true;
}

static int load_grpdef_data(const rz_bin_omf166_obj *obj, const ut8 *buf, const OMF_record *record, ut64 global_ct) {
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
	RZ_LOG_DEBUG("load_omf = GRPDEF  =  [%05d] [0x%08" PFMT64x "] 0x%02x\n",
		record->size, global_ct, record->type);
	return true;
}

static int load_deplst_data(const ut8 *buf, const OMF_record *record) {
#if RZ_BUILD_DEBUG
	size_t ct = 3;
	const ut8 some_byte = rz_read_le8_offset(buf, &ct);
	(void)some_byte;
	const ut8 info_n = rz_read_le8_offset(buf, &ct);
	char info[255] = RZ_EMPTY;
	rz_str_ncpy(info, (const char *)&buf[ct], info_n + 1);
	ct += info_n;
	while (ct < record->size) {
		/**
		 * iTyp | Mark8 | Time32 | Name(s)
		 *
		 * `iTyp` - Specifies the type of the dependency descriptor
		 * `Mark8` - Byte, required to be zero.
		 * `Time32` - File creation date in Microsoft’s ’fstat()’ format.
		 * `n` - size of Pathname.
		 * `Name` - Specifies the Pathname of one file.

		In case of iTyp 4, more than one pathname may be specified.
		*/
		const ut8 iTyp = rz_read_le8_offset(buf, &ct);
		const ut8 Mark8 = rz_read_le8_offset(buf, &ct);
		const ut32 Time32 = rz_read_le32_offset(buf, &ct);
		const ut8 n = rz_read_le8_offset(buf, &ct);
		char pathname[255] = RZ_EMPTY;
		rz_str_ncpy(pathname,
			(const char *)&buf[ct], n + 1);
		RZ_LOG_DEBUG("iTyp: [0x%02x] `%16s`, Mark8: 0x%02x, Time32: %d, n: %3d `%s`\n",
			iTyp, name_of_iTyp(iTyp), Mark8, Time32, n, pathname);
		ct += n;
	}
#endif
	return true;
}

static int load_linnum_data(const rz_bin_omf166_obj *obj, const ut8 *buf, const size_t buf_size, const OMF_record *record) {
	OMF_linnums *linnum = NULL;
	size_t ct = 3;

	const ut8 GroupIndex = omf166_get_idx(buf + ct, buf_size - ct); // ct = 3
	ct++;
	const ut8 SectionIndex = omf166_get_idx(buf + ct, buf_size - ct); // ct = 4
	ct++;
	ut16 FrameNumber = 0x00;
	if (!GroupIndex && !SectionIndex) {
		FrameNumber = rz_read_le16_offset(buf, &ct);
	}

	while (ct < record->size) {
		linnum = RZ_NEW0(OMF_linnums);
		if (!linnum) {
			return false;
		}
		linnum->LineNumber = rz_read_le16_offset(buf, &ct); // start with ct = 5
		const ut16 offset = rz_read_le16_offset(buf, &ct);
		linnum->address = ((ut64)FrameNumber << 16) | offset;
		OMF_coments *comment = rz_pvector_tail(obj->coments_vec);
		if (!comment) {
			RZ_FREE(linnum);
			return false;
		}
		linnum->n = comment->n;
		rz_str_ncpy(linnum->filename, comment->text, comment->n);
		rz_pvector_push(obj->linnums_vec, linnum);
	}
	return true;
}

static int load_omf_pedata(const rz_bin_omf166_obj *obj, const ut8 *buf, const OMF_record *record, const ut64 global_ct) {
	if (!(obj && obj->pe_vec)) {
		return false;
	}

	OMF_pes *pe = RZ_NEW0(OMF_pes);
	if (!pe) {
		return false;
	}

	size_t ct = 3;
	pe->SegmentNumber8 = rz_read_le8_offset(buf, &ct);
	pe->offset = rz_read_le16_offset(buf, &ct);
	pe->data_type = rz_read_le8_offset(buf, &ct);
	pe->isVector = (record->type == OMF166_VECTAB);

	/**
	 * 0xB9  | RecLen     |         ABS-Address         | DatTyp |        Data        | Chks
	 *       |            | SegmentNumber8 |  Offset16  |
	 * 0xc0  | 0x4c 0x1e  |     0x01       |  0x49 0x4e |  0x56  |  0x41 0x4c .. 0x00 | 0x36
	 *
	 *    DatTyp	0: BIT  1: DATA  2: CODE  3: CONST
	 */
	pe->size = pe->psize = record->size - 1 - (ct - 3);
	pe->paddr = global_ct + ct;
	rz_pvector_push(obj->pe_vec, pe);
	return true;
}

static int load_omf_unk1(const rz_bin_omf166_obj *obj, const ut8 *buf, const size_t buf_size, const OMF_record *record, const ut64 global_ct) {
	/**
	 * 61    40 00    2C 03 9D 55 01 00
	 * 38    43 3A 5C 4B 65 69 6C ... 5C 47 65 74 6C 69 6E 65 2E 63
	 * C:\Keil_v5\c166\Examples\XC16x Devices\MEASURE\Getline.c
	 * CA
	 */
#if RZ_BUILD_DEBUG
	OMF_debug_includes *dip = RZ_NEW0(OMF_debug_includes);
	if (!dip) {
		return false;
	}
	size_t offset = 9;
	dip->n = rz_read_le8_offset(buf, &offset);
	rz_str_ncpy(dip->name, (const char *)&buf[offset], dip->n + 1);
	RZ_LOG_DEBUG("load_omf = INCLUDES  =  [%05d] [0x%08" PFMT64x "] 0x%02x (%10" PFMTSZu ")\t `%s`\n",
		record->size, global_ct, record->type, buf_size, dip->name);
	rz_pvector_push(obj->includes_vec, dip);

#endif
	return true;
}

static int load_omf_unk2(const ut8 *buf, const size_t buf_size, const OMF_record *record, const ut64 global_ct) {
#if RZ_BUILD_DEBUG
	char name[255] = RZ_EMPTY;
	size_t offset = 7;
	const ut8 n = rz_read_le8_offset(buf, &offset);
	rz_str_ncpy(name, (const char *)&buf[offset], n + 1);
	RZ_LOG_DEBUG("load_omf = UNKNOWN2  =  [%05d] [0x%08" PFMT64x "] 0x%02x (%10" PFMTSZu ")\t 0x%02x 0x%02x 0x%02x 0x%02x  `%s`\n",
		record->size, global_ct,
		record->type, buf_size,
		buf[3], buf[4], buf[5], buf[6],
		name);
#endif
	return true;
}

static int load_omf_unk3(const ut8 *buf, const size_t buf_size, const OMF_record *record, const ut64 global_ct) {
#if RZ_BUILD_DEBUG
	char name[255] = RZ_EMPTY;
	size_t offset = 7;
	const ut8 n = rz_read_le8_offset(buf, &offset);
	rz_str_ncpy(name, (const char *)&buf[offset], n + 1); // cct = 12
	RZ_LOG_DEBUG("load_omf = UNKNOWN3  =  [%05d] [0x%08" PFMT64x "] 0x%02x (%10" PFMTSZu ")\t `%s`\n",
		record->size, global_ct, record->type, buf_size, name);
	RZ_LOG_DEBUG("%02x %02x %02x \n%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
		buf[0], buf[1], buf[2],
		buf[3], buf[4], buf[5], buf[6], buf[7],
		buf[8], buf[9], buf[10], buf[11], buf[12],
		buf[13], buf[14]);
#endif
	return true;
}

static int load_omf_unk4(const ut8 *buf, const size_t buf_size, const OMF_record *record, const ut64 global_ct) {
#if RZ_BUILD_DEBUG
	RZ_LOG_DEBUG("load_omf = UNKNOWN4  =  [%05d] [0x%08" PFMT64x "] 0x%02x (%10" PFMTSZu ")\n", record->size, global_ct, record->type, buf_size);
	size_t ct = 3;
	const ut16 count = rz_read_le16_offset(buf, &ct);

	RZ_LOG_DEBUG("count: %2d [%02x %02x]\n%02x %02x\n",
		count, buf[ct], buf[ct + 1], buf[ct + 2], buf[ct + 3]);
	ct += 2;

	for (ut16 i = 0; i < count; i++) {
		const ut8 b1 = rz_read_le8_offset(buf, &ct);
		const ut8 b2 = rz_read_le8_offset(buf, &ct);
		const ut8 b3 = rz_read_le8_offset(buf, &ct);
		const ut8 b4 = rz_read_le8_offset(buf, &ct);
		const ut16 line = rz_read_le16_offset(buf, &ct);

		RZ_LOG_DEBUG("%02x %02x %02x %02x  [line: %5d]   %02x %02x %s (0x%02x) %02x %02x %02x %02x %02x %02x %02x\n",
			b1, b2, b3, b4, line,
			buf[ct], buf[ct + 1],
			buf[ct + 2] ? "references" : "definition", buf[ct + 2],
			buf[ct + 3], buf[ct + 4], buf[ct + 5],
			buf[ct + 6], buf[ct + 7], buf[ct + 8], buf[ct + 9]);
		ct += 10;
	}
#endif
	return true;
}

static int load_omf_secdef(rz_bin_omf166_obj *obj, const ut8 *buf, const OMF_record *record) {
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
static int load_omf_modinf(rz_bin_omf166_obj *obj, const ut8 *buf, const OMF_record *record) {
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
static int load_omf_typnew(rz_bin_omf166_obj *obj, const ut8 *buf) {
	obj->TI_INDEX = obj->TI_INDEX | 0x80;

	OMF_type *newtype = RZ_NEW0(OMF_type);
	if (!newtype) {
		return false;
	}
	size_t cct = 3;
	newtype->index = obj->TI_INDEX;
	newtype->descr_type = rz_read_le8_offset(buf, &cct);

	switch (newtype->descr_type) {
	case COMPONENT_LIST_DESCRIPTOR: {
		newtype->is_data = true;
		/**
		 * \code
		 *  0x20 | NrOfComp16 | Components [*]  { TI16 | OFFS32 | REP8 | POS8 | n,’name’ }
		 * \endcode
		 */
		const ut16 raw_count = rz_read_le16_offset(buf, &cct);
		if (raw_count == 0 || raw_count > UINT16_MAX) {
			return false;
		}
		newtype->label = rz_str_dup("COMPONENT_LIST_DESCRIPTOR");
		newtype->descriptor.components.index = obj->TI_INDEX;
		newtype->descriptor.components.count = raw_count;
		newtype->descriptor.components.comp =
			RZ_NEWS0(OMF_component, newtype->descriptor.components.count);
		if (!newtype->descriptor.components.comp) {
			RZ_FREE(newtype->label);
			RZ_FREE(newtype);
			return false;
		}

		for (ut16 i = 0; i < newtype->descriptor.components.count; i++) {
			OMF_component *component = newtype->descriptor.components.comp + i;
			component->index = obj->TI_INDEX;
			component->ti = rz_read_le16_offset(buf, &cct);
			component->offset = rz_read_le16_offset(buf, &cct);
			cct += 2; ///< RESERVED16
			component->REP8 = rz_read_le8_offset(buf, &cct);
			component->POS8 = rz_read_le8_offset(buf, &cct);
			component->n = rz_read_le8_offset(buf, &cct);
			rz_str_ncpy(component->name, (const char *)&buf[cct], component->n + 1);
			cct += component->n;
		}
		break;
	}
	case POINTER_DESCRIPTOR: {
		newtype->label = rz_str_dup("POINTER_DESCRIPTOR");
		newtype->descriptor.pointer.size = rz_read_le8_offset(buf, &cct);
		newtype->descriptor.pointer.attrib = rz_read_le8_offset(buf, &cct);
		///< RESERVED16
		cct += 2;
		///< Specs bug (must be le16 by datasheet)
		newtype->descriptor.pointer.ti = rz_read_le8_offset(buf, &cct);
		break;
	}
	case ARRAY_DESCRIPTOR: {
		newtype->is_data = true;
		///< 0x22 | DIMS8 | ATTRIB8 | TI16 | DIMSZ32 [*]
		cct = 4;
		newtype->descriptor.array.dims = rz_read_le8_offset(buf, &cct);
		newtype->descriptor.array.attrib = rz_read_le8_offset(buf, &cct);
		newtype->descriptor.array.ti = rz_read_le16_offset(buf, &cct);
		newtype->descriptor.array.dimsz = rz_read_le32_offset(buf, &cct);
		char array_length[255] = RZ_EMPTY;
		if (newtype->descriptor.array.dimsz != 0xFFFFFFFF) {
			rz_strf(array_length, "%d", newtype->descriptor.array.dimsz);
		}
		newtype->label = rz_str_newf("%s array[%s]",
			name_of_ti(obj, newtype->descriptor.array.ti),
			array_length);
		break;
	}
	case FUNCTION_DESCRIPTOR: {
		///<  0x23 | ATTRIB8 | RTYPE-TI16 | PARMLIST-TI16
		///<  0x23   0x01       0x44 0x00    0x82 0x00 0x1f
		///<  0x23   0x01       0x4a 0x00    0x4a 0x00 0x51
		///<  0x23   0x01       0x44 0x00    0x4a 0x00 0x57
		cct = 4;
		newtype->descriptor.function.attrib = rz_read_le8_offset(buf, &cct);
		newtype->descriptor.function.rtype_ti = rz_read_le16_offset(buf, &cct);
		newtype->descriptor.function.parmlist_ti = rz_read_le16_offset(buf, &cct);
		newtype->label = rz_str_dup(newtype->descriptor.function.attrib ? "Near-Function" : "Far-Function");
		break;
	}
	case STRUCT_UNION_DESCRIPTOR: {
		///< 0x24 | ATTRIB8 | SIZE32 | MEMBER-TI16 | tagname
		cct = 4;
		newtype->descriptor.struct_union.is_struct = (rz_read_le8_offset(buf, &cct) == 1);
		newtype->descriptor.struct_union.size = rz_read_le32_offset(buf, &cct);
		newtype->descriptor.struct_union.member_ti = rz_read_le16_offset(buf, &cct);
		newtype->descriptor.struct_union.n = rz_read_le8_offset(buf, &cct);

		rz_str_ncpy(
			newtype->descriptor.struct_union.tagname,
			(const char *)&buf[cct],
			newtype->descriptor.struct_union.n + 1);
		newtype->label = rz_str_dup(newtype->descriptor.struct_union.tagname);
		break;
	}
	case BITFIELD_DESCRIPTOR: {
		newtype->label = rz_str_dup("BITFIELD_DESCRIPTOR");
		///< 0x25 | TI16 | OFFSET8 | WIDTH8
		break;
	}
	default: {
		rz_warn_if_reached();
		break;
	}
	}

	ht_up_insert(obj->ht_types, obj->TI_INDEX, newtype);
	obj->TI_INDEX++;
	return true;
}

static int rz_bin_format_omf166_load_content(rz_bin_omf166_obj *obj, OMF_record *record, const ut8 *buf, const ut64 global_ct, const size_t buf_size) {
	// generic loader just copy data from buf to content
	if (!record->size) {
		RZ_LOG_ERROR("Invalid record (size to short)\n");
		return false;
	}

	switch (record->type) {
	case OMF166_LNAMES: {
		return load_omf166_lnames(obj, record, buf, buf_size, global_ct);
	}
	case OMF166_GLBDEF:
	case OMF166_LOCSYM:
	case OMF166_PUBDEF:
	case OMF166_DEBSYM: {
		return load_omf166_global_sym_record(obj, record, buf, buf_size);
	}
	case OMF166_BLKDEF: {
		return load_omf_blkdef(obj, buf, buf_size, global_ct);
	}
	case OMF166_VECTAB:
	case OMF166_PEDATA: {
		return load_omf_pedata(obj, buf, record, global_ct);
	}
	case OMF166_LHEADR:
	case OMF166_THEADR: {
		char name[255] = RZ_EMPTY;
		size_t offset = 3;
		ut8 n = rz_read_le8_offset(buf, &offset);
		rz_str_ncpy(name, (const char *)&buf[offset], n + 1);
		RZ_LOG_DEBUG("load_omf = %s  =  [0x%08" PFMT64x "] (%05d) `%s`\n",
			record->type == OMF166_THEADR ? "THEADR" : "LHEADR",
			global_ct,
			record->size,
			name);
		return true;
	}
	case OMF166_MODINF: {
		return load_omf_modinf(obj, buf, record);
	}
	case OMF166_MODEND: {
		RZ_LOG_DEBUG("load_omf = MODEND  =  [%05d] [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
			record->size, global_ct, record->type, buf_size);
		return true;
	}
	case OMF166_BLKEND: {
		RZ_LOG_DEBUG("load_omf = BLKEND  =  [%05d] [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
			record->size, global_ct, record->type, buf_size);
		return true;
	}
	case OMF166_LINNUM: {
		return load_linnum_data(obj, buf, buf_size, record);
	}
	case OMF166_REGDEF: {
		/**
		 *     Type | RecLen | Offset | Base | n  | NAME             | RegMask | RESERVED | Chks
		 *      E3    0F 00    00 00     FC    07   INTREGS            FF FF      00         F1
		 *      E3    18 00    00 20     FC    10   ?C_MAINREGISTERS   FF FF      00         1D
		 */
		RZ_LOG_DEBUG("load_omf = REGDEF  =  [%05d] [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\n",
			record->size, global_ct, record->type, buf_size);
		return true;
	}
	case OMF166_COMMENT: {
		return load_comment_data(obj, buf, record, global_ct);
	}
	case OMF166_GRPDEF: {
		return load_grpdef_data(obj, buf, record, global_ct);
	}
	case OMF166_DEPLST: {
		return load_deplst_data(buf, record);
	}
	case OMF166_LEDATA: {
		return load_omf_data(obj, buf, buf_size, record);
	}

	case OMF166_TYPNEW: {
		return load_omf_typnew(obj, buf);
	}

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
		RZ_LOG_DEBUG("load_omf: [%05d] [0x%08" PFMT64x "] 0x%02x (%" PFMTSZu ")\t",
			record->size, global_ct, record->type, buf_size);
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

static OMF_record *rz_bin_format_omf166_load_record(rz_bin_omf166_obj *obj, const ut8 *buf, ut64 global_ct, size_t buf_size) {
	if (!is_valid_omf166_type(*buf) || !rz_bin_checksum_omf_ok(buf, buf_size)) {
		return NULL;
	}
	OMF_record *new = RZ_NEW0(OMF_record);
	if (!new) {
		return false;
	}
	size_t offset = 0;
	new->type = rz_read_le8_offset(buf, &offset);
	new->size = rz_read_le16_offset(buf, &offset);

	// at least a record has a type, a size and a checksum
	if (new->size > (buf_size - offset) || buf_size < (offset + 1)) {
		RZ_LOG_ERROR("Invalid record (too short)\n");
		RZ_FREE(new);
		return NULL;
	}
	if (!(rz_bin_format_omf166_load_content(obj, new, buf, global_ct, buf_size))) {
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

static void typnew_free(OMF_type *type) {
	if (!type) {
		return;
	}
	if (type->descr_type == FINAL_TYPE) {
		RZ_FREE(type->descriptor.final_types.label);
	}
	if (type->descr_type == FUNCTION_DESCRIPTOR) {
		rz_type_callable_free((RzCallable *)type->rz_type);
	}
	if (type->descr_type == COMPONENT_LIST_DESCRIPTOR) {
		RZ_FREE(type->descriptor.components.comp);
	}
	RZ_FREE(type->label);
	RZ_FREE(type);
}

#define new_pv_and_check(vec, destructor) \
	if (!((vec) = rz_pvector_new((RzPVectorFree)(destructor)))) \
		return false;

static int rz_bin_format_omf166_init_internal_storage(rz_bin_omf166_obj *obj) {
	obj->ht_types = ht_up_new(NULL, (HtUPFreeValue)typnew_free);
	if (!obj->ht_types) {
		return false;
	}

	const OMF_types final_types[] = {
		{ 0x40, true, 0, "untyped" },
		{ 0x41, true, 1, "bit" },
		{ 0x42, true, 8, "char" },
		{ 0x43, true, 8, "unsigned char" },
		{ 0x44, true, 32, "int" },
		{ 0x45, true, 32, "unsigned int" },
		{ 0x46, true, 32, "long" },
		{ 0x47, true, 32, "unsigned long" },
		{ 0x48, true, 32, "float" }, ///< (32-Bit IEEE)
		{ 0x49, true, 64, "double" }, ///< (64-Bit IEEE)
		{ 0x4A, false, 0, "void" },
		{ 0x4B, false, 0, "label" },
		{ 0x4C, true, 4, "<a166 BITWORD>" },
		{ 0x4D, false, 0, "<a166 NEAR>" },
		{ 0x4E, false, 0, "<a166 FAR>" },
		{ 0x4F, true, 3, "<a166 DATA3>" },
		{ 0x50, true, 4, "<a166 DATA4>" },
		{ 0x51, true, 8, "<a166 DATA8>" },
		{ 0x52, true, 16, "<a166 DATA16>" },
		{ 0x53, false, 0, "<a166 INTNO>" },
		{ 0x54, false, 0, "<a166 REGBANK>" }
	};
	const int ft_count = RZ_ARRAY_SIZE(final_types);
	for (ut8 i = 0; i < (ut8)ft_count; i++) {
		OMF_type *newtype = RZ_NEW0(OMF_type);
		if (!newtype) {
			return false;
		}
		newtype->index = final_types[i].index;
		newtype->descr_type = FINAL_TYPE;
		newtype->is_data = final_types[i].is_data;
		newtype->label = rz_str_dup(final_types[i].label);
		newtype->descriptor.final_types.index = final_types[i].index;
		newtype->descriptor.final_types.is_data = final_types[i].is_data;
		newtype->descriptor.final_types.size = final_types[i].size;
		newtype->descriptor.final_types.label = rz_str_dup(final_types[i].label);
		if (!ht_up_insert(obj->ht_types, final_types[i].index, newtype)) {
			eprintf("error insert `%s (0x%x)`\n", final_types[i].label, final_types[i].index);
		}
	}

	new_pv_and_check(obj->sections_vec, free);
	new_pv_and_check(obj->symbols_vec, free);
	new_pv_and_check(obj->blocks_vec, free);
	new_pv_and_check(obj->pe_vec, free);
	new_pv_and_check(obj->lnames_vec, free);
	new_pv_and_check(obj->deplsts_vec, free);
	new_pv_and_check(obj->linnums_vec, omf166_linnums_free);
	new_pv_and_check(obj->coments_vec, free);
	new_pv_and_check(obj->includes_vec, free);
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

static int rz_bin_format_omf166_load_all_records(rz_bin_omf166_obj *obj, const ut8 *buf, const ut64 size) {
	if (!obj) {
		return false;
	}

	ut64 ct = 0;
	OMF_record *new_rec = NULL;

	rz_bin_format_omf166_init_internal_storage(obj);

	while (ct < size) {
		new_rec = rz_bin_format_omf166_load_record(obj, buf + ct, ct, size - ct);
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

void rz_bin_format_omf166_free_all_records(rz_bin_omf166_obj *obj) {
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
	PVEC_FREE(obj->ledatas_vec);
}

rz_bin_omf166_obj *rz_bin_format_omf166_load(const ut8 *buf, ut64 size) {
	rz_bin_omf166_obj *ret = RZ_NEW0(rz_bin_omf166_obj);
	if (!ret) {
		return NULL;
	}

	if (!rz_bin_format_omf166_load_all_records(ret, buf, size)) {
		rz_bin_format_omf166_free_all_records(ret);
		return NULL;
	}
	return ret;
}

void rz_bin_format_omf166_fini(rz_bin_omf166_obj *obj) {
	rz_bin_format_omf166_free_all_records(obj);
	RZ_FREE(obj);
}

bool rz_bin_omf166_get_entry(rz_bin_omf166_obj *obj, RzBinAddr *addr) {
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
