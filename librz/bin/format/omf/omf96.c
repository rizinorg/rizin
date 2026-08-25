// SPDX-FileCopyrightText: 2015 ampotos <mercie_i@epitech.eu>
// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "omf96.h"

bool omf_is_valid_omf96_type(const ut8 type) {
	const ut8 types[] = {
		OMF_THEADR, OMF_LHEADR, OMF_COMMENT, OMF_MODEND, OMF_MODEND32,
		OMF_EXTDEF, OMF_PUBDEF, OMF_PUBDEF32, OMF_LINNUM,
		OMF_LINNUM32, OMF_LNAMES, OMF_LNAMES, OMF_SEGDEF,
		OMF_SEGDEF32, OMF_GRPDEF, OMF_FIXUPP, OMF_FIXUPP32,
		OMF_LEDATA, OMF_LEDATA32, OMF_LIDATA, OMF_LIDATA32,
		OMF_COMDEF, OMF_BAKPAT, OMF_BAKPAT32, OMF_LEXTDEF,
		OMF_LPUBDEF, OMF_LPUBDEF32, OMF_LCOMDEF, OMF_CEXTDEF,
		OMF_COMDAT, OMF_COMDAT32, OMF_LINSYM, OMF_LINSYM32,
		OMF_ALIAS, OMF_NBKPAT, OMF_NBKPAT32, OMF_LLNAMES, OMF_VERNUM,
		OMF_VENDEXT, 0
	};
	for (int ct = 0; types[ct]; ct++) {
		if (type == types[ct]) {
			return true;
		}
	}
	return false;
}

const char *omf96_seg_alignment_desc(const ut8 type) {
	/**
	 *  A 3-bit field that specifies the alignment required when this program segment is placed within a
	 *  logical segment.
	 *
	 * The new values for 32-bit linkers are A=4 and A=5. Double word alignment is expected to be
	 * useful as 32-bit memory paths become more prevalent. Page-align is useful for certain
	 * hardware-defined items (such as page tables) and error avoidance.
	 *
	 * Note: If A=0, the conditional Frame Number and Offset fields are present and
	 * indicate the starting address of the absolute segment. Microsoft LINK ignores the
	 * Offset field.
	 * Conflict: The original Intel 8086 specification included additional segmentalignment
	 * values not supported by Microsoft; alignment 5 now conflicts with the
	 * following Microsoft LINK extensions:
	 * 5 "unnamed absolute portion of memory address space"
	 * 6 "load-time locatable (LTL), paragraph aligned if not part of any group"
	 **/
	switch (type) {
	case 0x00:
		return "Absolute segment.";
	case 0x01:
		return "Relocatable, byte aligned.";
	case 0x02:
		return "Relocatable, word (2-byte, 16-bit) aligned.";
	case 0x03:
		return "Relocatable, paragraph (16-byte) aligned.";
	case 0x04:
		/**
		 * (The original Intel 8086 specification
		 * defines a page to be 256 bytes. The IBM implementation of OMF uses a 4096-byte
		 * or 4K page size).
		 **/
		return "Relocatable, aligned on a page boundary.";
	case 0x05:
		return "Relocatable, aligned on a double word (4-byte) boundary";
	case 0x06:
		return "Not supported.";
	case 0x07:
		return "Not defined.";
	default:
		rz_warn_if_reached();
		return "Unknown";
	}
}

const char *omf96_seg_combination_desc(const ut8 type) {
	/**
	 *  This 3-bit field describes how the linker can combine the segment with other segments.
	 *  Under MS-DOS, segments with the same name and class can be combined in two ways:
	 *  they can be concatenated to form one logical segment, or they can be overlapped.
	 *  In the latter case, they have either the same starting address or the same ending
	 *  address, and they describe a common area in memory. Values for the C field are:
	 *
	 * 0 Private. Do not combine with any other program segment.
	 * 1 Reserved.
	 * 2 Public. Combine by appending at an offset that meets the alignment requirement.
	 * 3 Reserved.
	 * 4 Same as C=2 (public).
	 * 5 Stack. Combine as for C=2. This combine type forces byte alignment.
	 * 6 Common. Combine by overlay using maximum size.
	 * 7 Same as C=2 (public).
	 *
	 * Conflict: The original Intel 8086 specification lists C=1 as Common, not C=6.
	 **/
	switch (type) {
	case 0x00:
		return "Private.";
	case 0x01:
	case 0x03:
		return "Reserved.";
	case 0x02:
	case 0x04:
	case 0x07:
		return "Public.";
	case 0x05:
		return "Stack.";
	case 0x06:
		return "Common.";
	default:
		rz_warn_if_reached();
		return "Unknown";
	}
}

const char *type_desc(const ut8 type) {
	if (type > 0x01 && type < 0x9c) {
		return "Intel reserved";
	}
	switch (type) {
	/**
	 *  Translator; it may name the source language or translator.
	 * We recommend that the translator name and version, plus
	 * the optimization level used for compilation, be recorded
	 * here. Other compiler or assembler options can be
	 * included, although current practice seems to be to place
	 * these under comment class 9D.
	 */
	case 0x00:
		return "Translator";
	/**
	 * Intel copyright. Ignored.
	 **/
	case 0x01:
		return "Intel copyright";
	/**
	 * Intel reserved These values are reserved for Intel products. Values from
	 * 9C through FF are ignored by Intel products.
	 */
	// 2 – 9B
	// case 2 – 9B:
	// 	return "Intel reserved";
	/**
	 * Library specifier—obsolete
	 * Replaced by comment class 9F; contents are identical to 9F.
	 **/
	case 0x81:
		return "Library specifier";
	/**
	 * MS-DOS version—obsolete
	 * The commentary byte string field is a 2 byte string that
	 * specifies the MS-DOS version number. This comment
	 * class is not supported by Microsoft LINK.
	 **/
	case 0x9C:
		return "MS-DOS version";
	/**
	 * Memory model This information is currently generated by the Microsoft C
	 * compiler for use by the XENIX linker; it is ignored by the
	 * MS-DOS and OS/2 versions of Microsoft LINK. The byte
	 * string consists of from one to three ASCII characters and
	 * indicates the following:
	 *	0, 1, 2, or 3 8086, 80186, 80286, or 80386
	 * instructions generated, respectively
	 *	O Optimization performed on code
	 *	s, m, c, l, or h Small, medium, compact, large, or huge model
	 *	A, B, C, D 68000, 68010, 68020, or 68030 instructions generated, respectively
	 **/
	case 0x9D:
		return "Memory model";
	/**
	 * DOSSEG Sets Microsoft LINK's DOSSEG switch. The byte string is
	 * null. This record is included in the startup module in each
	 * language library. It directs the linker to use the
	 * standardized segment ordering, according to the naming
	 * conventions documented with MS-DOS, OS/2, and accompanying language products.
	 **/
	case 0x9E:
		return "DOSSEG";
	/**
	 * Default library search name
	 * The byte string contains a library filename (without a lead
	 * count byte and without an extension), which is searched in
	 * order to resolve external references within the object
	 * module. The default library search can be overridden with
	 * LINK's /NODEFAULTLIBRARYSEARCH switch.
	 **/
	case 0x9F:
		return "Default library search name";
	/**
	 * OMF extensions This class consists of a set of records, identified by
	 * subtype (first byte of commentary string). Values supported by some linkers are:
	 *   01	IMPDEF Import definition record. See the IMPDEF section for a
	 *	complete description.
	 *   02	EXPDEF Export definition record. See the EXPDEF section for a
	 *	complete description.
	 *   03 INCDEF Incremental compilation record. See the INCDEF section
	 *	for a complete description.
	 *   04 Protected memory library
	 *	32-bit linkers only; relevant only to 32-bit dynamic-link
	 *	libraries (DLLs). This comment record is inserted in an
	 *	object module by the compiler when it encounters the
	 *	_loadds construct in the source code for a DLL. The linker
	 *	then sets a flag in the header of the executable file (DLL)
	 *	to indicate that the DLL should be loaded in such a way
	 *	that its shared data is protected from corruption. The
	 *	_loadds keyword tells the compiler to emit modified
	 *	function prolog code, which loads the DS segment
	 *	register. (Normal functions don't need this.)
	 *	When the flag is set in the .EXE header, the loader loads
	 *	the selector of a protected memory area into DS while
	 *	performing run-time fixups (relocations). All other DLLs
	 *	and applications get the regular DGROUP selector, which
	 *	doesn't allow access to the protected memory area set up
	 *	by the operating system.
	 *   05 LNKDIR Microsoft C++ linker directives record. See the LNKDIR
	 *	section for a complete description.
	 *   06	Big-endian The target for this OMF is a big-endian machine, as
	 *	opposed to little-endian. "Big-endian" describes an
	 *	architecture for which the most significant byte of a
	 *	multibyte value has the smallest address. "Little-endian"
	 *	describes an architecture for which the least significant
	 *	byte of a multibyte value has the smallest address.
	 *   07	PRECOMP When the Microsoft symbol and type information for this
	 *	object file is emitted, the directory entry for $$TYPES is to
	 *	be emitted as sstPreComp instead of sstTypes.
	 *   08-FF Reserved.
	 *
	 * Note: The presence of any unrecognized subtype causes the linker to
	 * generate a fatal error.
	 **/
	case 0xA0:
		return "OMF extensions";
	/**
	 * "New OMF" extension
	 *	This comment class is now used solely to indicate the version of the
	 *	symbolic debug information. If this comment class is not present, the
	 *	version of the debug information produced is defined by the linker. For
	 *	example, Microsoft LINK defaults to the oldest format of Microsoft symbol
	 *	and type information.
	 *
	 *	This comment class was previously used to indicate that the obsolete
	 *	method of communal representation through TYPDEF and EXTDEF pairs
	 *	was not used and that COMDEF records were used instead. In current
	 *	linkers, COMDEF records are always enabled, even without this comment
	 *	record present.
	 *
	 *	The byte string is currently empty, but the planned future contents will be a
	 *	version number (8-bit numeric field) followed by an ASCII character string
	 *	indicating the symbol style. Values will be:
	 *		n,'C','V' Microsoft symbol and type style
	 *		n,'D','X' AIX style
	 *		n,'H','L' IBM PM Debugger style
	 *
	 **/
	case 0xA1:
		return "New OMF extensions";
	/**
	 * Link Pass Separator
	 *	This record conveys information to the linker about the organization of the
	 *	file. The value of the first byte of the commentary string specifies the
	 *	comment subtype. Currently, a single subtype is defined:
	 *
	 *	01 Indicates the start of records generated from Pass 2 of the
	 *	linker. Additional bytes may follow, with their number
	 *	determined by the Record Length field, but they will be
	 *	ignored by the linker.
	 *	See the "Order of Records" section for information on which
	 *	records must come before and after this comment.
	 *
	 *	Warning: It is assumed that this comment will not
	 *		be present in a module whose MODEND record
	 *		contains a program starting address.
	 *
	 *	Note: This comment class may become obsolete with the advent of COMDAT records.
	 **/
	case 0xA2:
		return "Link Pass Separator";
	/**
	 * LIBMOD Library module comment record. Ignored by the linker; used only by the
	 *	librarian. See the LIBMOD section for a complete description.
	 **/
	case 0xA3:
		return "LIBMOD Library module comment record";
	/**
	 * EXESTR Executable string. See the EXESTR section for a complete description.
	 **/
	case 0xA4:
		return "EXESTR Executable string";
	/**
	 * INCERR Incremental compilation error. See the INCERR section for a complete description.
	 **/
	case 0xA6:
		return "INCERR Incremental compilation error";
	/**
	 * NOPAD No segment padding. See the NOPAD section for a complete description.
	 **/
	case 0xA7:
		return "NOPAD No segment padding";
	/**
	 * WKEXT Weak Extern record. See the WKEXT section for a complete description.
	 **/
	case 0xA8:
		return "WKEXT Weak Extern record";
	/**
	 * LZEXT Lazy Extern record. See the LZEXT section for a complete description.
	 **/
	case 0xA9:
		return "LZEXT Lazy Extern record";
	/**
	 * Comment For random comment.
	 **/
	case 0xDA:
		return "Comment For random comment";
	/**
	 * Compiler For pragma comment(compiler); version number.
	 **/
	case 0xDB:
		return "Compiler For pragma comment(compiler)";
	/**
	 * Date For pragma comment(date stamp).
	 **/
	case 0xDC:
		return "Date For pragma comment(date stamp)";
	/**
	 * Timestamp For pragma comment(timestamp).
	 **/
	case 0xDD:
		return "Timestamp For pragma comment(timestamp)";
	/**
	 * User For pragma comment(user). Sometimes used for copyright notices.
	 **/
	case 0xDF:
		return "User For pragma comment(user)";
	/**
	 * Dependency file (Borland)
	 *	Used to show the include files that were used to build this .OBJ file.
	 **/
	case 0xE9:
		return "Dependency file (Borland)";
	/**
	 * Command line (Microsoft QuickC)
	 *	Shows the compiler options chosen. May be obsolete. This record is also
	 *	used by Phoenix Technology Ltd. for library comments.
	 **/
	case 0xFF:
		return "Command line (Microsoft QuickC)";
	// C0H-FFH
	default:
		return "C0H-FFH";
		/**
		 * Comment classes within this range that are not otherwise used are
		 *	reserved for user-defined comment classes. In general, the VENDEXT
		 *	record replaces the need for new user-defined comment classes.
		 **/
	}
}

ut8 fixup_location_bits(const ut8 type) {
	switch (type) {
	case 0x00: // Low-order byte (8-bit displacement or low byte of 16-bit offset)
		return RZ_BIN_RELOC_8;
	case 0x01:
	case 0x02:
	case 0x04:
	case 0x05:
		return RZ_BIN_RELOC_16;
	case 0x03:
	case 0x09:
	case 0x0D:
		return RZ_BIN_RELOC_32;
	case 0x06:
	case 0x07:
	case 0x08:
	case 0x0A:
	case 0x0C:
		return 0;
	case 0x0B:
		return RZ_BIN_RELOC_64; ///< 48 bit
	default:
		rz_warn_if_reached();
		return 0;
	}
}

const char *fixup_location_desc(const ut8 type) {
	/**
	 * Location Is a 4-bit field that determines what type of LOCATION is
	 * to be fixed up:
	 *	0 Low-order byte (8-bit displacement or low byte of 16-bit offset).
	 *	1 16-bit offset.
	 *	2 16-bit base—logical segment base (selector).
	 *	3 32-bit Long pointer (16-bit base:16-bit offset).
	 *	4 High-order byte (high byte of 16-bit offset).
	 *		Microsoft LINK and IBM LINK386
	 *		do not support this type.
	 *	5 16-bit loader-resolved offset, treated as Location=1.
	 *		Conflict: The PharLap implementation of OMF uses Location=5
	 *		to indicate a 32-bit offset, where IBM and
	 *		Microsoft use Location=9.
	 *	6 Not defined, reserved.
	 *		Conflict: The PharLap implementation of OMF
	 *		uses Location=6 to indicate a 48-bit pointer
	 *		(16-bit base:32-bit offset), where IBM and
	 *		Microsoft use Location=11.
	 *	7 Not defined, reserved.
	 *	8 Not defined, reserved.
	 *	9 32-bit offset.
	 *	10 Not defined, reserved.
	 *	11 48-bit pointer (16-bit base:32-bit offset).
	 *	12 Not defined, reserved.
	 *	13 32-bit loader-resolved offset, treated as Location=9 by the linker.
	 */
	switch (type) {
	case 0x00:
		return "Low-order byte (8-bit displacement or low byte of 16-bit offset)";
	case 0x01:
		return "16-bit offset";
	case 0x02:
		return "16-bit base—logical segment base (selector)";
	case 0x03:
		return "32-bit Long pointer (16-bit base:16-bit offset)";
	case 0x04:
		return "High-order byte (high byte of 16-bit offset)";
	case 0x05:
		return "16-bit loader-resolved offset, treated as Location=1";
	case 0x09:
		return "32-bit offset";
	case 0x06:
	case 0x07:
	case 0x08:
	case 0x0A:
	case 0x0C:
		return "Not defined, reserved";
	case 0x0B:
		return "48-bit pointer (16-bit base:32-bit offset)";
	case 0x0D:
		return "32-bit loader-resolved offset, treated as Location=9 by the linker";
	default:
		rz_warn_if_reached();
		return "Unknown";
	}
}

#if 0
static void free_lname(OMF_multi_datas *lname) {
	ut32 ct = 0;

	while (ct < lname->nb_elem) {
		RZ_FREE(((char **)lname->elems)[ct]);
		ct++;
	}
	RZ_FREE(lname->elems);
	RZ_FREE(lname);
}
#endif

bool rz_bin_format_omf96_init_internal_storage(RZ_NONNULL void *target_obj) {
	rz_bin_omf96_obj *obj = (rz_bin_omf96_obj *)target_obj;

	new_pv_and_check(obj->groups_vec, free, false);
	new_pv_and_check(obj->sections_vec, free, false);
	new_pv_and_check(obj->extdef_vec, free, false);
	new_pv_and_check(obj->symbols_vec, free, false);
	new_pv_and_check(obj->lnames_vec, free, false);
	new_pv_and_check(obj->pe_vec, free, false);
	new_pv_and_check(obj->relocs_vec, free, false);
	new_pv_and_check(obj->linnums_vec, omf_linnums_free, false);
	new_pv_and_check(obj->coments_vec, free, false);

	return true;
}

ut8 rz_bin_omf96_get_bits(RZ_NONNULL void *target_obj) {
	rz_bin_omf96_obj *obj = (rz_bin_omf96_obj *)target_obj;
	if (!obj) {
		rz_warn_if_reached();
		return 32;
	}
	obj->bits = 32;
	if (!obj->sections_vec || !rz_pvector_len(obj->sections_vec)) {
		return obj->bits; // 32
	}
	// we assume if one segdef define a 32 segment all opcodes are 32bits
	void **it;
	rz_pvector_foreach (obj->sections_vec, it) {
		const OMF1_1_sections *section = (OMF1_1_sections *)*it;

		if (section && !section->seg_p) {
			obj->bits = 16;
			return obj->bits; // 16
		}
	}
	return obj->bits; // 32
}

static bool load_omf_lnames(const rz_bin_omf96_obj *obj, const OMF_record *record, const ut8 *buf, const size_t buf_size) {
	ut32 tmp_size = 0;

	OMF_lnames *lname = NULL;
	if (!(record && buf) || record->size <= 3) {
		return false;
	}

	while (tmp_size < record->size - 1) {
		const int next = buf[3 + tmp_size] + 1;
		if (next < 1)
			break;
		tmp_size += next;
	}
	tmp_size = 0;
	while (tmp_size < record->size - 1) {
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
		if ((tmp_size + 4 + cb) > buf_size) {
			RZ_LOG_ERROR("Invalid Lnames record (bad size)\n");
			RZ_FREE(lname);
			return false;
		}
		rz_mem_copy(lname->name, MAX_NAME_LEN,
			buf + 3 + tmp_size + 1, cb);

		lname->index = (ut16)rz_pvector_len(obj->lnames_vec);
		RZ_LOG_DEBUG("[%02d] lname->name: `%s`, (%d)\n", lname->index, lname->name, cb);

		rz_pvector_push(obj->lnames_vec, lname);
		tmp_size += cb + 1;
	}
	return true;
}

static int load_omf_segdef(rz_bin_omf96_obj *obj, OMF_record *record, const ut8 *buf, RZ_UNUSED const ut64 buf_size) {
	if (record->size < 2) {
		RZ_LOG_ERROR("Invalid Segdef record (bad size)\n");
		return false;
	}

	const size_t len = rz_pvector_len(obj->sections_vec);
	size_t ct = 3;
	OMF1_1_sections *section = RZ_NEW0(OMF1_1_sections);
	if (!section) {
		return false;
	}
	section->index = (ut8)len + 1;
	section->seg_attr = rz_read_le8_offset(buf, &ct);
	section->seg_alignment = (section->seg_attr & 0xE0) >> 5;
	section->seg_combination = (section->seg_attr & 0x1C) >> 2;
	/**
	 * B Big
	 * Used as the high-order bit of the Segment Length field. If this bit is set,
	 * the segment length value must be 0. If the record type is 98H and this bit is set,
	 * the segment is exactly 64K long. If the record type is 99H and this bit is set,
	 * the segment is exactly 2^32 bytes or 4 GB long.
	 **/
	section->seg_b = (section->seg_attr & 0x02) >> 1;
	/**
	 * P This bit corresponds to the bit field for segment descriptors,
	 * known as the B bit for data segments and the D bit for code segments in Intel documentation.
	 * If 0, then the segment is no larger than 64K (if data), and 16-bit addressing
	 * and operands are the default (if code). This is a Use16 segment.
	 * If nonzero, then the segment may be larger than 64K (if data), and 32-bit addressing and
	 * operands are the default (if code). This is a Use32 segment.
	 *
	 * Note: This is the only method for defining Use32 segments in the TIS OMF.
	 **/
	section->seg_p = section->seg_attr & 0x01;

	if (section->seg_alignment == 0) {
		section->frame_number = rz_read_le16_offset(buf, &ct);
		section->offset = rz_read_le8_offset(buf, &ct);
		RZ_LOG_DEBUG("seg_alignment = 0\t frame_number: 0x%04x, offset: 0x%02x\n",
			section->frame_number, section->offset);
	} else {
		RZ_LOG_DEBUG("seg_alignment = %d\n", section->seg_alignment);
	}

	if (record->size == 9) {
		section->seg_length = rz_read_le32_offset(buf, &ct);
		section->seg_b ? section->seg_length = UT32_MAX : section->seg_length;
		section->seg_name_idx = rz_read_le8_offset(buf, &ct);
		section->class_name_idx = rz_read_le8_offset(buf, &ct);
		section->overlay_name_idx = rz_read_le8_offset(buf, &ct);
	} else if (record->size == 7) {
		section->seg_length = rz_read_le16_offset(buf, &ct);
		section->seg_b ? section->seg_length = 64 * 1024 : section->seg_length;
		section->seg_name_idx = rz_read_le8_offset(buf, &ct);
		section->class_name_idx = rz_read_le8_offset(buf, &ct);
		section->overlay_name_idx = rz_read_le8_offset(buf, &ct);
	} else {
		RZ_LOG_ERROR("Invalid Segdef record (bad size)\n");
	}
	section->seg_name_idx -= 1;
	section->class_name_idx -= 1;
	section->overlay_name_idx -= 1;

	const OMF_lnames *lname = (OMF_lnames *)rz_pvector_at(obj->lnames_vec, section->seg_name_idx);
	if (!lname) {
		RZ_LOG_WARN("unknown section segment id: 0x%02x\n", section->seg_name_idx);
		rz_warn_if_reached();
	}
	section->bits = section->seg_p ? 32 : 16;
	rz_pvector_push(obj->sections_vec, section);

	RZ_LOG_DEBUG("\n"
		     "segment alignment: `%s` (%d)\nseg_combination_desc: `%s`\nseg_length: %u\nseg_name_idx: %u\n"
		     " class_name_idx: %u\noverlay_name_idx: %u\nseg_b: %s\nseg_p: %s\nindex: %lu, ret->name_idx: %u (%s), ret->bits: %u, record->type: 0x%02x\n",
		omf96_seg_alignment_desc(section->seg_alignment), section->seg_alignment,
		omf96_seg_combination_desc(section->seg_combination),
		section->seg_length,
		section->seg_name_idx,
		section->class_name_idx,
		section->overlay_name_idx,
		section->seg_b ? "true" : "false",
		section->seg_p ? "true" : "false",
		len,
		section->seg_name_idx, lname->name,
		// ret->size,
		section->bits,
		record->type);

	// tricks to keep the save index when copying content from record
	record->type = OMF_SEGDEF;

	return true;
}

static int load_comment_data(const rz_bin_omf96_obj *obj, const ut8 *buf, const OMF_record *record, ut64 buf_size, const ut64 global_ct) {
	if (!(obj && obj->coments_vec)) {
		return false;
	}
	RZ_LOG_DEBUG("\nImplemented record type: OMF_COMMENT (0x%02x) size: %d [%ld]\t\t",
		record->type, record->size, global_ct);

	OMF_coments *comment = RZ_NEW0(OMF_coments);
	if (!comment) {
		return false;
	}

	size_t ct = 3;
	const ut8 comment_type = rz_read_le8_offset(buf, &ct);
	const ut8 comment_class = rz_read_le8_offset(buf, &ct);

	/**
	 * NP (no purge bit) is set if the comment is to be preserved by
	 * utility programs that manipulate object modules.
	 * This bit can protect an important comment, such as a copyright message, from deletion
	 **/
	comment->nopurge = (comment_type & 0x80) >> 7; // Or (comment_type & 0x80) >> 7;
	comment->is_filename = (comment_type == 0x4b);
	if (comment->is_filename) {
		const size_t n = record->size + 3 - ct;
		comment->n = n <= MAX_NAME_LEN ? (ut8)n : MAX_NAME_LEN;
		rz_mem_copy(comment->text, MAX_NAME_LEN, buf + ct, comment->n);
		rz_pvector_push(obj->coments_vec, comment);
		return true;
	}

	/**
	 * NL (no list bit) is set if the comment is not to be displayed by
	 * utility programs that list the contents of object modules.
	 * This bit can hide a comment.
	 **/
	RZ_UNUSED const bool NL = (comment_type & 0x40) >> 6;
	if (record->size - 3 == 0) {
		return true;
	}

	if (comment_class == 0xe9) {
		if (record->size > ct + 4) {
			const ut32 tm = rz_read_le32_offset(buf, &ct);

			char buffer[80];
			const time_t raw_time = (time_t)tm;
			const struct tm *time_info = localtime(&raw_time); // Convert to local time structure
			strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", time_info);

			char name[MAX_NAME_LEN] = { 0 };
			const ut8 n = rz_read_le8_offset(buf, &ct);
			if (ct + n + 1 > buf_size) {
				RZ_LOG_ERROR("Invalid record (overflow)\n");
				return true;
			}
			rz_mem_copy(name, MAX_NAME_LEN, buf + ct, n);
			RZ_LOG_DEBUG("\t\t[ %s ] %u name: `%s` size: %d\n", buffer, tm, name, n);
			rz_pvector_push(obj->coments_vec, comment);
			return true;
		}
		RZ_FREE(comment);
		return true;
	}
	if (comment_class == 0x9b) {
		const ut32 tm = rz_read_le32_offset(buf, &ct);

		char buffer[80];
		const time_t raw_time = (time_t)tm;
		const struct tm *time_info = localtime(&raw_time); // Convert to local time structure
		strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", time_info);

		RZ_UNUSED char name[MAX_NAME_LEN] = { 0 };
		const ut8 unknown = rz_read_le8_offset(buf, &ct);
		if (ct + unknown + 1 > buf_size) {
			RZ_LOG_ERROR("Invalid record (overflow)\n");
			return true;
		}
		RZ_LOG_DEBUG("\t\t[ %s ] %u name: `%s` unknown: 0x%02x\n", buffer, tm, name, unknown);
		RZ_LOG_DEBUG("Subtype: DOS-Extension: Time/Date Stamp\n");
		rz_pvector_push(obj->coments_vec, comment);
		return true;
	}
	RZ_LOG_DEBUG("0x%02x   0x%02x 0x%02x   ", buf[0], buf[1], buf[2]);
	RZ_LOG_DEBUG("nopurge: %s, NL: %s, comment_type: 0x%02x, comment_class: 0x%02x `%s` ct: %lu\n",
		comment->nopurge ? "true" : "false", NL ? "true" : "false", comment_type, comment_class, type_desc(comment_class), ct);

	RZ_FREE(comment);
	return true;
}

static int load_linnum_data(const rz_bin_omf96_obj *obj, const ut8 *buf, const size_t buf_size, const OMF_record *record) {
	OMF_linnums *linnum = NULL;
	size_t ct = 3;

	const ut16 GroupIndex = omf_get_idx_offset(buf, buf_size, &ct); // ct = 3
	const ut16 SectionIndex = omf_get_idx_offset(buf, buf_size, &ct); // ct = 4
	ut16 FrameNumber = 0x00;
	if (!GroupIndex && !SectionIndex) {
		FrameNumber = rz_read_le16_offset(buf, &ct);
	}
	(void)FrameNumber;

	while (ct < record->size) {
		linnum = RZ_NEW0(OMF_linnums);
		if (!linnum) {
			return false;
		}
		linnum->LineNumber = rz_read_le16_offset(buf, &ct); // start with ct = 5
		const ut16 offset = rz_read_le16_offset(buf, &ct);
		linnum->address = SEGMENT_OFFSET((SectionIndex - 1), offset); // TODO: Check FN
		const OMF_coments *comment = rz_pvector_tail(obj->coments_vec);
		if (!comment) {
			RZ_FREE(linnum);
			return false;
		}
		rz_pvector_push(obj->linnums_vec, linnum);
		RZ_LOG_DEBUG("GroupIndex: 0x%02x, SectionIndex: 0x%02x, FrameNumber: 0x%02x, Linnum LineNumber: %d. 0x%06lx, `%s` \n",
			GroupIndex,
			SectionIndex,
			FrameNumber,
			linnum->LineNumber,
			linnum->address,
			linnum->filename);
	}
	return true;
}

static bool is_extdef(const rz_bin_omf96_obj *obj, const char *name) {
	if (!(obj && obj->extdef_vec)) {
		return false;
	}

	void **it;
	rz_pvector_foreach (obj->extdef_vec, it) {
		const OMF_extdef *extdef = (OMF_extdef *)*it;
		if (RZ_STR_EQ(extdef->name, name)) {
			return true;
		}
	}
	return false;
}

OMF_symbol *find_sym_by_address(const rz_bin_omf96_obj *obj, const ut64 address) {
	if (!(obj && obj->symbols_vec)) {
		return NULL;
	}

	void **it;
	rz_pvector_foreach (obj->symbols_vec, it) {
		OMF_symbol *sym = (OMF_symbol *)*it;
		const ut64 vaddr = rz_bin_omf_get_vaddr_sym(obj, sym);
		if (vaddr == address) {
			return sym;
		}
	}
	return NULL;
}

static int load_omf_pubdef(const rz_bin_omf96_obj *obj, OMF_record *record, const ut8 *buf, const ut64 buf_size) {
	OMF_symbol *sym = NULL;
	size_t ct = 3;
	ut16 base_grp = 0;
	ut16 seg_idx = 0;

	if (record->size <= 3) {
		return false;
	}
	if (record->type == OMF_PUBDEF || record->type == OMF_PUBDEF32 || record->type == OMF_LPUBDEF || record->type == OMF_LPUBDEF32) {
		base_grp = omf_get_idx_offset(buf, buf_size, &ct);
		if (record->size < ct - 2) {
			RZ_LOG_ERROR("Invalid Pubdef record (bad size)\n");
			return false;
		}
		seg_idx = omf_get_idx_offset(buf, buf_size, &ct);

		if (!base_grp && !seg_idx) {
			ct += 2;
		}
	}

	if (record->size < ct - 2) {
		RZ_LOG_ERROR("Invalid Pubdef record (bad size)\n");
		return false;
	}
	while (record->size > ct) {
		sym = RZ_NEW0(OMF_symbol);
		if (!sym) {
			return false;
		}
		sym->rec_type = record->type;
		sym->seg_idx = seg_idx;
		sym->base = base_grp;
		sym->n = rz_read_le8_offset(buf, &ct);
		if (ct + sym->n + 1 > buf_size) {
			RZ_LOG_ERROR("Invalid sym record (overflow)\n");
			RZ_FREE(sym);
			continue;
		}
		rz_mem_copy(sym->name2, MAX_NAME_LEN, buf + ct, sym->n);

		ct += sym->n;
		if (record->type == OMF_PUBDEF || record->type == OMF_PUBDEF32 || record->type == OMF_LPUBDEF || record->type == OMF_LPUBDEF32) {
			sym->offset = rz_read_le16_offset(buf, &ct);
		}
		sym->ti = omf_get_idx_offset(buf, buf_size, &ct);
		RZ_LOG_DEBUG("sym offset: 0x%06x, base_grp: %02x, seg_idx: %02x, name: [%d] `%s` ",
			sym->offset, base_grp, seg_idx, sym->n, sym->name2);
		if (sym->rec_type == OMF_PUBDEF) {
			RZ_LOG_DEBUG("OMF_PUBDEF - Public Names Definition Record 16 bits\n");
		} else if (sym->rec_type == OMF_PUBDEF32) {
			RZ_LOG_DEBUG("OMF_PUBDEF32 - Public Names Definition Record 32 bits\n");
		} else if (sym->rec_type == OMF_LPUBDEF) {
			RZ_LOG_DEBUG("OMF_LPUBDEF - Local Public Names Definition Record 16 bits\n");
		} else if (sym->rec_type == OMF_LPUBDEF32) {
			RZ_LOG_DEBUG("OMF_LPUBDEF32 - Local Public Names Definition Record 32 bits\n");
		}
		sym->is_extdef = is_extdef(obj, sym->name2);
		rz_pvector_push(obj->symbols_vec, sym);
	}
	return true;
}

static int load_omf_data(rz_bin_omf96_obj *obj, const ut8 *buf, ut64 buf_size, OMF_record *record, const ut64 global_ct) {
	size_t ct = 3;
	RZ_LOG_DEBUG("\t\trecord type: OMF_LEDATA(32) (0x%02x) size: %d [%ld]\n",
		record->type, record->size, global_ct);

	if (record->type == OMF_LEDATA && record->size < 4) {
		RZ_LOG_ERROR("Invalid Ledata16 record (bad size)\n");
		return false;
	}

	if (record->type == OMF_LEDATA32 && record->size < 6) {
		RZ_LOG_ERROR("Invalid Ledata32 record (bad size)\n");
		return false;
	}

	if (!(obj && obj->pe_vec)) {
		rz_warn_if_reached();
		return false;
	}
	OMF_pes *pe = RZ_NEW0(OMF_pes);
	if (!pe) {
		return false;
	}

	pe->seg_idx = omf_get_idx_offset(buf, buf_size, &ct);

	if (record->type == OMF_LEDATA32) {
		pe->use32 = true;
		pe->offset = rz_read_le32_offset(buf, &ct);
	} else {
		pe->use32 = false;
		pe->offset = rz_read_le16_offset(buf, &ct);
	}

	pe->psize = record->size - 1 - ((ut32)ct - 3);
	if (pe->psize > 1024) {
		RZ_LOG_DEBUG("pe->psize: %u, record->size: %u, ct: %ld\n", pe->psize, record->size, ct);
		// rz_print_bytes(NULL, buf, record->size + 3, "0x%02x ");
		rz_warn_if_reached();
	}
	pe->size = pe->psize;
	pe->paddr = (ut32)ct + (ut32)global_ct;
	RZ_LOG_DEBUG("OMF_LEDATA\t%s\tseg_idx: %d, offset: 0x%06x, pe->paddr: 0x%06x [%u] (%u) global_ct: %ld, ct: %ld\n",
		pe->use32 ? "32" : "16", pe->seg_idx, pe->offset, pe->paddr, pe->paddr, pe->psize, global_ct, ct);
	rz_pvector_push(obj->pe_vec, pe);
	return true;
}

static int load_omf_fixup(rz_bin_omf96_obj *obj, const ut8 *buf, ut64 buf_size, OMF_record *record, const ut64 global_ct) {
	size_t ct = 3;
	while (ct < record->size + 2) {
		const ut8 ff_l = rz_read_le8_offset(buf, &ct);
		/**
		 * If bit 7 contains 1, indicating that this is a fixup field.
		 * else if 0, indicating the start of a thread field.
		 */
		if (ff_l & 0x80) {
			const ut8 ff_h = rz_read_le8_offset(buf, &ct);
			/**
			 * Locat field has an unusual format. Contrary to the
			 * usual byte order in Intel data structures, the most
			 * significant bits of the Locat field are found in the
			 * low-order byte, rather than the high-order byte, as follows:
			 */
			const ut16 locat = (ut16)((ff_l << 8) | ff_h);

			OMF1_1_relocs *relocs = RZ_NEW0(OMF1_1_relocs);
			if (!relocs) {
				return false;
			}
			relocs->mode = (locat & 0x4000) >> 14;
			relocs->location = (locat & 0x3C00) >> 10;
			relocs->locat = locat;

			relocs->data_record_offset = locat & 0x3FF;

			relocs->fix_data = rz_read_le8_offset(buf, &ct);

			// bool has_target = !(relocs->fix_data & 0x08); // Bit 3: T
			relocs->F = (relocs->fix_data & 0x80) >> 7;
			if (relocs->F) {
				/**
				 * If F=1, the FRAME is given by a FRAME thread whose
				 * number is in the Frame field (modulo 4).
				 * There is no Frame Datum field in the subrecord.
				 */
				relocs->Frame = ((relocs->fix_data & 0x70) >> 4) % 4;
			} else {
				/**
				 * If F=0, the FRAME method (in the range F0 to F5)
				 * is explicitly defined in this FIXUP subrecord.
				 * The method is stored in the Frame field.
				 */
				relocs->Frame = (relocs->fix_data & 0x70) >> 4;
				// bool has_frame = !(relocs->fix_data & 0x80);  // Bit 7: F
				if (relocs->Frame > 5) {
					RZ_LOG_ERROR("Frame not in the range F0 to F5\n");
				}
				if (relocs->Frame <= 2) {
					/**
					 * The Frame Datum field is present and is an
					 * index field for FRAME methods F0, F1, and F2 only.
					 */
					relocs->Frame_Datum = rz_read_le8_offset(buf, &ct);
				} else {
					relocs->Frame_Datum = 0xff;
				}
			}

			// if (relocs->Frame >= 0 && relocs->Frame < 3) {
			// 	relocs->Frame_Datum = rz_read_le8_offset(buf, &ct);
			// }
			relocs->T = (relocs->fix_data & 0x08) >> 3;
			if (relocs->T) {
				/**
				 * If T=1, the TARGET is defined by a TARGET thread whose thread
				 * number is given in the 2-bit Targt field. The Targt field
				 * contains a number between 0 and 3 that refers to a previous
				 * THREAD subrecord containing the TARGET method. The P bit,
				 * combined with the two loworder bits of the Method field in
				 * the THREAD subrecord, determines the TARGET method.
				 */
				relocs->Targt = relocs->fix_data & 0x03;
				relocs->Target_Datum = 0xff;
			} else {
				/**
				 * If T=0, the TARGET is specified explicitly in this FIXUP subrecord.
				 * In this case, the P bit and the Targt field can be considered
				 * a 3-bit field analogous to the Frame field.
				 */
				relocs->Targt = relocs->fix_data & 0x07;
				// if (relocs->Targt > 5) {
				// 	RZ_LOG_ERROR("Targt not in the range F0 to F5\n");
				// }
				// if (relocs->Targt <= 2) {
				/**
				 * The Frame Datum field is present and is an
				 * index field for FRAME methods F0, F1, and F2 only.
				 */
				relocs->Target_Datum = rz_read_le8_offset(buf, &ct);
				// } else {
				// 	relocs->Target_Datum = 0xff;
				// }
				// if ()
				// relocs->Target_Datum = rz_read_le8_offset(buf, &ct);
			}
			relocs->P = (relocs->fix_data & 0x04) >> 2;

			// 0 (F0 / T0)	SEGDEF	Конкретный OMF-сегмент (по индексу)
			// 1 (F1 / T1)	GRPDEF	Вся OMF-группа (например, DGROUP)
			// 2 (F2 / T2)	EXTDEF	Внешний символ (по индексу во внешней таблице)
			// 4 (F4 / T4)	FRAME = TARGET	База берется равной цели (самый частый случай!)
			// 5 (F5 / T5)	LOCATION	База берется из сегмента, где лежит сама инструкция

			// RzBinReloc

			/**
			 * The Target Displacement field, a 16-bit or 32-bit field, is present only
			 * if the P bit in the Fix Data field is set to 0, in which case the Target
			 * Displacement field contains the offset used in methods 0, 1, and 2
			 * of specifying a TARGET.
			 */
			if (!relocs->P) {
				relocs->targdisp = rz_read_le16_offset(buf, &ct);
			} else {
				relocs->targdisp = 0xff;
			}

			relocs->ledata_index = (ut8)rz_pvector_len(obj->pe_vec);
			const OMF_pes *last_pe = (OMF_pes *)rz_pvector_tail(obj->pe_vec);
			relocs->ledata_seg_index = (ut8)last_pe->seg_idx;
			RZ_LOG_DEBUG("\t\t FIXUP le_idx: %d, le_seg_idx: %d, locat: 0x%04x `%32s` "
				     "DRO: [0x%06x] fix_data: 0x%02x "
				     "F: %d, Frame: %d, T: %d, P: %d, Targt: 0x%02x, targdisp: 0x%02x, "
				     "Frame_Datum: 0x%02x, Target_Datum: 0x%02x, location: (%d) `%s`\n",
				relocs->ledata_index, relocs->ledata_seg_index,
				locat,
				relocs->mode ? "M=1 for segment-relative fixups" : "M=0 for self-relative fixups",
				relocs->data_record_offset, relocs->fix_data,
				relocs->F,
				relocs->Frame,
				relocs->T,
				relocs->P,
				relocs->Targt, relocs->P ? 0 : relocs->targdisp,
				relocs->Frame_Datum,
				relocs->Target_Datum,
				relocs->location, fixup_location_desc(relocs->location));
			rz_pvector_push(obj->relocs_vec, relocs);
		} else {
			/**
			 * The D field (bit 6) indicates whether the thread field specifies
			 * a FRAME or a TARGET.
			 * The D bit is set to 1 to indicate a FRAME or to 0 to indicate a TARGET.
			 */
			const bool D = (ff_l & 0x40) >> 6;
			/**
			 * Bit 5 of the thread data byte is not used. It should always be set to 0.
			 */

			/**
			 * Bits 4 through 2 represent the method field.
			 * If D = 1, the method field contains 0, 1, 2, 4, or 5.
			 * Each of these numbers corresponds to one method of specifying a FRAME
			 *
			 * If D = 0, the method field contains 0, 1, 2, 4, 5, or 6,
			 * each of which corresponds to one of the methods of specifying
			 * a TARGET (see Table 19-3).
			 * In the case of a TARGET address, only bits 3 and 2 of the method
			 * field are used. When = 0, the high-order bit of the value in the
			 * method field is derived from the P bit in the fix dat field of
			 * any subsequent fixup field that refers to this thread field.
			 * Thus, if D = 0, bit 4 of the method field is also 0, and the
			 * only meaningful values for the method field are 0, 1 and 2.
			 */
			const ut8 Method = (ff_l & 0x1C) >> 2;
			/**
			 * The thread number field (bits 1 and 0) contains a number
			 * between 0 and 3. This number is used in subsequent fixup
			 * or thread fields to refer to this particular thread field.
			 *
			 * The thread number is implicitly associated with the D field
			 * by the linker, so as many as eight different thread fields
			 * (four FRAMEs and four TARGETs) can be referenced at any time.
			 * A thread number can be reused in an object module and, if
			 * it is, always refers to the thread field in which it last appeared.
			 */
			const ut8 Thred = ff_l & 0x03;
			ut32 idx = 0;
			if (D) { // ? "FRAME" : "TARGET"
				if (Method <= 3) {
					idx = rz_read_le8_offset(buf, &ct);
				}
			} else {
				idx = rz_read_le8_offset(buf, &ct);
			}
			printf("\t\t THREAD ct: %3lu 0x%04x `%s` %s%d %d, idx: 0x%02x\n",
				ct,
				ff_l,
				D ? "FRAME" : "TARGET",
				D ? "F" : "T", Method,
				Thred,
				idx);
		}
	}
	return true;
}

static int load_omf_lextdef(rz_bin_omf96_obj *obj, const ut8 *buf, ut64 buf_size, OMF_record *record, const ut64 global_ct) {
	size_t ct = 3;
	RZ_LOG_DEBUG("Implemented record type: OMF_EXTDEF (0x%02x) size: %d [%ld]\n",
		record->type, record->size, global_ct);

	while (ct < record->size + 2) {
		// External Type Checksum
		// B5  Length
		OMF_extdef *sym = RZ_NEW0(OMF_extdef);
		if (!sym) {
			return false;
		}
		sym->n = rz_read_le8_offset(buf, &ct);
		if (ct + sym->n + 1 > buf_size) {
			RZ_LOG_ERROR("Invalid record (overflow)\n");
			RZ_FREE(sym);
			return true;
		}
		rz_mem_copy(sym->name, MAX_NAME_LEN, buf + ct, sym->n);
		ct += sym->n;
		sym->type_index = rz_read_le8_offset(buf, &ct);
		sym->record_type = record->type;
		RZ_LOG_DEBUG("\t\t (%d) type_index: [0x%02x] %s\n", sym->n, sym->type_index, sym->name);
		rz_pvector_push(obj->extdef_vec, sym);
	}
	return true;
}

RZ_UNUSED static ut64 align_to_paragraph(const ut64 addr) {
	return (addr + 0xF) & ~0xF;
}

bool rz_bin_format_omf96_load_omf_content(RZ_NONNULL void *target_obj, OMF_record *record, const ut8 *buf, const ut64 global_ct, const size_t buf_size) {
	rz_bin_omf96_obj *obj = (rz_bin_omf96_obj *)target_obj;
	switch (record->type) {
	case OMF_LNAMES:
		RZ_LOG_DEBUG("\t\trecord type: OMF_LNAMES (0x%02x) size: %d [%ld]\n",
			record->type, record->size, global_ct);
		return load_omf_lnames(obj, record, buf, buf_size);
	case OMF_SEGDEF:
	case OMF_SEGDEF32:
		RZ_LOG_DEBUG("\t\trecord type: OMF_SEGDEF(32) (0x%02x) size: %d [%ld]\n",
			record->type, record->size, global_ct);
		return load_omf_segdef(obj, record, buf, buf_size);
	case OMF_PUBDEF:
	case OMF_PUBDEF32:
	case OMF_LPUBDEF:
	case OMF_LPUBDEF32:
		RZ_LOG_DEBUG("\t\trecord type: OMF_(L)PUBDEF(32) (0x%02x) size: %d [%ld]\n",
			record->type, record->size, global_ct);
		return load_omf_pubdef(obj, record, buf, buf_size);
	case OMF_LEXTDEF:
		return true;
	case OMF_EXTDEF:
		return load_omf_lextdef(obj, buf, buf_size, record, global_ct);
	case OMF_LEDATA:
	case OMF_LEDATA32:
		return load_omf_data(obj, buf, buf_size, record, global_ct);
	case OMF_THEADR:
		RZ_LOG_DEBUG("Implemented record type: OMF_THEADR (0x%02x) size: %d [%ld]\n",
			record->type, record->size, global_ct);
		size_t ct = 3;
		const ut8 n = rz_read_le8_offset(buf, &ct);
		if (ct + n + 1 > buf_size) {
			RZ_LOG_ERROR("Invalid record (overflow)\n");
			return true;
		}
		rz_mem_copy(obj->source_filename, MAX_NAME_LEN, buf + ct, n);
		RZ_LOG_DEBUG("\t\tobj->source_filename: `%s` size: %d\n", obj->source_filename, n);
		return true;
	case OMF_COMMENT:
		return load_comment_data(obj, buf, record, buf_size, global_ct);
	case OMF_GRPDEF: {
		size_t ct = 3;

		OMF_group *group = RZ_NEW0(OMF_group);
		if (!group) {
			return false;
		}
		group->index = rz_read_le8_offset(buf, &ct);
		if (group->index == 0) {
			RZ_LOG_ERROR("Invalid group_idx (must be > 0)\n");
			return false;
		}
		const OMF_lnames *lname = (OMF_lnames *)rz_pvector_at(obj->lnames_vec, group->index - 1);
		if (!lname) {
			printf("unknown group->index: 0x%02x\n", group->index - 1);
			rz_warn_if_reached();
		}
		RZ_LOG_DEBUG("\t 0x%02x: `%s`\n", group->index, lname->name);
		while (ct < record->size + 3) {
			const ut32 ff = rz_read_le8_offset(buf, &ct);
			if (ff != 0xFF) {
				break;
			}
			const ut32 idx = rz_read_le8_offset(buf, &ct);
			group->sections[group->count] = idx;
			const OMF1_1_sections *section = (OMF1_1_sections *)rz_pvector_at(
				obj->sections_vec, group->sections[group->count] - 1);

			const OMF_lnames *lname2 = (OMF_lnames *)rz_pvector_at(
				obj->lnames_vec, section->seg_name_idx);
			if (!lname2) {
				printf("unknown group->sections[group->count]: 0x%02x\n", group->sections[group->count] - 1);
				rz_warn_if_reached();
			}
			group->count++;
			RZ_LOG_DEBUG("\t\t 0x%02x: `%s`\n", idx, lname2->name);
		}
		rz_pvector_push(obj->groups_vec, group);
		return true;
	}
	case OMF_FIXUPP:
		/**
		 * \see [The MS-DOS Encyclopedia Ray Duncan](https://ia601807.us.archive.org/30/items/The_MS-DOS_Encyclopedia_Ray_Duncan/The_MS-DOS_Encyclopedia_Ray_Duncan.pdf)
		 */
		return load_omf_fixup(obj, buf, buf_size, record, global_ct);
	case OMF_FIXUPP32:
		RZ_LOG_DEBUG("Unimplemented record type: OMF_FIXUPP32 (0x%02x) size: %d [%ld]\n",
			record->type, record->size, global_ct);
		// rz_print_bytes(NULL, buf, record->size + 3, "0x%02x ");
		// RZ_LOG_DEBUG("\n");
		return true;
	case OMF_LINNUM:
		RZ_LOG_DEBUG("Implemented record type: OMF_LINNUM (0x%02x) size: %d [%ld]\n",
			record->type, record->size, global_ct);
		return load_linnum_data(obj, buf, buf_size, record);
	case OMF_LINNUM32:
		RZ_LOG_DEBUG("Unimplemented record type: OMF_LINNUM32 (0x%02x) size: %d [%ld]\n",
			record->type, record->size, global_ct);
		return true;
	case OMF_MODEND:
		RZ_LOG_DEBUG("Unimplemented record type: OMF_MODEND (0x%02x) size: %d [%ld]\n",
			record->type, record->size, global_ct);
		return true;
	default:
		RZ_LOG_DEBUG("Unimplemented record type: 0x%02x\n", record->type);
		rz_warn_if_reached();
	}

	// generic loader just copy data from buf to content
	if (!record->size) {
		RZ_LOG_ERROR("Invalid record (size to short)\n");
		return false;
	}
	record->content = RZ_NEWS0(char, record->size);
	if (!record->content) {
		return false;
	}
	((char *)record->content)[record->size - 1] = 0;
	return true;
}

ut64 omf_align_to_bytes(const ut8 seg_alignment) {
	switch (seg_alignment) {
	case 1: return 1; // Byte
	case 2: return 2; // Word
	case 3: return 16; // Paragraph
	case 4: return 256; // Page
	case 5: return 4; // Dword
	default: return 1;
	}
}

static void free_pubdef(OMF_multi_datas *datas) {
	if (!datas) {
		return;
	}
	ut32 nb_symb = 0;
	while (nb_symb < datas->nb_elem) {
		OMF_symbol *symbol = ((OMF_symbol *)datas->elems) + nb_symb;
		RZ_FREE(symbol->name);
		nb_symb++;
	}
	RZ_FREE(datas->elems);
	RZ_FREE(datas);
}

static void free_all_omf_records(rz_bin_omf96_obj *obj) {
	OMF_record_handler *tmp = NULL;
	OMF_record_handler *rec = obj->records;

	while (rec) {
		const ut8 type = ((OMF_record *)rec)->type;
		if (type == OMF_LNAMES) {
			// free_lname((OMF_multi_datas *)((OMF_record *)rec)->content);
		} else if (type == OMF_PUBDEF ||
			type == OMF_PUBDEF32 ||
			type == OMF_LPUBDEF ||
			type == OMF_LPUBDEF32) {
			free_pubdef((OMF_multi_datas *)((OMF_record *)rec)->content);
		} else {
			RZ_FREE(((OMF_record *)rec)->content);
		}
		tmp = rec->next;
		RZ_FREE(rec);
		rec = tmp;
	}
	obj->records = NULL;
}

static void free_all_omf_sections(rz_bin_omf96_obj *obj) {
	ut32 ct = 0;
	while (ct < obj->nb_section) {
		while (obj->sections[ct]->data) {
			OMF_data *data = obj->sections[ct]->data->next;
			RZ_FREE(obj->sections[ct]->data);
			obj->sections[ct]->data = data;
		}
		RZ_FREE(obj->sections[ct]);
		ct++;
	}
	RZ_FREE(obj->sections);
}

static void free_all_omf_names(rz_bin_omf96_obj *obj) {
	ut32 ct = 0;
	while (ct < obj->nb_name) {
		RZ_FREE(obj->names[ct]);
		ct++;
	}
	RZ_FREE(obj->names);
}

void rz_bin_free_all_omf96_obj(RZ_NONNULL void *target_obj) {
	if (!target_obj) {
		return;
	}
	rz_bin_omf96_obj *obj = (rz_bin_omf96_obj *)target_obj;
	if (obj->records) {
		free_all_omf_records(obj);
	}
	if (obj->sections) {
		free_all_omf_sections(obj);
	}
	if (obj->names) {
		free_all_omf_names(obj);
	}

	PVEC_FREE(obj->lnames_vec);
	PVEC_FREE(obj->sections_vec);
	PVEC_FREE(obj->groups_vec);
	PVEC_FREE(obj->symbols_vec);
	PVEC_FREE(obj->extdef_vec);
	PVEC_FREE(obj->pe_vec);
	PVEC_FREE(obj->relocs_vec);
	PVEC_FREE(obj->linnums_vec);
	PVEC_FREE(obj->coments_vec);
	free(obj);
	obj = NULL;
}

ut16 omf96_max_record_size(void) {
	return RECORD_MAX_SIZE;
}

RzBinAddr *rz_bin_omf96_get_entry(RZ_NONNULL const void *target_obj) {
	const rz_bin_omf96_obj *obj = (const rz_bin_omf96_obj *)target_obj;
	if (!obj) {
		return NULL;
	}
	const size_t nb_symbol = rz_pvector_len(obj->symbols_vec);
	if (nb_symbol == 0) {
		return NULL;
	}
	void **it;
	rz_pvector_foreach (obj->symbols_vec, it) {
		const OMF_symbol *omf_sym = (OMF_symbol *)*it;
		if (RZ_STR_NE(omf_sym->name2, "_start")) {
			continue;
		}
		const size_t sec_arr_offset = omf_sym->seg_idx - 1;
		const size_t nb_section = rz_pvector_len(obj->sections_vec);
		if (sec_arr_offset >= nb_section) {
			RZ_LOG_ERROR("Invalid segment index for symbol _start\n");
			return NULL;
		}
		const OMF1_1_sections *section = rz_pvector_at(obj->sections_vec, sec_arr_offset);
		const ut64 section_vaddr = (section->seg_name_idx << 4) + section->offset;
		const ut64 vaddr = section_vaddr + omf_sym->offset + obj->base_addr;
		RzBinAddr *addr = RZ_NEW0(RzBinAddr);
		if (!addr) {
			return NULL;
		}
		addr->paddr = (omf_sym->offset - section->offset) + section->paddr;
		addr->vaddr = vaddr;
		return addr;
	}
	return false;
}

ut64 rz_bin_omf96_get_paddr_sym(RZ_NONNULL const void *target_obj, const ut16 symbol_seg_idx, const ut32 symbol_offset) {
	const rz_bin_omf96_obj *obj = (const rz_bin_omf96_obj *)target_obj;
	if (!obj || !obj->sections_vec) {
		return 0LL;
	}
	const OMF1_1_sections *section = (OMF1_1_sections *)rz_pvector_at(obj->sections_vec, symbol_seg_idx - 1);
	if (!section) {
		return 0LL;
	}
	return symbol_offset - section->paddr;
}

ut64 rz_bin_omf_get_vaddr_sym(const rz_bin_omf96_obj *obj, const OMF_symbol *sym) {
	if (sym->seg_idx == 0) {
		return 0LL;
	}
	if (!obj || !obj->sections_vec) {
		return 0LL;
	}
	// we assume if one segdef define a 32 segment all opcodes are 32bits
	const OMF1_1_sections *section = (OMF1_1_sections *)rz_pvector_at(obj->sections_vec, sym->seg_idx - 1);
	if (!section) {
		RZ_LOG_ERROR("Invalid segment index for symbol %s\n", sym->name);
		return 0;
	}
	return section->vaddr + sym->offset;
}

const char *get_data_type(const ut8 data_type) {
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

static void omf_structure_add_names(RzStructuredData *omf, const rz_bin_omf96_obj *obj) {
	if (!rz_pvector_len(obj->lnames_vec)) {
		return;
	}

	RzStructuredData *names = rz_structured_data_map_add_array(omf, "names");
	if (!names) {
		return;
	}

	void **it;
	rz_pvector_foreach (obj->lnames_vec, it) {
		const OMF_lnames *lname = (OMF_lnames *)*it;
		if (RZ_STR_ISNOTEMPTY(lname->name)) {
			rz_structured_data_array_add_string(names, lname->name);
		}
	}
}

static const char *omf_segment_name(const rz_bin_omf96_obj *obj, const OMF1_1_sections *seg) {
	if (!seg || seg->seg_name_idx == 0 || seg->seg_name_idx > rz_pvector_len(obj->lnames_vec) || !obj->lnames_vec) {
		return NULL;
	}
	const OMF_lnames *lname = rz_pvector_at(obj->lnames_vec, seg->seg_name_idx - 1);
	if (lname) {
		return lname->name;
	}
	return NULL;
}

static void omf_structure_add_symbol(RzStructuredData *symbols, const OMF_symbol *sym, const rz_bin_omf96_obj *obj) {
	RzStructuredData *symbol = rz_structured_data_array_add_map(symbols);
	if (!symbol) {
		return;
	}

	rz_structured_data_map_add_string(symbol, "name", rz_str_get(sym->name2));
	rz_structured_data_map_add_unsigned(symbol, "base", sym->base, false);
	rz_structured_data_map_add_unsigned(symbol, "seg_idx", sym->seg_idx, false);
	rz_structured_data_map_add_unsigned(symbol, "offset", sym->offset, true);

	if (sym->seg_idx > 0 && sym->seg_idx <= rz_pvector_len(obj->lnames_vec) && obj->sections_vec) {
		const OMF1_1_sections *section = rz_pvector_at(obj->sections_vec, sym->seg_idx);
		const char *seg_name = omf_segment_name(obj, section);
		rz_structured_data_map_add_string(symbol, "segment", rz_str_get(seg_name));
	}

	const ut64 paddr = rz_bin_omf96_get_paddr_sym(obj, sym->seg_idx, sym->offset);
	const ut64 vaddr = rz_bin_omf_get_vaddr_sym(obj, sym);
	rz_structured_data_map_add_unsigned(symbol, "paddr", paddr, true);
	rz_structured_data_map_add_unsigned(symbol, "vaddr", vaddr, true);
	rz_structured_data_map_add_unsigned(symbol, "type_index", sym->ti, false);

	if (sym->rec_type == OMF_PUBDEF) {
		rz_structured_data_map_add_string(symbol, "visibility", "public");
		rz_structured_data_map_add_string(symbol, "type", "OMF_PUBDEF - Public Names Definition Record 16 bits");
	} else if (sym->rec_type == OMF_PUBDEF32) {
		rz_structured_data_map_add_string(symbol, "visibility", "public");
		rz_structured_data_map_add_string(symbol, "type", "OMF_PUBDEF32 - Public Names Definition Record 32 bits");
	} else if (sym->rec_type == OMF_LPUBDEF) {
		rz_structured_data_map_add_string(symbol, "visibility", "static");
		rz_structured_data_map_add_string(symbol, "type", "OMF_LPUBDEF - Local Public Names Definition Record 16 bits");
	} else if (sym->rec_type == OMF_LPUBDEF32) {
		rz_structured_data_map_add_string(symbol, "type", "OMF_LPUBDEF32 - Local Public Names Definition Record 32 bits");
	}
	if (sym->is_extdef) {
		rz_structured_data_map_add_boolean(symbol, "extrn", true);
	}
}

static void omf_structure_add_symbols(RzStructuredData *omf, const rz_bin_omf96_obj *obj) {
	if (!obj->symbols_vec || !rz_pvector_len(obj->sections_vec)) {
		return;
	}
	const size_t nb_symbol = rz_pvector_len(obj->symbols_vec);
	if (nb_symbol == 0) {
		return;
	}

	RzStructuredData *symbols = rz_structured_data_map_add_array(omf, "symbols");
	if (!symbols) {
		return;
	}
	void **it;
	rz_pvector_foreach (obj->symbols_vec, it) {
		const OMF_symbol *sym = (OMF_symbol *)*it;
		if (!sym) {
			continue;
		}
		omf_structure_add_symbol(symbols, sym, obj);
	}
}

#define OMF_MAX_DATA_BLOCKS 100

static void omf_structure_add_data_blocks(RzStructuredData *section, OMF_segment *seg) {
	if (!seg->data) {
		return;
	}

	RzStructuredData *data_blocks = rz_structured_data_map_add_array(section, "data_blocks");
	if (!data_blocks) {
		return;
	}

	const OMF_data *data = seg->data;
	ut32 block_count = 0;
	while (data && block_count < OMF_MAX_DATA_BLOCKS) {
		RzStructuredData *block = rz_structured_data_array_add_map(data_blocks);
		if (block) {
			rz_structured_data_map_add_unsigned(block, "paddr", data->paddr, true);
			rz_structured_data_map_add_unsigned(block, "size", data->size, false);
			rz_structured_data_map_add_unsigned(block, "offset", data->offset, true);
		}
		data = data->next;
		block_count++;
	}
	if (block_count >= OMF_MAX_DATA_BLOCKS && data) {
		RZ_LOG_WARN("OMF: Maximum number of data blocks (%d) reached, some blocks may be missing\n", OMF_MAX_DATA_BLOCKS);
	}
}

static void omf_structure_add_section(RzStructuredData *sections, const OMF1_1_sections *seg, const rz_bin_omf96_obj *obj) {
	RzStructuredData *section = rz_structured_data_array_add_map(sections);
	if (!section) {
		return;
	}

	const char *name = omf_segment_name(obj, seg);

	rz_structured_data_map_add_string(section, "name", rz_str_get(name));
	rz_structured_data_map_add_unsigned(section, "name_idx", seg->seg_name_idx, false);
	rz_structured_data_map_add_unsigned(section, "vaddr", seg->vaddr, true);
	rz_structured_data_map_add_unsigned(section, "size", seg->seg_length, false);
	rz_structured_data_map_add_unsigned(section, "bits", seg->bits, false);

	(void)omf_structure_add_data_blocks;
}

RzPVector /*<RzBinSection *>*/ *omf96_sections(RZ_NONNULL const void *target_obj) {
	const rz_bin_omf96_obj *obj = (const rz_bin_omf96_obj *)target_obj;

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}

	if (!obj->sections_vec || !obj->groups_vec) {
		return ret;
	}

	void **it;
	rz_pvector_foreach (obj->sections_vec, it) {
		const OMF1_1_sections *section = (OMF1_1_sections *)*it;

		RzBinSection *new = RZ_NEW0(RzBinSection);
		if (!new) {
			rz_pvector_free(ret);
			return NULL;
		}

		const OMF_lnames *lname = (OMF_lnames *)rz_pvector_at(obj->lnames_vec, section->seg_name_idx);
		if (!lname) {
			printf("unknown section segment id: 0x%02x\n", section->seg_name_idx);
			rz_warn_if_reached();
		}
		const OMF_lnames *c_lname = (OMF_lnames *)rz_pvector_at(obj->lnames_vec, section->class_name_idx);
		if (!c_lname) {
			rz_warn_if_reached();
		}
		const char *name = RZ_STR_ISNOTEMPTY(lname->name) ? lname->name : "UNKNOWN";
		const char *class_name = RZ_STR_ISNOTEMPTY(c_lname->name) ? c_lname->name : "UNKNOWN";
		const char *class_and_name = rz_str_newf("%s_%s", name, class_name);
		RZ_LOG_DEBUG("{%2d} seg_b: %s, seg_p: %s, seg_length: %3d, [%d] c_lname->name: `%s`, [%d] lname->name: `%s` [0x%06x], seg_alignment: %d\n",
			section->index,
			section->seg_b ? "true" : "false",
			section->seg_p ? "32-bit" : "16-bit",
			section->seg_length,
			section->class_name_idx,
			class_name,
			section->seg_name_idx,
			name,
			section->offset,
			section->seg_alignment);
		new->name = rz_str_dup(class_and_name);
		RZ_FREE(class_and_name);
		new->size = section->seg_length;
		new->vsize = section->seg_length;
		new->paddr = section->paddr;
		new->vaddr = section->vaddr;
		new->is_segment = 1;
		new->align = section->seg_alignment;

		if (RZ_STR_EQ(c_lname->name, "CODE")) {
			new->perm = RZ_PERM_RX;
		}
		if (RZ_STR_EQ(c_lname->name, "DATA")) {
			new->perm = RZ_PERM_RW;
		}
		if (RZ_STR_EQ(c_lname->name, "DWARF")) {
			new->perm = RZ_PERM_R;
		}
		if (RZ_STR_EQ(class_name, "UNKNOWN")) {
			new->perm = RZ_PERM_R;
		}
		new->bits = section->seg_p ? 32 : 16;
		new->align = omf_align_to_bytes(section->seg_alignment);
		rz_pvector_push(ret, new);
	}
	return ret;
}

static void omf_structure_add_sections(RzStructuredData *omf, const rz_bin_omf96_obj *obj) {
	if (!obj->sections_vec || rz_pvector_len(obj->sections_vec) == 0) {
		return;
	}

	RzStructuredData *sections = rz_structured_data_map_add_array(omf, "sections");
	if (!sections) {
		return;
	}

	void **it;
	rz_pvector_foreach (obj->sections_vec, it) {
		const OMF1_1_sections *section = (OMF1_1_sections *)*it;
		if (!section) {
			continue;
		}
		omf_structure_add_section(sections, section, obj);
	}
}

RzStructuredData *omf96_structure(RZ_NONNULL const void *target_obj) {
	const rz_bin_omf96_obj *obj = (const rz_bin_omf96_obj *)target_obj;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *omf = rz_structured_data_map_add_map(info, "omf");
	if (!omf) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(omf, "bits", obj->bits, false);
	rz_structured_data_map_add_unsigned(omf, "num_names",
		rz_pvector_len(obj->lnames_vec), false);
	const size_t nb_section = rz_pvector_len(obj->sections_vec);
	rz_structured_data_map_add_unsigned(omf, "num_sections", nb_section, false);
	const size_t nb_symbol = rz_pvector_len(obj->symbols_vec);
	rz_structured_data_map_add_unsigned(omf, "num_symbols", nb_symbol, false);
	omf_structure_add_names(omf, obj);
	omf_structure_add_sections(omf, obj);
	omf_structure_add_symbols(omf, obj);
	return info;
}

bool rz_bin_format_omf96_post_init(RZ_NONNULL const void *target_obj) {
	const rz_bin_omf96_obj *obj = (const rz_bin_omf96_obj *)target_obj;

	void **it;
	ut16 index = 0;
	RZ_UNUSED ut32 ct_offset = 0;
	rz_pvector_sort(obj->pe_vec, (RzPVectorComparator)omf_cmp_pes, NULL);
	rz_pvector_foreach (obj->sections_vec, it) {
		OMF1_1_sections *section = (OMF1_1_sections *)*it;
		if (!section) {
			return false;
		}
		section->seg_length = section->seg_length ? section->seg_length : 1;
		const OMF1_1_sections *prev_section = (OMF1_1_sections *)rz_pvector_at(
			obj->sections_vec, index - 1);
		if (!prev_section) {
			section->vaddr = SEGMENT_OFFSET(section->index, 0x0);
		} else {
			section->vaddr = align_to_paragraph(prev_section->vaddr + (ut64)prev_section->seg_length);
		}
		ct_offset += prev_section->seg_length;

		const OMF_lnames *lname = (OMF_lnames *)rz_pvector_at(obj->lnames_vec, section->seg_name_idx);
		if (!lname) {
			printf("unknown section segment id: 0x%02x\n", section->seg_name_idx);
			rz_warn_if_reached();
		}
		const OMF_lnames *c_lname = (OMF_lnames *)rz_pvector_at(obj->lnames_vec, section->class_name_idx);
		if (!c_lname) {
			printf("unknown section class id: 0x%02x\n", section->class_name_idx);
			rz_warn_if_reached();
		}
		RZ_UNUSED const char *name = RZ_STR_ISNOTEMPTY(lname->name) ? lname->name : "UNKNOWN";
		RZ_UNUSED const char *class_name = RZ_STR_ISNOTEMPTY(c_lname->name) ? c_lname->name : "UNKNOWN";
		RZ_LOG_DEBUG("segment alignment: `%s`\nseg_combination_desc: `%s`\nseg_length: %u\nseg_name_idx: %u (%s)\n"
			     "class_name_idx: %u [%s]\noverlay_name_idx: %u\nseg_b: %s\naddressing mode: %d (seg_p)\n"
			     "section->vaddr: 0x%lx\n"
			     "section->end: 0x%lx\n",
			omf96_seg_alignment_desc(section->seg_alignment),
			omf96_seg_combination_desc(section->seg_combination),
			section->seg_length,
			section->seg_name_idx, name,
			section->class_name_idx, class_name,
			section->overlay_name_idx,
			section->seg_b ? "true" : "false",
			section->seg_p ? 32 : 16,
			section->vaddr,
			section->vaddr + section->seg_length);
		index++;
	}

	const size_t linc = rz_pvector_len(obj->linnums_vec);
	if (linc > 0) {
		RzPVector *v = obj->linnums_vec;
		rz_pvector_sort(v, omf_line_sample_cmp, NULL);
	}
	return true;
}

RzBinInfo *omf96_info(RZ_NONNULL const void *target_obj) {
	const rz_bin_omf96_obj *obj = (const rz_bin_omf96_obj *)target_obj;
	if (!obj) {
		return NULL;
	}

	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->bclass = rz_str_dup("OMF");
	ret->rclass = rz_str_dup("OMF96");
	// the "E" is here to made rva return the same value for 16 bit en 32 bits files
	ret->type = rz_str_dup("E OMF (Relocatable Object Module Format)");
	ret->os = rz_str_dup("any");
	ret->machine = rz_str_dup("i386");
	ret->arch = rz_str_dup("x86");
	ret->big_endian = false;
	ret->has_va = true;
	ret->bits = obj->bits;
	ret->dbg_info = RZ_BIN_DBG_STRIPPED;
	return ret;
}

ut64 omf96_baddr(RZ_NONNULL const void *target_obj) {
	const rz_bin_omf96_obj *obj = (const rz_bin_omf96_obj *)target_obj;
	return obj->base_addr;
}
