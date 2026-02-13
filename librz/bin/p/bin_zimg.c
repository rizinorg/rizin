// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

typedef struct zimage_arm32_s {
	ut32 arm32_magic; ///< 0x016f2818
	ut32 kernel_start;
	ut32 kernel_end;
	ut32 endianness_flag;
	ut32 magic_table_flag;
	ut32 magic_table;
} zimage_arm32_t;

typedef struct zimage_riscv_s {
	ut64 image_load; ///< base address
	ut64 kernel_size;
	ut64 head_flags; ///< usually 0
	ut16 version_major;
	ut16 version_minor;
	ut32 padding0; ///< should be 0
	ut64 padding1; ///< should be 0
	ut8 riscv_magic1[8]; ///< "RISCV\0\0\0"
	ut8 riscv_magic2[4]; ///< "RSC\x05"
	ut32 pe_header_offset; ///< from offset 0
} zimage_riscv_t;

typedef enum zimage_arch {
	ZIMAGE_ARCH_ARM32_LE = 0,
	ZIMAGE_ARCH_ARM32_BE,
	ZIMAGE_ARCH_RISCV,
} zimage_arch_t;

typedef struct zimage_s {
	zimage_arch_t arch;
	const char *kernel;
	union {
		zimage_arm32_t arm32;
		zimage_riscv_t riscv;
	} info;
} zImage;

typedef bool (*zimage_parser_t)(zImage *image, RzBuffer *buf, ut64 off, bool big_endian);

typedef struct zimage_signature_s {
	const ut8 *bytes;
	size_t size;
	ut64 offset;
} zimage_signature_t;

typedef struct zimage_marker_s {
	const zimage_arch_t arch;
	const bool big_endian;
	const char *kernel;
	const zimage_parser_t parser;
	const zimage_signature_t *signatures;
	const size_t n_signatures;
} zimage_marker_t;

/**
 * Reference: https://github.com/torvalds/linux/blob/05f7e89ab9731565d8a62e3b5d1ec206485eeb0b/arch/riscv/kernel/head.S#L28
 *
 * #ifdef CONFIG_EFI
 * li      s4, -13  // encoding: [0x4d,0x5a] (compat)
 * j       64       // encoding: [0x81,0xa0] (compat)
 * #else
 * j       64       // encoding: [0x81,0xa0] (compat)
 *                  // encoding: [0x6f,0x00,0x00,0x04] (non-compat)
 * .word 0
 * #endif
 * .balign 8
 * #ifdef CONFIG_RISCV_M_MODE
 *     // Image load offset (0MB) from start of RAM for M-mode
 *     .dword 0
 * #else
 * #if __riscv_xlen == 64
 *     // Image load offset(2MB) from start of RAM
 *     .dword 0x200000
 * #else
 *     // Image load offset(4MB) from start of RAM
 *     .dword 0x400000
 * #endif
 * #endif
 *     // Effective size of kernel image
 *     .dword _end - _start
 *     .dword __HEAD_FLAGS           // likely 0
 *     .word RISCV_HEADER_VERSION    // (RISCV_HEADER_VERSION_MAJOR << 16 | RISCV_HEADER_VERSION_MINOR)
 *     .word 0
 *     .dword 0
 *     .ascii RISCV_IMAGE_MAGIC      // "RISCV\0\0\0"
 *     .balign 4
 *     .ascii RISCV_IMAGE_MAGIC2     // "RSC\x05"
 * #ifdef CONFIG_EFI
 *     .word pe_head_start - _start
 * pe_head_start:
 *     __EFI_PE_HEADER               // "MZ"
 * #else
 *     .word 0
 * #endif
 */

#define RISCV_ZIMAGE_MAGIC1_VALUE "RISCV\0\0\0"
#define RISCV_ZIMAGE_MAGIC2_VALUE "RSC\x05"
#define RISCV_ZIMAGE_INFO_OFFSET  0x08
#define RISCV_ZIMAGE_MAGIC_OFFSET 0x30

// clang-format off
const ut8 marker_riscv_efi_compact[4] = { 0x4d, 0x5a, 0x81, 0xa0 };
const ut8 marker_riscv_compact[6] = { 0x81, 0xa0, 0, 0, 0, 0 };
const ut8 marker_riscv_non_compact[8] = { 0x6f, 0x00, 0x00, 0x04, 0, 0, 0, 0 };
const ut8 marker_riscv_magic[12] = { 'R', 'I', 'S', 'C', 'V', 0, 0, 0, 'R', 'S', 'C', 5 };

static const zimage_signature_t zimage_signature_riscv_efi_compact_5_9[] = {
	{ marker_riscv_efi_compact, sizeof (marker_riscv_efi_compact), 0 },
	{ marker_riscv_magic, sizeof (marker_riscv_magic), RISCV_ZIMAGE_MAGIC_OFFSET },
};

static const zimage_signature_t zimage_signature_riscv_compact_5_2[] = {
	{ marker_riscv_compact, sizeof (marker_riscv_compact), 0 },
	{ marker_riscv_magic, sizeof (marker_riscv_magic), RISCV_ZIMAGE_MAGIC_OFFSET },
};

static const zimage_signature_t zimage_signature_riscv_non_compact_5_2[] = {
	{ marker_riscv_non_compact, sizeof (marker_riscv_non_compact), 0 },
	{ marker_riscv_magic, sizeof (marker_riscv_magic), RISCV_ZIMAGE_MAGIC_OFFSET },
};

static const zimage_signature_t zimage_signature_riscv_compact_4_14[] = {
	{ marker_riscv_compact, sizeof (marker_riscv_compact), 0 },
};

static const zimage_signature_t zimage_signature_riscv_non_compact_4_14[] = {
	{ marker_riscv_non_compact, sizeof (marker_riscv_non_compact), 0 },
};
// clang-format on

static bool zimage_parse_riscv(zImage *image, RzBuffer *buf, ut64 off, bool big_endian) {
	zimage_riscv_t *h = &image->info.riscv;
	off += RISCV_ZIMAGE_INFO_OFFSET;
	ut32 riscv_version = 0;

	bool ok = rz_buf_read_ble64_offset(buf, &off, &h->image_load, big_endian) &&
		rz_buf_read_ble64_offset(buf, &off, &h->kernel_size, big_endian) &&
		rz_buf_read_ble64_offset(buf, &off, &h->head_flags, big_endian) &&
		rz_buf_read_ble32_offset(buf, &off, &riscv_version, big_endian) &&
		rz_buf_read_ble32_offset(buf, &off, &h->padding0, big_endian) &&
		rz_buf_read_ble64_offset(buf, &off, &h->padding1, big_endian) &&
		rz_buf_read_offset(buf, &off, h->riscv_magic1, sizeof(h->riscv_magic1)) &&
		rz_buf_read_offset(buf, &off, h->riscv_magic2, sizeof(h->riscv_magic2)) &&
		rz_buf_read_ble32_offset(buf, &off, &h->pe_header_offset, big_endian);

	if (!ok) {
		return false;
	}

	h->version_major = riscv_version >> 16;
	h->version_minor = riscv_version & 0xffff;
	return true;
}

/**
 * Reference: https://github.com/torvalds/linux/blob/05f7e89ab9731565d8a62e3b5d1ec206485eeb0b/arch/arm/boot/compressed/head.S#L188
 *
 *         .rept   7
 *         __nop
 *         .endr
 * #ifndef CONFIG_THUMB2_KERNEL
 *         __nop
 * #else
 *  AR_CLASS(  sub pc, pc, #3  )   @ A/R: switch to Thumb2 mode
 *   M_CLASS(  nop.w           )   @ M: already in Thumb2 mode
 *         .thumb
 * #endif
 *
 *  W(b)    1f
 *
 *  .word   _magic_sig      @ Magic numbers to help the loader
 *  .word   _magic_start    @ absolute load/run zImage address
 *  .word   _magic_end      @ zImage end address
 *  .word   0x04030201      @ endianness flag
 *  .word   0x45454545      @ another magic number to indicate
 *  .word   _magic_table    @ additional data table
 *  __EFI_HEADER
 *
 *
 * Additional values.
 *
 * _magic_sig = ZIMAGE_MAGIC(0x016f2818);
 * _magic_start = ZIMAGE_MAGIC(_start);
 * _magic_end = ZIMAGE_MAGIC(_edata);
 * _magic_table = ZIMAGE_MAGIC(_table_start - _start);
 */

#define ARM_ZIMAGE_MAGIC_VALUE        0x016f2818
#define ARM_ZIMAGE_ENDIANNESS_VALUE   0x04030201
#define ARM_ZIMAGE_MAGIC_TABLE_VALUE  0x45454545
#define ARM_ZIMAGE_INFO_OFFSET        0x24
#define ARM_ZIMAGE_ENDIANNESS_OFFSET  0x30
#define ARM_ZIMAGE_MAGIC_TABLE_OFFSET 0x34

// clang-format off
const ut8 marker_arm32_mov_le[8] = { 0x00, 0x00, 0xa0, 0xe1, 0x00, 0x00, 0xa0, 0xe1 };
const ut8 marker_arm32_magic_le[4] = { 0x18, 0x28, 0x6f, 0x01 };
const ut8 marker_arm32_endianness_le[4] = { 1, 2, 3, 4 };
const ut8 marker_arm32_mov_be[8] = { 0xe1, 0xa0, 0x00, 0x00, 0xe1, 0xa0, 0x00, 0x00 };
const ut8 marker_arm32_magic_be[4] = { 0x01, 0x6f, 0x28, 0x18 };
const ut8 marker_arm32_endianness_be[4] = { 4, 3, 2, 1 };
const ut8 marker_arm32_magic_table[4] = { 0x45, 0x45, 0x45, 0x45 };

static const zimage_signature_t zimage_signature_arm32_le_4_14_plus[] = {
	{ marker_arm32_mov_le, sizeof (marker_arm32_mov_le), 0 },
	{ marker_arm32_magic_le, sizeof (marker_arm32_magic_le), ARM_ZIMAGE_INFO_OFFSET },
	{ marker_arm32_endianness_le, sizeof (marker_arm32_endianness_le), ARM_ZIMAGE_ENDIANNESS_OFFSET },
	{ marker_arm32_magic_table, sizeof (marker_arm32_magic_table), ARM_ZIMAGE_MAGIC_TABLE_OFFSET },
};

static const zimage_signature_t zimage_signature_arm32_le_3_16_4_14[] = {
	{ marker_arm32_mov_le, sizeof (marker_arm32_mov_le), 0 },
	{ marker_arm32_magic_le, sizeof (marker_arm32_magic_le), ARM_ZIMAGE_INFO_OFFSET },
	{ marker_arm32_endianness_le, sizeof (marker_arm32_endianness_le), ARM_ZIMAGE_ENDIANNESS_OFFSET },
};

static const zimage_signature_t zimage_signature_arm32_le_pre3_16[] = {
	{ marker_arm32_mov_le, sizeof (marker_arm32_mov_le), 0 },
	{ marker_arm32_magic_le, sizeof (marker_arm32_magic_le), ARM_ZIMAGE_INFO_OFFSET },
};

static const zimage_signature_t zimage_signature_arm32_be_4_14_plus[] = {
	{ marker_arm32_mov_be, sizeof (marker_arm32_mov_be), 0 },
	{ marker_arm32_magic_be, sizeof (marker_arm32_magic_be), ARM_ZIMAGE_INFO_OFFSET },
	{ marker_arm32_endianness_be, sizeof (marker_arm32_endianness_be), ARM_ZIMAGE_ENDIANNESS_OFFSET },
	{ marker_arm32_magic_table, sizeof (marker_arm32_magic_table), ARM_ZIMAGE_MAGIC_TABLE_OFFSET },
};

static const zimage_signature_t zimage_signature_arm32_be_3_16_4_14[] = {
	{ marker_arm32_mov_be, sizeof (marker_arm32_mov_be), 0 },
	{ marker_arm32_magic_be, sizeof (marker_arm32_magic_be), ARM_ZIMAGE_INFO_OFFSET },
	{ marker_arm32_endianness_be, sizeof (marker_arm32_endianness_be), ARM_ZIMAGE_ENDIANNESS_OFFSET },
};

static const zimage_signature_t zimage_signature_arm32_be_pre3_16[] = {
	{ marker_arm32_mov_be, sizeof (marker_arm32_mov_be), 0 },
	{ marker_arm32_magic_be, sizeof (marker_arm32_magic_be), ARM_ZIMAGE_INFO_OFFSET },
};

/*
	if (h->magic_table_flag == ARM_ZIMAGE_MAGIC_TABLE_VALUE) {
		return rz_str_dup("Linux zImage Kernel (4.14 or newer)");
	} else if (zo->endianness_flag == ARM_ZIMAGE_ENDIANNESS_VALUE) {
		return rz_str_dup("Linux zImage Kernel (3.16 - 4.14)");
	}
	return rz_str_dup("Linux zImage Kernel (3.16 or older)");
*/

// clang-format on

static bool zimage_parse_arm32(zImage *image, RzBuffer *buf, ut64 off, bool big_endian) {
	zimage_arm32_t *h = &image->info.arm32;

	off += ARM_ZIMAGE_INFO_OFFSET;
	return rz_buf_read_ble32_offset(buf, &off, &h->arm32_magic, big_endian) &&
		rz_buf_read_ble32_offset(buf, &off, &h->kernel_start, big_endian) &&
		rz_buf_read_ble32_offset(buf, &off, &h->kernel_end, big_endian) &&
		rz_buf_read_ble32_offset(buf, &off, &h->endianness_flag, big_endian) &&
		rz_buf_read_ble32_offset(buf, &off, &h->magic_table_flag, big_endian) &&
		rz_buf_read_ble32_offset(buf, &off, &h->magic_table, big_endian);
}

static const zimage_marker_t zimage_markers[] = {
	// clang-format off
	{ ZIMAGE_ARCH_ARM32_LE, false, "4.14+"    , zimage_parse_arm32, zimage_signature_arm32_le_4_14_plus, RZ_ARRAY_SIZE(zimage_signature_arm32_le_4_14_plus) },
	{ ZIMAGE_ARCH_ARM32_LE, false, "3.16-4.14", zimage_parse_arm32, zimage_signature_arm32_le_3_16_4_14, RZ_ARRAY_SIZE(zimage_signature_arm32_le_3_16_4_14) },
	{ ZIMAGE_ARCH_ARM32_LE, false, "2.6-3.16" , zimage_parse_arm32, zimage_signature_arm32_le_pre3_16, RZ_ARRAY_SIZE(zimage_signature_arm32_le_pre3_16) },
	{ ZIMAGE_ARCH_ARM32_BE,  true, "4.14+"    , zimage_parse_arm32, zimage_signature_arm32_be_4_14_plus, RZ_ARRAY_SIZE(zimage_signature_arm32_be_4_14_plus) },
	{ ZIMAGE_ARCH_ARM32_BE,  true, "3.16-4.14", zimage_parse_arm32, zimage_signature_arm32_be_3_16_4_14, RZ_ARRAY_SIZE(zimage_signature_arm32_be_3_16_4_14) },
	{ ZIMAGE_ARCH_ARM32_BE,  true, "2.6-3.16" , zimage_parse_arm32, zimage_signature_arm32_be_pre3_16, RZ_ARRAY_SIZE(zimage_signature_arm32_be_pre3_16) },
	{ ZIMAGE_ARCH_RISCV   , false, "5.9+"     , zimage_parse_riscv, zimage_signature_riscv_efi_compact_5_9 , RZ_ARRAY_SIZE(zimage_signature_riscv_efi_compact_5_9) },
	{ ZIMAGE_ARCH_RISCV   , false, "5.2+"     , zimage_parse_riscv, zimage_signature_riscv_compact_5_2     , RZ_ARRAY_SIZE(zimage_signature_riscv_compact_5_2) },
	{ ZIMAGE_ARCH_RISCV   , false, "5.2+"     , zimage_parse_riscv, zimage_signature_riscv_non_compact_5_2 , RZ_ARRAY_SIZE(zimage_signature_riscv_non_compact_5_2) },
	{ ZIMAGE_ARCH_RISCV   , false, "4.14-5.2" , zimage_parse_riscv, zimage_signature_riscv_compact_4_14    , RZ_ARRAY_SIZE(zimage_signature_riscv_compact_4_14) },
	{ ZIMAGE_ARCH_RISCV   , false, "4.14-5.2" , zimage_parse_riscv, zimage_signature_riscv_non_compact_4_14, RZ_ARRAY_SIZE(zimage_signature_riscv_non_compact_4_14) },
	// clang-format on
};

static bool zimage_signature_check(RzBuffer *b, const zimage_signature_t *sig) {
	ut8 bytes[16] = { 0 };
	rz_return_val_if_fail(sig->size < sizeof(bytes), false);

	if (!rz_buf_read_at(b, sig->offset, bytes, sig->size)) {
		return false;
	}

	return !memcmp(bytes, sig->bytes, sig->size);
}

static bool zimage_marker_check(RzBuffer *b, const zimage_marker_t *marker) {
	for (size_t i = 0; i < marker->n_signatures; ++i) {
		if (!zimage_signature_check(b, &marker->signatures[i])) {
			return false;
		}
	}
	return true;
}

static bool zimage_check_buffer(RzBuffer *b) {
	for (size_t i = 0; i < RZ_ARRAY_SIZE(zimage_markers); ++i) {
		const zimage_marker_t *marker = &zimage_markers[i];
		if (zimage_marker_check(b, marker)) {
			return true;
		}
	}

	return false;
}

static bool zimage_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	const zimage_marker_t *marker = NULL;
	for (size_t i = 0; i < RZ_ARRAY_SIZE(zimage_markers); ++i) {
		marker = &zimage_markers[i];
		if (zimage_marker_check(b, marker)) {
			break;
		}
		marker = NULL;
	}

	if (!marker) {
		// should never happen.
		return false;
	}

	zImage *image = RZ_NEW0(zImage);
	if (!image || !marker->parser(image, b, 0, marker->big_endian)) {
		free(image);
		return false;
	}

	image->arch = marker->arch;
	image->kernel = marker->kernel;
	obj->bin_obj = image;
	return true;
}

static ut64 zimage_kernel_base_address(const zImage *zo) {
	if (zo->arch == ZIMAGE_ARCH_RISCV) {
		return zo->info.riscv.image_load;
	}
	return 0;
}

static char *zimage_arch(const zImage *zo) {
	switch (zo->arch) {
	case ZIMAGE_ARCH_ARM32_LE:
		return rz_str_dup("arm");
	case ZIMAGE_ARCH_ARM32_BE:
		return rz_str_dup("arm");
	case ZIMAGE_ARCH_RISCV:
		return rz_str_dup("riscv");
	default:
		return rz_str_dup("unknown");
	}
}

static char *zimage_machine(const zImage *zo) {
	switch (zo->arch) {
	case ZIMAGE_ARCH_ARM32_LE:
		return rz_str_dup("ARM32 LE");
	case ZIMAGE_ARCH_ARM32_BE:
		return rz_str_dup("ARM32 BE");
	case ZIMAGE_ARCH_RISCV:
		return rz_str_dup("RISC-V");
	default:
		return rz_str_dup("unknown");
	}
}

static ut32 zimage_riscv_bits(const zImage *zo) {
	const zimage_riscv_t *h = &zo->info.riscv;
	switch (h->image_load) {
	case 0x200000:
		/* _riscv_xlen == 64 */
		return 64;
	case 0x400000:
		/* this could be _riscv_xlen == 128, but nobody supports it. */
		return 32;
	case 0: /* RISCV_M_MODE: no-mmu */
		return 32;
	default:
		// we keep this for any non-standard values.
		return 32;
	}
}

static char *zimage_riscv_cpu(const zImage *zo) {
	const zimage_riscv_t *h = &zo->info.riscv;
	switch (h->image_load) {
	case 0x200000:
		/* _riscv_xlen == 64 */
		return rz_str_dup("rv64");
	case 0x400000:
		/* this could be _riscv_xlen == 128, but nobody supports it. */
		return rz_str_dup("rv32");
	case 0: /* RISCV_M_MODE: no-mmu */
		return rz_str_dup("rv32+c");
	default:
		// we keep this for any non-standard values.
		return rz_str_dup("rv32");
	}
}

static char *zimage_cpu(const zImage *zo) {
	switch (zo->arch) {
	case ZIMAGE_ARCH_ARM32_LE:
		/* fall-thru */
	case ZIMAGE_ARCH_ARM32_BE:
		return rz_str_dup("arm");
	case ZIMAGE_ARCH_RISCV:
		return zimage_riscv_cpu(zo);
	default:
		return NULL;
	}
}

static ut32 zimage_bits(const zImage *zo) {
	switch (zo->arch) {
	case ZIMAGE_ARCH_ARM32_LE:
		/* fall-thru */
	case ZIMAGE_ARCH_ARM32_BE:
		return 32;
	case ZIMAGE_ARCH_RISCV:
		return zimage_riscv_bits(zo);
	default:
		rz_warn_if_reached();
		return 32;
	}
}

static bool zimage_big_endian(const zImage *zo) {
	switch (zo->arch) {
	case ZIMAGE_ARCH_ARM32_BE:
		return true;
	default:
		return false;
	}
}

static char *zimage_detect_kernel(const zImage *zo) {
	if (RZ_STR_ISNOTEMPTY(zo->kernel)) {
		return rz_str_newf("Linux zImage Kernel (%s)", zo->kernel);
	}
	return rz_str_dup("Linux zImage Kernel");
}

static RzBinInfo *zimage_info(RzBinFile *bf) {
	zImage *zo = bf->o->bin_obj;

	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("Linux zImage Kernel");
	ret->has_va = false;
	ret->bclass = zimage_detect_kernel(zo);
	ret->rclass = rz_str_dup("zimg");
	ret->os = rz_str_dup("linux");
	ret->subsystem = rz_str_dup("linux");
	ret->machine = zimage_machine(zo);
	ret->arch = zimage_arch(zo);
	ret->cpu = zimage_cpu(zo);
	ret->lang = "C";
	ret->bits = zimage_bits(zo);
	ret->big_endian = zimage_big_endian(zo);
	ret->dbg_info = 0;

	return ret;
}

static ut64 zimage_baddr(RzBinFile *bf) {
	const zImage *zo = bf->o->bin_obj;
	return zimage_kernel_base_address(zo);
}

static RzBinAddr *zimage_bin_addr(RzBinSpecialSymbol type, ut64 offset, zImage *zo) {
	RzBinAddr *ba = RZ_NEW0(RzBinAddr);
	if (!ba) {
		return NULL;
	}

	ba->type = type;
	ba->paddr = ba->hpaddr = offset;
	ba->vaddr = ba->hvaddr = zimage_kernel_base_address(zo) + offset;
	ba->bits = zimage_bits(zo);
	return ba;
}

static RzPVector /*<RzBinAddr *>*/ *zimage_entries(RzBinFile *bf) {
	zImage *zo = bf->o->bin_obj;

	RzBinAddr *ptr = NULL;

	RzPVector /*<RzBinAddr *>*/ *ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}

	// ipl3 always includes the header, but ipl2 will jump after the ROM header.
	ptr = zimage_bin_addr(RZ_BIN_SPECIAL_SYMBOL_ENTRY, 0, zo);
	if (!ptr) {
		rz_pvector_free(ret);
		return NULL;
	}
	rz_pvector_push(ret, ptr);

	return ret;
}

static void zimage_structure_arm32(zImage *image, RzStructuredData *root) {
	zimage_arm32_t *zo = &image->info.arm32;

	rz_structured_data_map_add_unsigned(root, "arm32_magic", zo->arm32_magic, true);
	rz_structured_data_map_add_unsigned(root, "kernel_start", zo->kernel_start, true);
	rz_structured_data_map_add_unsigned(root, "kernel_end", zo->kernel_end, true);

	if (zo->endianness_flag == ARM_ZIMAGE_ENDIANNESS_VALUE) {
		rz_structured_data_map_add_unsigned(root, "endianness_flag", zo->endianness_flag, true);
	}

	if (zo->magic_table_flag == ARM_ZIMAGE_MAGIC_TABLE_VALUE) {
		rz_structured_data_map_add_unsigned(root, "magic_table_flag", zo->magic_table_flag, true);
		rz_structured_data_map_add_unsigned(root, "magic_table", zo->magic_table, true);
	}
}

static void zimage_structure_riscv(zImage *image, RzStructuredData *root) {
	zimage_riscv_t *zo = &image->info.riscv;

	rz_structured_data_map_add_unsigned(root, "image_load", zo->image_load, true);
	rz_structured_data_map_add_unsigned(root, "kernel_size", zo->kernel_size, true);
	rz_structured_data_map_add_unsigned(root, "head_flags", zo->head_flags, true);

	RzStructuredData *version = rz_structured_data_map_add_map(root, "version");
	if (version) {
		rz_structured_data_map_add_unsigned(version, "major", zo->version_major, false);
		rz_structured_data_map_add_unsigned(version, "minor", zo->version_minor, false);
	}

	rz_structured_data_map_add_unsigned(root, "padding0", zo->padding0, true);
	rz_structured_data_map_add_unsigned(root, "padding1", zo->padding1, true);

	rz_structured_data_map_add_bytes(root, "riscv_magic1", zo->riscv_magic1, sizeof(zo->riscv_magic1), RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	rz_structured_data_map_add_bytes(root, "riscv_magic2", zo->riscv_magic2, sizeof(zo->riscv_magic2), RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);

	if (zo->pe_header_offset) {
		rz_structured_data_map_add_unsigned(root, "pe_header_offset", zo->pe_header_offset, true);
	}
}

static RzStructuredData *zimage_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	zImage *image = bf->o->bin_obj;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *root = rz_structured_data_map_add_map(info, "zImage");
	if (!root) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_string(root, "machine", zimage_machine(image));
	if (RZ_STR_ISNOTEMPTY(image->kernel)) {
		rz_structured_data_map_add_string(root, "kernel", image->kernel);
	}

	switch (image->arch) {
	case ZIMAGE_ARCH_ARM32_LE:
		/* fall-thru */
	case ZIMAGE_ARCH_ARM32_BE:
		zimage_structure_arm32(image, root);
		break;
	case ZIMAGE_ARCH_RISCV:
		zimage_structure_riscv(image, root);
		break;
	default:
		rz_structured_data_free(info);
		return NULL;
	}

	return info;
}

RzBinPlugin rz_bin_plugin_zimg = {
	.name = "zimg",
	.desc = "zImage format binary",
	.license = "LGPL3",
	.author = "deroad",
	.load_buffer = &zimage_load_buffer,
	.check_buffer = &zimage_check_buffer,
	.baddr = &zimage_baddr,
	.info = &zimage_info,
	.entries = &zimage_entries,
	.bin_structure = &zimage_structure
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_zimg,
	.version = RZ_VERSION
};
#endif
