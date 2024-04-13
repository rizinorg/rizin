// SPDX-FileCopyrightText: 2012-2020 houndthe <cgkajm@gmail.com>
// SPDX-FileCopyrightText: 2024 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <rz_analysis.h>
#include <rz_bin_dwarf.h>
#include <string.h>

#define Ht_FREE_IMPL(V, T, f) \
	static void Ht##V##_##T##_free(Ht##V##Kv *kv) { \
		if (!kv) \
			return; \
		f(kv->value); \
	}

typedef struct {
	char *c_str;
	ut64 length;
} String;

static void String_free(String *str) {
	if (!str) {
		return;
	}
	free(str->c_str);
	free(str);
}

Ht_FREE_IMPL(UP, String, String_free);

typedef struct dwarf_context_t {
	RzAnalysis *analysis;
	RzBinDwarfCompUnit *unit;
	RzBinDWARF *dw;
	HtUP /*<ut64, String *>*/ *str_escaped;
} DwContext;

static RZ_OWN RzType *type_parse_from_offset_internal(
	RZ_BORROW RZ_IN RZ_NONNULL DwContext *ctx,
	ut64 offset,
	RZ_BORROW RZ_OUT RZ_NULLABLE ut64 *size,
	RZ_BORROW RZ_IN RZ_NONNULL SetU *visited);

static RZ_OWN RzType *type_parse_from_offset(
	RZ_BORROW RZ_IN RZ_NONNULL DwContext *ctx,
	ut64 offset,
	RZ_BORROW RZ_OUT RZ_NULLABLE ut64 *size);

static bool enum_children_parse(
	RZ_BORROW RZ_IN RZ_NONNULL DwContext *ctx,
	RZ_BORROW RZ_IN RZ_NONNULL const RzBinDwarfDie *die,
	RZ_BORROW RZ_OUT RZ_NONNULL RzBaseType *base_type);

static bool struct_union_children_parse(
	RZ_BORROW RZ_IN RZ_NONNULL DwContext *ctx,
	RZ_BORROW RZ_IN RZ_NONNULL const RzBinDwarfDie *die,
	RZ_BORROW RZ_OUT RZ_NONNULL RzBaseType *base_type);

static bool function_from_die(
	RZ_BORROW RZ_IN RZ_NONNULL DwContext *ctx,
	RZ_BORROW RZ_IN RZ_NONNULL const RzBinDwarfDie *die);

static void die_parse(DwContext *ctx, RzBinDwarfDie *die);

/* For some languages linkage name is more informative like C++,
   but for Rust it's rubbish and the normal name is fine */
static bool prefer_linkage_name(DW_LANG lang) {
	switch (lang) {
	case DW_LANG_Rust:
	case DW_LANG_Ada83:
	case DW_LANG_Ada95:
	case DW_LANG_Ada2005:
	case DW_LANG_Ada2012:
		return false;
	default:
		return true;
	}
}

/// DWARF Register Number Mapping
static const char *map_dwarf_register_dummy(ut32 reg_num) {
	switch (reg_num) {
	case 0: return "reg0";
	case 1: return "reg1";
	case 2: return "reg2";
	case 3: return "reg3";
	case 4: return "reg4";
	case 5: return "reg5";
	case 6: return "reg6";
	case 7: return "reg7";
	case 8: return "reg8";
	case 9: return "reg9";
	case 10: return "reg10";
	case 11: return "reg11";
	case 12: return "reg12";
	case 13: return "reg13";
	case 14: return "reg14";
	case 15: return "reg15";
	case 16: return "reg16";
	case 17: return "reg17";
	case 18: return "reg18";
	case 19: return "reg19";
	case 20: return "reg20";
	case 21: return "reg21";
	case 22: return "reg22";
	case 23: return "reg23";
	case 24: return "reg24";
	case 25: return "reg25";
	case 26: return "reg26";
	case 27: return "reg27";
	case 28: return "reg28";
	case 29: return "reg29";
	case 30: return "reg30";
	case 31: return "reg31";
	case 32: return "reg32";
	case 33: return "reg33";
	case 34: return "reg34";
	case 35: return "reg35";
	case 36: return "reg36";
	case 37: return "reg37";
	case 38: return "reg38";
	case 39: return "reg39";
	case 40: return "reg40";
	case 41: return "reg41";
	case 42: return "reg42";
	case 43: return "reg43";
	case 44: return "reg44";
	case 45: return "reg45";
	case 46: return "reg46";
	case 47: return "reg47";
	case 48: return "reg48";
	case 49: return "reg49";
	case 50: return "reg50";
	case 51: return "reg51";
	case 52: return "reg52";
	case 53: return "reg53";
	case 54: return "reg54";
	case 55: return "reg55";
	case 56: return "reg56";
	case 57: return "reg57";
	case 58: return "reg58";
	case 59: return "reg59";
	case 60: return "reg60";
	case 61: return "reg61";
	case 62: return "reg62";
	case 63: return "reg63";
	default:
		rz_warn_if_reached();
		return "unsupported_reg";
	}
}

/**
 * Found in GDB and in the linux kernel perf tools.
 * linux/latest/source/tools/perf/arch/mips/include/dwarf-regs-table.h
 *
 * https://opensource.apple.com/source/gdb/gdb-2831/src/gdb/mips-tdep.c.auto.html
 * check the mips_dwarf_dwarf2_ecoff_reg_to_regnum function.
 */
static const char *map_dwarf_reg_to_mips_reg(ut32 reg_num) {
	switch (reg_num) {
	// General Register
	case 0: return "zero";
	case 1: return "at";
	case 2: return "v0";
	case 3: return "v1";
	case 4: return "a0";
	case 5: return "a1";
	case 6: return "a2";
	case 7: return "a3";
	case 8: return "t0";
	case 9: return "t1";
	case 10: return "t2";
	case 11: return "t3";
	case 12: return "t4";
	case 13: return "t5";
	case 14: return "t6";
	case 15: return "t7";
	case 16: return "s0";
	case 17: return "s1";
	case 18: return "s2";
	case 19: return "s3";
	case 20: return "s4";
	case 21: return "s5";
	case 22: return "s6";
	case 23: return "s7";
	case 24: return "t8";
	case 25: return "t9";
	case 26: return "k0";
	case 27: return "k1";
	case 28: return "gp";
	case 29: return "sp";
	case 30: return "fp";
	case 31: return "ra";
	// Floating Register
	case 32: return "fp0";
	case 33: return "fp1";
	case 34: return "fp2";
	case 35: return "fp3";
	case 36: return "fp4";
	case 37: return "fp5";
	case 38: return "fp6";
	case 39: return "fp7";
	case 40: return "fp8";
	case 41: return "fp9";
	case 42: return "fp10";
	case 43: return "fp11";
	case 44: return "fp12";
	case 45: return "fp13";
	case 46: return "fp14";
	case 47: return "fp15";
	case 48: return "fp16";
	case 49: return "fp17";
	case 50: return "fp18";
	case 51: return "fp19";
	case 52: return "fp20";
	case 53: return "fp21";
	case 54: return "fp22";
	case 55: return "fp23";
	case 56: return "fp24";
	case 57: return "fp25";
	case 58: return "fp26";
	case 59: return "fp27";
	case 60: return "fp28";
	case 61: return "fp29";
	case 62: return "fp30";
	case 63: return "fp31";
	// Special Register
	case 64: return "hi"; // Hi register
	case 65: return "lo"; // Low Register
	default:
		rz_warn_if_reached();
		return "unsupported_reg";
	}
}

/**
 * Found in the linux kernel perf tools.
 * latest/source/tools/perf/arch/sparc/include/dwarf-regs-table.h
 */
static const char *sparc_dwarf_table[] = {
	"g0", "g1", "g2", "g3", "g4", "g5", "g6", "g7",
	"o0", "o1", "o2", "o3", "o4", "o5", "sp", "o7",
	"l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7",
	"i0", "i1", "i2", "i3", "i4", "i5", "fp", "i7",
	"f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
	"f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15",
	"f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23",
	"f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31",
	"f32", "f33", "f34", "f35", "f36", "f37", "f38", "f39",
	"f40", "f41", "f42", "f43", "f44", "f45", "f46", "f47",
	"f48", "f49", "f50", "f51", "f52", "f53", "f54", "f55",
	"f56", "f57", "f58", "f59", "f60", "f61", "f62", "f63"
};

static const char *map_dwarf_reg_to_sparc_reg(ut32 reg_num) {
	if (reg_num < RZ_ARRAY_SIZE(sparc_dwarf_table)) {
		return sparc_dwarf_table[reg_num];
	}
	rz_warn_if_reached();
	return "unsupported_reg";
}

/**
 * Found in the linux kernel perf tools.
 * latest/source/tools/perf/arch/loongarch/include/dwarf-regs-table.h
 */
static const char *loongarch_dwarf_table[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
	"r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
	"r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31"
};

static const char *map_dwarf_reg_to_loongarch_reg(ut32 reg_num) {
	if (reg_num < RZ_ARRAY_SIZE(loongarch_dwarf_table)) {
		return loongarch_dwarf_table[reg_num];
	}
	rz_warn_if_reached();
	return "unsupported_reg";
}

/**
 * Found in the linux kernel perf tools.
 * latest/source/tools/perf/arch/s390/include/dwarf-regs-table.h
 */
static const char *map_dwarf_reg_to_s390_reg(ut32 reg_num) {
	switch (reg_num) {
	// General Register
	case 0: return "r0";
	case 1: return "r1";
	case 2: return "r2";
	case 3: return "r3";
	case 4: return "r4";
	case 5: return "r5";
	case 6: return "r6";
	case 7: return "r7";
	case 8: return "r8";
	case 9: return "r9";
	case 10: return "r10";
	case 11: return "r11";
	case 12: return "r12";
	case 13: return "r13";
	case 14: return "r14";
	case 15: return "r15";
	case 16: return "f0";
	case 17: return "f2";
	case 18: return "f4";
	case 19: return "f6";
	case 20: return "f1";
	case 21: return "f3";
	case 22: return "f5";
	case 23: return "f7";
	case 24: return "f8";
	case 25: return "f10";
	case 26: return "f12";
	case 27: return "f14";
	case 28: return "f9";
	case 29: return "f11";
	case 30: return "f13";
	case 31: return "f15";
	case 32: return "c0";
	case 33: return "c1";
	case 34: return "c2";
	case 35: return "c3";
	case 36: return "c4";
	case 37: return "c5";
	case 38: return "c6";
	case 39: return "c7";
	case 40: return "c8";
	case 41: return "c9";
	case 42: return "c10";
	case 43: return "c11";
	case 44: return "c12";
	case 45: return "c13";
	case 46: return "c14";
	case 47: return "c15";
	case 48: return "a0";
	case 49: return "a1";
	case 50: return "a2";
	case 51: return "a3";
	case 52: return "a4";
	case 53: return "a5";
	case 54: return "a6";
	case 55: return "a7";
	case 56: return "a8";
	case 57: return "a9";
	case 58: return "a10";
	case 59: return "a11";
	case 60: return "a12";
	case 61: return "a13";
	case 62: return "a14";
	case 63: return "a15";
	case 64: return "pswm";
	case 65: return "pswa";
	default:
		rz_warn_if_reached();
		return "unsupported_reg";
	}
}

/**
 * https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-dwarf.adoc
 */
static const char *map_dwarf_reg_to_riscv_reg(ut32 reg_num) {
	switch (reg_num) {
	// Integer Registers
	case 0: return "x0";
	case 1: return "x1";
	case 2: return "x2";
	case 3: return "x3";
	case 4: return "x4";
	case 5: return "x5";
	case 6: return "x6";
	case 7: return "x7";
	case 8: return "x8";
	case 9: return "x9";
	case 10: return "x10";
	case 11: return "x11";
	case 12: return "x12";
	case 13: return "x13";
	case 14: return "x14";
	case 15: return "x15";
	case 16: return "x16";
	case 17: return "x17";
	case 18: return "x18";
	case 19: return "x19";
	case 20: return "x20";
	case 21: return "x21";
	case 22: return "x22";
	case 23: return "x23";
	case 24: return "x24";
	case 25: return "x25";
	case 26: return "x26";
	case 27: return "x27";
	case 28: return "x28";
	case 29: return "x29";
	case 30: return "x30";
	case 31: return "x31";
	// Floating-point Registers
	case 32: return "f0";
	case 33: return "f1";
	case 34: return "f2";
	case 35: return "f3";
	case 36: return "f4";
	case 37: return "f5";
	case 38: return "f6";
	case 39: return "f7";
	case 40: return "f8";
	case 41: return "f9";
	case 42: return "f10";
	case 43: return "f11";
	case 44: return "f12";
	case 45: return "f13";
	case 46: return "f14";
	case 47: return "f15";
	case 48: return "f16";
	case 49: return "f17";
	case 50: return "f18";
	case 51: return "f19";
	case 52: return "f20";
	case 53: return "f21";
	case 54: return "f22";
	case 55: return "f23";
	case 56: return "f24";
	case 57: return "f25";
	case 58: return "f26";
	case 59: return "f27";
	case 60: return "f28";
	case 61: return "f29";
	case 62: return "f30";
	case 63: return "f31";
	// 64 Alternate Frame Return Column
	// 65 - 95 Reserved for future standard extensions
	// 96 - 127 Vector Registers
	case 96: return "v0";
	case 97: return "v1";
	case 98: return "v2";
	case 99: return "v3";
	case 100: return "v4";
	case 101: return "v5";
	case 102: return "v6";
	case 103: return "v7";
	case 104: return "v8";
	case 105: return "v9";
	case 106: return "v10";
	case 107: return "v11";
	case 108: return "v12";
	case 109: return "v13";
	case 110: return "v14";
	case 111: return "v15";
	case 112: return "v16";
	case 113: return "v17";
	case 114: return "v18";
	case 115: return "v19";
	case 116: return "v20";
	case 117: return "v21";
	case 118: return "v22";
	case 119: return "v23";
	case 120: return "v24";
	case 121: return "v25";
	case 122: return "v26";
	case 123: return "v27";
	case 124: return "v28";
	case 125: return "v29";
	case 126: return "v30";
	case 127: return "v31";
	// 128 - 3071 Reserved for future standard extensions
	// 3072 - 4095 Reserved for custom extensions
	// 4096 - 8191 CSRs
	default:
		rz_warn_if_reached();
		return "unsupported_reg";
	}
}

#define KASE(_num, _reg) \
	case _num: return #_reg;

#include <arm/arm_dwarf_regnum_table.h>
#include <hexagon/hexagon_dwarf_reg_num_table.inc>
#include <ppc/ppc_dwarf_regnum_table.h>
#include <v850/v850_dwarf_reg_num_table.h>
#include <rl78/rl78_dwarf_reg.h>
#include <rx/rx_dwarf_regnum_table.h>
#include <sh/sh_dwarf_regnum_table.h>
#include <tricore/tricore_dwarf_regnum_table.h>
#include <x86/x86_dwarf_regnum_table.h>

/**
 * \brief Returns a function that maps a DWARF register number to a register name
 * \param arch The architecture name
 * \param bits The architecture bitness
 * \return The function that maps a DWARF register number to a register name
 */
static DWARF_RegisterMapping dwarf_register_mapping_query(RZ_NONNULL char *arch, int bits) {
	if (RZ_STR_EQ(arch, "x86")) {
		if (bits == 64) {
			return map_dwarf_reg_to_x86_64_reg;
		} else {
			return map_dwarf_reg_to_x86_reg;
		}
	}
	if (RZ_STR_EQ(arch, "ppc")) {
		return map_dwarf_reg_to_ppc_reg;
	}
	if (RZ_STR_EQ(arch, "mips")) {
		return map_dwarf_reg_to_mips_reg;
	}
	if (RZ_STR_EQ(arch, "sh")) {
		return map_dwarf_reg_to_sh_reg;
	}
	if (RZ_STR_EQ(arch, "sparc")) {
		return map_dwarf_reg_to_sparc_reg;
	}
	if (RZ_STR_EQ(arch, "loongarch")) {
		return map_dwarf_reg_to_loongarch_reg;
	}
	if (RZ_STR_EQ(arch, "s390")) {
		return map_dwarf_reg_to_s390_reg;
	}
	if (RZ_STR_EQ(arch, "riscv")) {
		return map_dwarf_reg_to_riscv_reg;
	}
	if (RZ_STR_EQ(arch, "tricore")) {
		return map_dwarf_reg_to_tricore_reg;
	}
	if (RZ_STR_EQ(arch, "arm")) {
		if (bits == 64) {
			return map_dwarf_reg_to_arm64;
		} else if (bits <= 32) {
			return map_dwarf_reg_to_arm32;
		}
	}
	if (RZ_STR_EQ(arch, "hexagon")) {
		return map_dwarf_reg_to_hexagon_reg;
	}
	if (RZ_STR_EQ(arch, "v850e3v5")) {
		return v850e3v5_register_name;
	}
	if (RZ_STR_EQ(arch, "v850e2")) {
		return v850e2_register_name;
	}
	if (RZ_STR_EQ(arch, "v850e")) {
		return v850e_register_name;
	}
	if (RZ_STR_EQ(arch, "v850")) {
		return v850_register_name;
	}
	if (RZ_STR_EQ(arch, "rl78")) {
		return rl78_register_name;
	}
	if (RZ_STR_EQ(arch, "rx")) {
		return map_dwarf_reg_to_rx_reg;
	}
	RZ_LOG_ERROR("No DWARF register mapping function defined for %s %d bits\n", arch, bits);
	return map_dwarf_register_dummy;
}

static void variable_fini(RzAnalysisDwarfVariable *var) {
	rz_bin_dwarf_location_free(var->location);
	RZ_FREE(var->name);
	RZ_FREE(var->link_name);
	rz_type_free(var->type);
	rz_mem_memzero(var, sizeof(RzAnalysisDwarfVariable));
}

static char *at_string_escaped(const RzBinDwarfAttr *attr, DwContext *ctx) {
	if (!attr) {
		return NULL;
	}
	bool found;
	String *str = ht_up_find(ctx->str_escaped, (ut64)attr, &found);
	if (found) {
		return rz_mem_dup(str->c_str, str->length + 1);
	}

	char *c_str = rz_bin_dwarf_attr_string_escaped(attr, ctx->dw, ctx->unit->str_offsets_base);
	if (!c_str) {
		return NULL;
	}
	str = RZ_NEW0(String);
	if (!str) {
		return c_str;
	}
	str->c_str = c_str;
	str->length = strlen(c_str);
	ht_up_insert(ctx->str_escaped, (ut64)attr, str);
	return rz_mem_dup(str->c_str, str->length + 1);
}

static char *anonymous_name(const char *k, ut64 offset) {
	return rz_str_newf("anonymous_%s_0x%" PFMT64x, k, offset);
}

static char *anonymous_type_name(RzBaseTypeKind k, ut64 offset) {
	return anonymous_name(rz_type_base_type_kind_as_string(k), offset);
}

/**
 * \brief Get the DIE name or create unique one from its offset
 * \return char* DIEs name or NULL if error
 */
static char *die_name(const RzBinDwarfDie *die, DwContext *ctx) {
	RzBinDwarfAttr *name_at = rz_bin_dwarf_die_get_attr(die, DW_AT_name);
	if (name_at) {
		return at_string_escaped(name_at, ctx);
	}
	RzBinDwarfAttr *spec_at = rz_bin_dwarf_die_get_attr(die, DW_AT_specification);
	if (!spec_at) {
		return NULL;
	}
	RzBinDwarfDie *spec = ht_up_find(ctx->dw->info->die_by_offset, rz_bin_dwarf_attr_udata(spec_at), NULL);
	if (!spec) {
		return NULL;
	}
	name_at = rz_bin_dwarf_die_get_attr(spec, DW_AT_name);
	if (!name_at) {
		return NULL;
	}
	return at_string_escaped(name_at, ctx);
}

static RzPVector /*<RzBinDwarfDie *>*/ *die_children(const RzBinDwarfDie *die, RzBinDWARF *dw) {
	RzPVector /*<RzBinDwarfDie *>*/ *vec = rz_pvector_new(NULL);
	if (!vec) {
		return NULL;
	}
	RzBinDwarfCompUnit *unit = ht_up_find(dw->info->unit_by_offset, die->unit_offset, NULL);
	if (!unit) {
		goto err;
	}

	for (size_t i = die->index + 1; i < rz_vector_len(&unit->dies); ++i) {
		RzBinDwarfDie *child_die = rz_vector_index_ptr(&unit->dies, i);
		if (child_die->depth >= die->depth + 1) {
			rz_pvector_push(vec, child_die);
		} else if (child_die->depth == die->depth) {
			break;
		}
	}

	return vec;
err:
	rz_pvector_free(vec);
	return NULL;
}

/**
 * \brief Get the DIE size in bits
 * \return ut64 size in bits or 0 if not found
 */
static ut64 die_bits_size(const RzBinDwarfDie *die) {
	RzBinDwarfAttr *attr = rz_bin_dwarf_die_get_attr(die, DW_AT_byte_size);
	if (attr) {
		return rz_bin_dwarf_attr_udata(attr) * CHAR_BIT;
	}

	attr = rz_bin_dwarf_die_get_attr(die, DW_AT_bit_size);
	if (attr) {
		return rz_bin_dwarf_attr_udata(attr);
	}

	return 0;
}

static bool RzBaseType_eq(const RzBaseType *a, const RzBaseType *b) {
	if (a == NULL || b == NULL) {
		return a == NULL && b == NULL;
	}
	return a->kind == b->kind && a->attrs == b->attrs && RZ_STR_EQ(a->name, b->name);
}

#define RzBaseTypeWithMetadata_NEW_CHECKED(x, kind, cu) \
	(x) = rz_type_base_type_with_metadata_new((kind), (cu)); \
	if (!(x)) { \
		goto err; \
	}

static RzBaseTypeWithMetadata *RzBaseType_from_die(DwContext *ctx, const RzBinDwarfDie *die) {
	RzPVector /* <const RzBaseTypeWithMetadata*> */ *btypes_at_die_offset = ht_up_find(ctx->analysis->debug_info->base_types_by_offset, die->offset, NULL);
	if (btypes_at_die_offset) {
		void **it;
		rz_pvector_foreach(btypes_at_die_offset, it) {
			RzBaseTypeWithMetadata *btype_it = *it;
			if (btype_it && RZ_STR_EQ(btype_it->cu_name, ctx->unit->name)) {
				return btype_it;
			}
		}
	}

	RzBaseTypeWithMetadata *btype_with_mdata;

	switch (die->tag) {
	case DW_TAG_union_type:
		RzBaseTypeWithMetadata_NEW_CHECKED(btype_with_mdata, RZ_BASE_TYPE_KIND_UNION, ctx->unit->name);
		if (!struct_union_children_parse(ctx, die, btype_with_mdata)) {
			goto err;
		}
		break;
	case DW_TAG_class_type:
	case DW_TAG_structure_type:
		RzBaseTypeWithMetadata_NEW_CHECKED(btype_with_mdata, RZ_BASE_TYPE_KIND_STRUCT, ctx->unit->name);
		if (!struct_union_children_parse(ctx, die, btype_with_mdata)) {
			goto err;
		}
		break;
	case DW_TAG_unspecified_type:
	case DW_TAG_base_type:
		RzBaseTypeWithMetadata_NEW_CHECKED(btype_with_mdata, RZ_BASE_TYPE_KIND_ATOMIC, ctx->unit->name);
		break;
	case DW_TAG_enumeration_type:
		RzBaseTypeWithMetadata_NEW_CHECKED(btype_with_mdata, RZ_BASE_TYPE_KIND_ENUM, ctx->unit->name);
		if (!enum_children_parse(ctx, die, btype_with_mdata)) {
			goto err;
		}
		break;
	case DW_TAG_typedef:
		RzBaseTypeWithMetadata_NEW_CHECKED(btype_with_mdata, RZ_BASE_TYPE_KIND_TYPEDEF, ctx->unit->name);
		break;
	default:
		return NULL;
	}

	RzBaseType *btype = btype_with_mdata->base_type;

	RzBinDwarfAttr *attr = NULL;
	rz_vector_foreach(&die->attrs, attr) {
		switch (attr->at) {
		case DW_AT_specification: {
			RzBinDwarfDie *decl = ht_up_find(ctx->dw->info->die_by_offset, rz_bin_dwarf_attr_udata(attr), NULL);
			if (!decl) {
				goto err;
			}
			btype->name = die_name(decl, ctx);
			break;
		}
		case DW_AT_name:
			btype->name = at_string_escaped(attr, ctx);
			break;
		case DW_AT_byte_size:
			btype->size = rz_bin_dwarf_attr_udata(attr) * CHAR_BIT;
			break;
		case DW_AT_bit_size:
			btype->size = rz_bin_dwarf_attr_udata(attr);
			break;
		case DW_AT_type:
			btype->type = type_parse_from_offset(ctx, rz_bin_dwarf_attr_udata(attr), &btype->size);
			if (!btype->type) {
				goto err;
			}
			break;
		default: break;
		}
	}

	if (!btype->name) {
		btype->name = anonymous_type_name(btype->kind, die->offset);
	}

	if (!btype->type &&
		(btype->kind == RZ_BASE_TYPE_KIND_TYPEDEF ||
			btype->kind == RZ_BASE_TYPE_KIND_ATOMIC ||
			btype->kind == RZ_BASE_TYPE_KIND_ENUM)) {
		btype->type = rz_type_identifier_of_base_type_str(ctx->analysis->typedb, "void");
	}

	if (btypes_at_die_offset) {
		rz_pvector_push(btypes_at_die_offset, btype_with_mdata);
	} else {
		btypes_at_die_offset = rz_pvector_new(NULL); // NULL ???
		rz_pvector_push(btypes_at_die_offset, btype_with_mdata);
		if (!ht_up_insert(ctx->analysis->debug_info->base_types_by_offset, die->offset, btypes_at_die_offset)) {
			RZ_LOG_WARN("Failed to save base type %s [0x%" PFMT64x "]\n", btype->name, die->offset);
		}
	}

	RzPVector *btypes = ht_pp_find(ctx->analysis->debug_info->base_types_by_name, btype->name, NULL);
	if (!btypes) {
		btypes = rz_pvector_new(NULL);
		ht_pp_insert(ctx->analysis->debug_info->base_types_by_name, btype->name, btypes);
		rz_pvector_push(btypes, btype);
	} else {
		void **it;
		rz_pvector_foreach (btypes, it) {
			RzBaseType *b = *it;
			if (RzBaseType_eq(btype, b)) {
				goto ok;
			}
		}
		rz_pvector_push(btypes, btype);
	}
ok:
	return btype;
err:
	rz_type_base_type_free(btype);
	return NULL;
}

/**
 * \brief Parse and return the count of an array or 0 if not found/not defined
 */
static ut64 array_count_parse(DwContext *ctx, RzBinDwarfDie *die) {
	if (!die->has_children) {
		return 0;
	}
	RzPVector *children = die_children(die, ctx->dw);
	if (!children) {
		return 0;
	}

	void **it;
	rz_pvector_foreach (children, it) {
		RzBinDwarfDie *child_die = *it;
		if (child_die->tag != DW_TAG_subrange_type) {
			continue;
		}
		RzBinDwarfAttr *attr;
		rz_vector_foreach(&child_die->attrs, attr) {
			switch (attr->at) {
			case DW_AT_upper_bound:
			case DW_AT_count:
				rz_pvector_free(children);
				return rz_bin_dwarf_attr_udata(attr) + 1;
			default:
				break;
			}
		}
	}
	rz_pvector_free(children);
	return 0;
}

/**
 * \brief Parse type from a DWARF DIE and write the size to \p size if not NULL
 * \param ctx the context
 * \param die the DIE to parse
 * \param allow_void whether to return a void type instead of NULL if there is no type defined
 * \param size pointer to write the size to or NULL
 * \return return RzType* or NULL if \p type_idx == -1
 */
static RzType *type_parse_from_die_internal(
	DwContext *ctx,
	RzBinDwarfDie *die,
	bool allow_void,
	RZ_NULLABLE ut64 *size,
	RZ_NONNULL SetU *visited) {
	RzBinDwarfAttr *attr = rz_bin_dwarf_die_get_attr(die, DW_AT_type);
	if (!attr) {
		if (!allow_void) {
			return NULL;
		}
		return rz_type_identifier_of_base_type_str(ctx->analysis->typedb, "void");
	}
	return type_parse_from_offset_internal(ctx, rz_bin_dwarf_attr_udata(attr), size, visited);
}

static void RzType_from_base_type(RzType *t, RzBaseType *b) {
	rz_return_if_fail(t && b);
	t->kind = RZ_TYPE_KIND_IDENTIFIER;
	free(t->identifier.name);
	t->identifier.name = rz_str_dup(b->name);
	switch (b->kind) {
	case RZ_BASE_TYPE_KIND_STRUCT:
		t->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_STRUCT;
		break;
	case RZ_BASE_TYPE_KIND_UNION:
		t->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNION;
		break;
	case RZ_BASE_TYPE_KIND_ENUM:
		t->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_ENUM;
		break;
	case RZ_BASE_TYPE_KIND_TYPEDEF:
	case RZ_BASE_TYPE_KIND_ATOMIC:
		t->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;
		break;
	}
}

/**
 * \brief Recursively parses type entry of a certain offset and saves type size into *size
 *
 * \param ctx the context
 * \param offset offset of the type entry
 * \param size ptr to size of a type to fill up (can be NULL if unwanted)
 * \return the parsed RzType or NULL on failure
 */
static RZ_OWN RzType *type_parse_from_offset_internal(
	RZ_BORROW RZ_IN RZ_NONNULL DwContext *ctx,
	ut64 offset,
	RZ_BORROW RZ_OUT RZ_NULLABLE ut64 *size,
	RZ_BORROW RZ_IN RZ_NONNULL SetU *visited) {
	RzType *type = ht_up_find(ctx->analysis->debug_info->type_by_offset, offset, NULL);
	if (type) {
		return rz_type_clone(type);
	}

	if (set_u_contains(visited, offset)) {
		return NULL;
	}
	set_u_add(visited, offset);

	RzBinDwarfDie *die = ht_up_find(ctx->dw->info->die_by_offset, offset, NULL);
	if (!die) {
		return NULL;
	}

	// get size of first type DIE that has size
	if (size && *size == 0) {
		*size = die_bits_size(die);
	}
	switch (die->tag) {
	// this should be recursive search for the type until you find base/user defined type
	case DW_TAG_pointer_type:
	case DW_TAG_reference_type: // C++ references are just pointers to us
	case DW_TAG_rvalue_reference_type:
	case DW_TAG_ptr_to_member_type: {
		RzType *pointee = type_parse_from_die_internal(ctx, die, true, size, visited);
		if (!pointee) {
			goto end;
		}
		type = rz_type_pointer_of_type(ctx->analysis->typedb, pointee, false);
		if (!type) {
			rz_type_free(pointee);
			goto end;
		}
		break;
	}
	// We won't parse them as a complete type, because that will already be done
	// so just a name now
	case DW_TAG_typedef:
	case DW_TAG_base_type:
	case DW_TAG_structure_type:
	case DW_TAG_enumeration_type:
	case DW_TAG_union_type:
	case DW_TAG_class_type:
	case DW_TAG_unspecified_type: {
		type = RZ_NEW0(RzType);
		if (!type) {
			goto end;
		}
		RzPVector /* <RzBaseTypeWithMetadata*> */ *base_types_at_offset = ht_up_find(ctx->analysis->debug_info->base_types_by_offset, offset, NULL);
		if (base_types_at_offset && !rz_pvector_empty(base_types_at_offset)) {
			RzBaseTypeWithMetadata *ref = rz_pvector_head(base_types_at_offset); // TODO: which one to take? (instead of just head)
			RzType_from_base_type(type, ref);
			break;
		}
		RzBaseTypeKind k = -1;
		switch (die->tag) {
		case DW_TAG_base_type:
			k = RZ_BASE_TYPE_KIND_ATOMIC;
			break;
		case DW_TAG_structure_type:
		case DW_TAG_class_type:
			type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_STRUCT;
			k = RZ_BASE_TYPE_KIND_STRUCT;
			break;
		case DW_TAG_union_type:
			type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNION;
			k = RZ_BASE_TYPE_KIND_UNION;
			break;
		case DW_TAG_enumeration_type:
			type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_ENUM;
			k = RZ_BASE_TYPE_KIND_ENUM;
			break;
		case DW_TAG_unspecified_type:
		default:
			type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;
			break;
		}
		type->kind = RZ_TYPE_KIND_IDENTIFIER;
		char *name = die_name(die, ctx);
		type->identifier.name = name ? name
					     : (k != -1 ? anonymous_type_name(k, die->offset)
							: anonymous_name("unspecified", die->offset));
		break;
	}
	case DW_TAG_inlined_subroutine:
	case DW_TAG_subroutine_type: {
		RzCallable *callable = ht_up_find(ctx->analysis->debug_info->callable_by_offset, die->offset, NULL);
		if (!callable) {
			if (!function_from_die(ctx, die)) {
				goto end;
			}
			callable = ht_up_find(ctx->analysis->debug_info->callable_by_offset, die->offset, NULL);
			if (!callable) {
				goto end;
			}
		}
		type = rz_type_callable(callable);
		break;
	}
	case DW_TAG_array_type: {
		RzType *subtype = type_parse_from_die_internal(ctx, die, false, size, visited);
		if (!subtype) {
			goto end;
		}
		ut64 count = array_count_parse(ctx, die);
		type = rz_type_array_of_type(ctx->analysis->typedb, subtype, count);
		if (!type) {
			rz_type_free(subtype);
		}
		break;
	}
	case DW_TAG_const_type: {
		type = type_parse_from_die_internal(ctx, die, true, size, visited);
		if (type) {
			switch (type->kind) {
			case RZ_TYPE_KIND_IDENTIFIER:
				type->identifier.is_const = true;
				break;
			case RZ_TYPE_KIND_POINTER:
				type->pointer.is_const = true;
				break;
			default:
				// const not supported yet for other kinds
				break;
			}
		}
		break;
	}
	case DW_TAG_volatile_type:
	case DW_TAG_restrict_type:
		// TODO: volatile and restrict attributes not supported in RzType
		type = type_parse_from_die_internal(ctx, die, true, size, visited);
		break;
	default:
		break;
	}

	RzType *copy = type ? rz_type_clone(type) : NULL;
	if (copy && ht_up_insert(ctx->analysis->debug_info->type_by_offset, offset, copy)) {
#if RZ_BUILD_DEBUG
		char *tstring = rz_type_as_string(ctx->analysis->typedb, type);
		RZ_LOG_DEBUG("Insert RzType [%s] into type_by_offset\n", tstring);
		free(tstring);
#endif
	} else {
		RZ_LOG_ERROR("Failed to insert RzType [0x%" PFMT64x "] into type_by_offset\n", offset);
		rz_type_free(copy);
	}

end:
	set_u_delete(visited, offset);
	return type;
}

static RZ_OWN RzType *type_parse_from_offset(
	RZ_BORROW RZ_IN RZ_NONNULL DwContext *ctx,
	ut64 offset,
	RZ_BORROW RZ_OUT RZ_NULLABLE ut64 *size) {
	SetU *visited = set_u_new();
	if (!visited) {
		return NULL;
	}
	RzType *type = type_parse_from_offset_internal(ctx, offset, size, visited);
	set_u_free(visited);
	if (!type) {
		RZ_LOG_VERBOSE("DWARF Type failed at 0x%" PFMT64x "\n", offset);
	}
	return type;
}

static inline const char *select_name(const char *demangle_name, const char *link_name, const char *name, DW_LANG lang) {
	return prefer_linkage_name(lang) ? (demangle_name ? demangle_name : (link_name ? link_name : name)) : name;
}

static RzType *type_parse_from_abstract_origin(DwContext *ctx, ut64 offset, char **name_out) {
	RzBinDwarfDie *die = ht_up_find(ctx->dw->info->die_by_offset, offset, NULL);
	if (!die) {
		return NULL;
	}
	ut64 size = 0;
	char *name = NULL;
	char *linkname = NULL;
	RzType *type = NULL;
	const RzBinDwarfAttr *attr;
	rz_vector_foreach(&die->attrs, attr) {
		switch (attr->at) {
		case DW_AT_name:
			name = at_string_escaped(attr, ctx);
			break;
		case DW_AT_linkage_name:
		case DW_AT_MIPS_linkage_name:
			linkname = at_string_escaped(attr, ctx);
			break;
		case DW_AT_type:
			type = type_parse_from_offset(ctx, rz_bin_dwarf_attr_udata(attr), &size);
		default:
			break;
		}
	}
	if (!type) {
		goto beach;
	}
	const char *prefer_name = select_name(NULL, linkname, name, ctx->unit->language);
	if (prefer_name && name_out) {
		*name_out = rz_str_dup(prefer_name);
	}
beach:
	free(name);
	free(linkname);
	return type;
}

/**
 * \brief Parses structured entry into *result RzTypeStructMember
 * https://www.dwarfstd.org/doc/DWARF4.pdf#page=102
 */
static RzTypeStructMember *struct_member_parse(
	DwContext *ctx,
	RzBinDwarfDie *die,
	RzTypeStructMember *result) {
	rz_return_val_if_fail(result, NULL);
	char *name = NULL;
	RzType *type = NULL;
	ut64 offset = 0;
	ut64 size = 0;
	RzBinDwarfAttr *attr = NULL;
	rz_vector_foreach(&die->attrs, attr) {
		switch (attr->at) {
		case DW_AT_name:
			name = at_string_escaped(attr, ctx);
			break;
		case DW_AT_type:
			type = type_parse_from_offset(ctx, rz_bin_dwarf_attr_udata(attr), &size);
			break;
		case DW_AT_data_member_location:
			/*
				2 cases, 1.: If val is integer, it offset in bytes from
				the beginning of containing entity. If containing entity has
				a bit offset, member has that bit offset aswell
				2.: value is a location description
				https://www.dwarfstd.org/doc/DWARF4.pdf#page=39
			*/
			offset = rz_bin_dwarf_attr_udata(attr);
			break;
		// If the size of a data member is not the same as the
		//  size of the type given for the data member
		case DW_AT_byte_size:
			size = rz_bin_dwarf_attr_udata(attr) * CHAR_BIT;
			break;
		case DW_AT_bit_size:
			size = rz_bin_dwarf_attr_udata(attr);
			break;
		case DW_AT_accessibility: // private, public etc.
		case DW_AT_mutable: // flag is it is mutable
		case DW_AT_data_bit_offset:
			/*
				int that specifies the number of bits from beginning
				of containing entity to the beginning of the data member
			*/
		case DW_AT_containing_type:
		default:
			break;
		}
	}

	if (!name) {
		name = anonymous_name("member", die->offset);
	}
	if (!type) {
		RZ_LOG_WARN("DWARF [0x%" PFMT64x "] struct member missing type\n",
			die->offset);
		goto cleanup;
	}
	result->name = name;
	result->type = type;
	result->offset = offset;
	result->size = size;
	return result;

cleanup:
	free(name);
	rz_type_free(type);
	return NULL;
}

/**
 * \brief  Parses a structured entry (structs, classes, unions) into
 *         RzBaseType and saves it using rz_analysis_save_base_type ()
 */
// https://www.dwarfstd.org/doc/DWARF4.pdf#page=102
static bool struct_union_children_parse(
	RZ_BORROW RZ_IN RZ_NONNULL DwContext *ctx,
	RZ_BORROW RZ_IN RZ_NONNULL const RzBinDwarfDie *die,
	RZ_BORROW RZ_OUT RZ_NONNULL RzBaseType *base_type) {
	if (!die->has_children) {
		return true;
	}
	RzPVector *children = die_children(die, ctx->dw);
	if (!children) {
		return false;
	}

	void **it;
	rz_pvector_foreach (children, it) {
		RzBinDwarfDie *child_die = *it;
		// we take only direct descendats of the structure
		if (!(child_die->depth == die->depth + 1 &&
			    child_die->tag == DW_TAG_member)) {
			die_parse(ctx, child_die);
			continue;
		}
		RzTypeStructMember member = { 0 };
		RzTypeStructMember *result = struct_member_parse(ctx, child_die, &member);
		if (!result) {
			goto err;
		}
		void *element = rz_vector_push(&base_type->struct_data.members, &member);
		if (!element) {
			rz_type_free(result->type);
			goto err;
		}
	}
	rz_pvector_free(children);
	return true;
err:
	rz_pvector_free(children);
	return false;
}

/**
 * \brief  Parses enum entry into *result RzTypeEnumCase
 * https://www.dwarfstd.org/doc/DWARF4.pdf#page=110
 */
static RzTypeEnumCase *enumerator_parse(DwContext *ctx, RzBinDwarfDie *die, RzTypeEnumCase *result) {
	RzBinDwarfAttr *val_attr = rz_bin_dwarf_die_get_attr(die, DW_AT_const_value);
	if (!val_attr) {
		return NULL;
	}
	st64 val = rz_bin_dwarf_attr_sdata(val_attr);
	// ?? can be block, sdata, data, string w/e
	// TODO solve the encoding, I don't know in which union member is it store

	result->name = die_name(die, ctx);
	if (!result->name) {
		result->name = anonymous_name("enumerator", die->offset);
	}
	result->val = val;
	return result;
}

static bool enum_children_parse(
	RZ_BORROW RZ_IN RZ_NONNULL DwContext *ctx,
	RZ_BORROW RZ_IN RZ_NONNULL const RzBinDwarfDie *die,
	RZ_BORROW RZ_OUT RZ_NONNULL RzBaseType *base_type) {
	if (!die->has_children) {
		return true;
	}
	RzPVector *children = die_children(die, ctx->dw);
	if (!children) {
		return false;
	}

	void **it;
	rz_pvector_foreach (children, it) {
		RzBinDwarfDie *child_die = *it;
		if (!(child_die->depth == die->depth + 1 &&
			    child_die->tag == DW_TAG_enumerator)) {
			die_parse(ctx, child_die);
			continue;
		}
		RzTypeEnumCase cas = { 0 };
		RzTypeEnumCase *result = enumerator_parse(ctx, child_die, &cas);
		if (!result) {
			goto err;
		}
		void *element = rz_vector_push(&base_type->enum_data.cases, &cas);
		if (!element) {
			rz_type_base_enum_case_free(result, NULL);
			goto err;
		}
	}
	rz_pvector_free(children);
	return true;
err:
	rz_pvector_free(children);
	return false;
}

static void function_apply_specification(DwContext *ctx, const RzBinDwarfDie *die, RzAnalysisDwarfFunction *fn) {
	RzBinDwarfAttr *attr = NULL;
	rz_vector_foreach(&die->attrs, attr) {
		switch (attr->at) {
		case DW_AT_name:
			if (fn->name) {
				break;
			}
			fn->name = at_string_escaped(attr, ctx);
			break;
		case DW_AT_linkage_name:
		case DW_AT_MIPS_linkage_name:
			if (fn->link_name) {
				break;
			}
			fn->link_name = at_string_escaped(attr, ctx);
			break;
		case DW_AT_type: {
			if (fn->ret_type) {
				break;
			}
			ut64 size = 0;
			fn->ret_type = type_parse_from_offset(ctx, rz_bin_dwarf_attr_udata(attr), &size);
			break;
		}
		default:
			break;
		}
	}
}

static void RzBinDwarfBlock_log(DwContext *ctx, const RzBinDwarfBlock *block, ut64 offset, const RzBinDwarfRange *range) {
	RzBinDWARFDumpOption dump_opt = {
		.loclist_indent = "",
		.loclist_sep = ",\t",
		.expr_sep = " "
	};
	char *expr_str = rz_bin_dwarf_expression_to_string(&ctx->unit->hdr.encoding, block, &dump_opt);
	if (RZ_STR_ISNOTEMPTY(expr_str)) {
		if (!range) {
			RZ_LOG_VERBOSE("Location parse failed: 0x%" PFMT64x " [%s]\n", offset, expr_str);
		} else {
			RZ_LOG_VERBOSE("Location parse failed: 0x%" PFMT64x " (0x%" PFMT64x ", 0x%" PFMT64x ") [%s]\n",
				offset, range->begin, range->end, expr_str);
		}
	}
	free(expr_str);
}

static RzBinDwarfLocation *RzBinDwarfLocation_with_kind(RzBinDwarfLocationKind k) {
	RzBinDwarfLocation *location = RZ_NEW0(RzBinDwarfLocation);
	if (!location) {
		return NULL;
	}
	location->kind = k;
	return location;
}

static RzBinDwarfLocation *location_list_parse(
	DwContext *ctx, RzBinDwarfLocList *loclist, const RzBinDwarfDie *fn) {
	RzBinDwarfLocation *location = RzBinDwarfLocation_with_kind(RzBinDwarfLocationKind_LOCLIST);
	if (!location) {
		return NULL;
	}
	if (loclist->has_location) {
		location->loclist = loclist;
		return location;
	}

	void **it;
	rz_pvector_foreach (&loclist->entries, it) {
		RzBinDwarfLocListEntry *entry = *it;
		if (entry->location) {
			continue;
		}
		if (rz_bin_dwarf_block_empty(entry->expression)) {
			entry->location = RzBinDwarfLocation_with_kind(RzBinDwarfLocationKind_EMPTY);
			continue;
		}
		if (!rz_bin_dwarf_block_valid(entry->expression)) {
			entry->location = RzBinDwarfLocation_with_kind(RzBinDwarfLocationKind_DECODE_ERROR);
			continue;
		}
		entry->location = rz_bin_dwarf_location_from_block(entry->expression, ctx->dw, ctx->unit, fn);
		if (!entry->location) {
			RzBinDwarfBlock_log(ctx, entry->expression, loclist->offset, entry->range);
			entry->location = RzBinDwarfLocation_with_kind(RzBinDwarfLocationKind_DECODE_ERROR);
			continue;
		}
	}
	loclist->has_location = true;
	location->loclist = loclist;
	return location;
}

static RzBinDwarfLocation *location_parse(
	DwContext *ctx, const RzBinDwarfDie *die, const RzBinDwarfAttr *attr, const RzBinDwarfDie *fn) {
	/* Loclist offset is usually CONSTANT or REFERENCE at older DWARF versions, new one has LocListPtr for that */
	if (attr->value.kind == RzBinDwarfAttr_Block) {
		return rz_bin_dwarf_location_from_block(rz_bin_dwarf_attr_block(attr), ctx->dw, ctx->unit, fn);
	}

	if (attr->value.kind == RzBinDwarfAttr_LoclistPtr ||
		attr->value.kind == RzBinDwarfAttr_Reference ||
		attr->value.kind == RzBinDwarfAttr_UConstant ||
		attr->value.kind == RzBinDwarfAttr_SecOffset) {
		if (!ctx->dw->loclists) {
			RZ_LOG_VERBOSE("loclists is NULL\n");
			return NULL;
		}
		ut64 offset = rz_bin_dwarf_attr_udata(attr);
		RzBinDwarfLocList *loclist = rz_bin_dwarf_loclists_get(ctx->dw->loclists, ctx->dw->addr, ctx->unit, offset);
		if (!loclist) { /* for some reason offset isn't there, wrong parsing or malformed dwarf */
			goto err_find;
		}
		if (rz_pvector_len(&loclist->entries) > 1) {
			return location_list_parse(ctx, loclist, fn);
		}
		if (rz_pvector_len(&loclist->entries) == 1) {
			RzBinDwarfLocListEntry *entry = rz_pvector_at(&loclist->entries, 0);
			return rz_bin_dwarf_location_from_block(entry->expression, ctx->dw, ctx->unit, fn);
		}
		RzBinDwarfLocation *loc = RZ_NEW0(RzBinDwarfLocation);
		if (!loc) {
			return NULL;
		}
		loc->kind = RzBinDwarfLocationKind_EMPTY;
		loc->encoding = ctx->unit->hdr.encoding;
		return loc;
	err_find:
		RZ_LOG_ERROR("Location parse failed 0x%" PFMT64x " <Cannot find loclist>\n", offset);
		return NULL;
	}
	RZ_LOG_ERROR("Location parse failed 0x%" PFMT64x " <Unsupported form: %s>\n", die->offset, rz_bin_dwarf_form(attr->form))
	return NULL;
}

static bool function_var_parse(
	DwContext *ctx,
	RzAnalysisDwarfFunction *f,
	const RzBinDwarfDie *fn_die,
	RzAnalysisDwarfVariable *v,
	const RzBinDwarfDie *var_die,
	bool *has_unspecified_parameters) {
	v->offset = var_die->offset;
	switch (var_die->tag) {
	case DW_TAG_formal_parameter:
		v->kind = RZ_ANALYSIS_VAR_KIND_FORMAL_PARAMETER;
		break;
	case DW_TAG_variable:
		v->kind = RZ_ANALYSIS_VAR_KIND_VARIABLE;
		break;
	case DW_TAG_unspecified_parameters:
		if (f) {
			f->has_unspecified_parameters = true;
		}
		if (has_unspecified_parameters) {
			*has_unspecified_parameters = true;
		}
		return true;
	default:
		return false;
	}

	bool has_location = false;
	const RzBinDwarfAttr *attr;
	rz_vector_foreach(&var_die->attrs, attr) {
		switch (attr->at) {
		case DW_AT_name:
			v->name = at_string_escaped(attr, ctx);
			break;
		case DW_AT_linkage_name:
		case DW_AT_MIPS_linkage_name:
			v->link_name = at_string_escaped(attr, ctx);
			break;
		case DW_AT_type: {
			RzType *type = type_parse_from_offset(ctx, rz_bin_dwarf_attr_udata(attr), NULL);
			if (type) {
				rz_type_free(v->type);
				v->type = type;
			}
		} break;
		// abstract origin is supposed to have omitted information
		case DW_AT_abstract_origin: {
			RzType *type = type_parse_from_abstract_origin(ctx, rz_bin_dwarf_attr_udata(attr), &v->name);
			if (type) {
				rz_type_free(v->type);
				v->type = type;
			}
		} break;
		case DW_AT_location:
			v->location = location_parse(ctx, var_die, attr, fn_die);
			has_location = true;
			break;
		default:
			break;
		}
	}

	if (!has_location) {
		v->location = RzBinDwarfLocation_with_kind(RzBinDwarfLocationKind_EMPTY);
	} else if (!v->location) {
		v->location = RzBinDwarfLocation_with_kind(RzBinDwarfLocationKind_DECODE_ERROR);
	}

	v->prefer_name = select_name(NULL, v->link_name, v->name, ctx->unit->language);
	if (!v->prefer_name) {
		v->prefer_name = v->name = anonymous_name("var", var_die->offset);
	}
	return true;
}

static bool function_children_parse(
	DwContext *ctx, const RzBinDwarfDie *die, RzCallable *callable, RzAnalysisDwarfFunction *fn) {
	if (!die->has_children) {
		return false;
	}
	RzPVector *children = die_children(die, ctx->dw);
	if (!children) {
		return false;
	}
	void **it;
	rz_pvector_foreach (children, it) {
		RzBinDwarfDie *child_die = *it;
		if (child_die->depth != die->depth + 1) {
			die_parse(ctx, child_die);
			continue;
		}
		RzAnalysisDwarfVariable v = { 0 };
		bool has_unspecified_parameters = false;
		if (!function_var_parse(ctx, fn, die, &v, child_die, &has_unspecified_parameters)) {
			goto loop_end;
		}
		if (has_unspecified_parameters) {
			callable->has_unspecified_parameters = true;
			goto loop_end;
		}
		if (!v.type) {
			RZ_LOG_ERROR("DWARF function %s variable %s failed\n",
				fn->prefer_name, v.prefer_name);
			goto loop_end;
		}
		if (v.kind == RZ_ANALYSIS_VAR_KIND_FORMAL_PARAMETER) {
			RzCallableArg *arg = rz_type_callable_arg_new(
				ctx->analysis->typedb, v.prefer_name, rz_type_clone(v.type));
			rz_type_callable_arg_add(callable, arg);
		}
		rz_vector_push(&fn->variables, &v);
		ht_up_insert(ctx->analysis->debug_info->variable_by_offset, v.offset, &v);
		continue;
	loop_end:
		variable_fini(&v);
	}
	rz_pvector_free(children);
	return true;
}

static void function_free(RzAnalysisDwarfFunction *f) {
	if (!f) {
		return;
	}
	free(f->name);
	free(f->demangle_name);
	free(f->link_name);
	rz_vector_fini(&f->variables);
	rz_type_free(f->ret_type);
	free(f);
}

/**
 * \brief Parse function,it's arguments, variables and
 *        save the information into the Sdb
 */
static bool function_from_die(
	RZ_BORROW RZ_IN RZ_NONNULL DwContext *ctx,
	RZ_BORROW RZ_IN RZ_NONNULL const RzBinDwarfDie *die) {
	if (ht_up_find(ctx->analysis->debug_info->function_by_offset, die->offset, NULL)) {
		return true;
	}

	if (rz_bin_dwarf_die_get_attr(die, DW_AT_declaration)) {
		return true; /* just declaration skip */
	}
	RzAnalysisDwarfFunction *fcn = RZ_NEW0(RzAnalysisDwarfFunction);
	if (!fcn) {
		goto cleanup;
	}
	fcn->offset = die->offset;
	RZ_LOG_DEBUG("DWARF function parsing [0x%" PFMT64x "]\n", die->offset);
	RzBinDwarfAttr *attr;
	rz_vector_foreach(&die->attrs, attr) {
		switch (attr->at) {
		case DW_AT_name:
			fcn->name = at_string_escaped(attr, ctx);
			break;
		case DW_AT_linkage_name:
		case DW_AT_MIPS_linkage_name:
			fcn->link_name = at_string_escaped(attr, ctx);
			break;
		case DW_AT_low_pc:
			fcn->low_pc = rz_bin_dwarf_attr_addr(
				attr, ctx->dw, ctx->unit->hdr.encoding.address_size, ctx->unit->addr_base);
			break;
		case DW_AT_high_pc:
			fcn->high_pc = rz_bin_dwarf_attr_addr(
				attr, ctx->dw, ctx->unit->hdr.encoding.address_size, ctx->unit->addr_base);
			break;
		case DW_AT_entry_pc:
			fcn->entry_pc = rz_bin_dwarf_attr_addr(
				attr, ctx->dw, ctx->unit->hdr.encoding.address_size, ctx->unit->addr_base);
			break;
		case DW_AT_specification: /* u64 to declaration DIE with more info */
		{
			RzBinDwarfDie *spec = ht_up_find(ctx->dw->info->die_by_offset, rz_bin_dwarf_attr_udata(attr), NULL);
			if (!spec) {
				RZ_LOG_ERROR("DWARF cannot find specification DIE at 0x%" PFMT64x " f.offset=0x%" PFMT64x "\n",
					rz_bin_dwarf_attr_udata(attr), die->offset);
				break;
			}
			function_apply_specification(ctx, spec, fcn);
			break;
		}
		case DW_AT_type:
			rz_type_free(fcn->ret_type);
			fcn->ret_type = type_parse_from_offset(ctx, rz_bin_dwarf_attr_udata(attr), NULL);
			break;
		case DW_AT_virtuality:
			fcn->is_method = true; /* method specific attr */
			fcn->is_virtual = true;
			break;
		case DW_AT_object_pointer:
			fcn->is_method = true;
			break;
		case DW_AT_vtable_elem_location:
			fcn->is_method = true;
			fcn->vtable_addr = 0; /* TODO we might use this information */
			break;
		case DW_AT_accessibility:
			fcn->is_method = true;
			fcn->access = (ut8)rz_bin_dwarf_attr_udata(attr);
			break;
		case DW_AT_external:
			fcn->is_external = true;
			break;
		case DW_AT_trampoline:
			fcn->is_trampoline = true;
			break;
		case DW_AT_ranges:
		default:
			break;
		}
	}
	if (fcn->link_name) {
		fcn->demangle_name =
			ctx->analysis->binb.demangle(ctx->analysis->binb.bin,
				rz_bin_dwarf_lang_for_demangle(ctx->unit->language), fcn->link_name);
	}
	fcn->prefer_name = select_name(fcn->demangle_name, fcn->link_name, fcn->name, ctx->unit->language);
	if (!fcn->prefer_name) {
		fcn->prefer_name = fcn->name = anonymous_name("fcn", die->offset);
	}

	RzCallable *callable = rz_type_callable_new(fcn->prefer_name);
	callable->ret = fcn->ret_type ? rz_type_clone(fcn->ret_type) : NULL;
	rz_vector_init(&fcn->variables, sizeof(RzAnalysisDwarfVariable), (RzVectorFree)variable_fini, NULL);
	function_children_parse(ctx, die, callable, fcn);

	RZ_LOG_DEBUG("DWARF function saving %s 0x%" PFMT64x " [0x%" PFMT64x "]\n",
		fcn->prefer_name, fcn->low_pc, die->offset);
	if (!ht_up_update(ctx->analysis->debug_info->callable_by_offset, die->offset, callable)) {
		RZ_LOG_ERROR("DWARF callable saving failed [0x%" PFMT64x "]\n", die->offset);
		goto cleanup;
	}
	if (!ht_up_update(ctx->analysis->debug_info->function_by_offset, die->offset, fcn)) {
		RZ_LOG_ERROR("DWARF function saving failed [0x%" PFMT64x "]\n", fcn->low_pc);
		goto cleanup;
	}
	if (fcn->low_pc > 0) {
		if (!ht_up_update(ctx->analysis->debug_info->function_by_addr, fcn->low_pc, fcn)) {
			RZ_LOG_ERROR("DWARF function saving failed with addr: [0x%" PFMT64x "]\n",
				fcn->low_pc);
			goto cleanup;
		}
	}
	return true;
cleanup:
	RZ_LOG_ERROR("Failed to parse function %s at 0x%" PFMT64x "\n", fcn->prefer_name, die->offset);
	function_free(fcn);
	return false;
}

static bool variable_exist_global(RzAnalysis *a, RzAnalysisDwarfVariable *v) {
	RzAnalysisVarGlobal *existing_glob = NULL;
	if ((existing_glob = rz_analysis_var_global_get_byaddr_in(a, v->location->address))) {
		return true;
	}
	if ((existing_glob = rz_analysis_var_global_get_byname(a, v->prefer_name))) {
		return true;
	}
	return false;
}

static bool variable_from_die(
	RZ_BORROW RZ_IN RZ_NONNULL DwContext *ctx,
	RZ_BORROW RZ_IN RZ_NONNULL const RzBinDwarfDie *die) {
	RzAnalysisDwarfVariable v = { 0 };
	if (!function_var_parse(ctx, NULL, NULL, &v, die, NULL)) {
		variable_fini(&v);
		return false;
	}
	if (!(v.type && v.location->kind == RzBinDwarfLocationKind_ADDRESS)) {
		variable_fini(&v);
		return false;
	}

	if (variable_exist_global(ctx->analysis, &v)) {
		variable_fini(&v);
		return false;
	}

	bool result = rz_analysis_var_global_create(
		ctx->analysis, v.prefer_name, v.type, v.location->address);

	v.type = NULL;
	variable_fini(&v);
	return result;
}

static void die_parse(DwContext *ctx, RzBinDwarfDie *die) {
	if (set_u_contains(ctx->analysis->debug_info->visited, die->offset)) {
		return;
	}
	set_u_add(ctx->analysis->debug_info->visited, die->offset);
	switch (die->tag) {
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
	case DW_TAG_class_type:
	case DW_TAG_enumeration_type:
	case DW_TAG_typedef:
	case DW_TAG_unspecified_type:
	case DW_TAG_base_type: {
		RzBaseType_from_die(ctx, die);
		break;
	}
	case DW_TAG_entry_point:
	case DW_TAG_subprogram:
		function_from_die(ctx, die);
		break;
	case DW_TAG_variable:
		variable_from_die(ctx, die);
		break;
	default:
		break;
	}
}

static RzBinDwarfDie *die_next(RzBinDwarfDie *die, RzBinDWARF *dw) {
	return (die->sibling > die->offset)
		? ht_up_find(dw->info->die_by_offset, die->sibling, NULL)
		: die + 1;
}

static RzBinDwarfDie *die_end(RzBinDwarfCompUnit *unit) {
	RzVector *vec = &unit->dies;
	return (RzBinDwarfDie *)((char *)vec->a + vec->elem_size * vec->len);
}

/**
 * \brief Parses type and function information out of DWARF entries
 *        and stores them to analysis->debug_info
 * \param analysis RzAnalysis pointer
 * \param dw RzBinDwarf pointer
 */
RZ_API void rz_analysis_dwarf_preprocess_info(
	RZ_NONNULL RZ_BORROW RzAnalysis *analysis,
	RZ_NONNULL RZ_BORROW RzBinDWARF *dw) {
	rz_return_if_fail(analysis && dw);
	if (!dw->info) {
		return;
	}
	analysis->debug_info->dwarf_register_mapping = dwarf_register_mapping_query(analysis->cpu, analysis->bits);
	DwContext ctx = {
		.analysis = analysis,
		.dw = dw,
		.str_escaped = ht_up_new(NULL, HtUP_String_free, NULL),
		.unit = NULL,
	};
	RzBinDwarfCompUnit *unit;
	rz_vector_foreach(&dw->info->units, unit) {
		if (rz_vector_empty(&unit->dies)) {
			continue;
		}
		ctx.unit = unit;
		for (RzBinDwarfDie *die = rz_vector_head(&unit->dies);
			die && die < die_end(unit);
			die = die_next(die, dw)) {

			die_parse(&ctx, die);
		}
	}
	ht_up_free(ctx.str_escaped);
}

#define SWAP(T, a, b) \
	do { \
		T temp = a; \
		a = b; \
		b = temp; \
	} while (0)

static inline void update_base_type(const RzTypeDB *typedb, RzBaseType *type) {
	RzBaseType *t = rz_type_db_get_base_type(typedb, type->name);
	if (t && t == type) {
		return;
	}
	rz_type_db_update_base_type(typedb, rz_base_type_clone(type));
}

static void db_save_renamed(RzTypeDB *db, RzBaseType *b, char *name) {
	if (!name) {
		rz_warn_if_reached();
		return;
	}
	RzBaseType *t = rz_type_db_get_base_type(db, b->name);
	if (t == b) {
		return;
	}
	free(b->name);
	b->name = name;
	rz_type_db_update_base_type(db, b);
}

static bool store_base_type(void *u, const void *k, const void *v) {
	RzAnalysis *analysis = u;
	const char *name = k;
	RzPVector *types = (RzPVector *)v;
	const ut32 len = rz_pvector_len(types);
	if (len == 0) {
		RZ_LOG_WARN("BaseType %s has nothing", name);
	} else if (len == 1) {
		RzBaseType *t = rz_pvector_head(types);
		update_base_type(analysis->typedb, t);
	} else if (len == 2) {
		RzBaseType *a = rz_pvector_head(types);
		RzBaseType *b = rz_pvector_tail(types);
		if (a->kind != RZ_BASE_TYPE_KIND_TYPEDEF) {
			SWAP(RzBaseType *, a, b);
		}
		if (a->kind != RZ_BASE_TYPE_KIND_TYPEDEF) {
			update_base_type(analysis->typedb, a);
			db_save_renamed(analysis->typedb, rz_base_type_clone(b), rz_str_newf("%s_0", name));
			goto beach;
		}
		if (a->type->kind != RZ_TYPE_KIND_IDENTIFIER) {
			RZ_LOG_WARN("BaseType: type of typedef [%s] is not RZ_TYPE_KIND_IDENTIFIER\n", name);
			goto beach;
		}
		if (RZ_STR_NE(a->type->identifier.name, name)) {
			RZ_LOG_WARN("BaseType: type name [%s] of typedef [%s] is not valid\n",
				a->type->identifier.name, name);
			goto beach;
		}
		free(a->type->identifier.name);
		char *newname = rz_str_newf("%s_0", name);
		a->type->identifier.name = rz_str_dup(newname);
		update_base_type(analysis->typedb, a);

		db_save_renamed(analysis->typedb, rz_base_type_clone(b), newname);
	} else {
		RZ_LOG_WARN("BaseType: same name [%s] type count is more than 3\n", name);
	}
beach:
	return true;
}

static bool store_callable(void *u, ut64 k, const void *v) {
	RzAnalysis *analysis = u;
	RzCallable *c = (RzCallable *)v;
	if (!rz_type_func_update(analysis->typedb, rz_type_callable_clone(c))) {
		RZ_LOG_WARN("DWARF callable [%s] saving failed with offset: [0x%" PFMT64x "]\n",
			c->name, k);
	}
	return true;
}

/**
 * \brief Parses type and function information out of DWARF entries
 *        and stores them to analysis->debug_info and analysis->typedb
 * \param analysis RzAnalysis pointer
 * \param dw RzBinDwarf pointer
 */
RZ_API void rz_analysis_dwarf_process_info(RzAnalysis *analysis, RzBinDWARF *dw) {
	rz_return_if_fail(analysis && dw);
	rz_analysis_dwarf_preprocess_info(analysis, dw);
	ht_pp_foreach(analysis->debug_info->base_types_by_name, store_base_type, (void *)analysis);
	ht_up_foreach(analysis->debug_info->callable_by_offset, store_callable, (void *)analysis);
}

static bool fixup_regoff_to_stackoff(RzAnalysis *a, RzAnalysisFunction *f,
	RzAnalysisDwarfVariable *dw_var, const char *reg_name, RzAnalysisVar *var) {
	if (dw_var->location->kind != RzBinDwarfLocationKind_REGISTER_OFFSET) {
		return false;
	}
	ut16 reg = dw_var->location->register_number;
	st64 off = dw_var->location->offset;
	if (RZ_STR_EQ(a->cpu, "x86")) {
		if (a->bits == 64) {
			if (reg == 6) { // 6 = rbp
				rz_analysis_var_storage_init_stack(&var->storage, off - f->bp_off);
				return true;
			}
			if (reg == 7) { // 7 = rsp
				rz_analysis_var_storage_init_stack(&var->storage, off);
				return true;
			}
		} else {
			if (reg == 4) { // 4 = esp
				rz_analysis_var_storage_init_stack(&var->storage, off);
				return true;
			}
			if (reg == 5) { // 5 = ebp
				rz_analysis_var_storage_init_stack(&var->storage, off - f->bp_off);
				return true;
			}
		}
	} else if (RZ_STR_EQ(a->cpu, "ppc")) {
		if (reg == 1) { // 1 = r1
			rz_analysis_var_storage_init_stack(&var->storage, off);
			return true;
		}
	} else if (RZ_STR_EQ(a->cpu, "tricore")) {
		if (reg == 30) { // 30 = a14
			rz_analysis_var_storage_init_stack(&var->storage, off);
			return true;
		}
	}
	const char *SP = rz_reg_get_name(a->reg, RZ_REG_NAME_SP);
	if (SP && RZ_STR_EQ(SP, reg_name)) {
		rz_analysis_var_storage_init_stack(&var->storage, off);
		return true;
	}
	const char *BP = rz_reg_get_name(a->reg, RZ_REG_NAME_BP);
	if (BP && RZ_STR_EQ(BP, reg_name)) {
		rz_analysis_var_storage_init_stack(&var->storage, off - f->bp_off);
		return true;
	}
	return false;
}

static RzBinDwarfLocation *location_by_biggest_range(const RzBinDwarfLocList *loclist) {
	if (!loclist) {
		return NULL;
	}
	ut64 biggest_range = 0;
	RzBinDwarfLocation *biggest_range_loc = NULL;
	void **it;
	rz_pvector_foreach (&loclist->entries, it) {
		RzBinDwarfLocListEntry *entry = *it;
		ut64 range = entry->range->begin - entry->range->end;
		if (range > biggest_range && entry->location &&
			(entry->location->kind == RzBinDwarfLocationKind_REGISTER_OFFSET ||
				entry->location->kind == RzBinDwarfLocationKind_REGISTER ||
				entry->location->kind == RzBinDwarfLocationKind_CFA_OFFSET ||
				entry->location->kind == RzBinDwarfLocationKind_COMPOSITE)) {
			biggest_range = range;
			biggest_range_loc = entry->location;
		}
	}
	return biggest_range_loc;
}

static bool RzBinDwarfLocation_as_RzAnalysisVarStorage(
	RzAnalysis *a, RzAnalysisFunction *f,
	RzAnalysisDwarfVariable *dw_var, RzBinDwarfLocation *loc,
	RzAnalysisVar *var, RzAnalysisVarStorage *storage) {
	storage->type = RZ_ANALYSIS_VAR_STORAGE_EVAL_PENDING;
	var->origin.dw_var = dw_var;
	switch (loc->kind) {
	case RzBinDwarfLocationKind_REGISTER: {
		rz_analysis_var_storage_init_reg(storage, a->debug_info->dwarf_register_mapping(loc->register_number));
		break;
	}
	case RzBinDwarfLocationKind_REGISTER_OFFSET: {
		// Convert some register offset to stack offset
		if (fixup_regoff_to_stackoff(a, f, dw_var, a->debug_info->dwarf_register_mapping(loc->register_number), var)) {
			break;
		}
		break;
	}
	case RzBinDwarfLocationKind_ADDRESS: {
		if (variable_exist_global(a, dw_var)) {
			return false;
		}
		rz_analysis_var_global_create(a, dw_var->prefer_name,
			rz_type_clone(dw_var->type), loc->address);
		rz_analysis_var_fini(var);
		return false;
	}
	case RzBinDwarfLocationKind_EMPTY:
	case RzBinDwarfLocationKind_DECODE_ERROR:
	case RzBinDwarfLocationKind_VALUE:
	case RzBinDwarfLocationKind_BYTES:
	case RzBinDwarfLocationKind_IMPLICIT_POINTER:
	case RzBinDwarfLocationKind_EVALUATION_WAITING:
		break;
	case RzBinDwarfLocationKind_COMPOSITE:
		rz_analysis_var_storage_init_composite(storage);
		if (!storage->composite) {
			return false;
		}
		RzBinDwarfPiece *piece = NULL;
		rz_vector_foreach(loc->composite, piece) {
			RzAnalysisVarStorage *sto = RZ_NEW0(RzAnalysisVarStorage);
			if (!sto) {
				goto clean_composite;
			}
			RzBinDwarfLocation_as_RzAnalysisVarStorage(a, f, dw_var, piece->location, var, sto);
			RzAnalysisVarStoragePiece p = {
				.offset_in_bits = piece->bit_offset,
				.size_in_bits = piece->size_in_bits,
				.storage = sto,
			};
			rz_vector_push(storage->composite, &p);
		}
		break;
	clean_composite:
		rz_analysis_var_storage_fini(storage);
		return false;
	case RzBinDwarfLocationKind_CFA_OFFSET:
		// TODO: The following is only an educated guess. There is actually more involved in calculating the
		//       CFA correctly.
		rz_analysis_var_storage_init_stack(storage, loc->offset + a->bits / 8);
		break;
	case RzBinDwarfLocationKind_FB_OFFSET:
		rz_analysis_var_storage_init_stack(storage, loc->offset);
		break;
	case RzBinDwarfLocationKind_LOCLIST: {
		RzBinDwarfLocation *biggest_range_loc = location_by_biggest_range(loc->loclist);
		if (!biggest_range_loc) {
			break;
		}
		if (RzBinDwarfLocation_as_RzAnalysisVarStorage(a, f, dw_var, biggest_range_loc, var, storage)) {
			break;
		}
		break;
	}
	}
	return true;
}

static bool RzAnalysisDwarfVariable_as_RzAnalysisVar(RzAnalysis *a, RzAnalysisFunction *f, RzAnalysisDwarfVariable *DW_var, RzAnalysisVar *var) {
	RzBinDwarfLocation *loc = DW_var->location;
	if (!loc) {
		return false;
	}
	var->type = DW_var->type ? rz_type_clone(DW_var->type) : rz_type_new_default(a->typedb);
	var->name = strdup(DW_var->prefer_name ? DW_var->prefer_name : "");
	var->kind = DW_var->kind;
	var->fcn = f;
	var->origin.kind = RZ_ANALYSIS_VAR_ORIGIN_DWARF;
	return RzBinDwarfLocation_as_RzAnalysisVarStorage(a, f, DW_var, loc, var, &var->storage);
}

static bool dwarf_integrate_function(void *user, const ut64 k, const void *value) {
	RzAnalysis *analysis = user;
	const RzAnalysisDwarfFunction *dw_fn = value;
	RzAnalysisFunction *fn = rz_analysis_get_function_at(analysis, dw_fn->low_pc);
	if (!fn) {
		return true;
	}

	if (dw_fn->prefer_name && !rz_str_startswith(dw_fn->prefer_name, "anonymous")) {
		char *dwf_name = rz_str_newf("dbg.%s", dw_fn->prefer_name);
		rz_analysis_function_rename((RzAnalysisFunction *)fn, dwf_name);
		free(dwf_name);
	}

	RzAnalysisDwarfVariable *dw_var;
	rz_vector_foreach(&dw_fn->variables, dw_var) {
		RzAnalysisVar *var = RZ_NEW0(RzAnalysisVar);
		rz_analysis_var_init(var);
		if (!RzAnalysisDwarfVariable_as_RzAnalysisVar(analysis, fn, dw_var, var)) {
			free(var);
			continue;
		}
		rz_analysis_function_add_var(fn, var);
	}

	fn->has_debuginfo = true;
	fn->is_variadic = dw_fn->has_unspecified_parameters;
	if (dw_fn->high_pc && fn->meta._max < dw_fn->high_pc) {
		fn->meta._max = dw_fn->high_pc;
	}

	return true;
}

/**
 * \brief Use parsed DWARF function info in the function analysis
 * \param analysis The analysis
 * \param flags The flags
 */
RZ_API void rz_analysis_dwarf_integrate_functions(RzAnalysis *analysis, RzFlag *flags) {
	rz_return_if_fail(analysis && analysis->debug_info);
	ht_up_foreach(analysis->debug_info->function_by_addr, dwarf_integrate_function, analysis);
}

Ht_FREE_IMPL(UP, RzType, rz_type_free);
Ht_FREE_IMPL(UP, RzBaseTypeWithMetadata, rz_type_base_type_with_metadata_free);
Ht_FREE_IMPL(UP, RzAnalysisDwarfFunction, function_free);
Ht_FREE_IMPL(UP, RzCallable, rz_type_callable_free);

static void HtPP_RzPVector_free(HtPPKv *kv) {
	if (!kv) {
		return;
	}
	free(kv->key);
	rz_pvector_free(kv->value);
}

/**
 * \brief Create a new debug info
 * \return RzAnalysisDebugInfo pointer
 */
RZ_API RzAnalysisDebugInfo *rz_analysis_debug_info_new() {
	RzAnalysisDebugInfo *debug_info = RZ_NEW0(RzAnalysisDebugInfo);
	if (!debug_info) {
		return NULL;
	}
	debug_info->function_by_offset = ht_up_new(NULL, HtUP_RzAnalysisDwarfFunction_free, NULL);
	debug_info->function_by_addr = ht_up_new0();
	debug_info->variable_by_offset = ht_up_new0();
	debug_info->type_by_offset = ht_up_new(NULL, HtUP_RzType_free, NULL);
	debug_info->callable_by_offset = ht_up_new(NULL, HtUP_RzCallable_free, NULL);
	debug_info->base_types_by_offset = ht_up_new(NULL, HtUP_RzBaseTypeWithMetadata_free, NULL);
	debug_info->base_types_by_name = ht_pp_new(NULL, HtPP_RzPVector_free, NULL);
	debug_info->visited = set_u_new();
	return debug_info;
}

/**
 * \brief Free a debug info
 * \param debuginfo RzAnalysisDebugInfo pointer
 */
RZ_API void rz_analysis_debug_info_free(RzAnalysisDebugInfo *debuginfo) {
	if (!debuginfo) {
		return;
	}
	ht_up_free(debuginfo->function_by_offset);
	ht_up_free(debuginfo->function_by_addr);
	ht_up_free(debuginfo->variable_by_offset);
	ht_up_free(debuginfo->type_by_offset);
	ht_up_free(debuginfo->callable_by_offset);
	ht_up_free(debuginfo->base_types_by_offset);
	ht_pp_free(debuginfo->base_types_by_name);
	rz_bin_dwarf_free(debuginfo->dw);
	set_u_free(debuginfo->visited);
	free(debuginfo);
}
