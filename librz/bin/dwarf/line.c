// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

/**
 * \brief Opaque cache for fully resolved filenames during Dwarf Line Info Generation
 * This cache stores full file paths to be optionally used in LineOp_run().
 * It is strictly associated with the RzBinDwarfLineHeader it has been created with in rz_bin_dwarf_line_header_new_file_cache()
 * and must be freed with the same header in rz_bin_dwarf_line_header_free_file_cache().
 */
typedef RzPVector /*<char *>*/ FilePathCache;

typedef struct {
	ut64 address;
	ut64 op_index;
	ut64 file;
	ut64 line;
	ut64 column;
	ut8 is_stmt;
	ut8 basic_block;
	ut8 end_sequence;
	ut8 prologue_end;
	ut8 epilogue_begin;
	ut64 isa;
	ut64 discriminator;
} SMRegisters;

typedef struct {
	RzBinDWARF *dw;
	RzBinDwarfLine *line;
	RzBinDwarfLineUnitHdr *hdr;
	SMRegisters *regs;
	RzBinSourceLineInfoBuilder *source_line_info_builder;
	FilePathCache *file_path_cache;
} DWLineContext;

static void LineHdr_init(RzBinDwarfLineUnitHdr *hdr) {
	if (!hdr) {
		return;
	}
	memset(hdr, 0, sizeof(*hdr));
	rz_vector_init(&hdr->file_name_entry_formats, sizeof(RzBinDwarfFileEntryFormat), NULL, NULL);
	rz_vector_init(&hdr->file_names, sizeof(RzBinDwarfFileEntry), NULL, NULL);
	rz_vector_init(&hdr->directory_entry_formats, sizeof(RzBinDwarfFileEntryFormat), NULL, NULL);
	rz_pvector_init(&hdr->directories, NULL);
}

static void LineHdr_fini(RzBinDwarfLineUnitHdr *hdr) {
	if (!hdr) {
		return;
	}
	rz_vector_fini(&hdr->file_name_entry_formats);
	rz_vector_fini(&hdr->file_names);
	rz_vector_fini(&hdr->directory_entry_formats);
	rz_pvector_fini(&hdr->directories);
}

static bool FileEntryFormat_parse(
	RzBinEndianReader *R, RzVector /*<RzBinDwarfFileEntryFormat>*/ *out, RzBinDwarfLineUnitHdr *hdr) {
	ut8 count = 0;
	U8_OR_RET_FALSE(count);
	rz_vector_reserve(out, count);
	ut32 path_count = 0;
	for (ut8 i = 0; i < count; ++i) {
		RzBinDwarfFileEntryFormat format = { 0 };
		ULE128_OR_RET_FALSE(format.content_type);
		ULE128_OR_RET_FALSE(format.form);
		if (format.form > UT16_MAX) {
			RZ_LOG_ERROR("invalid file entry format form %" PFMT32x "\n", format.form);
			return false;
		}

		if (format.content_type == DW_LNCT_path) {
			path_count += 1;
		}

		rz_vector_push(out, &format);
	}

	if (path_count != 1) {
		RZ_LOG_DEBUG("Missing file entry format path <.debug_line+0x%" PFMT64x ">\n", hdr->offset);
		return false;
	}
	return true;
}

static const char *directory_parse_v5(DWLineContext *ctx, RzBinDwarfLineUnitHdr *hdr) {
	RzBinEndianReader *R = ctx->line->R;
	const char *path_name = NULL;
	RzBinDwarfFileEntryFormat *format = NULL;
	rz_vector_foreach (&hdr->directory_entry_formats, format) {
		RzBinDwarfAttr attr = { 0 };
		AttrOption opt = {
			.form = format->form,
			.encoding = &hdr->encoding,
		};
		RET_NULL_IF_FAIL(RzBinDwarfAttr_parse(R, &attr, &opt));
		if (format->content_type == DW_LNCT_path) {
			path_name = rz_bin_dwarf_attr_string(&attr, ctx->dw, UT64_MAX);
		}
	}
	return path_name;
}

static bool FileEntry_parse_v5(DWLineContext *ctx, RzBinDwarfFileEntry *entry) {
	RzBinEndianReader *R = ctx->line->R;
	RzBinDwarfLineUnitHdr *hdr = ctx->hdr;
	RzBinDwarfFileEntryFormat *format = NULL;
	rz_vector_foreach (&hdr->file_name_entry_formats, format) {
		RzBinDwarfAttr attr = { 0 };
		AttrOption opt = {
			.form = format->form,
			.encoding = &hdr->encoding,
		};
		if (!RzBinDwarfAttr_parse(R, &attr, &opt)) {
			return false;
		}
		switch (format->content_type) {
		case DW_LNCT_path:
			entry->path_name = rz_bin_dwarf_attr_string(&attr, ctx->dw, UT64_MAX);
			break;
		case DW_LNCT_directory_index:
			entry->directory_index = rz_bin_dwarf_attr_udata(&attr);
			break;
		case DW_LNCT_timestamp:
			entry->timestamp = rz_bin_dwarf_attr_udata(&attr);
			break;
		case DW_LNCT_size:
			entry->size = rz_bin_dwarf_attr_udata(&attr);
			break;
		case DW_LNCT_MD5: {
			rz_warn_if_fail(attr.form == DW_FORM_data16);
			const ut128 data = attr.value.u128;
			memcpy(entry->md5, &data, 16);
			break;
		}
		default: rz_warn_if_reached(); break;
		}
	}

	return true;
}

static bool FileEntry_parse_v4(RzBinEndianReader *R, RzBinDwarfFileEntry *entry) {
	ERR_IF_FAIL(R_read_cstring(R, &entry->path_name) && RZ_STR_ISNOTEMPTY(entry->path_name));
	ERR_IF_FAIL(entry->path_name);
	ULE128_OR_GOTO(entry->directory_index, err);
	ULE128_OR_GOTO(entry->timestamp, err);
	ULE128_OR_GOTO(entry->size, err);
	memset(entry->md5, 0, sizeof(entry->md5));
	return true;
err:
	return false;
}

/**
 * 6.2.4 The Line Number Program Header: https://dwarfstd.org/doc/DWARF5.pdf#page=172
 */
static bool LineHdr_parse_v5(DWLineContext *ctx) {
	RzBinEndianReader *R = ctx->line->R;
	RzBinDwarfLineUnitHdr *hdr = ctx->hdr;
	RET_FALSE_IF_FAIL(FileEntryFormat_parse(R, &hdr->directory_entry_formats, hdr));
	ut64 count = 0;
	ULE128_OR_RET_FALSE(count);
	for (ut64 i = 0; i < count; ++i) {
		const char *dir = directory_parse_v5(ctx, hdr);
		if (!dir) {
			break;
		}
		rz_pvector_push(&hdr->directories, (void *)dir);
	}

	RET_FALSE_IF_FAIL(FileEntryFormat_parse(R, &hdr->file_name_entry_formats, hdr));
	ULE128_OR_RET_FALSE(count);
	for (ut64 i = 0; i < count; ++i) {
		RzBinDwarfFileEntry entry = { 0 };
		if (!FileEntry_parse_v5(ctx, &entry)) {
			break;
		}
		rz_vector_push(&hdr->file_names, &entry);
	}
	return true;
}

static bool LineHdr_parse_v4(DWLineContext *ctx) {
	RzBinEndianReader *R = ctx->line->R;
	while (true) {
		const char *str = NULL;
		OK_OR(R_read_cstring(R, &str) && RZ_STR_ISNOTEMPTY(str), break);
		rz_pvector_push(&ctx->hdr->directories, (void *)str);
	}
	while (true) {
		RzBinDwarfFileEntry entry = { 0 };
		if (!FileEntry_parse_v4(R, &entry)) {
			break;
		}
		rz_vector_push(&ctx->hdr->file_names, &entry);
	}
	return true;
}

/**
 * \brief Get the full path from a file index, it will join the directory find in \p info with the filename
 * \param ctx the context
 * \param index the index of the file
 * \return the full path or NULL if the file index is invalid
 */
static char *full_file_path(
	DWLineContext *ctx,
	ut64 index) {
	rz_return_val_if_fail(ctx && ctx->hdr, NULL);
	if (index >= rz_vector_len(&ctx->hdr->file_names)) {
		return NULL;
	}
	RzBinDwarfFileEntry *file = rz_vector_index_ptr(&ctx->hdr->file_names, index);
	if (!file->path_name) {
		return NULL;
	}

	/*
	 * Dwarf standard does not seem to specify the exact separator (slash/backslash) of paths
	 * so apparently it is target-dependent. However we have yet to see a Windows binary that
	 * also contains dwarf and contains backslashes. The ones we have seen from MinGW have regular
	 * slashes.
	 * And since there seems to be no way to reliable check whether the target uses slashes
	 * or backslashes anyway, we will simply use slashes always here.
	 */

	const char *comp_dir = ctx->dw && ctx->dw->info
		? ht_up_find(ctx->dw->info->offset_comp_dir, ctx->hdr->offset, NULL)
		: NULL;
	const ut64 dir_index = ctx->hdr->encoding.version < 5 ? file->directory_index - 1 : file->directory_index;
	const char *dir = (dir_index >= 0 && dir_index < rz_pvector_len(&ctx->hdr->directories))
		? rz_pvector_at(&ctx->hdr->directories, dir_index)
		: NULL;
	char *file_path_abs = NULL;
	if (comp_dir && dir) {
		if (dir[0] == '/') {
			file_path_abs = rz_str_newf("%s/%s", dir, file->path_name);
		} else {
			file_path_abs = rz_str_newf("%s/%s/%s", comp_dir, dir, file->path_name);
		}
	} else if (comp_dir) {
		file_path_abs = rz_str_newf("%s/%s", comp_dir, file->path_name);
	} else if (dir) {
		file_path_abs = rz_str_newf("%s/%s", dir, file->path_name);
	} else {
		file_path_abs = rz_str_dup(file->path_name);
	}
	return file_path_abs;
}

static const char *full_file_path_cached(DWLineContext *ctx, ut64 file_index) {
	if (ctx->hdr->encoding.version <= 4) {
		file_index -= 1;
	}

	if (file_index >= rz_vector_len(&ctx->hdr->file_names)) {
		return NULL;
	}
	if (!ctx->file_path_cache) {
		return ((RzBinDwarfFileEntry *)rz_vector_index_ptr(&ctx->hdr->file_names, file_index))->path_name;
	}
	char *path = rz_pvector_at(ctx->file_path_cache, file_index);
	if (!path) {
		path = full_file_path(ctx, file_index);
		rz_pvector_set(ctx->file_path_cache, file_index, path);
	}
	return path;
}

static ut64 LineHdr_adj_opcode(const RzBinDwarfLineUnitHdr *hdr, ut8 opcode) {
	rz_return_val_if_fail(hdr, 0);
	return opcode - hdr->opcode_base;
}

static ut64 LineHdr_spec_op_advance_pc(const RzBinDwarfLineUnitHdr *hdr, ut8 opcode) {
	rz_return_val_if_fail(hdr, 0);
	if (!hdr->line_range) {
		// to dodge division by zero
		return 0;
	}
	ut8 adj_opcode = LineHdr_adj_opcode(hdr, opcode);
	ut64 op_advance = adj_opcode / hdr->line_range;
	if (hdr->max_ops_per_inst == 1) {
		return op_advance * hdr->min_inst_len;
	}
	return hdr->min_inst_len * (op_advance / hdr->max_ops_per_inst);
}

static st64 LineHdr_spec_op_advance_line(const RzBinDwarfLineUnitHdr *hdr, ut8 opcode) {
	rz_return_val_if_fail(hdr, 0);
	if (!hdr->line_range) {
		// to dodge division by zero
		return 0;
	}
	ut8 adj_opcode = LineHdr_adj_opcode(hdr, opcode);
	return hdr->line_base + (adj_opcode % hdr->line_range);
}

static bool LineHdr_parse(
	DWLineContext *ctx,
	RzBinDwarfEncoding encoding) {
	rz_return_val_if_fail(ctx, false);
	RzBinEndianReader *R = ctx->line->R;
	RzBinDwarfLineUnitHdr *hdr = ctx->hdr;
	LineHdr_init(ctx->hdr);
	hdr->offset = R_tell(R);
	MEM_ZERO(RzBinDwarfEncoding, &hdr->encoding);
	RET_FALSE_IF_FAIL(R_read_initial_length(R, &hdr->encoding.is_64bit, &hdr->unit_length));

	U_OR_RET_FALSE(16, hdr->encoding.version);
	if (hdr->encoding.version < 2 || hdr->encoding.version > 5) {
		RZ_LOG_VERBOSE("DWARF line hdr version %d is not supported\n", hdr->encoding.version);
		return false;
	}
	if (hdr->encoding.version == 5) {
		U8_OR_RET_FALSE(hdr->encoding.address_size);
		U8_OR_RET_FALSE(hdr->segment_selector_size);
		if (hdr->segment_selector_size != 0) {
			RZ_LOG_ERROR("DWARF line hdr segment selector size %d is not supported\n",
				hdr->segment_selector_size);
			return false;
		}
	} else if (hdr->encoding.version < 5) {
		// Dwarf < 5 needs this size to be supplied from outside
		hdr->encoding.address_size = encoding.address_size;
	}

	RET_FALSE_IF_FAIL(R_read_offset(R, &hdr->header_length, hdr->encoding.is_64bit));

	U8_OR_RET_FALSE(hdr->min_inst_len);
	if (hdr->min_inst_len == 0) {
		RZ_LOG_VERBOSE("DWARF line hdr min inst len %d is not supported\n", hdr->min_inst_len);
		return false;
	}

	if (hdr->encoding.version >= 4) {
		U8_OR_RET_FALSE(hdr->max_ops_per_inst);
	} else {
		hdr->max_ops_per_inst = 1;
	}
	if (hdr->max_ops_per_inst == 0) {
		RZ_LOG_VERBOSE("DWARF line hdr max ops per inst %d is not supported\n", hdr->max_ops_per_inst);
		return false;
	}

	U8_OR_RET_FALSE(hdr->default_is_stmt);
	st8 base = 0;
	READ8_OR(st8, base, return false);
	hdr->line_base = (st32)base;
	U8_OR_RET_FALSE(hdr->line_range);
	if (hdr->line_range == 0) {
		RZ_LOG_ERROR("DWARF line hdr line range %d is not supported\n", hdr->line_range);
		return false;
	}

	U8_OR_RET_FALSE(hdr->opcode_base);
	if (hdr->opcode_base == 0) {
		RZ_LOG_ERROR("DWARF line hdr opcode base 0 is not supported\n");
		return false;
	}
	if (hdr->opcode_base > 1) {
		RET_FALSE_IF_FAIL(R_take(R, &hdr->std_opcode_lengths, hdr->opcode_base - 1));
	} else {
		hdr->std_opcode_lengths = NULL;
	}

	if (hdr->encoding.version <= 4) {
		return LineHdr_parse_v4(ctx);
	} else if (hdr->encoding.version == 5) {
		return LineHdr_parse_v5(ctx);
	}
	RZ_LOG_ERROR("DWARF line hdr version %d is not supported\n", hdr->encoding.version);
	return false;
}

static bool LineOp_ext(
	RzBinEndianReader *R,
	RzBinDwarfLineOp *op,
	const RzBinDwarfLineUnitHdr *hdr) {
	rz_return_val_if_fail(op && hdr && R, false);
	ut64 op_len;
	ULE128_OR_RET_FALSE(op_len);
	// op_len must fit and be at least 1 (for the opcode byte)
	RET_FALSE_IF_FAIL(op_len > 0);

	RzBinEndianReader rest = { 0 };
	RET_FALSE_IF_FAIL(R_split(R, op_len, &rest));
	R = &rest;
	U8_OR_RET_FALSE(op->ext_opcode);
	op->type = RZ_BIN_DWARF_LINE_OP_TYPE_EXT;

	switch (op->ext_opcode) {
	case DW_LNE_set_address: {
		RET_FALSE_IF_FAIL(R_read_address(R, &op->args.set_address, hdr->encoding.address_size));
		break;
	}
	case DW_LNE_define_file: {
		if (hdr->encoding.version <= 4) {
			RET_FALSE_IF_FAIL(FileEntry_parse_v4(R, &op->args.define_file));
		} else {
			op->type = RZ_BIN_DWARF_LINE_OP_TYPE_EXT_UNKNOWN;
		}
		break;
	}
	case DW_LNE_set_discriminator:
		ULE128_OR_RET_FALSE(op->args.set_discriminator);
		break;
	case DW_LNE_end_sequence:
	default:
		break;
	}
	return true;
}

/**
 * \return the number of leb128 args the std opcode takes, EXCEPT for DW_LNS_fixed_advance_pc! (see Dwarf spec)
 */
static size_t LineOp_std_args_count(
	RzBinDwarfLineOp *op,
	const RzBinDwarfLineUnitHdr *hdr) {
	if (!op->opcode || op->opcode >= hdr->opcode_base || !hdr->std_opcode_lengths) {
		return 0;
	}
	return hdr->std_opcode_lengths[op->opcode - 1];
}

static bool LineOp_std(
	RzBinEndianReader *R,
	RzBinDwarfLineOp *op,
	const RzBinDwarfLineUnitHdr *hdr) {
	rz_return_val_if_fail(op && hdr && R, false);
	op->type = RZ_BIN_DWARF_LINE_OP_TYPE_STD;
	switch (op->opcode) {
	case DW_LNS_advance_pc:
		ULE128_OR_RET_FALSE(op->args.advance_pc);
		break;
	case DW_LNS_advance_line:
		SLE128_OR_RET_FALSE(op->args.advance_line);
		break;
	case DW_LNS_set_file:
		ULE128_OR_RET_FALSE(op->args.set_file);
		break;
	case DW_LNS_set_column:
		ULE128_OR_RET_FALSE(op->args.set_column);
		break;
	case DW_LNS_fixed_advance_pc:
		U_OR_RET_FALSE(16, op->args.fixed_advance_pc);
		break;
	case DW_LNS_set_isa:
		ULE128_OR_RET_FALSE(op->args.set_isa);
		break;
	// known opcodes that take no args
	case DW_LNS_copy:
	case DW_LNS_negate_stmt:
	case DW_LNS_set_basic_block:
	case DW_LNS_const_add_pc:
	case DW_LNS_set_prologue_end:
	case DW_LNS_set_epilogue_begin:
		break;
	// unknown operands, skip the number of args given in the header.
	default: {
		size_t args_count = LineOp_std_args_count(op, hdr);
		for (size_t i = 0; i < args_count; i++) {
			ULE128_OR_GOTO(op->args.advance_pc, ok);
		}
	}
	}
ok:
	return true;
}

static void SMRegisters_reset(
	const RzBinDwarfLineUnitHdr *hdr,
	SMRegisters *regs) {
	rz_return_if_fail(hdr && regs);
	regs->address = 0;
	regs->file = 1;
	regs->line = 1;
	regs->column = 0;
	regs->is_stmt = hdr->default_is_stmt;
	regs->basic_block = 0;
	regs->end_sequence = 0;
	regs->prologue_end = 0;
	regs->epilogue_begin = 0;
	regs->isa = 0;
}

static void store_line_sample(DWLineContext *ctx) {
	const char *filepath = full_file_path_cached(ctx, ctx->regs->file);
	rz_bin_source_line_info_builder_push_sample(
		ctx->source_line_info_builder, ctx->regs->address, (ut32)ctx->regs->line, (ut32)ctx->regs->column, filepath);
}

/**
 * \brief Execute a single line op on regs and optionally store the resulting line info in source_line_info_builder
 * \param line_file_cache if not null, filenames will be resolved to their full paths using this cache.
 */
static bool LineOp_run(
	RZ_NONNULL RZ_BORROW RzBinDwarfLineOp *op,
	RZ_NONNULL RZ_BORROW RZ_INOUT DWLineContext *ctx) {
	rz_return_val_if_fail(ctx && ctx->hdr && ctx->regs && op, false);
	switch (op->type) {
	case RZ_BIN_DWARF_LINE_OP_TYPE_STD:
		switch (op->opcode) {
		case DW_LNS_copy:
			store_line_sample(ctx);
			ctx->regs->basic_block = 0;
			break;
		case DW_LNS_advance_pc:
			ctx->regs->address += op->args.advance_pc * ctx->hdr->min_inst_len;
			break;
		case DW_LNS_advance_line:
			ctx->regs->line += op->args.advance_line;
			break;
		case DW_LNS_set_file:
			ctx->regs->file = op->args.set_file;
			break;
		case DW_LNS_set_column:
			ctx->regs->column = op->args.set_column;
			break;
		case DW_LNS_negate_stmt:
			ctx->regs->is_stmt = ctx->regs->is_stmt ? 0 : 1;
			break;
		case DW_LNS_set_basic_block:
			ctx->regs->basic_block = 1;
			break;
		case DW_LNS_const_add_pc:
			ctx->regs->address += LineHdr_spec_op_advance_pc(ctx->hdr, 255);
			break;
		case DW_LNS_fixed_advance_pc:
			ctx->regs->address += op->args.fixed_advance_pc;
			break;
		case DW_LNS_set_prologue_end:
			ctx->regs->prologue_end = ~0;
			break;
		case DW_LNS_set_epilogue_begin:
			ctx->regs->epilogue_begin = ~0;
			break;
		case DW_LNS_set_isa:
			ctx->regs->isa = op->args.set_isa;
			break;
		default:
			return false;
		}
		break;
	case RZ_BIN_DWARF_LINE_OP_TYPE_EXT:
		switch (op->ext_opcode) {
		case DW_LNE_end_sequence:
			ctx->regs->end_sequence = 1;
			rz_bin_source_line_info_builder_push_sample(
				ctx->source_line_info_builder, ctx->regs->address, 0, 0, NULL);
			SMRegisters_reset(ctx->hdr, ctx->regs);
			break;
		case DW_LNE_set_address:
			ctx->regs->address = op->args.set_address;
			break;
		case DW_LNE_define_file:
			rz_vector_push(&ctx->hdr->file_names, &op->args.define_file);
			break;
		case DW_LNE_set_discriminator:
			ctx->regs->discriminator = op->args.set_discriminator;
			break;
		default:
			return false;
		}
		break;
	case RZ_BIN_DWARF_LINE_OP_TYPE_SPEC:
		ctx->regs->address += LineHdr_spec_op_advance_pc(ctx->hdr, op->opcode);
		ctx->regs->line += LineHdr_spec_op_advance_line(ctx->hdr, op->opcode);
		store_line_sample(ctx);
		ctx->regs->basic_block = 0;
		ctx->regs->prologue_end = 0;
		ctx->regs->epilogue_begin = 0;
		ctx->regs->discriminator = 0;
		break;
	default:
		return false;
	}
	return true;
}

static bool LineOp_at(DWLineContext *ctx, ut64 offset, RzBinDwarfLineOp *op) {
	RzBinEndianReader *R = ctx->line->R;
	RET_FALSE_IF_FAIL(R_seek(R, offset, SEEK_SET));
	op->offset = offset;
	U8_OR_RET_FALSE(op->opcode);
	if (!op->opcode) {
		RET_FALSE_IF_FAIL(LineOp_ext(R, op, ctx->hdr));
	} else if (op->opcode >= ctx->hdr->opcode_base) {
		op->type = RZ_BIN_DWARF_LINE_OP_TYPE_SPEC;
	} else {
		RET_FALSE_IF_FAIL(LineOp_std(R, op, ctx->hdr));
	}
	return true;
}

static bool LineOp_all(
	DWLineContext *ctx,
	RzVector /*<RzBinDwarfLineOp>*/ *ops) {
	RzBinEndianReader *R = ctx->line->R;
	while (true) {
		ut64 offset = R_tell(R);
		if (offset > ctx->hdr->offset + ctx->hdr->unit_length + 1) {
			break;
		}
		RzBinDwarfLineOp op = { 0 };
		LineOp_at(ctx, offset, &op);
		rz_vector_push(ops, &op);
	}
	return true;
}

static void LineUnit_free(RzBinDwarfLineUnit *unit) {
	if (!unit) {
		return;
	}
	LineHdr_fini(&unit->hdr);
	rz_vector_fini(&unit->ops);
	free(unit);
}

static RzBinDwarfLine *Line_parse(
	RzBinEndianReader *R,
	RzBinDwarfEncoding *encoding,
	RzBinDWARF *dw) {
	// Dwarf 3 Standard 6.2 Line Number Information
	rz_return_val_if_fail(R, NULL);
	RzBinDwarfLine *li = RZ_NEW0(RzBinDwarfLine);
	if (!li) {
		return NULL;
	}
	li->R = R;
	li->units = rz_list_newf((RzListFree)LineUnit_free);
	if (!li->units) {
		free(li);
		return NULL;
	}

	RzBinSourceLineInfoBuilder source_line_info_builder;
	rz_bin_source_line_info_builder_init(&source_line_info_builder);
	SMRegisters regs;
	// each iteration we read one header AKA comp. unit
	while (true) {
		RzBinDwarfLineUnit *unit = RZ_NEW0(RzBinDwarfLineUnit);
		if (!unit) {
			break;
		}

		DWLineContext ctx = {
			.dw = dw,
			.line = li,
			.hdr = &unit->hdr,
		};
		if (!LineHdr_parse(&ctx, *encoding)) {
			LineUnit_free(unit);
			break;
		}
		rz_vector_init(&unit->ops, sizeof(RzBinDwarfLineOp), NULL, NULL);
		LineOp_all(&ctx, &unit->ops);

		ctx.regs = &regs;
		ctx.source_line_info_builder = &source_line_info_builder;
		ctx.file_path_cache = rz_pvector_new_with_len(
			free, rz_vector_len(&unit->hdr.file_names));
		SMRegisters_reset(&unit->hdr, &regs);

		RzBinDwarfLineOp *op;
		rz_vector_foreach (&unit->ops, op) {
			if (!LineOp_run(op, &ctx)) {
				break;
			}
		}

		rz_pvector_free(ctx.file_path_cache);
		rz_list_push(li->units, unit);
	}
	li->lines = rz_bin_source_line_info_builder_build_and_fini(&source_line_info_builder);
	return li;
}

RZ_API void rz_bin_dwarf_line_free(RZ_OWN RZ_NULLABLE RzBinDwarfLine *li) {
	if (!li) {
		return;
	}
	R_free(li->R);
	rz_list_free(li->units);
	rz_bin_source_line_info_free(li->lines);
	free(li);
}

RZ_API RZ_OWN RzBinDwarfLine *rz_bin_dwarf_line_new(
	RZ_BORROW RZ_NONNULL RzBinEndianReader *R,
	RZ_BORROW RZ_NONNULL RzBinDwarfEncoding *encoding,
	RZ_BORROW RZ_NULLABLE RzBinDWARF *dw) {
	rz_return_val_if_fail(R && encoding, NULL);
	return Line_parse(R, encoding, dw);
}

/**
 * \brief Parse the .debug_line section
 * \param bf RzBinFile to parse
 * \param dw RzBinDWARF instance
 * \return RzBinDwarfLineInfo or NULL if failed
 */
RZ_API RZ_OWN RzBinDwarfLine *rz_bin_dwarf_line_from_file(
	RZ_BORROW RZ_NONNULL RzBinFile *bf,
	RZ_BORROW RZ_NULLABLE RzBinDWARF *dw,
	bool is_dwo) {
	rz_return_val_if_fail(bf, NULL);
	RzBinDwarfEncoding encoding = { 0 };
	if (!RzBinDwarfEncoding_from_file(&encoding, bf)) {
		return NULL;
	}

	RzBinEndianReader *R = RzBinEndianReader_from_file(bf, ".debug_line", is_dwo);
	RET_NULL_IF_FAIL(R);
	return Line_parse(R, &encoding, dw);
}

/**
 * \param regs optional, the state after op has been executed. If not null, some meaningful results from this context will be shown.
 */
static void line_op_dump(
	RzBinDwarfLineOp *op,
	RzBinDwarfLineUnitHdr *hdr,
	RzStrBuf *sb) {
	rz_strbuf_appendf(sb, "0x%08" PFMT64x " ", op->offset);
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
		rz_strbuf_appendf(sb, "address += %" PFMT64d ", line += %" PFMT64d,
			LineHdr_spec_op_advance_pc(hdr, op->opcode),
			LineHdr_spec_op_advance_line(hdr, op->opcode));
		break;
	default:
		rz_strbuf_appendf(sb, "Unknown opcode type %u, opcode: %x",
			(unsigned int)op->type, op->opcode);
		break;
	}
	rz_strbuf_append(sb, "\n");
}

static void line_unit_dump(
	RZ_NONNULL RZ_BORROW RzBinDwarfLineUnit *unit,
	RZ_NONNULL RZ_BORROW RzStrBuf *sb) {
	RzBinDwarfLineUnitHdr *hdr = &unit->hdr;
	rz_strbuf_appendf(sb, "debug_line[0x%" PFMT64x "]\n", hdr->offset);
	rz_strbuf_append(sb, "Line table prologue:\n");
	rz_strbuf_appendf(sb, "\tlength\t%#" PFMT64x "\n", hdr->unit_length);
	rz_strbuf_appendf(sb, "\tformat\t%s\n", hdr->encoding.is_64bit ? "DWARF64" : "DWARF32");
	rz_strbuf_appendf(sb, "\tversion\t%d\n", hdr->encoding.version);
	rz_strbuf_appendf(sb, "\tprologue_length\t%#" PFMT64x "\n", hdr->header_length);
	rz_strbuf_appendf(sb, "\tmin_inst_length\t%d\n", hdr->min_inst_len);
	rz_strbuf_appendf(sb, "\tmax_ops_per_inst: %d\n", hdr->max_ops_per_inst);
	rz_strbuf_appendf(sb, "\tdefault_is_stmt\t%d\n", hdr->default_is_stmt);
	rz_strbuf_appendf(sb, "\tline base\t%d\n", hdr->line_base);
	rz_strbuf_appendf(sb, "\tline range\t%d\n", hdr->line_range);
	rz_strbuf_appendf(sb, "\topcode base\t%d\n", hdr->opcode_base);
	for (size_t i = 1; i < hdr->opcode_base; i++) {
		rz_strbuf_appendf(sb, "\tstd_opcode_lengths[%s]\t= %d\n",
			rz_str_get_null(rz_bin_dwarf_lns(i)), hdr->std_opcode_lengths[i - 1]);
	}
	if (rz_pvector_len(&hdr->directories) > 0) {
		rz_strbuf_append(sb, "The Directory Table:\n");
		for (size_t i = 0; i < rz_pvector_len(&hdr->directories); i++) {
			rz_strbuf_appendf(sb, "\t%u\t%s\n",
				(unsigned int)i + 1, (char *)rz_pvector_at(&hdr->directories, i));
		}
	}
	if (rz_vector_len(&hdr->file_names) > 0) {
		rz_strbuf_append(sb, "The File Name Table:\n");
		rz_strbuf_append(sb, "\tEntry Dir\tTime\tSize\tName\n");
		for (size_t i = 0; i < rz_vector_len(&hdr->file_names); i++) {
			RzBinDwarfFileEntry *f = rz_vector_index_ptr(&hdr->file_names, i);
			rz_strbuf_appendf(sb, "\t%u\t%" PFMT64u "\t%" PFMT64u "\t%" PFMT64u "\t",
				(unsigned int)i + 1, f->directory_index, f->timestamp, f->size);
			strbuf_append_string_own(sb, str_escape_utf8_copy(f->path_name));
			rz_strbuf_append(sb, "\n");
		}
	}
	rz_strbuf_append(sb, "Line table statements:\n");
	void *opsit;
	size_t i;
	rz_vector_enumerate(&unit->ops, opsit, i) {
		RzBinDwarfLineOp *op = opsit;
		rz_strbuf_append(sb, "\t");
		line_op_dump(op, &unit->hdr, sb);
		if (op->type == RZ_BIN_DWARF_LINE_OP_TYPE_EXT &&
			op->ext_opcode == DW_LNE_end_sequence &&
			i + 1 < rz_vector_len(&unit->ops)) {
			// extra newline for nice sequence separation
			rz_strbuf_append(sb, "\n");
		}
	}
	rz_strbuf_append(sb, "\n");
}

RZ_API void rz_bin_dwarf_line_units_dump(
	RZ_NONNULL RZ_BORROW RzBinDwarfLine *line,
	RZ_NONNULL RZ_BORROW RzStrBuf *sb) {
	rz_return_if_fail(line && line->R && sb);
	if (!(rz_list_empty(line->units))) {
		rz_strbuf_append(sb, ".debug_line content:\n");
	}
	RzListIter *it;
	RzBinDwarfLineUnit *unit;
	bool first = true;
	rz_list_foreach (line->units, it, unit) {
		if (!unit) {
			continue;
		}
		if (first) {
			first = false;
		} else {
			rz_strbuf_append(sb, "\n");
		}
		line_unit_dump(unit, sb);
	}
	rz_strbuf_append(sb, "\n");
}
