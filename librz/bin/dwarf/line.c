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
typedef RzPVector /*<char *>*/ LineFilePathCache;

typedef struct {
	const RzBinDwarfLineHdr *hdr;
	RzBinDwarfSMRegisters *regs;
	RzBinSourceLineInfoBuilder *source_line_info_builder;
	RzBinDwarfInfo *debug_info;
	LineFilePathCache *file_path_cache;
} DWLineOpEvalContext;

static void FileEntry_fini(RzBinDwarfFileEntry *x, void *user) {
	if (!x) {
		return;
	}
	free(x->path_name);
}

static void LineHdr_init(RzBinDwarfLineHdr *hdr) {
	if (!hdr) {
		return;
	}
	memset(hdr, 0, sizeof(*hdr));
	rz_vector_init(&hdr->file_name_entry_formats, sizeof(RzBinDwarfFileEntryFormat), NULL, NULL);
	rz_vector_init(&hdr->file_names, sizeof(RzBinDwarfFileEntry), (RzVectorFree)FileEntry_fini, NULL);
	rz_vector_init(&hdr->directory_entry_formats, sizeof(RzBinDwarfFileEntryFormat), NULL, NULL);
	rz_pvector_init(&hdr->directories, free);
}

static void LineHdr_fini(RzBinDwarfLineHdr *hdr) {
	if (!hdr) {
		return;
	}
	rz_vector_fini(&hdr->file_name_entry_formats);
	rz_vector_fini(&hdr->file_names);
	rz_vector_fini(&hdr->directory_entry_formats);
	rz_pvector_fini(&hdr->directories);
	free(hdr->std_opcode_lengths);
}

static bool FileEntryFormat_parse(
	RzBinEndianReader *reader, RzVector /*<RzBinDwarfFileEntryFormat>*/ *out, RzBinDwarfLineHdr *hdr) {
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

static char *directory_parse_v5(RzBinEndianReader *reader, RzBinDwarfLineHdr *hdr) {
	char *path_name = NULL;
	RzBinDwarfFileEntryFormat *format = NULL;
	rz_vector_foreach(&hdr->file_name_entry_formats, format) {
		RzBinDwarfAttr attr = { 0 };
		AttrOption opt = {
			.offset = hdr->offset,
			.form = format->form,
			.address_size = hdr->address_size,
			.is_64bit = hdr->is_64bit,
		};
		RET_NULL_IF_FAIL(RzBinDwarfAttr_parse(reader, &attr, &opt));
		if (format->content_type == DW_LNCT_path) {
			path_name = rz_bin_dwarf_attr_string(&attr, NULL, 0);
		}
	}
	return path_name;
}

static RzBinDwarfFileEntry *FileEntry_parse_v5(
	RzBinEndianReader *reader, RzBinDwarfLineHdr *hdr) {
	RzBinDwarfFileEntry *entry = RZ_NEW0(RzBinDwarfFileEntry);
	RET_FALSE_IF_FAIL(entry);
	RzBinDwarfFileEntryFormat *format = NULL;
	rz_vector_foreach(&hdr->file_name_entry_formats, format) {
		RzBinDwarfAttr attr = { 0 };
		AttrOption opt = {
			.offset = hdr->offset,
			.form = format->form,
			.address_size = hdr->address_size,
			.is_64bit = hdr->is_64bit,
		};
		ERR_IF_FAIL(RzBinDwarfAttr_parse(reader, &attr, &opt));
		switch (format->content_type) {
		case DW_LNCT_path:
			entry->path_name = rz_bin_dwarf_attr_string(&attr, NULL, 0);
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
			const RzBinDwarfBlock *b = rz_bin_dwarf_attr_block(&attr);
			memcpy(entry->md5, rz_bin_dwarf_block_data(b), 16);
			break;
		}
		default: rz_warn_if_reached(); break;
		}
	}

	return entry;
err:
	FileEntry_fini(entry, NULL);
	free(entry);
	return NULL;
}

static bool FileEntry_parse_v4(RzBinEndianReader *reader, RzBinDwarfFileEntry *entry) {
	entry->path_name = read_string_not_empty(reader);
	ERR_IF_FAIL(entry->path_name);
	ULE128_OR_GOTO(entry->directory_index, err);
	ULE128_OR_GOTO(entry->timestamp, err);
	ULE128_OR_GOTO(entry->size, err);
	memset(entry->md5, 0, sizeof(entry->md5));
	return true;
err:
	RZ_FREE(entry->path_name);
	return false;
}

/**
 * 6.2.4 The Line Number Program Header: https://dwarfstd.org/doc/DWARF5.pdf#page=172
 */
static bool LineHdr_parse_v5(RzBinEndianReader *reader, RzBinDwarfLineHdr *hdr) {
	RET_FALSE_IF_FAIL(FileEntryFormat_parse(reader, &hdr->directory_entry_formats, hdr));
	ut64 count = 0;
	ULE128_OR_RET_FALSE(count);
	for (ut64 i = 0; i < count; ++i) {
		char *dir = directory_parse_v5(reader, hdr);
		if (!dir) {
			break;
		}
		rz_pvector_push(&hdr->directories, dir);
	}

	RET_FALSE_IF_FAIL(FileEntryFormat_parse(reader, &hdr->file_name_entry_formats, hdr));
	ULE128_OR_RET_FALSE(count);
	for (ut64 i = 0; i < count; ++i) {
		RzBinDwarfFileEntry *entry = FileEntry_parse_v5(reader, hdr);
		if (!entry) {
			break;
		}
		rz_vector_push(&hdr->file_names, entry);
	}
	return true;
}

static bool LineHdr_parse_v4(RzBinEndianReader *reader, RzBinDwarfLineHdr *hdr) {
	while (true) {
		char *str = read_string_not_empty(reader);
		if (!str) {
			break;
		}
		rz_pvector_push(&hdr->directories, str);
	}
	while (true) {
		RzBinDwarfFileEntry entry = { 0 };
		if (!FileEntry_parse_v4(reader, &entry)) {
			break;
		}
		rz_vector_push(&hdr->file_names, &entry);
	}
	return true;
}

/**
 * \brief Get the full path from a file index, it will join the directory find in \p info with the filename
 * \param ctx the context
 * \param file_index the index of the file
 * \return the full path or NULL if the file index is invalid
 */
static char *full_file_path(
	DWLineOpEvalContext *ctx,
	ut64 file_index) {
	rz_return_val_if_fail(ctx && ctx->hdr, NULL);
	if (file_index >= rz_vector_len(&ctx->hdr->file_names)) {
		return NULL;
	}
	RzBinDwarfFileEntry *file = rz_vector_index_ptr(&ctx->hdr->file_names, file_index);
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

	const char *comp_dir = ctx->debug_info ? ht_up_find(ctx->debug_info->line_info_offset_comp_dir, ctx->hdr->offset, NULL)
					       : NULL;
	const char *include_dir = NULL;
	char *own_str = NULL;
	if (file->directory_index > 0 && file->directory_index - 1 < rz_pvector_len(&ctx->hdr->directories)) {
		include_dir = rz_pvector_at(&ctx->hdr->directories, file->directory_index - 1);
		if (include_dir && include_dir[0] != '/' && comp_dir) {
			include_dir = own_str = rz_str_newf("%s/%s/", comp_dir, include_dir);
		}
	} else {
		include_dir = comp_dir;
	}
	if (!include_dir) {
		include_dir = "./";
	}
	char *r = rz_str_newf("%s/%s", include_dir, file->path_name);
	free(own_str);
	return r;
}

static const char *full_file_path_cached(DWLineOpEvalContext *ctx, ut64 file_index) {
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

static ut64 LineHdr_adj_opcode(const RzBinDwarfLineHdr *hdr, ut8 opcode) {
	rz_return_val_if_fail(hdr, 0);
	return opcode - hdr->opcode_base;
}

static ut64 LineHdr_spec_op_advance_pc(const RzBinDwarfLineHdr *hdr, ut8 opcode) {
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

static st64 LineHdr_spec_op_advance_line(const RzBinDwarfLineHdr *hdr, ut8 opcode) {
	rz_return_val_if_fail(hdr, 0);
	if (!hdr->line_range) {
		// to dodge division by zero
		return 0;
	}
	ut8 adj_opcode = LineHdr_adj_opcode(hdr, opcode);
	return hdr->line_base + (adj_opcode % hdr->line_range);
}

static bool LineHdr_parse(
	RzBinEndianReader *reader,
	RzBinDwarfEncoding encoding,
	RzBinDwarfLineHdr *hdr) {
	rz_return_val_if_fail(hdr && reader && reader->buffer, false);
	LineHdr_init(hdr);
	hdr->offset = rz_buf_tell(reader->buffer);
	hdr->is_64bit = false;
	RET_FALSE_IF_FAIL(read_initial_length(reader, &hdr->is_64bit, &hdr->unit_length));

	U_OR_RET_FALSE(16, hdr->version);
	if (hdr->version < 2 || hdr->version > 5) {
		RZ_LOG_VERBOSE("DWARF line hdr version %d is not supported\n", hdr->version);
		return false;
	}
	if (hdr->version == 5) {
		U8_OR_RET_FALSE(hdr->address_size);
		U8_OR_RET_FALSE(hdr->segment_selector_size);
		if (hdr->segment_selector_size != 0) {
			RZ_LOG_ERROR("DWARF line hdr segment selector size %d is not supported\n",
				hdr->segment_selector_size);
			return false;
		}
	} else if (hdr->version < 5) {
		// Dwarf < 5 needs this size to be supplied from outside
		hdr->address_size = encoding.address_size;
	}

	RET_FALSE_IF_FAIL(read_offset(reader, &hdr->header_length, hdr->is_64bit));

	U8_OR_RET_FALSE(hdr->min_inst_len);
	if (hdr->min_inst_len == 0) {
		RZ_LOG_VERBOSE("DWARF line hdr min inst len %d is not supported\n", hdr->min_inst_len);
		return false;
	}

	if (hdr->version >= 4) {
		U8_OR_RET_FALSE(hdr->max_ops_per_inst);
	} else {
		hdr->max_ops_per_inst = 1;
	}
	if (hdr->max_ops_per_inst == 0) {
		RZ_LOG_VERBOSE("DWARF line hdr max ops per inst %d is not supported\n", hdr->max_ops_per_inst);
		return false;
	}

	U8_OR_RET_FALSE(hdr->default_is_stmt);
	ut8 line_base;
	U8_OR_RET_FALSE(line_base);
	hdr->line_base = (st8)line_base;
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
		hdr->std_opcode_lengths = calloc(sizeof(ut8), hdr->opcode_base - 1);
		RET_FALSE_IF_FAIL(hdr->std_opcode_lengths);
		RET_FALSE_IF_FAIL(rz_buf_read(reader->buffer, hdr->std_opcode_lengths, hdr->opcode_base - 1));
	} else {
		hdr->std_opcode_lengths = NULL;
	}

	if (hdr->version <= 4) {
		return LineHdr_parse_v4(reader, hdr);
	} else if (hdr->version == 5) {
		return LineHdr_parse_v5(reader, hdr);
	}
	RZ_LOG_ERROR("DWARF line hdr version %d is not supported\n", hdr->version);
	return false;
}

RZ_API void rz_bin_dwarf_line_op_fini(RZ_OWN RZ_NULLABLE RzBinDwarfLineOp *op) {
	rz_return_if_fail(op);
	if (op->type == RZ_BIN_DWARF_LINE_OP_TYPE_EXT && op->ext_opcode == DW_LNE_define_file) {
		FileEntry_fini(&op->args.define_file, NULL);
	}
}

static bool LineOp_parse_ext(
	RzBinEndianReader *reader,
	RzBinDwarfLineOp *op,
	const RzBinDwarfLineHdr *hdr) {
	rz_return_val_if_fail(op && hdr && reader && reader->buffer, false);
	ut64 op_len;
	ULE128_OR_RET_FALSE(op_len);
	// op_len must fit and be at least 1 (for the opcode byte)
	RET_FALSE_IF_FAIL(op_len > 0);

	U8_OR_RET_FALSE(op->ext_opcode);
	op->type = RZ_BIN_DWARF_LINE_OP_TYPE_EXT;

	switch (op->ext_opcode) {
	case DW_LNE_set_address: {
		UX_OR_RET_FALSE(hdr->address_size, op->args.set_address);
		break;
	}
	case DW_LNE_define_file: {
		if (hdr->version <= 4) {
			RET_FALSE_IF_FAIL(FileEntry_parse_v4(reader, &op->args.define_file));
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
		rz_buf_seek(reader->buffer, (st64)(op_len - 1), RZ_IO_SEEK_CUR);
		break;
	}
	return true;
}

/**
 * \return the number of leb128 args the std opcode takes, EXCEPT for DW_LNS_fixed_advance_pc! (see Dwarf spec)
 */
static size_t std_opcode_args_count(
	const RzBinDwarfLineHdr *hdr, ut8 opcode) {
	if (!opcode || opcode > hdr->opcode_base - 1 || !hdr->std_opcode_lengths) {
		return 0;
	}
	return hdr->std_opcode_lengths[opcode - 1];
}

static bool LineOp_parse_std(
	RzBinEndianReader *reader,
	RzBinDwarfLineOp *op,
	const RzBinDwarfLineHdr *hdr,
	DW_LNS opcode) {
	rz_return_val_if_fail(op && hdr && reader && reader->buffer, false);
	op->type = RZ_BIN_DWARF_LINE_OP_TYPE_STD;
	op->opcode = opcode;
	switch (opcode) {
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
		size_t args_count = std_opcode_args_count(hdr, opcode);
		for (size_t i = 0; i < args_count; i++) {
			ULE128_OR_GOTO(op->args.advance_pc, ok);
		}
	}
	}
ok:
	return true;
}

static void SMRegisters_reset(
	const RzBinDwarfLineHdr *hdr,
	RzBinDwarfSMRegisters *regs) {
	rz_return_if_fail(hdr && regs);
	regs->address = 0;
	regs->file = 1;
	regs->line = 1;
	regs->column = 0;
	regs->is_stmt = hdr->default_is_stmt;
	regs->basic_block = DWARF_FALSE;
	regs->end_sequence = DWARF_FALSE;
	regs->prologue_end = DWARF_FALSE;
	regs->epilogue_begin = DWARF_FALSE;
	regs->isa = 0;
}

static void store_line_sample(DWLineOpEvalContext *ctx) {
	const char *file = NULL;
	if (ctx->regs->file) {
		file = full_file_path_cached(ctx, ctx->regs->file - 1);
	}
	rz_bin_source_line_info_builder_push_sample(
		ctx->source_line_info_builder, ctx->regs->address, (ut32)ctx->regs->line, (ut32)ctx->regs->column, file);
}

/**
 * \brief Execute a single line op on regs and optionally store the resulting line info in source_line_info_builder
 * \param line_file_cache if not null, filenames will be resolved to their full paths using this cache.
 */
static bool LineOp_run(
	RZ_NONNULL RZ_BORROW RzBinDwarfLineOp *op,
	RZ_NONNULL RZ_BORROW RZ_INOUT DWLineOpEvalContext *ctx) {
	rz_return_val_if_fail(ctx && ctx->hdr && ctx->regs && op, false);
	switch (op->type) {
	case RZ_BIN_DWARF_LINE_OP_TYPE_STD:
		switch (op->opcode) {
		case DW_LNS_copy:
			if (ctx->source_line_info_builder) {
				store_line_sample(ctx);
			}
			ctx->regs->basic_block = DWARF_FALSE;
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
			ctx->regs->is_stmt = ctx->regs->is_stmt ? DWARF_FALSE : DWARF_TRUE;
			break;
		case DW_LNS_set_basic_block:
			ctx->regs->basic_block = DWARF_TRUE;
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
			ctx->regs->end_sequence = DWARF_TRUE;
			if (ctx->source_line_info_builder) {
				// closing entry
				rz_bin_source_line_info_builder_push_sample(
					ctx->source_line_info_builder, ctx->regs->address, 0, 0, NULL);
			}
			SMRegisters_reset(ctx->hdr, ctx->regs);
			break;
		case DW_LNE_set_address:
			ctx->regs->address = op->args.set_address;
			break;
		case DW_LNE_define_file:
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
		if (ctx->source_line_info_builder) {
			store_line_sample(ctx);
		}
		ctx->regs->basic_block = DWARF_FALSE;
		ctx->regs->prologue_end = DWARF_FALSE;
		ctx->regs->epilogue_begin = DWARF_FALSE;
		ctx->regs->discriminator = 0;
		break;
	default:
		return false;
	}
	return true;
}

static bool LineOp_parse_all(
	DWLineOpEvalContext *ctx,
	RzBinEndianReader *reader,
	RzVector /*<RzBinDwarfLineOp>*/ *ops_out) {
	while (true) {
		RzBinDwarfLineOp op = { .offset = rz_buf_tell(reader->buffer), 0 };
		if (rz_buf_tell(reader->buffer) > ctx->hdr->offset + ctx->hdr->unit_length + 1) {
			break;
		}
		ut8 opcode;
		U8_OR_RET_FALSE(opcode);
		if (!opcode) {
			RET_FALSE_IF_FAIL(LineOp_parse_ext(reader, &op, ctx->hdr));
		} else if (opcode >= ctx->hdr->opcode_base) {
			// special opcode without args, no further parsing needed
			op.type = RZ_BIN_DWARF_LINE_OP_TYPE_SPEC;
			op.opcode = opcode;
		} else {
			RET_FALSE_IF_FAIL(LineOp_parse_std(reader, &op, ctx->hdr, opcode));
		}
		if (ctx->source_line_info_builder) {
			RET_FALSE_IF_FAIL(LineOp_run(&op, ctx));
		}
		rz_vector_push(ops_out, &op);
	}
	return true; // number of bytes we've moved by
}

static void LineUnit_free(RzBinDwarfLineUnit *unit) {
	if (!unit) {
		return;
	}
	LineHdr_fini(&unit->header);
	rz_vector_fini(&unit->ops);
	free(unit);
}

static RzBinDwarfLine *Line_parse(
	RzBinEndianReader *reader,
	RzBinDwarfEncoding *encoding,
	RzBinDwarfInfo *debug_info) {
	// Dwarf 3 Standard 6.2 Line Number Information
	rz_return_val_if_fail(reader && reader->buffer, NULL);
	RzBinDwarfLine *li = RZ_NEW0(RzBinDwarfLine);
	if (!li) {
		return NULL;
	}
	li->units = rz_list_newf((RzListFree)LineUnit_free);
	if (!li->units) {
		free(li);
		return NULL;
	}

	RzBinSourceLineInfoBuilder source_line_info_builder;
	rz_bin_source_line_info_builder_init(&source_line_info_builder);

	// each iteration we read one header AKA comp. unit
	while (true) {
		RzBinDwarfLineUnit *unit = RZ_NEW0(RzBinDwarfLineUnit);
		if (!unit) {
			break;
		}

		if (!LineHdr_parse(reader, *encoding, &unit->header)) {
			LineUnit_free(unit);
			break;
		}

		rz_vector_init(&unit->ops, sizeof(RzBinDwarfLineOp), NULL, NULL);
		LineFilePathCache *line_file_cache = rz_pvector_new_with_len(
			free, rz_vector_len(&unit->header.file_names));
		RzBinDwarfSMRegisters regs;
		SMRegisters_reset(&unit->header, &regs);
		// we read the whole compilation unit (that might be composed of more sequences)
		do {
			if (rz_buf_tell(reader->buffer) > unit->header.offset + unit->header.unit_length + 1) {
				break;
			}
			DWLineOpEvalContext ctx = {
				.hdr = &unit->header,
				.regs = &regs,
				.source_line_info_builder = &source_line_info_builder,
				.debug_info = debug_info,
				.file_path_cache = line_file_cache,
			};
			// reads one whole sequence
			if (!LineOp_parse_all(&ctx, reader, &unit->ops)) {
				break;
			}
		} while (true); // if nothing is read -> error, exit

		rz_pvector_free(line_file_cache);
		rz_list_push(li->units, unit);
	}
	li->lines = rz_bin_source_line_info_builder_build_and_fini(&source_line_info_builder);
	return li;
}

RZ_API void rz_bin_dwarf_line_free(RZ_OWN RZ_NULLABLE RzBinDwarfLine *li) {
	if (!li) {
		return;
	}
	rz_list_free(li->units);
	rz_bin_source_line_info_free(li->lines);
	free(li);
}

RZ_API RzBinDwarfLine *rz_bin_dwarf_line_new(
	RZ_BORROW RZ_NONNULL RzBinEndianReader *reader,
	RZ_BORROW RZ_NONNULL RzBinDwarfEncoding *encoding,
	RZ_BORROW RZ_NULLABLE RzBinDwarfInfo *debug_info) {
	rz_return_val_if_fail(reader && reader->buffer && encoding, NULL);
	return Line_parse(reader, encoding, debug_info);
}

/**
 * \brief Parse the .debug_line section
 * \param bf RzBinFile to parse
 * \param info RzBinDwarfDebugInfo instance
 * \param mask RzBinDwarfLineInfoMask
 * \return RzBinDwarfLineInfo or NULL if failed
 */
RZ_API RzBinDwarfLine *rz_bin_dwarf_line_from_file(
	RZ_BORROW RZ_NONNULL RzBinFile *bf,
	RZ_BORROW RZ_NULLABLE RzBinDwarfInfo *debug_info) {
	rz_return_val_if_fail(bf, NULL);
	RzBinDwarfEncoding encoding_bf = { 0 };
	if (!RzBinDwarfEncoding_from_file(&encoding_bf, bf)) {
		return NULL;
	}

	RzBinEndianReader *reader = RzBinEndianReader_from_file(bf, ".debug_line");
	RET_NULL_IF_FAIL(reader);
	return Line_parse(reader, &encoding_bf, debug_info);
}
