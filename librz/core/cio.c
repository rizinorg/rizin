// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_core.h"
#include "core_private.h"

RZ_API int rz_core_setup_debugger(RzCore *r, const char *debugbackend, bool attach) {
	int pid, *p = NULL;
	RzIODesc *fd = r->file ? rz_io_desc_get(r->io, r->file->fd) : NULL;

	p = fd ? fd->data : NULL;
	if (!p) {
		RZ_LOG_ERROR("core: invalid debug io descriptor\n");
		return false;
	}

	rz_config_set_b(r->config, "cfg.debug", true);
	rz_config_set_b(r->config, "io.ff", true);
	rz_config_set(r->config, "dbg.backend", debugbackend);
	pid = rz_io_desc_get_pid(fd);
	rz_debug_select(r->dbg, pid, r->dbg->tid);
	r->dbg->main_pid = pid;
	if (attach) {
		rz_core_debug_attach(r, pid);
	}
	// this makes to attach twice showing warnings in the output
	// we get "resource busy" so it seems isn't an issue
	rz_core_reg_update_flags(r);
	/* honor dbg.bep */
	{
		const char *bep = rz_config_get(r->config, "dbg.bep");
		if (bep) {
			ut64 address = 0;
			if (!strcmp(bep, "loader")) {
				/* do nothing here */
			} else if (!strcmp(bep, "entry")) {
				address = rz_num_math(r->num, "entry0");
				rz_core_debug_continue_until(r, address, address);
			} else {
				address = rz_num_math(r->num, bep);
				rz_core_debug_continue_until(r, address, address);
			}
		}
	}
	rz_core_seek_to_register(r, "PC", false);

	return true;
}

RZ_API bool rz_core_dump(RzCore *core, const char *file, ut64 addr, ut64 size, int append) {
	ut64 i;
	ut8 *buf;
	int bs = core->blocksize;
	FILE *fd;
	if (append) {
		fd = rz_sys_fopen(file, "ab");
	} else {
		rz_sys_truncate(file, 0);
		fd = rz_sys_fopen(file, "wb");
	}
	if (!fd) {
		RZ_LOG_ERROR("core: cannot open '%s' for writing\n", file);
		return false;
	}
	/* some io backends seems to be buggy in those cases */
	if (bs > 4096) {
		bs = 4096;
	}
	buf = malloc(bs);
	if (!buf) {
		RZ_LOG_ERROR("core: cannot alloc %d byte(s)\n", bs);
		fclose(fd);
		return false;
	}
	rz_cons_break_push(NULL, NULL);
	for (i = 0; i < size; i += bs) {
		if (rz_cons_is_breaked()) {
			break;
		}
		if ((i + bs) > size) {
			bs = size - i;
		}
		rz_io_read_at(core->io, addr + i, buf, bs);
		if (fwrite(buf, bs, 1, fd) < 1) {
			RZ_LOG_ERROR("core: cannot write to buffer\n");
			break;
		}
	}
	rz_cons_break_pop();
	fclose(fd);
	free(buf);
	return true;
}

// Get address-specific bits and arch at a certain address.
// If there are no specific infos (i.e. asm.bits and asm.arch should apply), the bits and arch will be 0 or NULL respectively!
RZ_API void rz_core_arch_bits_at(RzCore *core, ut64 addr, RZ_OUT RZ_NULLABLE int *bits, RZ_OUT RZ_BORROW RZ_NULLABLE const char **arch) {
	int bitsval = 0;
	const char *archval = NULL;
	RzBinObject *o = rz_bin_cur_object(core->bin);
	RzBinSection *s = o ? rz_bin_get_section_at(o, addr, core->io->va) : NULL;
	if (s) {
		if (!core->fixedarch) {
			archval = s->arch;
		}
		if (!core->fixedbits && s->bits) {
			// only enforce if there's one bits set
			switch (s->bits) {
			case RZ_SYS_BITS_16:
			case RZ_SYS_BITS_32:
			case RZ_SYS_BITS_64:
				bitsval = s->bits * 8;
				break;
			}
		}
	}
	// if we found bits related with analysis hints pick it up
	if (bits && !bitsval && !core->fixedbits) {
		bitsval = rz_analysis_hint_bits_at(core->analysis, addr, NULL);
	}
	if (arch && !archval && !core->fixedarch) {
		archval = rz_analysis_hint_arch_at(core->analysis, addr, NULL);
	}
	if (bits && bitsval) {
		*bits = bitsval;
	}
	if (arch && archval) {
		*arch = archval;
	}
}

RZ_API void rz_core_seek_arch_bits(RzCore *core, ut64 addr) {
	int bits = 0;
	const char *arch = NULL;
	rz_core_arch_bits_at(core, addr, &bits, &arch);
	if (bits) {
		rz_config_set_i(core->config, "asm.bits", bits);
	}
	if (arch) {
		rz_config_set(core->config, "asm.arch", arch);
	}
}

RZ_API bool rz_core_write_at(RzCore *core, ut64 addr, const ut8 *buf, int size) {
	rz_return_val_if_fail(core && buf && addr != UT64_MAX, false);
	if (size < 1) {
		return false;
	}
	bool ret = rz_io_write_at(core->io, addr, buf, size);
	// whether the written contents affect core->block
	bool start_in_block = addr >= core->offset && addr <= core->offset + core->blocksize - 1;
	bool end_in_block = addr + size > core->offset && addr + size <= core->offset + core->blocksize;
	if (start_in_block || end_in_block) {
		rz_core_block_read(core);
	}
	if (rz_config_get_i(core->config, "cfg.wseek")) {
		rz_core_seek_delta(core, size, true);
	}
	return ret;
}

/**
 * \brief Extend the file at current offset by inserting \p size 0 bytes at \p addr
 *
 * \p addr is an physical/virtual address based on the value of eval "io.va".
 * When virtual it is translated to a physical address according to the IO map
 * at the current offset
 *
 * \param core Reference to RzCore instance
 * \param addr Address where to insert new 0 bytes.
 * \param size Number of 0 bytes to insert
 * \return true if extend operation was successful, false otherwise
 */
RZ_API bool rz_core_extend_at(RzCore *core, ut64 addr, ut64 size) {
	rz_return_val_if_fail(core, false);

	int io_va = rz_config_get_i(core->config, "io.va");
	if (io_va) {
		RzIOMap *map = rz_io_map_get(core->io, core->offset);
		if (map) {
			addr = addr - map->itv.addr + map->delta;
		}
	}
	bool ret = rz_io_extend_at(core->io, addr, size);
	rz_core_block_read(core);
	return ret;
}

/**
 * \brief Shift a block of data from \p addr of size \p b_size left or right based on \p dist.
 *
 * \param core Reference to RzCore instance
 * \param addr Address of the block of data to move
 * \param b_size Size of the block of data to move
 * \param dist Where to shift the data, whether backward or forward and how
 *             distant from the original position
 * \return true if the shift operation was succesful, false otherwise
 */
RZ_API bool rz_core_shift_block(RzCore *core, ut64 addr, ut64 b_size, st64 dist) {
	// bstart - block start, fstart file start
	ut64 fend = 0, fstart = 0, bstart = 0, file_sz = 0;
	ut8 *shift_buf = NULL;
	int res = false;

	if (!core->io || !core->file) {
		return false;
	}

	if (b_size == 0 || b_size == (ut64)-1) {
		rz_io_use_fd(core->io, core->file->fd);
		file_sz = rz_io_size(core->io);
		if (file_sz == UT64_MAX) {
			file_sz = 0;
		}
		bstart = 0;
		fend = file_sz;
		fstart = file_sz - fend;
		b_size = fend > bstart ? fend - bstart : 0;
	}

	if ((st64)b_size < 1) {
		return false;
	}
	shift_buf = calloc(b_size, 1);
	if (!shift_buf) {
		RZ_LOG_ERROR("core: cannot allocate %d byte(s)\n", (int)b_size);
		return false;
	}

	if (addr + dist < fstart) {
		res = false;
	} else if ((addr) + dist > fend) {
		res = false;
	} else {
		rz_io_use_fd(core->io, core->file->fd);
		rz_io_read_at(core->io, addr, shift_buf, b_size);
		rz_io_write_at(core->io, addr + dist, shift_buf, b_size);
		res = true;
	}
	rz_core_seek(core, addr, true);
	free(shift_buf);
	return res;
}

RZ_API int rz_core_block_read(RzCore *core) {
	if (core && core->block) {
		return rz_io_read_at(core->io, core->offset, core->block, core->blocksize);
	}
	return -1;
}

RZ_API int rz_core_is_valid_offset(RZ_NONNULL RzCore *core, ut64 offset) {
	rz_return_val_if_fail(core, -1);
	return rz_io_is_valid_offset(core->io, offset, 0);
}

/**
 * Writes the hexadecimal string at the given offset
 *
 * Returns the length of the written data.
 *
 * \param core RzCore reference
 * \param addr Address to where to write
 * \param pairs Data as the hexadecimal string
 */
RZ_API int rz_core_write_hexpair(RzCore *core, ut64 addr, const char *pairs) {
	rz_return_val_if_fail(core && pairs, 0);
	ut8 *buf = malloc(strlen(pairs) + 1);
	if (!buf) {
		return 0;
	}
	int len = rz_hex_str2bin(pairs, buf);
	if (len < 0) {
		RZ_LOG_ERROR("Could not convert hexpair '%s' to bin data\n", pairs);
		goto err;
	}
	if (!rz_core_write_at(core, addr, buf, len)) {
		RZ_LOG_ERROR("Could not write hexpair '%s' at %" PFMT64x "\n", pairs, addr);
		goto err;
	}
err:
	free(buf);
	return len;
}

/**
 * Writes the bytes \p data at address \p addr cyclically until it fills the whole block
 *
 * It repeats the data \p data with length \p len until it fills an entire block
 * starting at \p addr.
 *
 * \param core RzCore reference
 * \param addr Address to where to write
 * \param data Array of bytes to cyclically write in the block at \p addr
 * \param len Length of \p data
 */
RZ_API bool rz_core_write_block(RzCore *core, ut64 addr, ut8 *data, size_t len) {
	rz_return_val_if_fail(core && data, 0);

	ut8 *buf = RZ_NEWS(ut8, core->blocksize);
	if (!buf) {
		return false;
	}

	bool res = false;
	rz_mem_copyloop(buf, data, core->blocksize, len);
	if (!rz_core_write_at(core, addr, buf, core->blocksize)) {
		RZ_LOG_ERROR("Could not write cyclic data (%d bytes) at %" PFMT64x "\n", core->blocksize, addr);
		goto err;
	}
	res = true;
err:
	free(buf);
	return res;
}

/**
 * \brief Assembles instructions and writes the resulting data at the given offset.
 *
 * \param core RzCore reference
 * \param addr Address to where to write
 * \param instructions List of instructions to assemble as a string
 * \return Returns the length of the written data or -1 in case of error
 */
RZ_API int rz_core_write_assembly(RzCore *core, ut64 addr, RZ_NONNULL const char *instructions) {
	rz_return_val_if_fail(core && instructions, -1);

	int ret = -1;

	rz_asm_set_pc(core->rasm, core->offset);
	RzAsmCode *acode = rz_asm_massemble(core->rasm, instructions);
	if (!acode) {
		return -1;
	}
	if (acode->len <= 0) {
		ret = 0;
		goto err;
	}

	if (!rz_core_write_at(core, core->offset, acode->bytes, acode->len)) {
		RZ_LOG_ERROR("Cannot write %d bytes at 0x%" PFMT64x " address\n", acode->len, core->offset);
		core->num->value = 1;
		goto err;
	}
	ret = acode->len;
err:
	rz_asm_code_free(acode);
	return ret;
}

/**
 * \brief Assemble instructions and write the resulting data inside the current instruction.
 *
 * Assemble one or more instructions and write the resulting data inside the
 * current instruction, if the new instructions fit. Fill the rest of the bytes
 * of the old instruction with NOP
 *
 * \param core RzCore reference
 * \param addr Address to where to write
 * \param instructions List of instructions to assemble as a string
 * \return Returns the length of the written data or -1 in case of error (e.g. the new instruction does not fit)
 */
RZ_API int rz_core_write_assembly_fill(RzCore *core, ut64 addr, RZ_NONNULL const char *instructions) {
	rz_return_val_if_fail(core && instructions, -1);

	int ret = -1;

	rz_asm_set_pc(core->rasm, core->offset);
	RzAsmCode *acode = rz_asm_massemble(core->rasm, instructions);
	if (!acode) {
		return -1;
	}
	if (acode->len <= 0) {
		ret = 0;
		goto err;
	}

	RzAnalysisOp op = { 0 };
	rz_analysis_op_init(&op);
	if (rz_analysis_op(core->analysis, &op, core->offset, core->block, core->blocksize, RZ_ANALYSIS_OP_MASK_BASIC) < 1) {
		RZ_LOG_ERROR("Invalid instruction at %" PFMT64x "\n", core->offset);
		goto err;
	}
	if (op.size < acode->len) {
		RZ_LOG_ERROR("Instructions do not fit at %" PFMT64x "\n", core->offset);
		goto err;
	}
	rz_core_hack(core, "nop");

	if (!rz_core_write_at(core, core->offset, acode->bytes, acode->len)) {
		RZ_LOG_ERROR("Cannot write %d bytes at 0x%" PFMT64x " address\n", acode->len, core->offset);
		core->num->value = 1;
		goto err;
	}
	ret = acode->len;
err:
	rz_analysis_op_fini(&op);
	rz_asm_code_free(acode);
	return ret;
}

/**
 * \brief Print an IO plugin according to \p state
 *
 * \param plugin Reference to RzIOPlugin
 * \param state Specify how the plugin shall be printed
 */
RZ_API RzCmdStatus rz_core_io_plugin_print(RzIOPlugin *plugin, RzCmdStateOutput *state) {
	char str[4];
	PJ *pj = state->d.pj;
	str[0] = 'r';
	str[1] = plugin->write ? 'w' : '_';
	str[2] = plugin->isdbg ? 'd' : '_';
	str[3] = 0;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		pj_o(pj);
		pj_ks(pj, "permissions", str);
		pj_ks(pj, "name", plugin->name);
		pj_ks(pj, "description", plugin->desc);
		pj_ks(pj, "license", plugin->license);

		if (plugin->uris) {
			char *uri;
			char *uris = rz_str_dup(plugin->uris);
			RzList *plist = rz_str_split_list(uris, ",", 0);
			RzListIter *piter;
			pj_k(pj, "uris");
			pj_a(pj);
			rz_list_foreach (plist, piter, uri) {
				pj_s(pj, uri);
			}
			pj_end(pj);
			rz_list_free(plist);
			free(uris);
		}
		if (plugin->version) {
			pj_ks(pj, "version", plugin->version);
		}
		if (plugin->author) {
			pj_ks(pj, "author", plugin->author);
		}
		pj_end(pj);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_set_columnsf(state->d.t, "sssss", "perm", "license", "name", "uri", "description");
		rz_table_add_rowf(state->d.t, "sssss", str, plugin->license, plugin->name, plugin->uris, plugin->desc);
		break;
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_printf("%s\n", plugin->name);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("%s  %-8s %s (%s)",
			str, plugin->name,
			plugin->desc, plugin->license);
		if (plugin->uris) {
			rz_cons_printf(" %s", plugin->uris);
		}
		if (plugin->version) {
			rz_cons_printf(" v%s", plugin->version);
		}
		if (plugin->author) {
			rz_cons_printf(" %s", plugin->author);
		}
		rz_cons_printf("\n");
		break;
	default: {
		rz_warn_if_reached();
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}
	}
	return RZ_CMD_STATUS_OK;
}

/**
 * \brief Print the registered IO plugins according to \p state
 *
 * \param io Reference to RzIO instance
 * \param state Specify how plugins shall be printed
 */
RZ_API RzCmdStatus rz_core_io_plugins_print(RzIO *io, RzCmdStateOutput *state) {
	RzIOPlugin *plugin;
	RzIterator *iter = ht_sp_as_iter(io->plugins);
	if (!io) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "sssss", "perm", "license", "name", "uri", "description");
	rz_iterator_foreach(iter, plugin) {
		rz_core_io_plugin_print(plugin, state);
	}
	rz_iterator_free(iter);
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}

/**
 * \brief Write a given \p value at the specified \p address, using \p sz bytes
 *
 * \param core RzCore reference
 * \param addr Address where to write the value
 * \param value Value to write
 * \param sz Number of bytes to write. Can be 1, 2, 4, 8 or the special value 0
 *           if you want the function to choose based on \p value (4 if \p value
 *           is <4GB, 8 otherwise)
 */
RZ_API bool rz_core_write_value_at(RzCore *core, ut64 addr, ut64 value, int sz) {
	rz_return_val_if_fail(sz == 0 || sz == 1 || sz == 2 || sz == 4 || sz == 8, false);
	ut8 buf[sizeof(ut64)];
	bool be = rz_config_get_i(core->config, "cfg.bigendian");

	core->num->value = 0;
	if (sz == 0) {
		sz = value & UT64_32U ? 8 : 4;
	}

	switch (sz) {
	case 1:
		rz_write_ble8(buf, (ut8)(value & UT8_MAX));
		break;
	case 2:
		rz_write_ble16(buf, (ut16)(value & UT16_MAX), be);
		break;
	case 4:
		rz_write_ble32(buf, (ut32)(value & UT32_MAX), be);
		break;
	case 8:
		rz_write_ble64(buf, value, be);
		break;
	default:
		return false;
	}

	if (!rz_core_write_at(core, addr, buf, sz)) {
		RZ_LOG_ERROR("Could not write %d bytes at %" PFMT64x "\n", sz, addr);
		core->num->value = 1;
		return false;
	}
	return true;
}

/**
 * \brief Write at \p addr the current value + \p value passed as argument
 *
 * The values read/written are considered as integers of \p sz bytes.
 *
 * \param core RzCore reference
 * \param addr Address where to overwrite the value
 * \param value Value to sum to the existing value in \p addr
 * \param sz Size of the values, in bytes, to consider. Can be 1, 2, 4, 8.
 */
RZ_API bool rz_core_write_value_inc_at(RzCore *core, ut64 addr, st64 value, int sz) {
	rz_return_val_if_fail(sz == 1 || sz == 2 || sz == 4 || sz == 8, false);

	ut8 buf[sizeof(ut64)];
	bool be = rz_config_get_i(core->config, "cfg.bigendian");

	if (!rz_io_read_at_mapped(core->io, addr, buf, sz)) {
		return false;
	}

	switch (sz) {
	case 1: {
		ut8 cur = rz_read_ble8(buf);
		cur += value;
		rz_write_ble8(buf, cur);
		break;
	}
	case 2: {
		ut16 cur = rz_read_ble16(buf, be);
		cur += value;
		rz_write_ble16(buf, cur, be);
		break;
	}
	case 4: {
		ut32 cur = rz_read_ble32(buf, be);
		cur += value;
		rz_write_ble32(buf, cur, be);
		break;
	}
	case 8: {
		ut64 cur = rz_read_ble64(buf, be);
		cur += value;
		rz_write_ble64(buf, cur, be);
		break;
	}
	default:
		rz_warn_if_reached();
		break;
	}

	if (!rz_core_write_at(core, addr, buf, sz)) {
		RZ_LOG_ERROR("Could not write %d bytes at %" PFMT64x "\n", sz, addr);
		return false;
	}
	return true;
}

/**
 * \brief Write a given string \p s at the specified \p addr
 *
 * \param core RzCore reference
 * \param addr Address where to write the string
 * \param s String to write. The string is unescaped, meaning that if there is `\n` it becomes 0x0a
 */
RZ_API bool rz_core_write_string_at(RzCore *core, ut64 addr, RZ_NONNULL const char *s) {
	rz_return_val_if_fail(core && s, false);

	char *str = rz_str_dup(s);
	if (!str) {
		return false;
	}

	int len = rz_str_unescape(str);
	if (!rz_core_write_at(core, addr, (const ut8 *)str, len)) {
		RZ_LOG_ERROR("Could not write '%s' at %" PFMT64x "\n", s, addr);
		free(str);
		return false;
	}
	free(str);
	return true;
}

/**
 * \brief Write a given string \p s as a wide string at the specified \p addr
 *
 * \param core RzCore reference
 * \param addr Address where to write the string
 * \param s String to write. The string is unescaped, meaning that if there is `\n` it becomes 0x0a
 */
RZ_API bool rz_core_write_string_wide_at(RzCore *core, ut64 addr, const char *s) {
	rz_return_val_if_fail(core && s, false);

	bool res = false;
	char *str = rz_str_dup(s);
	if (!str) {
		return false;
	}

	int len = rz_str_unescape(str);
	if (len < 1) {
		goto str_err;
	}

	len++; // Consider for the terminator char
	char *tmp = RZ_NEWS(char, len * 2);
	if (!tmp) {
		goto str_err;
	}

	for (int i = 0; i < len; i++) {
		tmp[i * 2] = str[i];
		tmp[i * 2 + 1] = 0;
	}

	if (!rz_core_write_at(core, addr, (const ut8 *)tmp, len * 2)) {
		RZ_LOG_ERROR("Could not write wide string '%s' at %" PFMT64x "\n", s, addr);
		free(str);
		return false;
	}
	res = true;
str_err:
	free(str);
	return res;
}
/**
 * \brief Write at the specified \p addr the length of the string in one byte,
 * followed by the given string \p s
 *
 * \param core RzCore reference
 * \param addr Address where to write the string
 * \param s String to write. The string is unescaped, meaning that if there is `\n` it becomes 0x0a
 */
RZ_API bool rz_core_write_length_string_at(RzCore *core, ut64 addr, const char *s) {
	rz_return_val_if_fail(core && s, false);

	char *str = rz_str_dup(s);
	if (!str) {
		return false;
	}

	int len = rz_str_unescape(str);
	ut8 ulen = (ut8)len;
	if (!rz_core_write_at(core, addr, &ulen, sizeof(ulen)) ||
		!rz_core_write_at(core, addr + 1, (const ut8 *)str, len)) {
		RZ_LOG_ERROR("Could not write length+'%s' at %" PFMT64x "\n", s, addr);
		free(str);
		return false;
	}
	free(str);
	return true;
}

/**
 * \brief Write a given string \p s at the specified \p addr encoded as base64.
 *
 * \param core RzCore reference
 * \param addr Address where to write the string
 * \param s String to encode as base64 and then written.
 */
RZ_API bool rz_core_write_base64_at(RzCore *core, ut64 addr, RZ_NONNULL const char *s) {
	rz_return_val_if_fail(core && s, false);

	bool res = false;
	size_t str_len = strlen(s) + 1;
	ut8 *bin_buf = malloc(str_len);
	if (!bin_buf) {
		return false;
	}

	const int bin_len = rz_hex_str2bin(s, bin_buf);
	if (bin_len <= 0) {
		free(bin_buf);
		return false;
	}

	ut8 *buf = calloc(str_len + 1, 4);
	if (!buf) {
		free(bin_buf);
		return false;
	}

	int len = rz_base64_encode((char *)buf, bin_buf, bin_len);
	free(bin_buf);
	if (len == 0) {
		goto err;
	}

	if (!rz_core_write_at(core, addr, buf, len)) {
		RZ_LOG_ERROR("Could not write base64 encoded string '%s' at %" PFMT64x "\n", s, addr);
		goto err;
	}
	res = true;
err:
	free(buf);
	return res;
}

/**
 * \brief Write a given base64 string \p s at the specified \p addr, decoded
 *
 * \param core RzCore reference
 * \param addr Address where to write the string
 * \param s String to decode from base64 and then written
 */
RZ_API bool rz_core_write_base64d_at(RzCore *core, ut64 addr, RZ_NONNULL const char *s) {
	rz_return_val_if_fail(core && s, false);

	bool res = false;
	size_t str_len = strlen(s) + 1;
	ut8 *buf = malloc(str_len);
	int len = rz_base64_decode(buf, s, -1);
	if (len < 0) {
		goto err;
	}

	if (!rz_core_write_at(core, addr, buf, len)) {
		RZ_LOG_ERROR("Could not write base64 decoded string '%s' at %" PFMT64x "\n", s, addr);
		goto err;
	}
	res = true;
err:
	free(buf);
	return res;
}

/**
 * \brief Write \p len random bytes at address \p addr
 *
 * \param core RzCore reference
 * \param addr Address where to write the data
 * \param len Length of the random data to write
 */
RZ_API bool rz_core_write_random_at(RzCore *core, ut64 addr, size_t len) {
	rz_return_val_if_fail(core, false);

	bool res = false;
	ut8 *buf = malloc(len);
	if (!buf) {
		return false;
	}

	rz_num_irand();
	for (int i = 0; i < len; i++) {
		buf[i] = rz_num_rand32(256);
	}

	if (!rz_core_write_at(core, addr, buf, len)) {
		RZ_LOG_ERROR("Could not write random data of length %zd at %" PFMT64x "\n", len, addr);
		goto err;
	}
	res = true;
err:
	free(buf);
	return res;
}

RZ_API RzCmdStatus rz_core_io_cache_print(RzCore *core, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && core->io, RZ_CMD_STATUS_ERROR);

	size_t i, j = 0;
	void **iter;
	RzIOCache *c;

	rz_pvector_foreach (&core->io->cache, iter) {
		c = *iter;
		const ut64 dataSize = rz_itv_size(c->itv);
		switch (state->mode) {
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("idx=%" PFMTSZu " addr=0x%08" PFMT64x " size=%" PFMT64u " ", j, rz_itv_begin(c->itv), dataSize);
			for (i = 0; i < dataSize; i++) {
				rz_cons_printf("%02x", c->odata[i]);
			}
			rz_cons_printf(" -> ");
			for (i = 0; i < dataSize; i++) {
				rz_cons_printf("%02x", c->data[i]);
			}
			rz_cons_printf(" %s\n", c->written ? "(written)" : "(not written)");
			break;
		case RZ_OUTPUT_MODE_JSON:
			pj_o(state->d.pj);
			pj_kn(state->d.pj, "idx", j);
			pj_kn(state->d.pj, "addr", rz_itv_begin(c->itv));
			pj_kn(state->d.pj, "size", dataSize);
			char *hex = rz_hex_bin2strdup(c->odata, dataSize);
			pj_ks(state->d.pj, "before", hex);
			free(hex);
			hex = rz_hex_bin2strdup(c->data, dataSize);
			pj_ks(state->d.pj, "after", hex);
			free(hex);
			pj_kb(state->d.pj, "written", c->written);
			pj_end(state->d.pj);
			break;
		case RZ_OUTPUT_MODE_RIZIN:
			rz_cons_printf("wx ");
			for (i = 0; i < dataSize; i++) {
				rz_cons_printf("%02x", (ut8)(c->data[i] & 0xff));
			}
			rz_cons_printf(" @ 0x%08" PFMT64x, rz_itv_begin(c->itv));
			rz_cons_printf(" # replaces: ");
			for (i = 0; i < dataSize; i++) {
				rz_cons_printf("%02x", (ut8)(c->odata[i] & 0xff));
			}
			rz_cons_printf("\n");
			break;
		default:
			rz_warn_if_reached();
			break;
		}
		j++;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_API RzCmdStatus rz_core_io_pcache_print(RzCore *core, RzIODesc *desc, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && core->io, RZ_CMD_STATUS_ERROR);
	rz_return_val_if_fail(desc, RZ_CMD_STATUS_ERROR);

	RzList *caches = rz_io_desc_cache_list(desc);
	RzListIter *iter;
	RzIOCache *c;

	if (state->mode == RZ_OUTPUT_MODE_RIZIN) {
		rz_cons_printf("e io.va = false\n");
	}
	rz_list_foreach (caches, iter, c) {
		const int cacheSize = rz_itv_size(c->itv);
		int i;

		switch (state->mode) {
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("0x%08" PFMT64x ": %02x",
				rz_itv_begin(c->itv), c->odata[0]);
			for (i = 1; i < cacheSize; i++) {
				rz_cons_printf("%02x", c->odata[i]);
			}
			rz_cons_printf(" -> %02x", c->data[0]);
			for (i = 1; i < cacheSize; i++) {
				rz_cons_printf("%02x", c->data[i]);
			}
			rz_cons_printf("\n");
			break;
		case RZ_OUTPUT_MODE_RIZIN:
			rz_cons_printf("wx %02x", c->data[0]);
			for (i = 1; i < cacheSize; i++) {
				rz_cons_printf("%02x", c->data[i]);
			}
			rz_cons_printf(" @ 0x%08" PFMT64x " \n", rz_itv_begin(c->itv));
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	rz_list_free(caches);
	return RZ_CMD_STATUS_OK;
}

/**
 * \brief Write a given string \p s, followed by the zero terminator, at the specified \p addr
 *
 * \param core RzCore reference
 * \param addr Address where to write the string
 * \param s String to write. The string is unescaped, meaning that if there is `\n` it becomes 0x0a
 */
RZ_API bool rz_core_write_string_zero_at(RzCore *core, ut64 addr, const char *s) {
	rz_return_val_if_fail(core && s, false);

	char *str = rz_str_dup(s);
	if (!str) {
		return false;
	}

	int len = rz_str_unescape(str);
	if (!rz_core_write_at(core, addr, (const ut8 *)str, len + 1)) {
		RZ_LOG_ERROR("Could not write '%s' at %" PFMT64x "\n", s, addr);
		free(str);
		return false;
	}
	free(str);
	return true;
}

/**
 * \brief Transform a block of data at \p addr according to the operation \p op and the hexvalue \p hex
 *
 * \param core Reference to RzCore instance
 * \param addr Where the block of data to modify starts
 * \param op Operation to perform on the block of data
 * \param hex Optional hex string that may be required by the specific operation
 * \param hexlen Optional length of the \p hex string. Must be present if \p hex is specified.
 * \param buflen Used to return the length of the returned buffer
 * \return The transformed buffer
 */
RZ_API RZ_OWN ut8 *rz_core_transform_op(RzCore *core, ut64 addr, RzCoreWriteOp op, RZ_NULLABLE ut8 *hex, size_t hexlen, size_t *buflen) {
	rz_return_val_if_fail(core, NULL);
	rz_return_val_if_fail(buflen, NULL);

	switch (op) {
	case RZ_CORE_WRITE_OP_ADD:
	case RZ_CORE_WRITE_OP_SUB:
	case RZ_CORE_WRITE_OP_DIV:
	case RZ_CORE_WRITE_OP_MUL:
	case RZ_CORE_WRITE_OP_AND:
	case RZ_CORE_WRITE_OP_OR:
	case RZ_CORE_WRITE_OP_XOR:
	case RZ_CORE_WRITE_OP_SHIFT_LEFT:
	case RZ_CORE_WRITE_OP_SHIFT_RIGHT:
		rz_return_val_if_fail(hex, NULL);
		break;
	default:
		break;
	}

	ut8 *buf = RZ_NEWS(ut8, core->blocksize);
	if (!buf) {
		return NULL;
	}

	int len = rz_io_nread_at(core->io, addr, buf, core->blocksize);
	if (len < 0) {
		free(buf);
		return NULL;
	}

	for (int i = 0, j = 0; i < len; i++, j = (j + 1) % (hexlen ? hexlen : 1)) {
		ut16 tmp16;
		ut32 tmp32;
		ut64 tmp64;
		switch (op) {
		case RZ_CORE_WRITE_OP_BYTESWAP2:
			if (i + 1 < len) {
				tmp16 = rz_read_le16(buf + i);
				rz_write_be16(buf + i, tmp16);
				i++;
			}
			break;
		case RZ_CORE_WRITE_OP_BYTESWAP4:
			if (i + 3 < len) {
				tmp32 = rz_read_le32(buf + i);
				rz_write_be32(buf + i, tmp32);
				i += 3;
			}
			break;
		case RZ_CORE_WRITE_OP_BYTESWAP8:
			if (i + 7 < len) {
				tmp64 = rz_read_le64(buf + i);
				rz_write_be64(buf + i, tmp64);
				i += 7;
			}
			break;
		case RZ_CORE_WRITE_OP_ADD:
			buf[i] += hex[j];
			break;
		case RZ_CORE_WRITE_OP_SUB:
			buf[i] -= hex[j];
			break;
		case RZ_CORE_WRITE_OP_DIV:
			buf[i] = hex[j] ? buf[i] / hex[j] : 0;
			break;
		case RZ_CORE_WRITE_OP_MUL:
			buf[i] *= hex[j];
			break;
		case RZ_CORE_WRITE_OP_AND:
			buf[i] &= hex[j];
			break;
		case RZ_CORE_WRITE_OP_OR:
			buf[i] |= hex[j];
			break;
		case RZ_CORE_WRITE_OP_XOR:
			buf[i] ^= hex[j];
			break;
		case RZ_CORE_WRITE_OP_SHIFT_LEFT:
			buf[i] <<= hex[j];
			break;
		case RZ_CORE_WRITE_OP_SHIFT_RIGHT:
			buf[i] >>= hex[j];
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	*buflen = (size_t)len;
	return buf;
}

/**
 * \brief Write a full block of data according to the operation \p op and the hexvalue \p hex
 *
 * \param core Reference to RzCore instance
 * \param addr Where the block of data to modify starts
 * \param op Operation to perform on the block of data
 * \param hex Optional hex string that may be required by the specific operation
 * \param hexlen Optional length of the \p hex string. Must be present if \p hex is specified.
 * \return true if the write operation succeeds, false otherwise
 */
RZ_API bool rz_core_write_block_op_at(RzCore *core, ut64 addr, RzCoreWriteOp op, RZ_NULLABLE ut8 *hex, size_t hexlen) {
	size_t buflen;
	ut8 *buf = rz_core_transform_op(core, addr, op, hex, hexlen, &buflen);
	if (!buf) {
		return false;
	}

	if (!rz_core_write_at(core, addr, buf, buflen)) {
		RZ_LOG_ERROR("Could not write block operation at %" PFMT64x "\n", addr);
		free(buf);
		return false;
	}

	return true;
}

/**
 * \brief Write a full block of data with a sequence
 *
 * Write a full block of data with a sequence of numbers starting from \p from
 * up to \p to, with a step of \p step. The values are written as numbers of
 * \p value_size bytes.
 *
 * \param core Reference to RzCore instance
 * \param addr Where the block of data to modify starts
 * \param from From where to start the sequence of numbers
 * \param to Where to stop in the sequence
 * \param step Difference between two numbers in the sequence
 * \param value_size Size of each number of the sequence, in bytes
 * \return true if the write operation succeeds, false otherwise
 */
RZ_API bool rz_core_write_seq_at(RzCore *core, ut64 addr, ut64 from, ut64 to, ut64 step, int value_size) {
	rz_return_val_if_fail(core, false);
	rz_return_val_if_fail(value_size == 1 || value_size == 2 || value_size == 4 || value_size == 8, false);
	ut64 max_val = (1ULL << (8 * value_size));
	rz_return_val_if_fail(from < max_val, false);
	rz_return_val_if_fail(to < max_val, false);

	ut8 *buf = RZ_NEWS0(ut8, core->blocksize);
	if (!buf) {
		return false;
	}

	ut64 diff = to <= from ? max_val : to - from + 1;
	ut64 p = from;
	for (size_t i = 0; i < core->blocksize; i += value_size, p = (from + ((p + step - from) % diff)) % max_val) {
		rz_write_ble(buf + i, p, rz_config_get_b(core->config, "cfg.bigendian"), value_size * 8);
	}

	if (!rz_core_write_at(core, addr, buf, core->blocksize)) {
		RZ_LOG_ERROR("Could not write sequence [%" PFMT64d ", %" PFMT64d "] step=%" PFMT64d ",value_size=%d at %" PFMT64x "\n", from, to, step, value_size, addr);
		free(buf);
		return false;
	}

	free(buf);
	return true;
}

/**
 * \brief Copy \p len bytes from \p from to \p addr
 *
 * \param core Reference to RzCore instance
 * \param addr Where the data should be copied to
 * \param from Where the data should be read from
 * \param len Number of bytes to copy, expected to not be negative
 * \return true if the write operation succeeds, false otherwise
 */
RZ_API bool rz_core_write_duplicate_at(RzCore *core, ut64 addr, ut64 from, int len) {
	rz_return_val_if_fail(core, false);
	rz_return_val_if_fail(len >= 0, false);

	bool res = false;
	ut8 *data = RZ_NEWS(ut8, len);
	if (!data) {
		return false;
	}

	int n = rz_io_nread_at(core->io, from, data, len);
	if (n < 0) {
		RZ_LOG_ERROR("Cannot read data from %" PFMT64x ".\n", from);
		goto err;
	}
	if (!rz_core_write_at(core, addr, data, n)) {
		RZ_LOG_ERROR("Cannot write %d bytes to %" PFMT64x ".\n", n, addr);
		goto err;
	}
	res = true;
err:
	free(data);
	return res;
}
