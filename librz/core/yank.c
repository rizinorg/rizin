// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2019 dso <dso@rice.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_util.h>
#include <rz_io.h>

#include "core_private.h"

/* \brief Maps in a file and yank from \p offset the number of \p len bytes from \p filename.
 *
 * If the len is -1, the all the bytes are mapped into the yank buffer.
 */
static int perform_mapped_file_yank(RzCore *core, ut64 offset, ut64 len, const char *filename) {
	// grab the current file descriptor, so we can reset core and io state
	// after our io op is done
	RzIODesc *yankdesc = NULL;
	ut64 fd = core->file ? core->file->fd : -1, yank_file_sz = 0, addr = offset;
	int res = false;

	if (RZ_STR_ISNOTEMPTY(filename)) {
		ut64 load_align = rz_config_get_i(core->config, "file.loadalign");
		yankdesc = rz_io_open_nomap(core->io, filename, RZ_PERM_R, 0644);
		// map the file in for IO operations.
		if (yankdesc && load_align) {
			yank_file_sz = rz_io_size(core->io);
			ut64 addr = rz_io_map_next_available(core->io, 0, yank_file_sz, load_align);
			RzIOMap *map = rz_io_map_new(core->io, yankdesc->fd, RZ_PERM_R, 0, addr, yank_file_sz);
			if (!map || map->itv.addr == -1) {
				RZ_LOG_ERROR("Unable to map the opened file: %s\n", filename);
				rz_io_desc_close(yankdesc);
				yankdesc = NULL;
			}
		}
	}

	// if len is -1 then we yank in everything
	if (len == -1) {
		len = yank_file_sz;
	}

	// this wont happen if the file failed to open or the file failed to
	// map into the IO layer
	if (yankdesc) {
		ut64 res = rz_io_seek(core->io, addr, RZ_IO_SEEK_SET);
		ut64 actual_len = len <= yank_file_sz ? len : 0;
		ut8 *buf = NULL;
		if (actual_len > 0 && res == addr) {
			buf = malloc(actual_len);
			rz_io_read_at(core->io, addr, buf, actual_len);
			rz_core_yank_set(core, RZ_CORE_FOREIGN_ADDR, buf, len);
		} else if (res != addr) {
			RZ_LOG_ERROR(
				"Unable to yank data from file: (loadaddr (0x%" PFMT64x ") (addr (0x%" PFMT64x ") > file_sz (0x%" PFMT64x ")\n", res, addr,
				yank_file_sz);
		} else if (actual_len == 0) {
			RZ_LOG_ERROR(
				"Unable to yank from file: addr+len (0x%" PFMT64x ") > file_sz (0x%" PFMT64x ")\n", addr + len,
				yank_file_sz);
		}
		rz_io_desc_close(yankdesc);
		free(buf);
	}
	if (fd != -1) {
		rz_io_use_fd(core->io, fd);
		core->switch_file_view = 1;
		rz_core_block_read(core);
	}
	return res;
}

/* \brief Sets the contents of the yank clipboard
 *
 * Function sets the contents of the yank clibpoards as the raw bytes
 *
 * \p core RzCore instance
 * \p addr Address "where" the information was yanked from
 * \p buf Contents of the buffer to be set as the clipboard
 * \p len Length of the buffer
 */
RZ_API bool rz_core_yank_set(RzCore *core, ut64 addr, RZ_NONNULL const ut8 *buf, ut64 len) {
	rz_return_val_if_fail(buf, false);
	if (!len) {
		return false;
	}
	rz_buf_set_bytes(core->yank_buf, buf, len);
	core->yank_addr = addr;
	return true;
}

/* \brief Sets the contents of the yank clipboard
 *
 * Function sets the contents of the yank clibpoards as the NULL-terminated string
 *
 * \p core RzCore instance
 * \p addr Address "where" the information was yanked from
 * \p str Zero-terminated string to be set as the clipboard
 * \p len Length of the buffer
 */
RZ_API bool rz_core_yank_set_str(RzCore *core, ut64 addr, RZ_NONNULL const char *str) {
	rz_return_val_if_fail(str, false);
	size_t len = strlen(str) + 1;
	bool res = rz_core_yank_set(core, addr, (ut8 *)str, len);
	if (res == true) {
		ut8 zero = 0;
		rz_buf_write_at(core->yank_buf, len - 1, &zero, sizeof(zero));
	}
	return res;
}

/* \brief Yank the data at address \p addr into the clipboard
 *
 * \p core RzCore instance
 * \p addr Address we yank the data from
 * \p len Length of the data to be yanked
 */
RZ_API bool rz_core_yank(RzCore *core, ut64 addr, ut64 len) {
	if (len == 0) {
		len = core->blocksize;
	}
	ut64 curseek = core->offset;
	ut8 *buf = malloc(len);
	if (!buf) {
		return false;
	}
	if (addr != core->offset) {
		rz_core_seek(core, addr, true);
	}
	rz_io_read_at(core->io, addr, buf, len);
	rz_core_yank_set(core, addr, buf, len);
	if (curseek != addr) {
		rz_core_seek(core, curseek, true);
	}
	free(buf);
	return true;
}

/* \brief Copy a zero-terminated string to the clipboard.
 *
 * Limited either by \p maxlen or the block size
 *
 * \p core RzCore instance
 * \p addr Address we yank the data from
 * \p maxlen Maximum length of the string
 */
RZ_API bool rz_core_yank_string(RzCore *core, ut64 addr, ut64 maxlen) {
	ut64 curseek = core->offset;
	if (addr != core->offset) {
		rz_core_seek(core, addr, true);
	}
	/* Ensure space and safe termination for largest possible string allowed */
	ut8 *buf = calloc(1, core->blocksize + 1);
	if (!buf) {
		return false;
	}
	buf[core->blocksize] = 0;
	rz_io_read_at(core->io, addr, buf, core->blocksize);
	if (maxlen == 0) {
		maxlen = rz_str_nlen((const char *)buf, core->blocksize);
	} else if (maxlen > core->blocksize) {
		maxlen = core->blocksize;
	}
	rz_core_yank_set(core, addr, buf, maxlen);
	if (curseek != addr) {
		rz_core_seek(core, curseek, true);
	}
	free(buf);
	return true;
}

/* \brief Paste \p len bytes from the clipboard to the \p addr address
 */
RZ_API bool rz_core_yank_paste(RzCore *core, ut64 addr, ut64 len) {
	if (len == 0 || len >= rz_buf_size(core->yank_buf)) {
		len = rz_buf_size(core->yank_buf);
	}
	ut8 *buf = RZ_NEWS(ut8, len);
	if (!buf) {
		return false;
	}
	rz_buf_read_at(core->yank_buf, 0, buf, len);
	bool res = rz_core_write_at(core, addr, buf, len);
	free(buf);
	return res;
}

/* \brief Yanks data from the current offset to the specified offset
 *
 * At first, it copies the \p len bytes from the current offset,
 * then it pastes the same amount of bytes to the specified \p addr address
 */
RZ_API bool rz_core_yank_to(RzCore *core, ut64 len, ut64 addr) {
	bool res = false;
	if (rz_core_yank(core, core->offset, len) == true) {
		res = rz_core_yank_paste(core, addr, len);
	}
	return res;
}

/* \brief Represents yank clipboard contents as hexadecimal string starting from the \p pos position
 */
RZ_API RZ_OWN char *rz_core_yank_as_string(RzCore *core, ut64 pos) {
	int i = 0;
	RzStrBuf *buf = rz_strbuf_new("");
	for (i = pos; i < rz_buf_size(core->yank_buf); i++) {
		ut8 tmp;
		if (!rz_buf_read8_at(core->yank_buf, i, &tmp)) {
			rz_strbuf_free(buf);
			return NULL;
		}
		rz_strbuf_appendf(buf, "%02x", tmp);
	}
	return rz_strbuf_drain(buf);
}

/* \brief Prints yank clipboard contents starting from the \p pos position in various modes
 */
RZ_API bool rz_core_yank_dump(RzCore *core, ut64 pos, RzCmdStateOutput *state) {
	RzOutputMode mode = state->mode;
	PJ *pj = state->d.pj;
	int ybl = rz_buf_size(core->yank_buf);
	if (ybl <= 0) {
		RZ_LOG_ERROR("No buffer yanked already\n");
		return false;
	}
	if (pos >= ybl) {
		RZ_LOG_ERROR("Position exceeds buffer length.\n");
		return false;
	}
	char *str = rz_core_yank_as_string(core, pos);
	if (!str) {
		return false;
	}

	switch (mode) {
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_println(str);
		break;
	case RZ_OUTPUT_MODE_JSON: {
		pj_o(pj);
		pj_kn(pj, "addr", core->yank_addr);
		pj_ks(pj, "bytes", str);
		pj_end(pj);
		break;
	}
	case RZ_OUTPUT_MODE_RIZIN:
		rz_cons_printf("wx %s", str);
		rz_cons_newline();
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("0x%08" PFMT64x " %" PFMT64d " ",
			core->yank_addr + pos,
			rz_buf_size(core->yank_buf) - pos);
		rz_cons_println(str);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	free(str);
	return true;
}

/* \brief Shows yank clipboard contents as columns of hexadecimal output with headers
 */
RZ_API bool rz_core_yank_print_hexdump(RzCore *core, ut64 pos) {
	int ybl = rz_buf_size(core->yank_buf);
	if (ybl <= 0) {
		RZ_LOG_ERROR("No buffer yanked already\n");
		return false;
	}
	if (pos >= ybl) {
		RZ_LOG_ERROR("Position exceeds buffer length.\n");
		return false;
	}
	ut8 *buf = RZ_NEWS(ut8, ybl - pos);
	if (!buf) {
		return false;
	}
	rz_buf_read_at(core->yank_buf, pos, buf, ybl - pos);
	rz_core_print_hexdump(core, pos, buf, ybl - pos, 16, 1, 1);
	return true;
}

/* \brief Shows yank clipboard contents as raw string starting from the \p pos position
 */
RZ_API bool rz_core_yank_print(RzCore *core, ut64 pos) {
	int ybl = rz_buf_size(core->yank_buf);
	if (ybl <= 0) {
		RZ_LOG_ERROR("No buffer yanked already\n");
		return false;
	}
	if (pos >= ybl) {
		RZ_LOG_ERROR("Position exceeds buffer length.\n");
		return false;
	}
	ut64 sz = ybl - pos;
	char *buf = RZ_NEWS(char, sz);
	if (!buf) {
		return false;
	}
	rz_buf_read_at(core->yank_buf, pos, (ut8 *)buf, sz);
	rz_cons_memcat(buf, sz);
	rz_cons_newline();
	return true;
}

/* \brief Shows yank clipboard contents as zero-terminated string starting from the \p pos position
 */
RZ_API bool rz_core_yank_print_string(RzCore *core, ut64 pos) {
	int ybl = rz_buf_size(core->yank_buf);
	if (ybl <= 0) {
		RZ_LOG_ERROR("No buffer yanked already\n");
		return false;
	}
	if (pos >= ybl) {
		RZ_LOG_ERROR("Position exceeds buffer length.\n");
		return false;
	}
	size_t sz = ybl - pos;
	char *buf = RZ_NEWS(char, sz);
	if (!buf) {
		return false;
	}
	rz_buf_read_at(core->yank_buf, pos, (ut8 *)buf, sz);
	int len = rz_str_nlen(buf, sz);
	rz_cons_memcat(buf, len);
	rz_cons_newline();
	return true;
}

RZ_API bool rz_core_yank_hud_file(RzCore *core, const char *input) {
	if (RZ_STR_ISEMPTY(input)) {
		return false;
	}
	char *buf = rz_cons_hud_file(input);
	if (RZ_STR_ISEMPTY(buf)) {
		return false;
	}
	bool res = rz_core_yank_set_str(core, RZ_CORE_FOREIGN_ADDR, buf);
	free(buf);
	return res;
}

RZ_API bool rz_core_yank_hud_path(RzCore *core, const char *input, int dir) {
	if (RZ_STR_ISEMPTY(input)) {
		return false;
	}
	char *buf = rz_cons_hud_path(input, dir);
	if (RZ_STR_ISEMPTY(buf)) {
		free(buf);
		return false;
	}
	bool res = rz_core_yank_set_str(core, RZ_CORE_FOREIGN_ADDR, buf);
	free(buf);
	return res;
}

/* \brief Set the yank clipboard contents to the hexadecimal string
 */
RZ_API bool rz_core_yank_hexpair(RzCore *core, const char *str) {
	if (RZ_STR_ISEMPTY(str)) {
		return false;
	}
	char *out = strdup(str);
	int len = rz_hex_str2bin(str, (ut8 *)str);
	if (len > 0) {
		rz_core_yank_set(core, core->offset, (ut8 *)out, len);
	}
	free(out);
	return true;
}

/* \brief Yank the data from the file into the clipboard
 *
 * Reads \p len bytes from the \p filename starting at the \p addr position.
 *
 * \p core RzCore instance
 * \p len Length of the data to be yanked
 * \p addr Address we yank the data from (offset in the file)
 * \p filename File we yank the data from
 */
RZ_API bool rz_core_yank_file(RzCore *core, ut64 len, ut64 addr, const char *filename) {
	if (RZ_STR_ISEMPTY(filename)) {
		return false;
	}
	return perform_mapped_file_yank(core, addr, len, filename);
}

/* \brief Yank all the data from the file into the clipboard
 *
 * Reads everything from the \p filename starting at the 0 position.
 *
 * \p core RzCore instance
 * \p filename File we yank the data from
 */
RZ_API bool rz_core_yank_file_all(RzCore *core, const char *filename) {
	if (RZ_STR_ISEMPTY(filename)) {
		return false;
	}
	return perform_mapped_file_yank(core, 0, -1, filename);
}
