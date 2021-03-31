// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2019 dso <dso@rice.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_core.h"
#include "rz_util.h"
#include "rz_io.h"

/*
 * perform_mapped_file_yank will map in a file and yank from offset the number of len bytes from
 * filename.  if the len is -1, the all the bytes are mapped into the yank buffer.
 */
static int perform_mapped_file_yank(RzCore *core, ut64 offset, ut64 len, const char *filename);
static ut32 find_next_char(const char *input, char b);
static ut32 consume_chars(const char *input, char b);

static ut32 find_next_char(const char *input, char b) {
	ut32 i = 0;
	if (!input) {
		return i;
	}
	for (; *input != b; i++, input++) {
		/* nothing */
	}
	return i;
}

static ut32 consume_chars(const char *input, char b) {
	ut32 i = 0;
	if (!input) {
		return i;
	}
	for (; *input == b; i++, input++) {
		/* nothing */
	}
	return i;
}

static int perform_mapped_file_yank(RzCore *core, ut64 offset, ut64 len, const char *filename) {
	// grab the current file descriptor, so we can reset core and io state
	// after our io op is done
	RzIODesc *yankdesc = NULL;
	ut64 fd = core->file ? core->file->fd : -1, yank_file_sz = 0, addr = offset;
	int res = false;

	if (filename && *filename) {
		ut64 load_align = rz_config_get_i(core->config, "file.loadalign");
		yankdesc = rz_io_open_nomap(core->io, filename, RZ_PERM_R, 0644);
		// map the file in for IO operations.
		if (yankdesc && load_align) {
			yank_file_sz = rz_io_size(core->io);
			ut64 addr = rz_io_map_next_available(core->io, 0, yank_file_sz, load_align);
			RzIOMap *map = rz_io_map_new(core->io, yankdesc->fd, RZ_PERM_R, 0, addr, yank_file_sz);
			if (!map || map->itv.addr == -1) {
				eprintf("Unable to map the opened file: %s", filename);
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
			eprintf(
				"ERROR: Unable to yank data from file: (loadaddr (0x%" PFMT64x ") (addr (0x%" PFMT64x ") > file_sz (0x%" PFMT64x ")\n", res, addr,
				yank_file_sz);
		} else if (actual_len == 0) {
			eprintf(
				"ERROR: Unable to yank from file: addr+len (0x%" PFMT64x ") > file_sz (0x%" PFMT64x ")\n", addr + len,
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

RZ_API int rz_core_yank_set(RzCore *core, ut64 addr, const ut8 *buf, ut32 len) {
	// free (core->yank_buf);
	if (buf && len) {
		// FIXME: direct access to base should be avoided (use _sparse
		// when you need buffer that starts at given addr)
		rz_buf_set_bytes(core->yank_buf, buf, len);
		core->yank_addr = addr;
		return true;
	}
	return false;
}

// Call set and then null terminate the bytes.
RZ_API int rz_core_yank_set_str(RzCore *core, ut64 addr, const char *str, ut32 len) {
	// free (core->yank_buf);
	int res = rz_core_yank_set(core, addr, (ut8 *)str, len);
	if (res == true) {
		ut8 zero = 0;
		rz_buf_write_at(core->yank_buf, len - 1, &zero, sizeof(zero));
	}
	return res;
}

RZ_API int rz_core_yank(struct rz_core_t *core, ut64 addr, int len) {
	ut64 curseek = core->offset;
	ut8 *buf = NULL;
	if (len < 0) {
		eprintf("rz_core_yank: cannot yank negative bytes\n");
		return false;
	}
	if (len == 0) {
		len = core->blocksize;
	}
	buf = malloc(len);
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

/* Copy a zero terminated string to the clipboard. Clamp to maxlen or blocksize. */
RZ_API int rz_core_yank_string(RzCore *core, ut64 addr, int maxlen) {
	ut64 curseek = core->offset;
	ut8 *buf = NULL;
	if (maxlen < 0) {
		eprintf("rz_core_yank_string: cannot yank negative bytes\n");
		return false;
	}
	if (addr != core->offset) {
		rz_core_seek(core, addr, true);
	}
	/* Ensure space and safe termination for largest possible string allowed */
	buf = calloc(1, core->blocksize + 1);
	if (!buf) {
		return false;
	}
	buf[core->blocksize] = 0;
	rz_io_read_at(core->io, addr, buf, core->blocksize);
	if (maxlen == 0) {
		// Don't use strnlen, see: http://sourceforge.net/p/mingw/bugs/1912/
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

RZ_API int rz_core_yank_paste(RzCore *core, ut64 addr, int len) {
	if (len < 0) {
		return false;
	}
	if (len == 0 || len >= rz_buf_size(core->yank_buf)) {
		len = rz_buf_size(core->yank_buf);
	}
	ut8 *buf = RZ_NEWS(ut8, len);
	if (!buf) {
		return false;
	}
	rz_buf_read_at(core->yank_buf, 0, buf, len);
	if (!rz_core_write_at(core, addr, buf, len)) {
		return false;
	}
	return true;
}

RZ_API int rz_core_yank_to(RzCore *core, const char *_arg) {
	ut64 len = 0;
	ut64 pos = -1;
	char *str, *arg;
	int res = false;

	while (*_arg == ' ') {
		_arg++;
	}
	arg = strdup(_arg);
	str = strchr(arg, ' ');
	if (str) {
		str[0] = '\0';
		len = rz_num_math(core->num, arg);
		pos = rz_num_math(core->num, str + 1);
		str[0] = ' ';
	}
	if (!str || pos == -1 || len == 0) {
		eprintf("Usage: yt [len] [dst-addr]\n");
		free(arg);
		return res;
	}
	if (rz_core_yank(core, core->offset, len) == true) {
		res = rz_core_yank_paste(core, pos, len);
	}
	free(arg);
	return res;
}

RZ_API bool rz_core_yank_dump(RzCore *core, ut64 pos, int format) {
	bool res = false;
	int i = 0;
	int ybl = rz_buf_size(core->yank_buf);
	if (ybl > 0) {
		if (pos < ybl) {
			switch (format) {
			case 'q':
				for (i = pos; i < rz_buf_size(core->yank_buf); i++) {
					rz_cons_printf("%02x", rz_buf_read8_at(core->yank_buf, i));
				}
				rz_cons_newline();
				break;
			case 'j': {
				PJ *pj = rz_core_pj_new(core);
				if (!pj) {
					break;
				}
				pj_o(pj);
				pj_kn(pj, "addr", core->yank_addr);
				RzStrBuf *buf = rz_strbuf_new("");
				for (i = pos; i < rz_buf_size(core->yank_buf); i++) {
					rz_strbuf_appendf(buf, "%02x", rz_buf_read8_at(core->yank_buf, i));
				}
				pj_ks(pj, "bytes", rz_strbuf_get(buf));
				rz_strbuf_free(buf);
				pj_end(pj);
				rz_cons_println(pj_string(pj));
				pj_free(pj);
				break;
			}
			case '*':
				//rz_cons_printf ("yfx ");
				rz_cons_printf("wx ");
				for (i = pos; i < rz_buf_size(core->yank_buf); i++) {
					rz_cons_printf("%02x", rz_buf_read8_at(core->yank_buf, i));
				}
				//rz_cons_printf (" @ 0x%08"PFMT64x, core->yank_addr);
				rz_cons_newline();
				break;
			default:
				rz_cons_printf("0x%08" PFMT64x " %" PFMT64d " ",
					core->yank_addr + pos,
					rz_buf_size(core->yank_buf) - pos);
				for (i = pos; i < rz_buf_size(core->yank_buf); i++) {
					rz_cons_printf("%02x", rz_buf_read8_at(core->yank_buf, i));
				}
				rz_cons_newline();
			}
			res = true;
		} else {
			eprintf("Position exceeds buffer length.\n");
		}
	} else {
		if (format == 'j') {
			rz_cons_printf("{}\n");
		} else {
			eprintf("No buffer yanked already\n");
		}
	}
	return res;
}

RZ_API int rz_core_yank_hexdump(RzCore *core, ut64 pos) {
	int res = false;
	int ybl = rz_buf_size(core->yank_buf);
	if (ybl > 0) {
		if (pos < ybl) {
			ut8 *buf = RZ_NEWS(ut8, ybl - pos);
			if (!buf) {
				return false;
			}
			rz_buf_read_at(core->yank_buf, pos, buf, ybl - pos);
			rz_print_hexdump(core->print, pos,
				buf, ybl - pos, 16, 1, 1);
			res = true;
		} else {
			eprintf("Position exceeds buffer length.\n");
		}
	} else {
		eprintf("No buffer yanked already\n");
	}
	return res;
}

RZ_API int rz_core_yank_cat(RzCore *core, ut64 pos) {
	int ybl = rz_buf_size(core->yank_buf);
	if (ybl > 0) {
		if (pos < ybl) {
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
		eprintf("Position exceeds buffer length.\n");
	} else {
		rz_cons_newline();
	}
	return false;
}

RZ_API int rz_core_yank_cat_string(RzCore *core, ut64 pos) {
	int ybl = rz_buf_size(core->yank_buf);
	if (ybl > 0) {
		if (pos < ybl) {
			ut64 sz = ybl - pos;
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
		eprintf("Position exceeds buffer length.\n");
	} else {
		rz_cons_newline();
	}
	return false;
}

RZ_API int rz_core_yank_hud_file(RzCore *core, const char *input) {
	char *buf = NULL;
	bool res = false;
	ut32 len = 0;
	if (!input || !*input) {
		return false;
	}
	for (input++; *input == ' '; input++) {
		/* nothing */
	}
	buf = rz_cons_hud_file(input);
	len = buf ? strlen((const char *)buf) + 1 : 0;
	res = rz_core_yank_set_str(core, RZ_CORE_FOREIGN_ADDR, buf, len);
	free(buf);
	return res;
}

RZ_API int rz_core_yank_hud_path(RzCore *core, const char *input, int dir) {
	char *buf = NULL;
	ut32 len = 0;
	int res;
	for (input++; *input == ' '; input++) {
		/* nothing */
	}
	buf = rz_cons_hud_path(input, dir);
	len = buf ? strlen((const char *)buf) + 1 : 0;
	res = rz_core_yank_set_str(core, RZ_CORE_FOREIGN_ADDR, buf, len);
	free(buf);
	return res;
}

RZ_API bool rz_core_yank_hexpair(RzCore *core, const char *input) {
	if (!input || !*input) {
		return false;
	}
	char *out = strdup(input);
	int len = rz_hex_str2bin(input, (ut8 *)out);
	if (len > 0) {
		rz_core_yank_set(core, core->offset, (ut8 *)out, len);
	}
	free(out);
	return true;
}

RZ_API bool rz_core_yank_file_ex(RzCore *core, const char *input) {
	ut64 len = 0, adv = 0, addr = 0;
	bool res = false;

	if (!input) {
		return res;
	}
	// get the number of bytes to yank
	adv = consume_chars(input, ' ');
	len = rz_num_math(core->num, input + adv);
	if (len == 0) {
		eprintf("ERROR: Number of bytes read must be > 0\n");
		return res;
	}
	// get the addr/offset from in the file we want to read
	adv += find_next_char(input + adv, ' ');
	if (adv == 0) {
		eprintf("ERROR: Address must be specified\n");
		return res;
	}
	adv++;

	// XXX - bug, will fail if address needs to be computed and has spaces
	addr = rz_num_math(core->num, input + adv);

	adv += find_next_char(input + adv, ' ');
	if (adv == 0) {
		eprintf("ERROR: File must be specified\n");
		return res;
	}
	adv++;

	// grab the current file descriptor, so we can reset core and io state
	// after our io op is done
	return perform_mapped_file_yank(core, addr, len, input + adv);
}

RZ_API int rz_core_yank_file_all(RzCore *core, const char *input) {
	ut64 adv = 0;
	if (!input) {
		return false;
	}
	adv = consume_chars(input, ' ');
	return perform_mapped_file_yank(core, 0, -1, input + adv);
}
