/* rizin - LGPL - Copyright 2009-2019 - pancake */

#include "rz_core.h"

RZ_API int rz_core_setup_debugger (RzCore *r, const char *debugbackend, bool attach) {
	int pid, *p = NULL;
	bool is_gdb = !strcmp (debugbackend, "gdb");
	RzIODesc * fd = r->file ? rz_io_desc_get (r->io, r->file->fd) : NULL;
	const char *prompt = NULL;

	p = fd ? fd->data : NULL;
	rz_config_set_i (r->config, "cfg.debug", 1);
	if (!p) {
		eprintf ("Invalid debug io\n");
		return false;
	}

	rz_config_set (r->config, "io.ff", "true");
	rz_core_cmdf (r, "dL %s", debugbackend);
	if (!is_gdb) {
		pid = rz_io_desc_get_pid (fd);
		rz_core_cmdf (r, "dp=%d", pid);
		if (attach) {
			rz_core_cmdf (r, "dpa %d", pid);
		}
	}
	//this makes to attach twice showing warnings in the output
	//we get "resource busy" so it seems isn't an issue
	rz_core_cmd (r, ".dr*", 0);
	/* honor dbg.bep */
	{
		const char *bep = rz_config_get (r->config, "dbg.bep");
		if (bep) {
			if (!strcmp (bep, "loader")) {
				/* do nothing here */
			} else if (!strcmp (bep, "entry")) {
				rz_core_cmd (r, "dcu entry0", 0);
			} else {
				rz_core_cmdf (r, "dcu %s", bep);
			}
		}
	}
	rz_core_cmd (r, "sr PC", 0);

	/* set the prompt if it's not been set already by the callbacks */
	prompt = rz_config_get (r->config, "cmd.prompt");
	if (prompt && !strcmp (prompt, "")) {
		if (rz_config_get_i (r->config, "dbg.status")) {
			rz_config_set (r->config, "cmd.prompt", ".dr*;drd;sr PC;pi 1;s-");
		} else {
			rz_config_set (r->config, "cmd.prompt", ".dr*");
		}
	}
	rz_config_set (r->config, "cmd.vprompt", ".dr*");
	rz_config_set (r->config, "cmd.gprompt", ".dr*");
	return true;
}

RZ_API int rz_core_seek_base (RzCore *core, const char *hex) {
	ut64 addr = rz_num_tail (core->num, core->offset, hex);
	return rz_core_seek (core, addr, true);
}

RZ_API bool rz_core_dump(RzCore *core, const char *file, ut64 addr, ut64 size, int append) {
	ut64 i;
	ut8 *buf;
	int bs = core->blocksize;
	FILE *fd;
	if (append) {
		fd = rz_sandbox_fopen (file, "ab");
	} else {
		rz_sys_truncate (file, 0);
		fd = rz_sandbox_fopen (file, "wb");
	}
	if (!fd) {
		eprintf ("Cannot open '%s' for writing\n", file);
		return false;
	}
	/* some io backends seems to be buggy in those cases */
	if (bs > 4096) {
		bs = 4096;
	}
	buf = malloc (bs);
	if (!buf) {
		eprintf ("Cannot alloc %d byte(s)\n", bs);
		fclose (fd);
		return false;
	}
	rz_cons_break_push (NULL, NULL);
	for (i = 0; i < size; i += bs) {
		if (rz_cons_is_breaked ()) {
			break;
		}
		if ((i + bs) > size) {
			bs = size - i;
		}
		rz_io_read_at (core->io, addr + i, buf, bs);
		if (fwrite (buf, bs, 1, fd) < 1) {
			eprintf ("write error\n");
			break;
		}
	}
	rz_cons_break_pop ();
	fclose (fd);
	free (buf);
	return true;
}

static bool __endian_swap(ut8 *buf, ut32 blocksize, ut8 len) {
	ut32 i;
	ut16 v16;
	ut32 v32;
	ut64 v64;
	if (len != 8 && len != 4 && len != 2 && len != 1) {
		eprintf ("Invalid word size. Use 1, 2, 4 or 8\n");
		return false;
	}
	if (len == 1) {
		return true;
	}
	for (i = 0; i < blocksize; i += len) {
		switch (len) {
		case 8:
			v64 = rz_read_at_be64 (buf, i);
			rz_write_at_le64 (buf, v64, i);
			break;
		case 4:
			v32 = rz_read_at_be32 (buf, i);
			rz_write_at_le32 (buf, v32, i);
			break;
		case 2:
			v16 = rz_read_at_be16 (buf, i);
			rz_write_at_le16 (buf, v16, i);
			break;
		}
	}
	return true;
}

RZ_API ut8* rz_core_transform_op(RzCore *core, const char *arg, char op) {
	int i, j;
	ut64 len;
	char *str = NULL;
	ut8 *buf;

	buf = (ut8 *)malloc (core->blocksize);
	if (!buf) {
		return NULL;
	}
	memcpy (buf, core->block, core->blocksize);

	if (op!='e') {
		// fill key buffer either from arg or from clipboard
		if (arg) {  // parse arg for key
			// rz_hex_str2bin() is guaranteed to output maximum half the
			// input size, or 1 byte if there is just a single nibble.
			str = (char *)malloc (strlen (arg) / 2 + 1);
			if (!str) {
				goto beach;
			}
			len = rz_hex_str2bin (arg, (ut8 *)str);
			// Output is invalid if there was just a single nibble,
			// but in that case, len is negative (-1).
			if (len <= 0) {
				eprintf ("Invalid hexpair string\n");
				goto beach;
			}
		} else {  // use clipboard as key
			const ut8 *tmp = rz_buf_data (core->yank_buf, &len);
			str = rz_mem_dup (tmp, len);
			if (!str) {
				goto beach;
			}
		}
	} else {
		len = 0;
	}

	// execute the operand
	if (op=='e') {
		int wordsize = 1;
		char *os, *p, *s = strdup (arg);
		int n = 0, from = 0, to = UT8_MAX, dif = 0, step = 1;
		os = s;
		p = strchr (s, ' ');
		if (p) {
			*p = 0;
			from = rz_num_math (core->num, s);
			s = p + 1;
		}
		p = strchr (s, ' ');
		if (p) {
			*p = 0;
			to = rz_num_math (core->num, s);
			s = p + 1;
		}
		p = strchr (s, ' ');
		if (p) {
			*p = 0;
			step = rz_num_math (core->num, s);
			s = p + 1;
			wordsize = rz_num_math (core->num, s);
		} else {
			step = rz_num_math (core->num, s);
		}
		free (os);
		eprintf ("from %d to %d step %d size %d\n", from, to, step, wordsize);
		dif = (to <= from)? UT8_MAX: to - from + 1;
		if (wordsize == 1) {
			from %= (UT8_MAX + 1);
		}
		if (dif < 1) {
			dif = UT8_MAX + 1;
		}
		if (step < 1) {
			step = 1;
		}
		if (wordsize < 1) {
			wordsize = 1;
		}
		if (wordsize == 1) {
			for (i = n = 0; i < core->blocksize; i++, n += step) {
				buf[i] = (ut8)(n % dif) + from;
			}
		} else if (wordsize == 2) {
			ut16 num16 = from;
			for (i = 0; i < core->blocksize; i += wordsize, num16 += step) {
				rz_write_le16 (buf + i, num16);
			}
		} else if (wordsize == 4) {
			ut32 num32 = from;
			for (i = 0; i < core->blocksize; i += wordsize, num32 += step) {
				rz_write_le32 (buf + i, num32);
			}
		} else if (wordsize == 8) {
			ut64 num64 = from;
			for (i = 0; i < core->blocksize; i += wordsize, num64 += step) {
				rz_write_le64 (buf + i, num64);
			}
		} else {
			eprintf ("Invalid word size. Use 1, 2, 4 or 8\n");
		}
	} else if (op == '2' || op == '4' || op == '8') { // "wo2" "wo4" "wo8"
		int inc = op - '0';
		ut8 tmp;
		for (i = 0; (i + inc) <= core->blocksize; i += inc) {
			if (inc == 2) {
				tmp = buf[i];
				buf[i] = buf[i+1];
				buf[i+1] = tmp;
			} else if (inc == 4) {
				tmp = buf[i];
				buf[i] = buf[i+3];
				buf[i+3] = tmp;
				tmp = buf[i+1];
				buf[i+1] = buf[i+2];
				buf[i+2] = tmp;
			} else if (inc == 8) {
				tmp = buf[i];
				buf[i] = buf[i+7];
				buf[i+7] = tmp;

				tmp = buf[i+1];
				buf[i+1] = buf[i+6];
				buf[i+6] = tmp;

				tmp = buf[i+2];
				buf[i+2] = buf[i+5];
				buf[i+5] = tmp;

				tmp = buf[i+3];
				buf[i+3] = buf[i+4];
				buf[i+4] = tmp;
			} else {
				eprintf ("Invalid inc, use 2, 4 or 8.\n");
				break;
			}
		}
	} else {
		bool be = rz_config_get_i (core->config, "cfg.bigendian");
		if (!be) {
			if (!__endian_swap ((ut8*)str, len, len)) {
				goto beach;
			}
		}
		for (i = j = 0; i < core->blocksize; i++) {
			switch (op) {
			case 'x': buf[i] ^= str[j]; break;
			case 'a': buf[i] += str[j]; break;
			case 's': buf[i] -= str[j]; break;
			case 'm': buf[i] *= str[j]; break;
			case 'w': buf[i] = str[j]; break;
			case 'd': buf[i] = (str[j])? (buf[i] / str[j]): 0; break;
			case 'r': buf[i] >>= str[j]; break;
			case 'l': buf[i] <<= str[j]; break;
			case 'o': buf[i] |= str[j]; break;
			case 'A': buf[i] &= str[j]; break;
			}
			j++;
			if (j >= len) {
				j = 0; /* cyclic key */
			}
		}
	}

	free (str);
	return buf;
beach:
	free (str);
	free (buf);
	return NULL;
}

RZ_API int rz_core_write_op(RzCore *core, const char *arg, char op) {
	ut8 *buf = rz_core_transform_op(core, arg, op);
	if (!buf) {
		return false;
	}
	int ret = rz_core_write_at (core, core->offset, buf, core->blocksize);
	free (buf);
	return ret;
}

// Get address-specific bits and arch at a certain address.
// If there are no specific infos (i.e. asm.bits and asm.arch should apply), the bits and arch will be 0 or NULL respectively!
RZ_API void rz_core_arch_bits_at(RzCore *core, ut64 addr, RZ_OUT RZ_NULLABLE int *bits, RZ_OUT RZ_BORROW RZ_NULLABLE const char **arch) {
	int bitsval = 0;
	const char *archval = NULL;
	RzBinObject *o = rz_bin_cur_object (core->bin);
	RzBinSection *s = o ? rz_bin_get_section_at (o, addr, core->io->va) : NULL;
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
	//if we found bits related with anal hints pick it up
	if (bits && !bitsval && !core->fixedbits) {
		bitsval = rz_anal_hint_bits_at (core->anal, addr, NULL);
	}
	if (arch && !archval && !core->fixedarch) {
		archval = rz_anal_hint_arch_at (core->anal, addr, NULL);
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
	rz_core_arch_bits_at (core, addr, &bits, &arch);
	if (bits) {
		rz_config_set_i (core->config, "asm.bits", bits);
	}
	if (arch) {
		rz_config_set (core->config, "asm.arch", arch);
	}
}

RZ_API bool rz_core_seek(RzCore *core, ut64 addr, bool rb) {
	core->offset = rz_io_seek (core->io, addr, RZ_IO_SEEK_SET);
	if (rb) {
		rz_core_block_read (core);
	}
	if (core->binat) {
		RzBinFile *bf = rz_bin_file_at (core->bin, core->offset);
		if (bf) {
			core->bin->cur = bf;
			rz_bin_select_bfid (core->bin, bf->id);
			// XXX rz_core_cmdf (core, "obb %d", bf->id);
		} else {
			core->bin->cur = NULL;
		}
	}
	return core->offset == addr;
}

RZ_API int rz_core_seek_delta(RzCore *core, st64 addr) {
	ut64 tmp = core->offset;
	if (addr == 0) {
		return true;
	}
	if (addr > 0LL) {
		/* TODO: check end of file */
		addr += tmp;
	} else {
		/* check < 0 */
		if (-addr > tmp) {
			addr = 0;
		} else {
			addr += tmp;
		}
	}
	core->offset = addr;
	return rz_core_seek (core, addr, true);
}

// TODO: kill this wrapper
RZ_API bool rz_core_write_at(RzCore *core, ut64 addr, const ut8 *buf, int size) {
	rz_return_val_if_fail (core && buf && addr != UT64_MAX, false);
	if (size < 1) {
		return false;
	}
	bool ret = rz_io_write_at (core->io, addr, buf, size);
	if (addr >= core->offset && addr <= core->offset + core->blocksize - 1) {
		rz_core_block_read (core);
	}
	return ret;
}

RZ_API bool rz_core_extend_at(RzCore *core, ut64 addr, int size) {
	if (!core->io || !core->file || size < 1) {
		return false;
	}
	int io_va = rz_config_get_i (core->config, "io.va");
	if (io_va) {
		RzIOMap *map = rz_io_map_get (core->io, core->offset);
		if (map) {
			addr = addr - map->itv.addr + map->delta;
		}
		rz_config_set_i (core->config, "io.va", false);
	}
	int ret = rz_io_extend_at (core->io, addr, size);
	if (addr >= core->offset && addr <= core->offset+core->blocksize) {
		rz_core_block_read (core);
	}
	rz_config_set_i (core->config, "io.va", io_va);
	return ret;
}

RZ_API int rz_core_shift_block(RzCore *core, ut64 addr, ut64 b_size, st64 dist) {
	// bstart - block start, fstart file start
	ut64 fend = 0, fstart = 0, bstart = 0, file_sz = 0;
	ut8 * shift_buf = NULL;
	int res = false;

	if (!core->io || !core->file) {
		return false;
	}

	if (b_size == 0 || b_size == (ut64) -1) {
		rz_io_use_fd (core->io, core->file->fd);
		file_sz = rz_io_size (core->io);
		if (file_sz == UT64_MAX) {
			file_sz = 0;
		}
#if 0
		bstart = rz_io_seek (core->io, addr, RZ_IO_SEEK_SET);
		fend = rz_io_seek (core->io, 0, RZ_IO_SEEK_END);
		if (fend < 1) {
			fend = 0;
		}
#else
		bstart = 0;
		fend = file_sz;
#endif
		fstart = file_sz - fend;
		b_size = fend > bstart ? fend - bstart: 0;
	}

	if ((st64)b_size < 1) {
		return false;
	}
	shift_buf = calloc (b_size, 1);
	if (!shift_buf) {
		eprintf ("Cannot allocated %d byte(s)\n", (int)b_size);
		return false;
	}

	// cases
	// addr + b_size + dist > file_end
	//if ( (addr+b_size) + dist > file_end ) {
	//	res = false;
	//}
	// addr + b_size + dist < file_start (should work since dist is signed)
	//else if ( (addr+b_size) + dist < 0 ) {
	//	res = false;
	//}
	// addr + dist < file_start
	if (addr + dist < fstart) {
		res = false;
	// addr + dist > file_end
	} else if ( (addr) + dist > fend) {
		res = false;
	} else {
		rz_io_use_fd (core->io, core->file->fd);
		rz_io_read_at (core->io, addr, shift_buf, b_size);
		rz_io_write_at (core->io, addr + dist, shift_buf, b_size);
		res = true;
	}
	rz_core_seek (core, addr, true);
	free (shift_buf);
	return res;
}

RZ_API int rz_core_block_read(RzCore *core) {
	if (core && core->block) {
		return rz_io_read_at (core->io, core->offset, core->block, core->blocksize);
	}
	return -1;
}

RZ_API int rz_core_is_valid_offset (RzCore *core, ut64 offset) {
	if (!core) {
		eprintf ("rz_core_is_valid_offset: core is NULL\n");
		rz_sys_backtrace ();
		return -1;
	}
	return rz_io_is_valid_offset (core->io, offset, 0);
}
