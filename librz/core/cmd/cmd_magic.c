// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

/* ugly global vars */
static int magicdepth = 99; // XXX: do not use global var here
static RzMagic *ck = NULL; // XXX: Use RzCore->magic
static char *ofile = NULL;
static int kw_count = 0;

static void rz_core_magic_reset(RzCore *core) {
	kw_count = 0;
}

static int rz_core_magic_at(RzCore *core, const char *file, ut64 addr, int depth, int v, PJ *pj, int *hits) {
	const char *fmt;
	char *q, *p;
	const char *str;
	int delta = 0, adelta = 0, ret;
	ut64 curoffset = core->offset;
	int maxHits = rz_config_get_i(core->config, "search.maxhits");
	if (maxHits > 0 && *hits >= maxHits) {
		return 0;
	}
#define NAH 32

	if (--depth < 0) {
		ret = 0;
		goto seek_exit;
	}
	if (addr != core->offset) {
#if 1
		if (addr >= core->offset && (addr + NAH) < (core->offset + core->blocksize)) {
			delta = addr - core->offset;
		} else {
			rz_core_seek(core, addr, true);
		}
#endif
	}
	if (core->search->align) {
		int mod = addr % core->search->align;
		if (mod) {
			RZ_LOG_ERROR("core: Unaligned search at %d\n", mod);
			ret = mod;
			goto seek_exit;
		}
	}
	if (((addr & 7) == 0) && ((addr & (7 << 8)) == 0))
		if (!pj) { // update search display
			eprintf("0x%08" PFMT64x " [%d matches found]\r", addr, *hits);
		}
	if (file) {
		if (*file == ' ')
			file++;
		if (!*file)
			file = NULL;
	}
	if (file && ofile && file != ofile) {
		if (strcmp(file, ofile)) {
			rz_magic_free(ck);
			ck = NULL;
		}
	}
	if (!ck) {
		// TODO: Move RzMagic into RzCore
		rz_magic_free(ck);
		// allocate once
		ck = rz_magic_new(0);
		if (file) {
			free(ofile);
			ofile = rz_str_dup(file);
			if (!rz_magic_load(ck, file)) {
				RZ_LOG_ERROR("core: failed rz_magic_load (\"%s\") %s\n", file, rz_magic_error(ck));
				ck = NULL;
				ret = -1;
				goto seek_exit;
			}
		} else {
			const char *magicpath = rz_config_get(core->config, "dir.magic");
			if (!rz_magic_load(ck, magicpath)) {
				ck = NULL;
				RZ_LOG_ERROR("core: failed rz_magic_load (dir.magic) %s\n", rz_magic_error(ck));
				ret = -1;
				goto seek_exit;
			}
		}
	}
	// repeat:
	// if (v) rz_cons_printf ("  %d # pm %s @ 0x%"PFMT64x"\n", depth, file? file: "", addr);
	if (delta + 2 > core->blocksize) {
		RZ_LOG_ERROR("core: EOB\n");
		ret = -1;
		goto seek_exit;
	}
	str = rz_magic_buffer(ck, core->block + delta, core->blocksize - delta);
	if (str) {
		const char *cmdhit;
#if USE_LIB_MAGIC
		if (!v && (!strcmp(str, "data") || strstr(str, "ASCII") || strstr(str, "ISO") || strstr(str, "no line terminator"))) {
#else
		if (!v && (!strcmp(str, "data"))) {
#endif
			int mod = core->search->align;
			if (mod < 1) {
				mod = 1;
			}
			// rz_magic_free (ck);
			// ck = NULL;
			// return -1;
			ret = mod + 1;
			goto seek_exit;
		}
		p = rz_str_dup(str);
		fmt = p;
		// processing newlinez
		for (q = p; *q; q++) {
			if (q[0] == '\\' && q[1] == 'n') {
				*q = '\n';
				strcpy(q + 1, q + ((q[2] == ' ') ? 3 : 2));
			}
		}
		(*hits)++;
		cmdhit = rz_config_get(core->config, "cmd.hit");
		if (cmdhit && *cmdhit) {
			rz_core_cmd0(core, cmdhit);
		}
		{
			const char *searchprefix = rz_config_get(core->config, "search.prefix");
			char *flag = rz_str_newf("%s%d_%d", searchprefix, 0, kw_count++);
			rz_flag_set(core->flags, flag, addr + adelta, 1);
			free(flag);
		}
		// TODO: This must be a callback .. move this into RSearch?
		if (!pj) {
			rz_cons_printf("0x%08" PFMT64x " %d %s\n", addr + adelta, magicdepth - depth, p);
		} else {
			pj_o(pj);
			pj_kN(pj, "offset", addr + adelta);
			pj_ki(pj, "depth", magicdepth - depth);
			pj_ks(pj, "info", p);
			pj_end(pj);
		}
		rz_cons_clear_line(1);
		// eprintf ("0x%08"PFMT64x" 0x%08"PFMT64x" %d %s\n", addr+adelta, addr+adelta, magicdepth-depth, p);
		//  walking children
		for (q = p; *q; q++) {
			switch (*q) {
			case ' ':
				fmt = q + 1;
				break;
			case '@': {
				ut64 addr = 0LL;
				*q = 0;
				if (!strncmp(q + 1, "0x", 2)) {
					sscanf(q + 3, "%" PFMT64x, &addr);
				} else {
					sscanf(q + 1, "%" PFMT64d, &addr);
				}
				if (!fmt || !*fmt) {
					fmt = file;
				}
				rz_core_magic_at(core, fmt, addr, depth, 1, pj, hits);
				*q = '@';
			} break;
			}
		}
		free(p);
		rz_magic_free(ck);
		ck = NULL;
		//		return adelta+1;
	}
	adelta++;
	delta++;
#if 0
	rz_magic_free (ck);
	ck = NULL;
#endif
	{
		int mod = core->search->align;
		if (mod) {
			ret = mod; // adelta%addr + deR_ABS(mod-adelta)+1;
			goto seek_exit;
		}
	}
	ret = adelta; // found;

seek_exit:
	rz_core_seek(core, curoffset, true);
	return ret;
}

static void rz_core_magic(RzCore *core, const char *file, int v, PJ *pj) {
	ut64 addr = core->offset;
	int hits = 0;
	magicdepth = rz_config_get_i(core->config, "magic.depth"); // TODO: do not use global var here
	rz_core_magic_at(core, file, addr, magicdepth, v, pj, &hits);
	if (addr != core->offset) {
		rz_core_seek(core, addr, true);
	}
}
