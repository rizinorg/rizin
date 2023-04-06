// SPDX-FileCopyrightText: 2010-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <ht_uu.h>
#include <rz_asm.h>
#include <rz_core.h>
#include <rz_io.h>
#include <rz_list.h>
#include <rz_types_base.h>
#include "../core_private.h"

#include "cmd_search_rop.c"

#define AES_SEARCH_LENGTH         40
#define PRIVATE_KEY_SEARCH_LENGTH 11

static int preludecnt = 0;
static int searchflags = 0;
static int searchshow = 0;
static const char *searchprefix = NULL;

struct search_parameters {
	RzCore *core;
	RzList /*<RzIOMap *>*/ *boundaries;
	const char *mode;
	const char *cmd_hit;
	PJ *pj;
	int outmode; // 0 or RZ_MODE_RIZINCMD or RZ_MODE_JSON
	bool inverse;
	bool aes_search;
	bool privkey_search;
};

struct endlist_pair {
	int instr_offset;
	int delay_size;
};

static int __prelude_cb_hit(RzSearchKeyword *kw, void *user, ut64 addr) {
	RzCore *core = (RzCore *)user;
	int depth = rz_config_get_i(core->config, "analysis.depth");
	// eprintf ("ap: Found function prelude %d at 0x%08"PFMT64x"\n", preludecnt, addr);
	rz_core_analysis_fcn(core, addr, -1, RZ_ANALYSIS_XREF_TYPE_NULL, depth);
	preludecnt++;
	return 1;
}

RZ_API int rz_core_search_prelude(RzCore *core, ut64 from, ut64 to, const ut8 *buf, int blen, const ut8 *mask, int mlen) {
	ut64 at;
	ut8 *b = (ut8 *)malloc(core->blocksize);
	if (!b) {
		return 0;
	}
	// TODO: handle sections ?
	if (from >= to) {
		RZ_LOG_ERROR("core: Invalid search range 0x%08" PFMT64x " - 0x%08" PFMT64x "\n", from, to);
		free(b);
		return 0;
	}
	rz_search_reset(core->search, RZ_SEARCH_KEYWORD);
	rz_search_kw_add(core->search, rz_search_keyword_new(buf, blen, mask, mlen, NULL));
	rz_search_begin(core->search);
	rz_search_set_callback(core->search, &__prelude_cb_hit, core);
	preludecnt = 0;
	for (at = from; at < to; at += core->blocksize) {
		if (rz_cons_is_breaked()) {
			break;
		}
		if (!rz_io_is_valid_offset(core->io, at, 0)) {
			break;
		}
		(void)rz_io_read_at(core->io, at, b, core->blocksize);
		if (rz_search_update(core->search, at, b, core->blocksize) == -1) {
			RZ_LOG_ERROR("core: update read error at 0x%08" PFMT64x "\n", at);
			break;
		}
	}
	// rz_search_reset might also benifet from having an if(s->data) RZ_FREE(s->data), but im not sure.
	// add a commit that puts it in there to this PR if it wouldn't break anything. (don't have to worry about this happening again, since all searches start by resetting core->search)
	// For now we will just use rz_search_kw_reset
	rz_search_kw_reset(core->search);
	free(b);
	return preludecnt;
}

RZ_API int rz_core_search_preludes(RzCore *core, bool log) {
	int ret = -1;
	ut64 from = UT64_MAX;
	ut64 to = UT64_MAX;
	int keyword_length = 0;
	ut8 *keyword = NULL;
	const char *prelude = rz_config_get(core->config, "analysis.prelude");
	const char *where = rz_config_get(core->config, "analysis.in");

	RzList *list = rz_core_get_boundaries_prot(core, RZ_PERM_X, where, "search");
	RzList *arch_preludes = NULL;
	RzListIter *iter = NULL, *iter2 = NULL;
	RzIOMap *p = NULL;
	RzSearchKeyword *kw = NULL;

	if (!list) {
		return -1;
	}

	if (RZ_STR_ISNOTEMPTY(prelude)) {
		keyword = malloc(strlen(prelude) + 1);
		if (!keyword) {
			RZ_LOG_ERROR("aap: cannot allocate 'analysis.prelude' buffer\n");
			rz_list_free(list);
			return -1;
		}
		keyword_length = rz_hex_str2bin(prelude, keyword);
	} else {
		arch_preludes = rz_analysis_preludes(core->analysis);
		if (!arch_preludes) {
			rz_list_free(list);
			return -1;
		}
	}

	rz_list_foreach (list, iter, p) {
		if (!(p->perm & RZ_PERM_X)) {
			continue;
		}
		from = p->itv.addr;
		to = rz_itv_end(p->itv);
		if (keyword && keyword_length > 0) {
			ret = rz_core_search_prelude(core, from, to, keyword, keyword_length, NULL, 0);
		} else {
			rz_list_foreach (arch_preludes, iter2, kw) {
				ret = rz_core_search_prelude(core, from, to,
					kw->bin_keyword, kw->keyword_length,
					kw->bin_binmask, kw->binmask_length);
			}
		}
	}
	free(keyword);
	rz_list_free(list);
	rz_list_free(arch_preludes);
	return ret;
}

/* TODO: maybe move into util/str */
static char *getstring(char *b, int l) {
	char *r, *res = malloc(l + 1);
	int i;
	if (!res) {
		return NULL;
	}
	for (i = 0, r = res; i < l; b++, i++) {
		if (IS_PRINTABLE(*b)) {
			*r++ = *b;
		}
	}
	*r = 0;
	return res;
}

static int _cb_hit(RzSearchKeyword *kw, void *user, ut64 addr) {
	struct search_parameters *param = user;
	RzCore *core = param->core;
	const RzSearch *search = core->search;
	ut64 base_addr = 0;
	bool use_color = core->print->flags & RZ_PRINT_FLAGS_COLOR;
	int keyword_len = kw ? kw->keyword_length + (search->mode == RZ_SEARCH_DELTAKEY) : 0;

	if (searchshow && kw && kw->keyword_length > 0) {
		int len, i, extra, mallocsize;
		char *s = NULL, *str = NULL, *p = NULL;
		extra = (param->outmode == RZ_MODE_JSON) ? 3 : 1;
		const char *type = "hexpair";
		ut8 *buf = malloc(keyword_len);
		if (!buf) {
			return 0;
		}
		switch (kw->type) {
		case RZ_SEARCH_KEYWORD_TYPE_STRING: {
			const int ctx = 16;
			const int prectx = addr > 16 ? ctx : addr;
			char *pre, *pos, *wrd;
			const int len = keyword_len;
			char *buf = calloc(1, len + 32 + ctx * 2);
			type = "string";
			rz_io_read_at(core->io, addr - prectx, (ut8 *)buf, len + (ctx * 2));
			pre = getstring(buf, prectx);
			pos = getstring(buf + prectx + len, ctx);
			if (!pos) {
				pos = strdup("");
			}
			if (param->outmode == RZ_MODE_JSON) {
				wrd = getstring(buf + prectx, len);
				s = rz_str_newf("%s%s%s", pre, wrd, pos);
			} else {
				wrd = rz_str_utf16_encode(buf + prectx, len);
				s = rz_str_newf(use_color ? ".%s" Color_YELLOW "%s" Color_RESET "%s."
							  : "\"%s%s%s\"",
					pre, wrd, pos);
			}
			free(buf);
			free(pre);
			free(wrd);
			free(pos);
		}
			free(p);
			break;
		default:
			len = keyword_len; // 8 byte context
			mallocsize = (len * 2) + extra;
			str = (len > 0xffff) ? NULL : malloc(mallocsize);
			if (str) {
				p = str;
				memset(str, 0, len);
				rz_io_read_at(core->io, base_addr + addr, buf, keyword_len);
				if (param->outmode == RZ_MODE_JSON) {
					p = str;
				}
				const int bytes = (len > 40) ? 40 : len;
				for (i = 0; i < bytes; i++) {
					sprintf(p, "%02x", buf[i]);
					p += 2;
				}
				if (bytes != len) {
					strcpy(p, "...");
					p += 3;
				}
				*p = 0;
			} else {
				RZ_LOG_ERROR("core: Cannot allocate %d\n", mallocsize);
			}
			s = str;
			str = NULL;
			break;
		}

		if (param->outmode == RZ_MODE_JSON) {
			pj_o(param->pj);
			pj_kN(param->pj, "offset", base_addr + addr);
			pj_ks(param->pj, "type", type);
			pj_ks(param->pj, "data", s);
			pj_end(param->pj);
		} else {
			rz_cons_printf("0x%08" PFMT64x " %s%d_%d %s\n",
				base_addr + addr, searchprefix, kw->kwidx, kw->count, s);
		}
		free(s);
		free(buf);
		free(str);
	} else if (kw) {
		if (param->outmode == RZ_MODE_JSON) {
			pj_o(param->pj);
			pj_kN(param->pj, "offset", base_addr + addr);
			pj_ki(param->pj, "len", keyword_len);
			pj_end(param->pj);
		} else {
			if (searchflags) {
				rz_cons_printf("%s%d_%d\n", searchprefix, kw->kwidx, kw->count);
			} else {
				rz_cons_printf("f %s%d_%d %d @ 0x%08" PFMT64x "\n", searchprefix,
					kw->kwidx, kw->count, keyword_len, base_addr + addr);
			}
		}
	}
	if (searchflags && kw) {
		const char *flag = sdb_fmt("%s%d_%d", searchprefix, kw->kwidx, kw->count);
		rz_flag_set(core->flags, flag, base_addr + addr, keyword_len);
	}
	if (*param->cmd_hit) {
		ut64 here = core->offset;
		rz_core_seek(core, base_addr + addr, true);
		rz_core_cmd(core, param->cmd_hit, 0);
		rz_core_seek(core, here, true);
	}
	return true;
}

static int c = 0;

static inline void print_search_progress(ut64 at, ut64 to, int n, struct search_parameters *param) {
	if ((++c % 64) || (param->outmode == RZ_MODE_JSON)) {
		return;
	}
	if (rz_cons_singleton()->columns < 50) {
		eprintf("\r[  ]  0x%08" PFMT64x "  hits = %d   \r%s",
			at, n, (c % 2) ? "[ #]" : "[# ]");
	} else {
		eprintf("\r[  ]  0x%08" PFMT64x " < 0x%08" PFMT64x "  hits = %d   \r%s",
			at, to, n, (c % 2) ? "[ #]" : "[# ]");
	}
}

static void append_bound(RzList /*<RzIOMap *>*/ *list, RzIO *io, RzInterval search_itv, ut64 from, ut64 size, int perms) {
	RzIOMap *map = RZ_NEW0(RzIOMap);
	if (!map) {
		return;
	}
	if (io && io->desc) {
		map->fd = rz_io_fd_get_current(io);
	}

	map->perm = perms;
	RzInterval itv = { from, size };
	if (size == -1) {
		RZ_LOG_ERROR("core: Invalid range. Use different search.in=? or analysis.in=dbg.maps.x\n");
		free(map);
		return;
	}
	// TODO UT64_MAX is a valid address. search.from and search.to are not specified
	if (search_itv.addr == UT64_MAX && !search_itv.size) {
		map->itv = itv;
		rz_list_append(list, map);
	} else if (rz_itv_overlap(itv, search_itv)) {
		map->itv = rz_itv_intersect(itv, search_itv);
		if (map->itv.size) {
			rz_list_append(list, map);
		} else {
			free(map);
		}
	} else {
		free(map);
	}
}

static bool maskMatches(int perm, int mask, bool only) {
	if (mask) {
		if (only) {
			return ((perm & 7) != mask);
		}
		return (perm & mask) != mask;
	}
	return false;
}

RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_prot(RzCore *core, int perm, const char *mode, const char *prefix) {
	rz_return_val_if_fail(core, NULL);

	RzList *list = rz_list_newf(free); // XXX rz_io_map_free);
	if (!list) {
		return NULL;
	}

	char bound_in[32];
	char bound_from[32];
	char bound_to[32];
	snprintf(bound_in, sizeof(bound_in), "%s.%s", prefix, "in");
	snprintf(bound_from, sizeof(bound_from), "%s.%s", prefix, "from");
	snprintf(bound_to, sizeof(bound_to), "%s.%s", prefix, "to");
	const ut64 search_from = rz_config_get_i(core->config, bound_from),
		   search_to = rz_config_get_i(core->config, bound_to);
	const RzInterval search_itv = { search_from, search_to - search_from };
	if (!mode) {
		mode = rz_config_get(core->config, bound_in);
	}
	if (!rz_config_get_b(core->config, "cfg.debug") && !core->io->va) {
		append_bound(list, core->io, search_itv, 0, rz_io_size(core->io), 7);
	} else if (!strcmp(mode, "file")) {
		append_bound(list, core->io, search_itv, 0, rz_io_size(core->io), 7);
	} else if (!strcmp(mode, "block")) {
		append_bound(list, core->io, search_itv, core->offset, core->blocksize, 7);
	} else if (!strcmp(mode, "io.map")) {
		RzIOMap *m = rz_io_map_get(core->io, core->offset);
		if (m) {
			append_bound(list, core->io, search_itv, m->itv.addr, m->itv.size, m->perm);
		}
	} else if (!strcmp(mode, "io.maps")) { // Non-overlapping RzIOMap parts not overridden by others (skyline)
		ut64 begin = UT64_MAX;
		ut64 end = UT64_MAX;
#define USE_SKYLINE 0
#if USE_SKYLINE
		const RzPVector *skyline = &core->io->map_skyline;
		size_t i;
		for (i = 0; i < rz_pvector_len(skyline); i++) {
			const RzIOMapSkyline *part = rz_pvector_at(skyline, i);
			ut64 from = rz_itv_begin(part->itv);
			ut64 to = rz_itv_end(part->itv);
			// XXX skyline's fake map perms are wrong
			RzIOMap *m = rz_io_map_get(core->io, from);
			int rwx = m ? m->perm : part->map->perm;
#else
		void **it;
		RzPVector *maps = rz_io_maps(core->io);
		rz_pvector_foreach (maps, it) {
			RzIOMap *map = *it;
			ut64 from = rz_itv_begin(map->itv);
			ut64 to = rz_itv_end(map->itv);
			int rwx = map->perm;
#endif
			// eprintf ("--------- %llx %llx    (%llx %llx)\n", from, to, begin, end);
			if (begin == UT64_MAX) {
				begin = from;
			}
			if (end == UT64_MAX) {
				end = to;
			} else {
				if (end == from) {
					end = to;
				} else {
					append_bound(list, NULL, search_itv,
						begin, end - begin, rwx);
					begin = from;
					end = to;
				}
			}
		}
		if (end != UT64_MAX) {
			append_bound(list, NULL, search_itv, begin, end - begin, 7);
		}
	} else if (rz_str_startswith(mode, "io.maps.")) {
		int len = strlen("io.maps.");
		int mask = (mode[len - 1] == '.') ? rz_str_rwx(mode + len) : 0;
		// bool only = (bool)(size_t)strstr (mode, ".only");

		void **it;
		RzPVector *maps = rz_io_maps(core->io);
		rz_pvector_foreach (maps, it) {
			RzIOMap *map = *it;
			ut64 from = rz_itv_begin(map->itv);
			// ut64 to = rz_itv_end (map->itv);
			int rwx = map->perm;
			if ((rwx & mask) != mask) {
				continue;
			}
			append_bound(list, core->io, search_itv, from, rz_itv_size(map->itv), rwx);
		}
	} else if (rz_str_startswith(mode, "io.sky.")) {
		int len = strlen("io.sky.");
		int mask = (mode[len - 1] == '.') ? rz_str_rwx(mode + len) : 0;
		bool only = (bool)(size_t)strstr(mode, ".only");
		RzVector *skyline = &core->io->map_skyline.v;
		ut64 begin = UT64_MAX;
		ut64 end = UT64_MAX;
		size_t i;
		for (i = 0; i < rz_vector_len(skyline); i++) {
			const RzSkylineItem *part = rz_vector_index_ptr(skyline, i);
			ut64 from = part->itv.addr;
			ut64 to = part->itv.addr + part->itv.size;
			int perm = ((RzIOMap *)part->user)->perm;
			if (maskMatches(perm, mask, only)) {
				continue;
			}
			// eprintf ("--------- %llx %llx    (%llx %llx)\n", from, to, begin, end);
			if (begin == UT64_MAX) {
				begin = from;
			}
			if (end == UT64_MAX) {
				end = to;
			} else {
				if (end == from) {
					end = to;
				} else {
					// eprintf ("[%llx - %llx]\n", begin, end);
					append_bound(list, NULL, search_itv, begin, end - begin, perm);
					begin = from;
					end = to;
				}
			}
		}
		if (end != UT64_MAX) {
			append_bound(list, NULL, search_itv, begin, end - begin, 7);
		}
	} else if (rz_str_startswith(mode, "bin.segments")) {
		int len = strlen("bin.segments.");
		int mask = (mode[len - 1] == '.') ? rz_str_rwx(mode + len) : 0;
		bool only = (bool)(size_t)strstr(mode, ".only");
		RzBinObject *obj = rz_bin_cur_object(core->bin);
		if (obj) {
			RzBinSection *s;
			RzListIter *iter;
			rz_list_foreach (obj->sections, iter, s) {
				if (!s->is_segment) {
					continue;
				}
				if (maskMatches(s->perm, mask, only)) {
					continue;
				}
				ut64 addr = core->io->va ? s->vaddr : s->paddr;
				ut64 size = core->io->va ? s->vsize : s->size;
				append_bound(list, core->io, search_itv, addr, size, s->perm);
			}
		}
	} else if (rz_str_startswith(mode, "code")) {
		RzBinObject *obj = rz_bin_cur_object(core->bin);
		if (obj) {
			ut64 from = UT64_MAX;
			ut64 to = 0;
			RzBinSection *s;
			RzListIter *iter;
			rz_list_foreach (obj->sections, iter, s) {
				if (s->is_segment) {
					continue;
				}
				if (maskMatches(s->perm, 1, false)) {
					continue;
				}
				ut64 addr = core->io->va ? s->vaddr : s->paddr;
				ut64 size = core->io->va ? s->vsize : s->size;
				from = RZ_MIN(addr, from);
				to = RZ_MAX(to, addr + size);
			}
			if (from == UT64_MAX) {
				int mask = 1;
				void **it;
				RzPVector *maps = rz_io_maps(core->io);
				rz_pvector_foreach (maps, it) {
					RzIOMap *map = *it;
					ut64 from = rz_itv_begin(map->itv);
					ut64 size = rz_itv_size(map->itv);
					int rwx = map->perm;
					if ((rwx & mask) != mask) {
						continue;
					}
					append_bound(list, core->io, search_itv, from, size, rwx);
				}
			}
			append_bound(list, core->io, search_itv, from, to - from, 1);
		}
	} else if (rz_str_startswith(mode, "bin.sections")) {
		int len = strlen("bin.sections.");
		int mask = (mode[len - 1] == '.') ? rz_str_rwx(mode + len) : 0;
		bool only = (bool)(size_t)strstr(mode, ".only");
		RzBinObject *obj = rz_bin_cur_object(core->bin);
		if (obj) {
			RzBinSection *s;
			RzListIter *iter;
			rz_list_foreach (obj->sections, iter, s) {
				if (s->is_segment) {
					continue;
				}
				if (maskMatches(s->perm, mask, only)) {
					continue;
				}
				ut64 addr = core->io->va ? s->vaddr : s->paddr;
				ut64 size = core->io->va ? s->vsize : s->size;
				append_bound(list, core->io, search_itv, addr, size, s->perm);
			}
		}
	} else if (!strcmp(mode, "bin.segment")) {
		RzBinObject *obj = rz_bin_cur_object(core->bin);
		if (obj) {
			RzBinSection *s;
			RzListIter *iter;
			rz_list_foreach (obj->sections, iter, s) {
				if (!s->is_segment) {
					continue;
				}
				ut64 addr = core->io->va ? s->vaddr : s->paddr;
				ut64 size = core->io->va ? s->vsize : s->size;
				if (RZ_BETWEEN(addr, core->offset, addr + size)) {
					append_bound(list, core->io, search_itv, addr, size, s->perm);
				}
			}
		}
	} else if (!strcmp(mode, "bin.section")) {
		RzBinObject *obj = rz_bin_cur_object(core->bin);
		if (obj) {
			RzBinSection *s;
			RzListIter *iter;
			rz_list_foreach (obj->sections, iter, s) {
				if (s->is_segment) {
					continue;
				}
				ut64 addr = core->io->va ? s->vaddr : s->paddr;
				ut64 size = core->io->va ? s->vsize : s->size;
				if (RZ_BETWEEN(addr, core->offset, addr + size)) {
					append_bound(list, core->io, search_itv, addr, size, s->perm);
				}
			}
		}
	} else if (!strcmp(mode, "analysis.fcn") || !strcmp(mode, "analysis.bb")) {
		RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset,
			RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
		if (f) {
			ut64 from = f->addr, size = rz_analysis_function_size_from_entry(f);

			/* Search only inside the basic block */
			if (!strcmp(mode, "analysis.bb")) {
				RzListIter *iter;
				RzAnalysisBlock *bb;

				rz_list_foreach (f->bbs, iter, bb) {
					ut64 at = core->offset;
					if ((at >= bb->addr) && (at < (bb->addr + bb->size))) {
						from = bb->addr;
						size = bb->size;
						break;
					}
				}
			}
			append_bound(list, core->io, search_itv, from, size, 5);
		} else {
			RZ_LOG_WARN("core: search.in = ( analysis.bb | analysis.fcn )"
				    "requires to seek into a valid function\n");
			append_bound(list, core->io, search_itv, core->offset, 1, 5);
		}
	} else if (!strncmp(mode, "dbg.", 4)) {
		if (core->bin->is_debugger) {
			int mask = 0;
			int add = 0;
			bool heap = false;
			bool stack = false;
			bool all = false;
			bool first = false;
			RzListIter *iter;
			RzDebugMap *map;

			rz_debug_map_sync(core->dbg);

			if (!strcmp(mode, "dbg.map")) {
				int perm = 0;
				ut64 from = core->offset;
				ut64 to = core->offset;
				rz_list_foreach (core->dbg->maps, iter, map) {
					if (from >= map->addr && from < map->addr_end) {
						from = map->addr;
						to = map->addr_end;
						perm = map->perm;
						break;
					}
				}
				if (perm) {
					RzIOMap *nmap = RZ_NEW0(RzIOMap);
					if (nmap) {
						// nmap->fd = core->io->desc->fd;
						nmap->itv.addr = from;
						nmap->itv.size = to - from;
						nmap->perm = perm;
						nmap->delta = 0;
						rz_list_append(list, nmap);
					}
				}
			} else {
				bool only = false;
				mask = 0;
				if (!strcmp(mode, "dbg.program")) {
					first = true;
					mask = RZ_PERM_X;
				} else if (!strcmp(mode, "dbg.maps")) {
					all = true;
				} else if (rz_str_startswith(mode, "dbg.maps.")) {
					mask = rz_str_rwx(mode + 9);
					only = (bool)(size_t)strstr(mode, ".only");
				} else if (!strcmp(mode, "dbg.heap")) {
					heap = true;
				} else if (!strcmp(mode, "dbg.stack")) {
					stack = true;
				}

				ut64 from = UT64_MAX;
				ut64 to = 0;
				rz_list_foreach (core->dbg->maps, iter, map) {
					if (!all && maskMatches(map->perm, mask, only)) {
						continue;
					}
					add = (stack && strstr(map->name, "stack")) ? 1 : 0;
					if (!add && (heap && (map->perm & RZ_PERM_W)) && strstr(map->name, "heap")) {
						add = 1;
					}
					if ((mask && (map->perm & mask)) || add || all) {
						if (!list) {
							list = rz_list_newf(free);
						}
						RzIOMap *nmap = RZ_NEW0(RzIOMap);
						if (!nmap) {
							break;
						}
						nmap->itv.addr = map->addr;
						nmap->itv.size = map->addr_end - map->addr;
						if (nmap->itv.addr) {
							from = RZ_MIN(from, nmap->itv.addr);
							to = RZ_MAX(to - 1, rz_itv_end(nmap->itv) - 1) + 1;
						}
						nmap->perm = map->perm;
						nmap->delta = 0;
						rz_list_append(list, nmap);
						if (first) {
							break;
						}
					}
				}
			}
		}
	} else {
		/* obey temporary seek if defined '/x 8080 @ addr:len' */
		if (core->tmpseek) {
			append_bound(list, core->io, search_itv, core->offset, core->blocksize, 5);
		} else {
			// TODO: repeat last search doesnt works for /a
			ut64 from = rz_config_get_i(core->config, bound_from);
			if (from == UT64_MAX) {
				from = core->offset;
			}
			ut64 to = rz_config_get_i(core->config, bound_to);
			if (to == UT64_MAX) {
				if (core->io->va) {
					/* TODO: section size? */
				} else {
					if (core->file) {
						to = rz_io_fd_size(core->io, core->file->fd);
					}
				}
			}
			append_bound(list, core->io, search_itv, from, to - from, 5);
		}
	}
	return list;
}

static bool is_end_gadget(const RzAnalysisOp *aop, const ut8 crop) {
	if (aop->family == RZ_ANALYSIS_OP_FAMILY_SECURITY) {
		return false;
	}
	switch (aop->type) {
	case RZ_ANALYSIS_OP_TYPE_TRAP:
	case RZ_ANALYSIS_OP_TYPE_RET:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
	case RZ_ANALYSIS_OP_TYPE_RCALL:
	case RZ_ANALYSIS_OP_TYPE_ICALL:
	case RZ_ANALYSIS_OP_TYPE_IRCALL:
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_RJMP:
	case RZ_ANALYSIS_OP_TYPE_IJMP:
	case RZ_ANALYSIS_OP_TYPE_IRJMP:
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_CALL:
		return true;
	}
	if (crop) { // if conditional jumps, calls and returns should be used for the gadget-search too
		switch (aop->type) {
		case RZ_ANALYSIS_OP_TYPE_CJMP:
		case RZ_ANALYSIS_OP_TYPE_UCJMP:
		case RZ_ANALYSIS_OP_TYPE_CCALL:
		case RZ_ANALYSIS_OP_TYPE_UCCALL:
		case RZ_ANALYSIS_OP_TYPE_CRET:
			return true;
		}
	}
	return false;
}

static bool insert_into(void *user, const ut64 k, const ut64 v) {
	HtUU *ht = (HtUU *)user;
	ht_uu_insert(ht, k, v);
	return true;
}

// TODO: follow unconditional jumps
static RzList /*<RzCoreAsmHit *>*/ *construct_rop_gadget(RzCore *core, ut64 addr, ut8 *buf, int buflen, int idx, const char *grep, int regex, RzList /*<char *>*/ *rx_list, struct endlist_pair *end_gadget, HtUU *badstart) {
	int endaddr = end_gadget->instr_offset;
	int branch_delay = end_gadget->delay_size;
	RzAnalysisOp aop = { 0 };
	const char *start = NULL, *end = NULL;
	char *grep_str = NULL;
	RzCoreAsmHit *hit = NULL;
	RzList *hitlist = rz_core_asm_hit_list_new();
	ut8 nb_instr = 0;
	const ut8 max_instr = rz_config_get_i(core->config, "rop.len");
	bool valid = false;
	int grep_find;
	int search_hit;
	char *rx = NULL;
	HtUUOptions opt = { 0 };
	HtUU *localbadstart = ht_uu_new_opt(&opt);
	int count = 0;

	if (grep) {
		start = grep;
		end = strchr(grep, ';');
		if (!end) { // We filter on a single opcode, so no ";"
			end = start + strlen(grep);
		}
		grep_str = calloc(1, end - start + 1);
		strncpy(grep_str, start, end - start);
		if (regex) {
			// get the first regexp.
			if (rz_list_length(rx_list) > 0) {
				rx = rz_list_get_n(rx_list, count++);
			}
		}
	}

	bool found;
	ht_uu_find(badstart, idx, &found);
	if (found) {
		valid = false;
		goto ret;
	}
	while (nb_instr < max_instr) {
		ht_uu_insert(localbadstart, idx, 1);

		int error = rz_analysis_op(core->analysis, &aop, addr, buf + idx, buflen - idx, RZ_ANALYSIS_OP_MASK_DISASM);
		if (error < 0 || (nb_instr == 0 && (is_end_gadget(&aop, 0) || aop.type == RZ_ANALYSIS_OP_TYPE_NOP))) {
			valid = false;
			goto ret;
		}

		const int opsz = aop.size;
		// opsz = rz_strbuf_length (asmop.buf);
		char *opst = aop.mnemonic;
		if (!opst) {
			RZ_LOG_WARN("Analysis plugin %s did not return disassembly\n", core->analysis->cur->name);
			RzAsmOp asmop;
			rz_asm_set_pc(core->rasm, addr);
			if (rz_asm_disassemble(core->rasm, &asmop, buf + idx, buflen - idx) < 0) {
				valid = false;
				goto ret;
			}
			opst = strdup(rz_asm_op_get_asm(&asmop));
			rz_asm_op_fini(&asmop);
		}
		if (!rz_str_ncasecmp(opst, "invalid", strlen("invalid")) ||
			!rz_str_ncasecmp(opst, ".byte", strlen(".byte"))) {
			valid = false;
			goto ret;
		}

		hit = rz_core_asm_hit_new();
		if (hit) {
			hit->addr = addr;
			hit->len = opsz;
			rz_list_append(hitlist, hit);
		}

		// Move on to the next instruction
		idx += opsz;
		addr += opsz;
		if (rx) {
			grep_find = !rz_regex_match(rx, "e", opst);
			search_hit = (end && grep && (grep_find < 1));
		} else {
			search_hit = (end && grep && strstr(opst, grep_str));
		}

		// Handle (possible) grep
		if (search_hit) {
			if (end[0] == ';') { // fields are semicolon-separated
				start = end + 1; // skip the ;
				end = strchr(start, ';');
				end = end ? end : start + strlen(start); // latest field?
				free(grep_str);
				grep_str = calloc(1, end - start + 1);
				if (grep_str) {
					strncpy(grep_str, start, end - start);
				}
			} else {
				end = NULL;
			}
			if (regex) {
				rx = rz_list_get_n(rx_list, count++);
			}
		}
		if (endaddr <= (idx - opsz)) {
			valid = (endaddr == idx - opsz);
			goto ret;
		}
		rz_analysis_op_fini(&aop);
		nb_instr++;
	}
ret:
	rz_analysis_op_fini(&aop);
	free(grep_str);
	if (regex && rx) {
		rz_list_free(hitlist);
		ht_uu_free(localbadstart);
		return NULL;
	}
	if (!valid || (grep && end)) {
		rz_list_free(hitlist);
		ht_uu_free(localbadstart);
		return NULL;
	}
	ht_uu_foreach(localbadstart, insert_into, badstart);
	ht_uu_free(localbadstart);
	// If our arch has bds then we better be including them
	if (branch_delay && rz_list_length(hitlist) < (1 + branch_delay)) {
		rz_list_free(hitlist);
		return NULL;
	}
	return hitlist;
}

static void print_rop(RzCore *core, RzList /*<RzCoreAsmHit *>*/ *hitlist, PJ *pj, int mode) {
	RzCoreAsmHit *hit = NULL;
	RzListIter *iter;
	RzList *ropList = NULL;
	unsigned int size = 0;
	RzAnalysisOp analop = RZ_EMPTY;
	RzAsmOp asmop;
	Sdb *db = NULL;
	const bool colorize = rz_config_get_i(core->config, "scr.color");
	const bool rop_comments = rz_config_get_i(core->config, "rop.comments");
	const bool esil = rz_config_get_i(core->config, "asm.esil");
	const bool rop_db = rz_config_get_i(core->config, "rop.db");

	if (rop_db) {
		db = sdb_ns(core->sdb, "rop", true);
		ropList = rz_list_newf(free);
		if (!db) {
			RZ_LOG_ERROR("core: Could not create SDB 'rop' namespace\n");
			rz_list_free(ropList);
			return;
		}
	}

	switch (mode) {
	case 'j':
		pj_o(pj);
		pj_ka(pj, "opcodes");
		rz_list_foreach (hitlist, iter, hit) {
			ut8 *buf = malloc(hit->len);
			if (!buf) {
				return;
			}
			rz_io_read_at(core->io, hit->addr, buf, hit->len);
			rz_asm_set_pc(core->rasm, hit->addr);
			rz_asm_disassemble(core->rasm, &asmop, buf, hit->len);
			rz_analysis_op(core->analysis, &analop, hit->addr, buf, hit->len, RZ_ANALYSIS_OP_MASK_ESIL);
			size += hit->len;
			if (analop.type != RZ_ANALYSIS_OP_TYPE_RET) {
				char *opstr_n = rz_str_newf(" %s", RZ_STRBUF_SAFEGET(&analop.esil));
				rz_list_append(ropList, (void *)opstr_n);
			}
			pj_o(pj);
			pj_kN(pj, "offset", hit->addr);
			pj_ki(pj, "size", hit->len);
			pj_ks(pj, "opcode", rz_asm_op_get_asm(&asmop));
			pj_ks(pj, "type", rz_analysis_optype_to_string(analop.type));
			pj_end(pj);
			free(buf);
			rz_analysis_op_fini(&analop);
		}
		pj_end(pj);
		if (db && hit) {
			const ut64 addr = ((RzCoreAsmHit *)hitlist->head->data)->addr;
			// rz_cons_printf ("Gadget size: %d\n", (int)size);
			const char *key = sdb_fmt("0x%08" PFMT64x, addr);
			rop_classify(core, db, ropList, key, size);
		}
		if (hit) {
			pj_kN(pj, "retaddr", hit->addr);
			pj_ki(pj, "size", size);
		}
		pj_end(pj);
		break;
	case 'q':
		// Print gadgets in a 'linear manner', each sequence
		// on one line.
		rz_cons_printf("0x%08" PFMT64x ":",
			((RzCoreAsmHit *)hitlist->head->data)->addr);
		rz_list_foreach (hitlist, iter, hit) {
			ut8 *buf = malloc(hit->len);
			rz_io_read_at(core->io, hit->addr, buf, hit->len);
			rz_asm_set_pc(core->rasm, hit->addr);
			rz_asm_disassemble(core->rasm, &asmop, buf, hit->len);
			rz_analysis_op(core->analysis, &analop, hit->addr, buf, hit->len, RZ_ANALYSIS_OP_MASK_BASIC);
			size += hit->len;
			const char *opstr = RZ_STRBUF_SAFEGET(&analop.esil);
			if (analop.type != RZ_ANALYSIS_OP_TYPE_RET) {
				rz_list_append(ropList, rz_str_newf(" %s", opstr));
			}
			if (esil) {
				rz_cons_printf("%s\n", opstr);
			} else if (colorize) {
				RzStrBuf *colored_asm, *bw_str = rz_strbuf_new(rz_asm_op_get_asm(&asmop));
				colored_asm = rz_asm_colorize_asm_str(bw_str, core->print, rz_asm_get_parse_param(core->analysis->reg, analop.type), asmop.asm_toks);
				rz_cons_printf(" %s%s;", colored_asm ? rz_strbuf_get(colored_asm) : "", Color_RESET);
				rz_strbuf_free(colored_asm);
			} else {
				rz_cons_printf(" %s;", rz_asm_op_get_asm(&asmop));
			}
			free(buf);
			rz_analysis_op_fini(&analop);
		}
		if (db && hit) {
			const ut64 addr = ((RzCoreAsmHit *)hitlist->head->data)->addr;
			// rz_cons_printf ("Gadget size: %d\n", (int)size);
			const char *key = sdb_fmt("0x%08" PFMT64x, addr);
			rop_classify(core, db, ropList, key, size);
		}
		break;
	default:
		// Print gadgets with new instruction on a new line.
		rz_list_foreach (hitlist, iter, hit) {
			const char *comment = rop_comments ? rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, hit->addr) : NULL;
			if (hit->len < 0) {
				RZ_LOG_ERROR("core: Invalid hit length here\n");
				continue;
			}
			ut8 *buf = malloc(1 + hit->len);
			if (!buf) {
				break;
			}
			buf[hit->len] = 0;
			rz_io_read_at(core->io, hit->addr, buf, hit->len);
			rz_asm_set_pc(core->rasm, hit->addr);
			rz_asm_disassemble(core->rasm, &asmop, buf, hit->len);
			rz_analysis_op(core->analysis, &analop, hit->addr, buf, hit->len, RZ_ANALYSIS_OP_MASK_ESIL);
			size += hit->len;
			if (analop.type != RZ_ANALYSIS_OP_TYPE_RET) {
				char *opstr_n = rz_str_newf(" %s", RZ_STRBUF_SAFEGET(&analop.esil));
				rz_list_append(ropList, (void *)opstr_n);
			}
			char *asm_op_hex = rz_asm_op_get_hex(&asmop);
			if (colorize) {
				RzStrBuf *colored_asm, *bw_str = rz_strbuf_new(rz_asm_op_get_asm(&asmop));
				colored_asm = rz_asm_colorize_asm_str(bw_str, core->print, rz_asm_get_parse_param(core->analysis->reg, analop.type), asmop.asm_toks);
				if (comment) {
					rz_cons_printf("  0x%08" PFMT64x " %18s  %s%s ; %s\n",
						hit->addr, asm_op_hex, colored_asm ? rz_strbuf_get(colored_asm) : "", Color_RESET, comment);
				} else {
					rz_cons_printf("  0x%08" PFMT64x " %18s  %s%s\n",
						hit->addr, asm_op_hex, colored_asm ? rz_strbuf_get(colored_asm) : "", Color_RESET);
				}
				rz_strbuf_free(colored_asm);
			} else {
				if (comment) {
					rz_cons_printf("  0x%08" PFMT64x " %18s  %s ; %s\n",
						hit->addr, asm_op_hex, rz_asm_op_get_asm(&asmop), comment);
				} else {
					rz_cons_printf("  0x%08" PFMT64x " %18s  %s\n",
						hit->addr, asm_op_hex, rz_asm_op_get_asm(&asmop));
				}
			}
			free(asm_op_hex);
			free(buf);
			rz_analysis_op_fini(&analop);
		}
		if (db && hit) {
			const ut64 addr = ((RzCoreAsmHit *)hitlist->head->data)->addr;
			// rz_cons_printf ("Gadget size: %d\n", (int)size);
			const char *key = sdb_fmt("0x%08" PFMT64x, addr);
			rop_classify(core, db, ropList, key, size);
		}
	}
	if (mode != 'j') {
		rz_cons_newline();
	}
	rz_list_free(ropList);
}

#define MAXINSTR 8
#define SUMARRAY(arr, size, res) \
	do \
		(res) += (arr)[--(size)]; \
	while ((size))

static int memcmpdiff(const ut8 *a, const ut8 *b, int len) {
	int i, diff = 0;
	for (i = 0; i < len; i++) {
		if (a[i] == b[i] && a[i] == 0x00) {
			/* ignore nulls */
		} else if (a[i] != b[i]) {
			diff++;
		}
	}
	return diff;
}

static void search_similar_pattern_in(RzCore *core, int count, ut64 from, ut64 to) {
	ut64 addr = from;
	ut8 *block = calloc(core->blocksize, 1);
	if (!block) {
		return;
	}
	while (addr < to) {
		(void)rz_io_read_at(core->io, addr, block, core->blocksize);
		if (rz_cons_is_breaked()) {
			break;
		}
		int diff = memcmpdiff(core->block, block, core->blocksize);
		int equal = core->blocksize - diff;
		if (equal >= count) {
			int pc = (equal * 100) / core->blocksize;
			rz_cons_printf("0x%08" PFMT64x " %4d/%d %3d%%  ", addr, equal, core->blocksize, pc);
			ut8 ptr[2] = {
				(ut8)(pc * 2.5), 0
			};
			RzHistogramOptions opts = {
				.unicode = rz_config_get_b(core->config, "scr.utf8"),
				.thinline = !rz_config_get_b(core->config, "scr.hist.block"),
				.legend = false,
				.offset = rz_config_get_b(core->config, "hex.offset"),
				.offpos = UT64_MAX,
				.cursor = false,
				.curpos = 0,
				.color = rz_config_get_i(core->config, "scr.color"),
				.pal = &core->cons->context->pal
			};
			RzStrBuf *strbuf = rz_histogram_vertical(&opts, ptr, 1, core->blocksize);
			if (!strbuf) {
				RZ_LOG_ERROR("Cannot generate vertical histogram\n");
			} else {
				rz_cons_print(rz_strbuf_drain(strbuf));
			}
		}
		addr += core->blocksize;
	}
	free(block);
}

static void search_similar_pattern(RzCore *core, int count, struct search_parameters *param) {
	RzIOMap *p;
	RzListIter *iter;

	rz_cons_break_push(NULL, NULL);
	rz_list_foreach (param->boundaries, iter, p) {
		search_similar_pattern_in(core, count, p->itv.addr, rz_itv_end(p->itv));
	}
	rz_cons_break_pop();
}

static bool isArm(RzCore *core) {
	RzAsm *as = core ? core->rasm : NULL;
	if (as && as->cur && as->cur->arch) {
		if (rz_str_startswith(as->cur->arch, "arm")) {
			if (as->cur->bits < 64) {
				return true;
			}
		}
	}
	return false;
}

void _CbInRangeSearchV(RzCore *core, ut64 from, ut64 to, int vsize, void *user) {
	struct search_parameters *param = user;
	bool isarm = isArm(core);
	// this is expensive operation that could be cached but is a callback
	// and for not messing adding a new param
	const char *prefix = rz_config_get(core->config, "search.prefix");
	if (isarm) {
		if (to & 1) {
			to--;
		}
	}
	if (param->outmode != RZ_MODE_JSON) {
		rz_cons_printf("0x%" PFMT64x ": 0x%" PFMT64x "\n", from, to);
	} else {
		pj_o(param->pj);
		pj_kN(param->pj, "offset", from);
		pj_kN(param->pj, "value", to);
		pj_end(param->pj);
	}
	rz_core_cmdf(core, "f %s.value.0x%08" PFMT64x " %d @ 0x%08" PFMT64x " \n", prefix, to, vsize, to); // flag at value of hit
	rz_core_cmdf(core, "f %s.offset.0x%08" PFMT64x " %d @ 0x%08" PFMT64x " \n", prefix, from, vsize, from); // flag at offset of hit
	const char *cmdHit = rz_config_get(core->config, "cmd.hit");
	if (cmdHit && *cmdHit) {
		ut64 addr = core->offset;
		rz_core_seek(core, from, true);
		rz_core_cmd(core, cmdHit, 0);
		rz_core_seek(core, addr, true);
	}
}

// maybe useful as in util/big.c .?
static void incBuffer(ut8 *buf, int bufsz) {
	int i = 0;
	while (i < bufsz) {
		buf[i]++;
		if (!buf[i]) {
			i++;
			continue;
		}
		break;
	}
	// may overflow/hang/end/stop/whatever here
}

static void incPrintBuffer(ut8 *buf, int bufsz) {
	int i = 0;
	while (i < bufsz) {
		buf[i]++;
		if (!buf[i]) {
			i++;
			continue;
		}
		if (IS_PRINTABLE(buf[i])) {
			break;
		}
	}
}

static void incLowerBuffer(ut8 *buf, int bufsz) {
	int i = 0;
	while (i < bufsz) {
		buf[i]++;
		if (buf[i] && isalpha(buf[i]) && islower(buf[i])) {
			break;
		}
		if (!buf[i]) {
			i++;
			continue;
		}
	}
}

static void incUpperBuffer(ut8 *buf, int bufsz) {
	int i = 0;
	while (i < bufsz) {
		buf[i]++;
		if (buf[i] && isalpha(buf[i]) && isupper(buf[i])) {
			break;
		}
		if (!buf[i]) {
			i++;
			continue;
		}
	}
}

static void incAlphaBuffer(ut8 *buf, int bufsz) {
	int i = 0;
	while (i < bufsz) {
		buf[i]++;
		if (buf[i] && isalpha(buf[i])) {
			break;
		}
		if (!buf[i]) {
			i++;
			continue;
		}
	}
	// may overflow/hang/end/stop/whatever here
}

static void incDigitBuffer(ut8 *buf, int bufsz) {
	int i = 0;
	while (i < bufsz) {
		buf[i]++;
		if (buf[i] && isdigit(buf[i])) {
			break;
		}
		if (!buf[i]) {
			i++;
			continue;
		}
	}
	// may overflow/hang/end/stop/whatever here
}

RZ_IPI int rz_cmd_search(void *data, const char *input) {
	return 0;
}
