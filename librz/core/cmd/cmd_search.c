// SPDX-FileCopyrightText: 2010-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

#define USE_EMULATION 0

#define AES_SEARCH_LENGTH         40
#define PRIVATE_KEY_SEARCH_LENGTH 11

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
	int searchflags;
	int searchshow;
	const char *searchprefix;
	RzInterval *search_itv;
};

static bool check_if_search_possible(RzCore *core) {
	if (!core || !core->io) {
		RZ_LOG_ERROR("Can't search if we don't have an open file.\n");
		return false;
	}
	if (core->in_search) {
		RZ_LOG_ERROR("Can't search from within a search.\n");
		return false;
	}
	return true;
}

static int _cb_hit(RzSearchKeyword *kw, void *user, ut64 addr) {
	struct search_parameters *param = user;
	RzCore *core = param->core;
	const RzSearch *search = core->search;
	ut64 base_addr = 0;
	bool use_color = core->print->flags & RZ_PRINT_FLAGS_COLOR;
	int keyword_len = kw ? kw->keyword_length + (search->mode == RZ_SEARCH_DELTAKEY) : 0;

	if (param->searchshow && kw && kw->keyword_length > 0) {
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
			pre = rz_str_extract_printable(buf, prectx);
			pos = rz_str_extract_printable(buf + prectx + len, ctx);
			if (!pos) {
				pos = strdup("");
			}
			if (param->outmode == RZ_MODE_JSON) {
				wrd = rz_str_extract_printable(buf + prectx, len);
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
				RZ_LOG_ERROR("Cannot allocate %d\n", mallocsize);
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
				base_addr + addr, param->searchprefix, kw->kwidx, kw->count, s);
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
			if (param->searchflags) {
				rz_cons_printf("%s%d_%d\n", param->searchprefix, kw->kwidx, kw->count);
			} else {
				rz_cons_printf("f %s%d_%d %d @ 0x%08" PFMT64x "\n", param->searchprefix,
					kw->kwidx, kw->count, keyword_len, base_addr + addr);
			}
		}
	}
	if (param->searchflags && kw) {
		const char *flag = sdb_fmt("%s%d_%d", param->searchprefix, kw->kwidx, kw->count);
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

static int progress = 0;

static inline void print_search_progress(ut64 at, ut64 to, int n, struct search_parameters *param) {
	if ((++progress % 64) || (param->outmode == RZ_MODE_JSON)) {
		return;
	}
	if (rz_cons_singleton()->columns < 50) {
		rz_cons_printf("\r[  ]  0x%08" PFMT64x "  hits = %d   \r%s",
			at, n, (progress % 2) ? "[ #]" : "[# ]");
	} else {
		rz_cons_printf("\r[  ]  0x%08" PFMT64x " < 0x%08" PFMT64x "  hits = %d   \r%s",
			at, to, n, (progress % 2) ? "[ #]" : "[# ]");
	}
}

static void do_string_search(RzCore *core, struct search_parameters *param) {
	ut64 at;
	ut8 *buf;
	RzSearch *search = core->search;

	if (param->outmode == RZ_MODE_JSON) {
		pj_a(param->pj);
	}
	RzListIter *iter;
	RzIOMap *map;
	if (!param->searchflags && param->outmode != RZ_MODE_JSON) {
		rz_cons_printf("fs hits\n");
	}
	core->search->inverse = param->inverse;
	// TODO Bad but is to be compatible with the legacy behavior
	if (param->inverse) {
		core->search->maxhits = 1;
	}
	if (core->search->n_kws > 0) {
		/* set callback */
		/* TODO: handle last block of data */
		/* TODO: handle ^C */
		/* TODO: launch search in background support */
		// REMOVE OLD FLAGS rz_core_cmdf (core, "f-%s*", rz_config_get (core->config, "search.prefix"));
		rz_search_set_callback(core->search, &_cb_hit, param);
		if (!(buf = malloc(core->blocksize))) {
			return;
		}
		if (search->bckwrds) {
			rz_search_string_prepare_backward(search);
		}
		rz_cons_break_push(NULL, NULL);
		// TODO search cross boundary
		rz_list_foreach (param->boundaries, iter, map) {
			if (!rz_itv_overlap(*param->search_itv, map->itv)) {
				continue;
			}
			const ut64 saved_nhits = search->nhits;
			RzInterval itv = rz_itv_intersect(*param->search_itv, map->itv);
			if (rz_cons_is_breaked()) {
				break;
			}
			if (param->outmode != RZ_MODE_JSON) {
				RzSearchKeyword *kw = rz_list_first(core->search->kws);
				int lenstr = kw ? kw->keyword_length : 0;
				const char *bytestr = lenstr > 1 ? "bytes" : "byte";
				rz_cons_printf("Searching %d %s in [0x%" PFMT64x "-0x%" PFMT64x "]\n",
					kw ? kw->keyword_length : 0, bytestr, itv.addr, rz_itv_end(itv));
			}
			if (!core->search->bckwrds) {
				RzListIter *it;
				RzSearchKeyword *kw;
				rz_list_foreach (core->search->kws, it, kw) {
					kw->last = 0;
				}
			}

			const ut64 from = itv.addr, to = rz_itv_end(itv),
				   from1 = search->bckwrds ? to : from,
				   to1 = search->bckwrds ? from : to;
			ut64 len;
			for (at = from1; at != to1; at = search->bckwrds ? at - len : at + len) {
				print_search_progress(at, to1, search->nhits, param);
				if (rz_cons_is_breaked()) {
					rz_cons_printf("\n\n");
					break;
				}
				if (search->bckwrds) {
					len = RZ_MIN(core->blocksize, at - from);
					// TODO prefix_read_at
					if (!rz_io_is_valid_offset(core->io, at - len, 0)) {
						break;
					}
					(void)rz_io_read_at(core->io, at - len, buf, len);
				} else {
					len = RZ_MIN(core->blocksize, to - at);
					if (!rz_io_is_valid_offset(core->io, at, 0)) {
						break;
					}
					(void)rz_io_read_at(core->io, at, buf, len);
				}
				rz_search_update(core->search, at, buf, len);
				if (param->aes_search) {
					// Adjust length to search between blocks.
					if (len == core->blocksize) {
						len -= AES_SEARCH_LENGTH - 1;
					}
				} else if (param->privkey_search) {
					// Adjust length to search between blocks.
					if (len == core->blocksize) {
						len -= PRIVATE_KEY_SEARCH_LENGTH - 1;
					}
				}
				if (core->search->maxhits > 0 && core->search->nhits >= core->search->maxhits) {
					goto done;
				}
			}
			print_search_progress(at, to1, search->nhits, param);
			rz_cons_clear_line(1);
			core->num->value = search->nhits;
			if (param->outmode != RZ_MODE_JSON) {
				rz_cons_printf("hits: %" PFMT64d "\n", search->nhits - saved_nhits);
			}
		}
	done:
		rz_cons_break_pop();
		free(buf);
	} else {
		RZ_LOG_ERROR("No keywords defined\n");
	}

	if (param->outmode == RZ_MODE_JSON) {
		pj_end(param->pj);
	}
}

/**
 * \brief Set up the search_parameters struct, and store it in \p param
 *
 * This allocates \p param->search_itv on the heap
 * The onus of freeing this is on the caller
 *
 * \param core Current RzCore instance
 * \param param Struct to save the parameters in (out variable)
 * \return bool true if successful, false otherwise
 *
 */
static bool setup_params(RzCore *core, struct search_parameters *param) {
	param->core = core;
	param->cmd_hit = rz_config_get(core->config, "cmd.hit");
	param->cmd_hit = param->cmd_hit ? param->cmd_hit : "";
	param->outmode = 0;
	param->inverse = false;
	param->aes_search = false;
	param->privkey_search = false;

	if (!param->cmd_hit) {
		param->cmd_hit = "";
	}

	core->in_search = true;
	param->search_itv = NULL;
	rz_flag_space_push(core->flags, "search");
	const ut64 search_from = rz_config_get_i(core->config, "search.from");
	const ut64 search_to = rz_config_get_i(core->config, "search.to");
	if (search_from > search_to && search_to) {
		RZ_LOG_ERROR("search.from > search.to is not supported\n");
		return false;
	}
	// {.addr = UT64_MAX, .size = 0} means search range is unspecified
	RzInterval *search_itv = RZ_NEW(RzInterval);
	search_itv->addr = search_from;
	search_itv->size = search_to - search_from;
	bool empty_search_itv = search_from == search_to && search_from != UT64_MAX;
	if (empty_search_itv) {
		RZ_LOG_WARN("WARNING from == to?\n");
		return false;
	}
	// TODO full address cannot be represented, shrink 1 byte to [0, UT64_MAX)
	if (search_from == UT64_MAX && search_to == UT64_MAX) {
		search_itv->addr = 0;
		search_itv->size = UT64_MAX;
	}

	param->search_itv = search_itv;

	progress = 0;

	param->searchshow = rz_config_get_i(core->config, "search.show");
	param->mode = rz_config_get(core->config, "search.in");
	param->boundaries = rz_core_get_boundaries_prot(core, -1, param->mode, "search");

	core->search->align = rz_config_get_i(core->config, "search.align");
	param->searchflags = rz_config_get_i(core->config, "search.flags");
	core->search->maxhits = rz_config_get_i(core->config, "search.maxhits");
	param->searchprefix = rz_config_get(core->config, "search.prefix");
	core->search->overlap = rz_config_get_i(core->config, "search.overlap");
	core->search->bckwrds = false;

	return true;
}

#define UPDATE_LASTSEARCH(x) \
	free(core->lastsearch); \
	core->lastsearch = RZ_STR_DUP(x);

// /
RZ_IPI RzCmdStatus rz_cmd_search_string_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (!check_if_search_possible(core)) {
		return RZ_CMD_STATUS_ERROR;
	}

	UPDATE_LASTSEARCH(argv[1]);

	char *search_term = RZ_STR_DUP(argv[1]);
	int len = rz_str_unescape(search_term);

	struct search_parameters param;
	if (!setup_params(core, &param)) {
		goto beach;
	}
	param.pj = state->d.pj;
	param.outmode = state->mode == RZ_OUTPUT_MODE_JSON ? RZ_MODE_JSON : RZ_MODE_PRINT;
	if (param.outmode == RZ_MODE_JSON) {
		pj_o(param.pj);
	}

	rz_search_reset(core->search, RZ_SEARCH_KEYWORD);
	rz_search_set_distance(core->search, (int)rz_config_get_i(core->config, "search.distance"));
	RzSearchKeyword *search_kw = rz_search_keyword_new((const ut8 *)search_term, len, NULL, 0, NULL);
	if (search_kw) {
		search_kw->icase = false;
		search_kw->type = RZ_SEARCH_KEYWORD_TYPE_STRING;
		rz_search_kw_add(core->search, search_kw);
	} else {
		RZ_LOG_ERROR("Invalid search keyword\n");
		goto beach;
	}
	rz_search_begin(core->search);
	rz_config_set_i(core->config, "search.kwidx", core->search->n_kws);
	do_string_search(core, &param);

beach:
	core->num->value = core->search->nhits;
	core->in_search = false;
	rz_flag_space_pop(core->flags);
	if (param.outmode == RZ_MODE_JSON) {
		pj_end(param.pj);
	}
	rz_list_free(param.boundaries);
	rz_search_kw_reset(core->search);
	rz_free(param.search_itv);
	return RZ_CMD_STATUS_OK;
}

// /x
RZ_IPI RzCmdStatus rz_cmd_search_hex_string_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (!check_if_search_possible(core)) {
		return RZ_CMD_STATUS_ERROR;
	}

	UPDATE_LASTSEARCH(argv[1]);

	struct search_parameters param;
	if (!setup_params(core, &param)) {
		goto beach;
	}
	param.pj = state->d.pj;
	param.outmode = state->mode == RZ_OUTPUT_MODE_JSON ? RZ_MODE_JSON : RZ_MODE_PRINT;
	if (param.outmode == RZ_MODE_JSON) {
		pj_o(param.pj);
	}

	RzSearchKeyword *kw;
	rz_search_reset(core->search, RZ_SEARCH_KEYWORD);
	rz_search_set_distance(core->search, (int)rz_config_get_i(core->config, "search.distance"));
	char *mask_sep = strchr(argv[1], ':');

	if (mask_sep) {
		char *search_string;
		search_string = rz_str_ndup(argv[1], mask_sep - argv[1]);
		kw = rz_search_keyword_new_hex(search_string, mask_sep + 1, NULL);
		free(search_string);
	} else {
		kw = rz_search_keyword_new_hexmask(argv[1], NULL);
	}

	if (kw) {
		rz_search_kw_add(core->search, kw);
		rz_search_begin(core->search);
	} else {
		RZ_LOG_ERROR("No keyword\n");
		return RZ_CMD_STATUS_ERROR;
	}

	rz_config_set_i(core->config, "search.kwidx", core->search->n_kws);
	do_string_search(core, &param);

beach:
	core->num->value = core->search->nhits;
	core->in_search = false;
	rz_flag_space_pop(core->flags);
	if (param.outmode == RZ_MODE_JSON) {
		pj_end(param.pj);
	}
	rz_list_free(param.boundaries);
	rz_search_kw_reset(core->search);
	rz_free(param.search_itv);

	return RZ_CMD_STATUS_OK;
}

// /a
RZ_IPI RzCmdStatus rz_cmd_search_assembly_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzCmdStatus ret = RZ_CMD_STATUS_ERROR;
	if (!check_if_search_possible(core)) {
		return RZ_CMD_STATUS_ERROR;
	}

	UPDATE_LASTSEARCH(argv[1]);

	struct search_parameters param;
	if (!setup_params(core, &param)) {
		goto beach;
	}
	param.pj = state->d.pj;
	param.outmode = state->mode == RZ_OUTPUT_MODE_JSON ? RZ_MODE_JSON : RZ_MODE_PRINT;
	if (param.outmode == RZ_MODE_JSON) {
		pj_o(param.pj);
	}

	char *assembled = rz_core_asm_search(core, argv[1]);
	if (!assembled) {
		goto beach;
	}
	rz_search_reset(core->search, RZ_SEARCH_KEYWORD);
	rz_search_set_distance(core->search, (int)rz_config_get_i(core->config, "search.distance"));
	rz_search_kw_add(core->search, rz_search_keyword_new_hexmask(assembled, NULL));
	free(assembled);
	rz_config_set_i(core->config, "search.kwidx", core->search->n_kws);
	do_string_search(core, &param);

beach:
	core->num->value = core->search->nhits;
	core->in_search = false;
	rz_flag_space_pop(core->flags);
	if (param.outmode == RZ_MODE_JSON) {
		pj_end(param.pj);
	}
	rz_list_free(param.boundaries);
	rz_search_kw_reset(core->search);
	rz_free(param.search_itv);

	return ret;
}
