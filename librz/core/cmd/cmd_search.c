// SPDX-FileCopyrightText: 2010-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_io.h>
#include <rz_list.h>
#include <rz_search.h>
#include <rz_types_base.h>

#include "cmd_search_rop.c"
#include "rz_cons.h"
#include <rz_config.h>
#include <rz_flag.h>
#include <rz_util/rz_file.h>
#include <rz_util/rz_log.h>
#include <rz_util/rz_itv.h>
#include <rz_util/rz_num.h>
#include <rz_util/rz_mem.h>
#include <rz_util/rz_str_util.h>
#include <rz_util/rz_strbuf.h>
#include <rz_util/rz_regex.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_assert.h>
#include <rz_vector.h>

#define AES_SEARCH_LENGTH         40
#define PRIVATE_KEY_SEARCH_LENGTH 11

struct search_parameters {
	RzCore *core;
	RzList /*<RzIOMap *>*/ *boundaries;
	const char *mode;
	const char *cmd_hit;
	const char *hit_prefix;
	int searchflags;
	int searchshow;
	PJ *pj;
	RzOutputMode outmode; // 0 or RZ_OUTPUT_MODE_STANDARD or RZ_OUTPUT_MODE_JSON
	bool inverse;
	bool aes_search;
	bool privkey_search;
	bool regex_search;
};

RZ_IPI RzCmdStatus rz_cmd_info_gadget_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	const char *input = argc > 1 ? argv[1] : "";
	if (!input) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzRopSearchContext *context = rz_core_rop_search_context_new(core, argv[1], false, RZ_ROP_GADGET_PRINT, RZ_ROP_DETAIL_SEARCH_NON, state);
	RzCmdStatus status = rz_core_rop_gadget_info(core, context);
	return status;
}

RZ_IPI RzCmdStatus rz_cmd_query_gadget_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzPVector /*<RzRopConstraint *>*/ *constraints = rop_constraint_map_parse(core, argc, argv);
	if (!constraints) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (rz_pvector_empty(constraints)) {
		rz_pvector_free(constraints);
		return RZ_CMD_STATUS_INVALID;
	}

	RzRopSearchContext *context = rz_core_rop_search_context_new(core, NULL, false,
		RZ_ROP_GADGET_PRINT | RZ_ROP_GADGET_ANALYZE, RZ_ROP_DETAIL_SEARCH_NON, state);
	if (!context) {
		rz_pvector_free(constraints);
		return RZ_CMD_STATUS_ERROR;
	}
	context->constraints = constraints;
	const RzCmdStatus cmd_status = rz_core_rop_search(core, context);
	rz_core_rop_search_context_free(context);
	return cmd_status;
}

RZ_IPI RzCmdStatus rz_cmd_search_gadget_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	const char *input = argc > 1 ? argv[1] : "";
	if (!input) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzRopSearchContext *context = rz_core_rop_search_context_new(core, input, true, RZ_ROP_GADGET_PRINT, RZ_ROP_DETAIL_SEARCH_NON, state);
	RzCmdStatus status = rz_core_rop_search(core, context);
	rz_core_rop_search_context_free(context);
	return status;
}

RZ_IPI RzCmdStatus rz_cmd_detail_gadget_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	const char *input = argc > 1 ? argv[1] : "";
	RzRopSearchContext *context = rz_core_rop_search_context_new(core, input, false, RZ_ROP_GADGET_PRINT_DETAIL | RZ_ROP_GADGET_ANALYZE, RZ_ROP_DETAIL_SEARCH_NON, state);
	RzCmdStatus status = rz_core_rop_search(core, context);
	rz_core_rop_search_context_free(context);
	return status;
}

RZ_IPI RzCmdStatus rz_cmd_rop_search_stack_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzRopSearchContext *context = rz_core_rop_search_context_new(core, argv[1], false, RZ_ROP_GADGET_PRINT_DETAIL | RZ_ROP_GADGET_ANALYZE, RZ_ROP_DETAIL_SEARCH_STACK, state);
	RzCmdStatus status = rz_core_rop_gadget_info(core, context);
	return status;
}

RZ_IPI RzCmdStatus rz_cmd_rop_search_size_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzRopSearchContext *context = rz_core_rop_search_context_new(core, argv[1], false, RZ_ROP_GADGET_PRINT_DETAIL | RZ_ROP_GADGET_ANALYZE, RZ_ROP_DETAIL_SEARCH_SIZE, state);
	RzCmdStatus status = rz_core_rop_gadget_info(core, context);
	return status;
}

static void cmd_search_bin(RzCore *core, RzInterval itv) {
	ut64 from = itv.addr, to = rz_itv_end(itv);
	int size; // , sz = sizeof (buf);

	int fd = core->file->fd;
	RzBuffer *b = rz_buf_new_with_io_fd(&core->analysis->iob, fd);
	rz_cons_break_push(NULL, NULL);
	while (from < to) {
		if (rz_cons_is_breaked()) {
			break;
		}
		RzBuffer *ref = rz_buf_new_slice(b, from, to);
		RzBinPlugin *plug = rz_bin_get_binplugin_by_buffer(core->bin, ref);
		if (plug) {
			rz_cons_printf("0x%08" PFMT64x "  %s\n", from, plug->name);
			if (plug->size) {
				RzBinOptions opt = {
					.pluginname = plug->name,
					.obj_opts = { 0 },
					.sz = 4096,
					.xtr_idx = 0,
					.fd = fd,
				};
				rz_bin_open_io(core->bin, &opt);
				size = plug->size(core->bin->cur);
				if (size > 0) {
					rz_cons_printf("size %d\n", size);
				}
			}
		}
		rz_buf_free(ref);
		from++;
	}
	rz_buf_free(b);
	rz_cons_break_pop();
}

static int __prelude_cb_hit(RzSearchKeyword *kw, void *user, ut64 addr) {
	RzCore *core = (RzCore *)user;
	rz_return_val_if_fail(core->search, 0);
	int depth = rz_config_get_i(core->config, "analysis.depth");
	// eprintf ("ap: Found function prelude %d at 0x%08"PFMT64x"\n", preludecnt, addr);
	rz_core_analysis_fcn(core, addr, -1, RZ_ANALYSIS_XREF_TYPE_NULL, depth);
	core->search->preludecnt++;
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
	core->search->preludecnt = 0;
	for (at = from; at < to; at += core->blocksize) {
		if (rz_cons_is_breaked()) {
			break;
		}
		if (!rz_io_is_valid_offset(core->io, at, 0)) {
			break;
		}
		(void)rz_io_read_at_mapped(core->io, at, b, core->blocksize);
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
	return core->search->preludecnt;
}

RZ_API int rz_core_search_preludes(RzCore *core, bool log) {
	int ret = -1;
	ut64 from = UT64_MAX;
	ut64 to = UT64_MAX;
	int keyword_length = 0;
	ut8 *keyword = NULL;
	const char *prelude = rz_config_get(core->config, "analysis.prelude");
	ut64 limit = rz_config_get_i(core->config, "analysis.prelude.limit");

	RzList *list = rz_core_get_boundaries_select(core, "search.from", "search.to", "search.in");
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
		if ((to - from) >= limit) {
			RZ_LOG_WARN("aap: search interval (from 0x%" PFMT64x
				    " to 0x%" PFMT64x ") exceeds analysis.prelude.limit (0x%" PFMT64x "), skipping it.\n",
				from, to, limit);
			continue;
		}
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
static char *getstring(char *b, int l, bool use_color) {
	char *r, *res = malloc(l + 1);
	int i;
	if (!res) {
		return NULL;
	}
	for (i = 0, r = res; i < l; b++, i++) {
		if (IS_PRINTABLE(*b)) {
			*r++ = *b;
		} else {
			// This is very ASCII-centric
			*r++ = use_color ? '\xff' : '.';
		}
	}
	*r = 0;
	return res;
}

static RZ_OWN char *get_colored_context(RZ_NONNULL const char *ctx) {
	RzBuffer *buf = rz_buf_new_with_bytes(NULL, 0);
	if (!buf) {
		return NULL;
	}
	bool prev_nonprintable = false;
	for (; *ctx; ctx++) {
		if (*ctx == '\xff') {
			if (!prev_nonprintable) {
				rz_buf_append_string(buf, Color_BLUE);
			}
			rz_buf_append_string(buf, ".");
			prev_nonprintable = true;
		} else {
			if (prev_nonprintable) {
				rz_buf_append_string(buf, Color_RESET);
			}
			rz_buf_append_bytes(buf, (const ut8 *)ctx, 1);
			prev_nonprintable = false;
		}
	}
	if (prev_nonprintable) {
		rz_buf_append_string(buf, Color_RESET);
	}
	char *ctx_color = rz_buf_to_string(buf);
	rz_buf_free(buf);
	return ctx_color;
}

static int _cb_hit(RzSearchKeyword *kw, void *user, ut64 addr) {
	struct search_parameters *param = user;
	RzCore *core = param->core;
	const RzSearch *search = core->search;
	ut64 base_addr = 0;
	bool use_color = core->print->flags & RZ_PRINT_FLAGS_COLOR;
	int keyword_len = kw ? kw->keyword_length + (search->mode == RZ_SEARCH_DELTAKEY) : 0;
	char tmpbuf[128];

	if (param->searchshow && kw && kw->keyword_length > 0) {
		int len, i, extra, mallocsize;
		char *s = NULL, *str = NULL, *p = NULL;
		extra = (param->outmode == RZ_OUTPUT_MODE_JSON) ? 3 : 1;
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
			rz_io_read_at_mapped(core->io, addr - prectx, (ut8 *)buf, len + (ctx * 2));
			pre = getstring(buf, prectx, use_color);
			pos = getstring(buf + prectx + len, ctx, use_color);
			if (!pos) {
				pos = rz_str_dup("");
			}
			if (param->outmode == RZ_OUTPUT_MODE_JSON) {
				wrd = getstring(buf + prectx, len, false);
				s = rz_str_newf("%s%s%s", pre, wrd, pos);
			} else {
				wrd = rz_str_utf16_encode(buf + prectx, len);
				if (use_color) {
					char *pre_color = get_colored_context(pre);
					char *pos_color = get_colored_context(pos);
					s = rz_str_newf("\"%s" Color_YELLOW "%s" Color_RESET "%s\"",
						pre_color, wrd, pos_color);
					free(pre_color);
					free(pos_color);
				} else {
					s = rz_str_newf("\"%s%s%s\"", pre, wrd, pos);
				}
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
				rz_io_read_at_mapped(core->io, base_addr + addr, buf, keyword_len);
				if (param->outmode == RZ_OUTPUT_MODE_JSON) {
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

		if (param->outmode == RZ_OUTPUT_MODE_JSON) {
			pj_o(param->pj);
			pj_kn(param->pj, "offset", base_addr + addr);
			pj_ks(param->pj, "type", type);
			pj_ks(param->pj, "data", s);
			pj_end(param->pj);
		} else {
			rz_cons_printf("0x%08" PFMT64x " %s%d_%d %s\n",
				base_addr + addr, param->hit_prefix, kw->kwidx, kw->count, s);
		}
		free(s);
		free(buf);
		free(str);
	} else if (kw) {
		if (param->outmode == RZ_OUTPUT_MODE_JSON) {
			pj_o(param->pj);
			pj_kn(param->pj, "offset", base_addr + addr);
			pj_ki(param->pj, "len", keyword_len);
			pj_end(param->pj);
		} else {
			if (param->searchflags) {
				rz_cons_printf("%s%d_%d\n", param->hit_prefix, kw->kwidx, kw->count);
			} else {
				rz_cons_printf("f %s%d_%d %d @ 0x%08" PFMT64x "\n", param->hit_prefix,
					kw->kwidx, kw->count, keyword_len, base_addr + addr);
			}
		}
	}
	if (param->searchflags && kw) {
		const char *flag = rz_strf(tmpbuf, "%s%d_%d", param->hit_prefix, kw->kwidx, kw->count);
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

static inline void print_search_progress(ut64 at, ut64 to, int n, struct search_parameters *param, size_t c) {
	if ((c % 64) || (param->outmode == RZ_OUTPUT_MODE_JSON)) {
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

#define MAXINSTR 8
#define SUMARRAY(arr, size, res) \
	do \
		(res) += (arr)[--(size)]; \
	while ((size))

static void do_syscall_search(RzCore *core, struct search_parameters *param) {
	RzSearch *search = core->search;
	ut64 at;
	ut8 *buf;
	int curpos, idx = 0, count = 0;
	RzAnalysisOp aop = { 0 };
	int i, ret, bsize = RZ_MAX(64, core->blocksize);
	int kwidx = core->search->n_kws;
	RzIOMap *map;
	RzListIter *iter;
	const int mininstrsz = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = RZ_MAX(1, mininstrsz);
	RzAnalysisEsil *esil;
	int align = core->search->align;
	int stacksize = rz_config_get_i(core->config, "esil.stack.depth");
	int iotrap = rz_config_get_i(core->config, "esil.iotrap");
	unsigned int addrsize = rz_config_get_i(core->config, "esil.addr.size");

	if (!(esil = rz_analysis_esil_new(stacksize, iotrap, addrsize))) {
		return;
	}
	int *previnstr = calloc(MAXINSTR + 1, sizeof(int));
	if (!previnstr) {
		rz_analysis_esil_free(esil);
		return;
	}
	buf = malloc(bsize);
	if (!buf) {
		RZ_LOG_ERROR("core: Cannot allocate %d byte(s)\n", bsize);
		rz_analysis_esil_free(esil);
		free(previnstr);
		return;
	}
	ut64 oldoff = core->offset;
	int syscallNumber = 0;
	rz_cons_break_push(NULL, NULL);
	const char *a0 = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SN);
	char *esp = rz_str_newf("%s,=", a0);
	char *esp32 = NULL;
	if (core->analysis->bits == 64) {
		const char *reg = rz_reg_64_to_32(core->analysis->reg, a0);
		if (reg) {
			esp32 = rz_str_newf("%s,=", reg);
		}
	}
	rz_list_foreach (param->boundaries, iter, map) {
		ut64 from = map->itv.addr;
		ut64 to = rz_itv_end(map->itv);
		if (from >= to) {
			RZ_LOG_ERROR("core: `from` value must be lower than `to` value\n");
			goto beach;
		}
		if (to == UT64_MAX) {
			RZ_LOG_ERROR("core: Invalid destination boundary\n");
			goto beach;
		}
		for (i = 0, at = from; at < to; at++, i++) {
			if (rz_cons_is_breaked()) {
				break;
			}
			if (i >= (bsize - 32)) {
				i = 0;
			}
			if (align > 1 && (at % align)) {
				continue;
			}
			if (!i) {
				rz_io_read_at_mapped(core->io, at, buf, bsize);
			}
			rz_analysis_op_init(&aop);
			ret = rz_analysis_op(core->analysis, &aop, at, buf + i, bsize - i, RZ_ANALYSIS_OP_MASK_ESIL);
			curpos = idx++ % (MAXINSTR + 1);
			previnstr[curpos] = ret; // This array holds prev n instr size + cur instr size
			if (aop.type == RZ_ANALYSIS_OP_TYPE_MOV) {
				const char *es = RZ_STRBUF_SAFEGET(&aop.esil);
				if (strstr(es, esp)) {
					if (aop.val != -1) {
						syscallNumber = aop.val;
					}
				} else if (esp32 && strstr(es, esp32)) {
					if (aop.val != -1) {
						syscallNumber = aop.val;
					}
				}
			}
			if ((aop.type == RZ_ANALYSIS_OP_TYPE_SWI) && ret) { // && (aop.val > 10)) {
				int scVector = -1; // int 0x80, svc 0x70, ...
				int scNumber = 0; // r0/eax/...
				scNumber = syscallNumber;
				scVector = (aop.val > 0) ? aop.val : -1; // int 0x80 (aop.val = 0x80)
				RzSyscallItem *item = rz_syscall_get(core->analysis->syscall, scNumber, scVector);
				if (item) {
					rz_cons_printf("0x%08" PFMT64x " %s\n", at, item->name);
				}
				memset(previnstr, 0, (MAXINSTR + 1) * sizeof(*previnstr)); // clearing the buffer
				if (param->searchflags) {
					char *flag = rz_str_newf("%s%d_%d.%s", param->hit_prefix, kwidx, count, item ? item->name : "syscall");
					rz_flag_set(core->flags, flag, at, ret);
					free(flag);
				}
				rz_syscall_item_free(item);
				if (*param->cmd_hit) {
					ut64 here = core->offset;
					rz_core_seek(core, at, true);
					rz_core_cmd(core, param->cmd_hit, 0);
					rz_core_seek(core, here, true);
				}
				count++;
				if (search->maxhits > 0 && count >= search->maxhits) {
					rz_analysis_op_fini(&aop);
					break;
				}
				syscallNumber = 0;
			}
			int inc = (core->search->align > 1) ? core->search->align - 1 : ret - 1;
			if (inc < 0) {
				inc = minopcode;
			}
			i += inc;
			at += inc;
			rz_analysis_op_fini(&aop);
		}
	}
beach:
	rz_core_seek(core, oldoff, true);
	rz_analysis_esil_free(esil);
	rz_cons_break_pop();
	free(buf);
	free(esp32);
	free(esp);
	free(previnstr);
}

static void do_ref_search(RzCore *core, ut64 addr, ut64 from, ut64 to, struct search_parameters *param) {
	const int size = 12;
	char str[512];
	RzAnalysisFunction *fcn;
	RzAnalysisXRef *xref;
	RzListIter *iter;
	ut8 buf[12];
	RzList *list = rz_analysis_xrefs_get_to(core->analysis, addr);
	if (list) {
		rz_list_foreach (list, iter, xref) {
			rz_io_read_at_mapped(core->io, xref->from, buf, size);
			rz_asm_set_pc(core->rasm, xref->from);
			RzAsmOp asmop = { 0 };
			rz_asm_disassemble(core->rasm, &asmop, buf, size);
			fcn = rz_analysis_get_fcn_in(core->analysis, xref->from, 0);
			RzAnalysisHint *hint = rz_analysis_hint_get(core->analysis, xref->from);
			rz_parse_filter(core->parser, xref->from, core->flags, hint, rz_strbuf_get(&asmop.buf_asm),
				str, sizeof(str), core->print->big_endian);
			rz_asm_op_fini(&asmop);
			rz_analysis_hint_free(hint);
			const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, xref->from);
			char *print_comment = NULL;
			const char *nl = comment ? strchr(comment, '\n') : NULL;
			if (nl) { // display only until the first newline
				comment = print_comment = rz_str_ndup(comment, nl - comment);
			}
			char *buf_fcn = comment
				? rz_str_newf("%s; %s", fcn ? fcn->name : "(nofunc)", comment)
				: rz_str_newf("%s", fcn ? fcn->name : "(nofunc)");
			free(print_comment);
			if (from <= xref->from && to >= xref->from) {
				rz_cons_printf("%s 0x%" PFMT64x " [%s] %s\n",
					buf_fcn, xref->from, rz_analysis_xrefs_type_tostring(xref->type), str);
				if (*param->cmd_hit) {
					ut64 here = core->offset;
					rz_core_seek(core, xref->from, true);
					rz_core_cmd(core, param->cmd_hit, 0);
					rz_core_seek(core, here, true);
				}
			}
			free(buf_fcn);
		}
	}
	rz_list_free(list);
}

static bool do_analysis_search(RzCore *core, struct search_parameters *param, const char *input) {
	RzSearch *search = core->search;
	ut64 at;
	RzAnalysisOp aop = { 0 };
	int type = 0;
	int mode = 0;
	int kwidx = core->search->n_kws;
	int i, ret, count = 0;

	while (*input && *input != ' ') {
		switch (*input) {
		case 'j':
		case 'q':
			mode = *input;
			break;
		case 'l': // "/alt" "/alf"
			switch (type) {
			case 't': // "/alt"
			case 'f': // "/alf"
				for (i = 0; i < 64; i++) {
					const char *str = type == 'f'
						? rz_analysis_op_family_to_string(i)
						: rz_analysis_optype_to_string(i);
					if (!str || !*str) {
						break;
					}
					if (!strcmp(str, "undefined")) {
						continue;
					}
					rz_cons_println(str);
				}
				break;
			case 's': { // "/als"
				RzListIter *iter;
				RzSyscallItem *si;
				RzList *list = rz_syscall_list(core->analysis->syscall);
				rz_list_foreach (list, iter, si) {
					if (si->num > SYSCALL_HEX_LIMIT) {
						rz_cons_printf("%s = 0x%02x.%x\n", si->name, si->swi, si->num);
					} else {
						rz_cons_printf("%s = 0x%02x.%d\n", si->name, si->swi, si->num);
					}
				}
				rz_list_free(list);
				break;
			}
			case 0:
				rz_core_cmd0(core, "aoml");
				break;
			default:
				RZ_LOG_ERROR("/al%c - unknown command\n", type);
				break;
			}
			return false;
		case 'f': // "/af"
		case 's': // "/as"
		case 't': // "/at"
		case 'm': // "/am"
		case ' ':
			type = *input;
			break;
		case 0:
		default:
			return false;
		}
		input++;
	}
	if (type == 's') {
		rz_warn_if_reached();
		return true;
	}
	if (mode == 'j') {
		pj_a(param->pj);
	}
	input = rz_str_trim_head_ro(input);
	rz_cons_break_push(NULL, NULL);
	RzIOMap *map;
	RzListIter *iter;
	rz_list_foreach (param->boundaries, iter, map) {
		ut64 from = map->itv.addr;
		ut64 to = rz_itv_end(map->itv);
		for (i = 0, at = from; at < to; i++, at++) {
			if (rz_cons_is_breaked()) {
				break;
			}
			at = from + i;
			ut8 bufop[32];
			rz_io_read_at_mapped(core->io, at, bufop, sizeof(bufop));
			rz_analysis_op_init(&aop);
			ret = rz_analysis_op(core->analysis, &aop, at, bufop, sizeof(bufop), RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_DISASM);
			if (ret > 0) {
				bool match = false;
				if (type == 'm') {
					const char *fam = aop.mnemonic;
					if (fam && (!*input || rz_str_startswith(fam, input))) {
						match = true;
					}
				} else if (type == 'f') {
					const char *fam = rz_analysis_op_family_to_string(aop.family);
					if (fam && (!*input || !strcmp(input, fam))) {
						match = true;
					}
				} else {
					const char *type = rz_analysis_optype_to_string(aop.type);
					if (type) {
						bool isCandidate = !*input;
						if (!strcmp(input, "cswi")) {
							if (*input && !strcmp(input + 1, type)) {
								isCandidate = true;
							}
						} else {
							if (!strcmp(input, type)) {
								isCandidate = true;
							}
						}
						if (isCandidate) {
							if (strstr(input, "swi")) {
								if (*input == 'c') {
									match = true; // aop.cond;
								} else {
									match = aop.cond == RZ_TYPE_COND_AL;
								}
							} else {
								match = true;
							}
						}
					}
				}
				if (match) {
					// char *opstr = rz_core_disassemble_instr (core, at, 1);
					char *opstr = rz_core_op_str(core, at);
					switch (mode) {
					case 'j':
						pj_o(param->pj);
						pj_kn(param->pj, "addr", at);
						pj_ki(param->pj, "size", ret);
						pj_ks(param->pj, "opstr", opstr);
						pj_end(param->pj);
						break;
					case 'q':
						rz_cons_printf("0x%08" PFMT64x "\n", at);
						break;
					default:
						if (type == 'f') {
							const char *fam = rz_analysis_op_family_to_string(aop.family);
							rz_cons_printf("0x%08" PFMT64x " %d %s %s\n", at, ret, fam, opstr);
						} else {
							rz_cons_printf("0x%08" PFMT64x " %d %s\n", at, ret, opstr);
						}
						break;
					}
					RZ_FREE(opstr);
					if (*input && param->searchflags) {
						char flag[64];
						snprintf(flag, sizeof(flag), "%s%d_%d",
							param->hit_prefix, kwidx, count);
						rz_flag_set(core->flags, flag, at, ret);
					}
					if (*param->cmd_hit) {
						ut64 here = core->offset;
						rz_core_seek(core, at, true);
						rz_core_cmd(core, param->cmd_hit, 0);
						rz_core_seek(core, here, true);
					}
					count++;
					if (search->maxhits && count >= search->maxhits) {
						goto done;
					}
				}
				int inc = (core->search->align > 1) ? core->search->align - 1 : ret - 1;
				if (inc < 0) {
					inc = 0;
				}
				i += inc;
				at += inc;
			}
			rz_analysis_op_fini(&aop);
		}
	}
done:
	if (mode == 'j') {
		pj_end(param->pj);
	}
	rz_cons_break_pop();
	return false;
}

static void do_asm_search(RzCore *core, struct search_parameters *param, const char *input, int mode, RzInterval search_itv) {
	RzCoreAsmHit *hit;
	RzListIter *iter, *itermap;
	int count = 0, maxhits = 0, filter = 0;
	int kwidx = core->search->n_kws; // (int)rz_config_get_i (core->config, "search.kwidx")-1;
	RzList *hits;
	RzIOMap *map;
	bool regexp = input[0] == '/'; // "/c/"
	bool everyByte = regexp && input[1] == 'a';
	char tmpbuf[128];
	char *end_cmd = strchr(input, ' ');
	switch ((end_cmd ? *(end_cmd - 1) : input[0])) {
	case 'j':
		param->outmode = RZ_OUTPUT_MODE_JSON;
		break;
	default:
		break;
	}
	if (mode == 'o') {
		everyByte = true;
	}

	maxhits = (int)rz_config_get_i(core->config, "search.maxhits");
	filter = (int)rz_config_get_i(core->config, "asm.sub.names");
	if (param->outmode == RZ_OUTPUT_MODE_JSON) {
		pj_a(param->pj);
	}
	rz_cons_break_push(NULL, NULL);
	if (everyByte) {
		input++;
	}
	rz_list_foreach (param->boundaries, itermap, map) {
		if (!rz_itv_overlap(search_itv, map->itv)) {
			continue;
		}
		ut64 from = map->itv.addr;
		ut64 to = rz_itv_end(map->itv);
		if (rz_cons_is_breaked()) {
			break;
		}
		if (maxhits && count >= maxhits) {
			break;
		}
		hits = rz_core_asm_strsearch(core, end_cmd,
			from, to, maxhits, regexp, everyByte, mode);
		if (hits) {
			const char *cmdhit = rz_config_get(core->config, "cmd.hit");
			rz_list_foreach (hits, iter, hit) {
				if (rz_cons_is_breaked()) {
					rz_list_free(hits);
					break;
				}
				if (cmdhit && *cmdhit) {
					rz_core_cmdf(core, "%s @ 0x%" PFMT64x, cmdhit, hit->addr);
				}
				switch (param->outmode) {
				case RZ_OUTPUT_MODE_JSON:
					pj_o(param->pj);
					pj_kn(param->pj, "offset", hit->addr);
					pj_ki(param->pj, "len", hit->len);
					pj_ks(param->pj, "code", hit->code);
					pj_end(param->pj);
					break;
				default:
					if (filter) {
						char tmp[128] = {
							0
						};
						RzAnalysisHint *hint = rz_analysis_hint_get(core->analysis, hit->addr);
						rz_parse_filter(core->parser, hit->addr, core->flags, hint, hit->code, tmp, sizeof(tmp),
							core->print->big_endian);
						rz_analysis_hint_free(hint);
						rz_cons_printf("0x%08" PFMT64x "   # %i: %s\n",
							hit->addr, hit->len, tmp);
					} else {
						rz_cons_printf("0x%08" PFMT64x "   # %i: %s\n",
							hit->addr, hit->len, hit->code);
					}
					break;
				}
				if (param->searchflags) {
					const char *flagname = rz_strf(tmpbuf, "%s%d_%d", param->hit_prefix, kwidx, count);
					if (flagname) {
						rz_flag_set(core->flags, flagname, hit->addr, hit->len);
					}
				}
				count++;
			}
			rz_list_purge(hits);
			rz_list_free(hits);
		}
	}
	if (param->outmode == RZ_OUTPUT_MODE_JSON) {
		pj_end(param->pj);
	}
	rz_cons_break_pop();
}

static void do_string_search(RzCore *core, RzInterval search_itv, struct search_parameters *param) {
	ut64 at;
	ut8 *buf = NULL;
	RzSearch *search = core->search;

	if (param->outmode == RZ_OUTPUT_MODE_JSON) {
		pj_a(param->pj);
	}
	RzListIter *iter;
	RzIOMap *map;
	if (!param->searchflags && param->outmode != RZ_OUTPUT_MODE_JSON) {
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
		if (!param->regex_search && !(buf = malloc(core->blocksize))) {
			return;
		}
		rz_cons_break_push(NULL, NULL);
		// TODO search cross boundary
		rz_list_foreach (param->boundaries, iter, map) {
			if (!rz_itv_overlap(search_itv, map->itv)) {
				continue;
			}
			const ut64 saved_nhits = search->nhits;
			RzInterval itv = rz_itv_intersect(search_itv, map->itv);
			if (rz_cons_is_breaked()) {
				break;
			}
			if (param->outmode != RZ_OUTPUT_MODE_JSON) {
				RzSearchKeyword *kw = rz_list_first_val(core->search->kws);
				eprintf("Searching");
				if (!param->regex_search) {
					int lenstr = kw ? kw->keyword_length : 0;
					const char *bytestr = lenstr > 1 ? "bytes" : "byte";
					eprintf(" %d %s", kw ? kw->keyword_length : 0, bytestr);
				}
				eprintf(" in [0x%" PFMT64x ",0x%" PFMT64x ")\n", itv.addr, rz_itv_end(itv));
			}
			RzListIter *it;
			RzSearchKeyword *kw;
			rz_list_foreach (core->search->kws, it, kw) {
				kw->last = 0;
			}

			const ut64 from = itv.addr, to = rz_itv_end(itv),
				   from1 = from,
				   to1 = to;
			ut64 len;
			size_t c = 0;
			for (at = from1; at != to1; at = at + len) {
				print_search_progress(at, to1, search->nhits, param, c);
				if (rz_cons_is_breaked()) {
					eprintf("\n\n");
					break;
				}
				if (param->regex_search) {
					// Since regex match length can be infinite, for 100% correctness
					// it is not possible to chunk the search. This could be a problem
					// for large binaries.
					free(buf);
					len = to - at;
					if (!(buf = malloc(len))) {
						RZ_LOG_ERROR("Cannot allocate search buffer"
							     " of size 0x%" PFMT64x "\n",
							len);
						return;
					}
				} else {
					len = RZ_MIN(core->blocksize, to - at);
				}
				if (!rz_io_is_valid_offset(core->io, at, 0)) {
					break;
				}
				(void)rz_io_read_at_mapped(core->io, at, buf, len);
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
			print_search_progress(at, to1, search->nhits, param, c);
			rz_cons_clear_line(stderr);
			core->num->value = search->nhits;
			if (param->outmode != RZ_OUTPUT_MODE_JSON) {
				eprintf("hits: %" PFMT64d "\n", search->nhits - saved_nhits);
			}
		}
	done:
		rz_cons_break_pop();
		free(buf);
	} else {
		RZ_LOG_ERROR("core: No keywords defined\n");
	}

	if (param->outmode == RZ_OUTPUT_MODE_JSON) {
		pj_end(param->pj);
	}
}

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
		(void)rz_io_read_at_mapped(core->io, addr, block, core->blocksize);
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
	if (param->outmode != RZ_OUTPUT_MODE_JSON) {
		rz_cons_printf("0x%" PFMT64x ": 0x%" PFMT64x "\n", from, to);
	} else {
		pj_o(param->pj);
		pj_kn(param->pj, "offset", from);
		pj_kn(param->pj, "value", to);
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

static void __core_cmd_search_asm_infinite(RzCore *core, const char *arg) {
	RzList *boundaries = rz_core_get_boundaries_select(core, "search.from", "search.to", "search.in");
	RzListIter *iter;
	RzIOMap *map;
	RzAnalysisOp aop = { 0 };
	ut64 at;
	rz_list_foreach (boundaries, iter, map) {
		ut64 map_begin = map->itv.addr;
		ut64 map_size = map->itv.size;
		ut64 map_end = map_begin + map_size;
		ut8 *buf = calloc(map_end - map_begin, 1);
		if (!buf) {
			continue;
		}
		(void)rz_io_read_at_mapped(core->io, map_begin, buf, map_size);
		for (at = map->itv.addr; at + 24 < map_end; at += 1) {
			rz_analysis_op_init(&aop);
			rz_analysis_op(core->analysis, &aop, at, buf + (at - map_begin), 24, RZ_ANALYSIS_OP_MASK_HINT);
			if (at == aop.jump) {
				rz_cons_printf("0x%08" PFMT64x "\n", at);
			}
			at += aop.size;
			rz_analysis_op_fini(&aop);
		}
		free(buf);
	}
}

static void __core_cmd_search_asm_byteswap(RzCore *core, int nth) {
	ut8 buf[32];
	int i;
	rz_io_read_at_mapped(core->io, 0, buf, sizeof(buf));
	if (nth < 0 || nth >= sizeof(buf) - 1) {
		return;
	}
	for (i = 0; i <= 0xff; i++) {
		buf[nth] = i;
		RzAsmOp asmop = { 0 };
		if (rz_asm_disassemble(core->rasm, &asmop, buf, sizeof(buf)) > 0) {
			const char *asmstr = rz_strbuf_get(&asmop.buf_asm);
			rz_asm_op_fini(&asmop);
			if (!strstr(asmstr, "invalid") && !strstr(asmstr, "unaligned")) {
				rz_cons_printf("%02x  %s\n", i, asmstr);
			}
		} else {
			rz_asm_op_fini(&asmop);
		}
	}
}

static int cmd_search_legacy_handler(void *data, const char *input) {
	bool dosearch = false;
	int ret = true;
	RzCore *core = (RzCore *)data;
	struct search_parameters param = {
		.core = core,
		.cmd_hit = rz_config_get(core->config, "cmd.hit"),
		.outmode = RZ_OUTPUT_MODE_STANDARD,
		.inverse = false,
		.aes_search = false,
		.privkey_search = false,
		.regex_search = false,
	};
	if (!param.cmd_hit) {
		param.cmd_hit = "";
	}
	RzSearch *search = core->search;
	int param_offset = 2;
	if (!core || !core->io) {
		RZ_LOG_ERROR("core: Can't search if we don't have an open file.\n");
		return false;
	}
	if (core->in_search) {
		RZ_LOG_ERROR("core: Can't search from within a search.\n");
		return false;
	}
	if (input[0] == '/') {
		if (core->lastsearch) {
			input = core->lastsearch;
		} else {
			RZ_LOG_ERROR("core: No previous search done\n");
			return false;
		}
	} else {
		free(core->lastsearch);
		core->lastsearch = rz_str_dup(input);
	}

	core->in_search = true;
	rz_flag_space_push(core->flags, "search");
	const ut64 search_from = rz_config_get_i(core->config, "search.from"),
		   search_to = rz_config_get_i(core->config, "search.to");
	if (search_from > search_to && search_to) {
		RZ_LOG_ERROR("core: search.from > search.to is not supported\n");
		ret = false;
		goto beach;
	}
	// {.addr = UT64_MAX, .size = 0} means search range is unspecified
	RzInterval search_itv = { search_from, search_to - search_from };
	bool empty_search_itv = search_from == search_to && search_from != UT64_MAX;
	if (empty_search_itv) {
		RZ_LOG_ERROR("core: `from` address is equal `to`\n");
		ret = false;
		goto beach;
	}
	// TODO full address cannot be represented, shrink 1 byte to [0, UT64_MAX)
	if (search_from == UT64_MAX && search_to == UT64_MAX) {
		search_itv.addr = 0;
		search_itv.size = UT64_MAX;
	}

	param.searchshow = rz_config_get_i(core->config, "search.show");
	param.mode = rz_config_get(core->config, "search.in");
	param.boundaries = rz_core_get_boundaries_select(core, "search.from", "search.to", "search.in");

	core->search->align = rz_config_get_i(core->config, "search.align");
	param.searchflags = rz_config_get_i(core->config, "search.flags");
	core->search->maxhits = rz_config_get_i(core->config, "search.maxhits");
	param.hit_prefix = rz_config_get(core->config, "search.prefix");
	core->search->overlap = rz_config_get_i(core->config, "search.overlap");

	/* Quick & dirty check for json output */
	if (input[0] && (input[1] == 'j') && (input[0] != ' ')) {
		param.outmode = RZ_OUTPUT_MODE_JSON;
		param_offset++;
	}
	param.pj = pj_new();

reread:
	switch (*input) {
	case '!':
		input++;
		param.inverse = true;
		goto reread;
	case 'r': // "/r"
	{
		ut64 n = (input[1] == ' ' || (input[1] && input[2] == ' '))
			? rz_num_math(core->num, input + 2)
			: UT64_MAX;
		if (n == 0LL) {
			RZ_LOG_ERROR("core: Cannot find null references.\n");
			break;
		}
		switch (input[1]) {
		case 'c': // "/rc"
		{
			RzListIter *iter;
			RzIOMap *map;
			rz_list_foreach (param.boundaries, iter, map) {
				eprintf("-- 0x%" PFMT64x " 0x%" PFMT64x "\n", map->itv.addr, rz_itv_end(map->itv));
				rz_core_analysis_search(core, map->itv.addr, rz_itv_end(map->itv), n, 'c');
			}
		} break;
		case 'a': // "/ra"
		{
			RzListIter *iter;
			RzIOMap *map;
			rz_list_foreach (param.boundaries, iter, map) {
				eprintf("-- 0x%" PFMT64x " 0x%" PFMT64x "\n", map->itv.addr, rz_itv_end(map->itv));
				rz_core_analysis_search(core, map->itv.addr, rz_itv_end(map->itv), n, 0);
			}
		} break;
		case 'r': // "/rr" - read refs
		{
			RzListIter *iter;
			RzIOMap *map;
			rz_list_foreach (param.boundaries, iter, map) {
				eprintf("-- 0x%" PFMT64x " 0x%" PFMT64x "\n", map->itv.addr, rz_itv_end(map->itv));
				rz_core_analysis_search(core, map->itv.addr, rz_itv_end(map->itv), n, 'r');
			}
		} break;
		case 'w': // "/rw" - write refs
		{
			RzListIter *iter;
			RzIOMap *map;
			rz_list_foreach (param.boundaries, iter, map) {
				eprintf("-- 0x%" PFMT64x " 0x%" PFMT64x "\n", map->itv.addr, rz_itv_end(map->itv));
				rz_core_analysis_search(core, map->itv.addr, rz_itv_end(map->itv), n, 'w');
			}
		} break;
		case ' ': // "/r $$"
		case 0: // "/r"
		{
			RzListIter *iter;
			RzIOMap *map;
			rz_list_foreach (param.boundaries, iter, map) {
				ut64 from = map->itv.addr;
				ut64 to = rz_itv_end(map->itv);
				if (input[param_offset - 1] == ' ') {
					rz_core_analysis_search(core, from, to,
						rz_num_math(core->num, input + 2), 0);
					do_ref_search(core, rz_num_math(core->num, input + 2), from, to, &param);
				} else {
					rz_core_analysis_search(core, from, to, core->offset, 0);
					do_ref_search(core, core->offset, from, to, &param);
				}
				if (rz_cons_is_breaked()) {
					break;
				}
			}
		} break;
		}
	} break;
	case 'a': // "/a"
		if (input[1] == 'd') { // "ad"
			dosearch = 0;
			do_asm_search(core, &param, input + 2, 0, search_itv);
		} else if (input[1] == 'e') { // "ae"
			dosearch = 0;
			do_asm_search(core, &param, input + 2, 'e', search_itv);
		} else if (input[1] == 'c') { // "/ac"
			dosearch = 0;
			do_asm_search(core, &param, input + 2, 'c', search_itv);
		} else if (input[1] == 'o') { // "/ao"
			dosearch = 0;
			do_asm_search(core, &param, input + 2, 'o', search_itv);
		} else if (input[1] == 'a') { // "/aa"
			dosearch = 0;
			do_asm_search(core, &param, input + 2, 'a', search_itv);
		} else if (input[1] == 'i') { // "/ai"
			do_asm_search(core, &param, input + 2, 'i', search_itv);
		} else if (input[1] == '1') { // "a1"
			__core_cmd_search_asm_byteswap(core, (int)rz_num_math(core->num, input + 2));
		} else if (input[1] == 'I') { // "/aI" - infinite
			__core_cmd_search_asm_infinite(core, rz_str_trim_head_ro(input + 1));
		} else if (input[1] == 's') {
			if (input[2] == 'l') { // "asl"
				rz_core_cmd0(core, "asl");
			} else { // "as"
				do_syscall_search(core, &param);
			}
			dosearch = false;
		} else {
			dosearch = do_analysis_search(core, &param, input + 1);
		}
		break;
	case 'p': // "/p"
	{
		if (input[param_offset - 1]) {
			int ps = atoi(input + param_offset);
			if (ps > 1) {
				RzListIter *iter;
				RzIOMap *map;
				rz_list_foreach (param.boundaries, iter, map) {
					eprintf("-- %llx %llx\n", map->itv.addr, rz_itv_end(map->itv));
					rz_cons_break_push(NULL, NULL);
					rz_search_pattern_size(core->search, ps);
					rz_search_pattern(core->search, map->itv.addr, rz_itv_end(map->itv));
					rz_cons_break_pop();
				}
				break;
			}
		}
		RZ_LOG_ERROR("core: Invalid pattern size (must be > 0)\n");
	} break;
	case 'd': // "/d" search delta key
		if (input[1]) {
			rz_search_reset(core->search, RZ_SEARCH_DELTAKEY);
			rz_search_kw_add(core->search,
				rz_search_keyword_new_hexmask(input + param_offset, NULL));
			rz_search_begin(core->search);
			dosearch = true;
		} else {
			RZ_LOG_ERROR("core: Missing delta\n");
		}
		break;
	case '+': // "/+"
		if (input[1] == ' ') {
			// TODO: support /+j
			char *buf = malloc(strlen(input) * 2);
			char *str = rz_str_dup(input + 2);
			int ochunksize;
			int i, len, chunksize = rz_config_get_i(core->config, "search.chunk");
			if (chunksize < 1) {
				chunksize = core->rasm->bits / 8;
			}
			len = rz_str_unescape(str);
			ochunksize = chunksize = RZ_MIN(len, chunksize);
			RZ_LOG_ERROR("core: Using chunksize: %d\n", chunksize);
			core->in_search = false;
			for (i = 0; i < len; i += chunksize) {
				chunksize = ochunksize;
			again:
				rz_hex_bin2str((ut8 *)str + i, RZ_MIN(chunksize, len - i), buf);
				RZ_LOG_ERROR("core: /x %s\n", buf);
				rz_core_cmdf(core, "/x %s", buf);
				if (core->num->value == 0) {
					chunksize--;
					if (chunksize < 1) {
						RZ_LOG_ERROR("core: Oops\n");
						free(buf);
						free(str);
						goto beach;
					}
					RZ_LOG_ERROR("core: Repeat with chunk size %d\n", chunksize);
					goto again;
				}
			}
			free(str);
			free(buf);
		} else {
			RZ_LOG_ERROR("core: Usage: /+ [string]\n");
		}
		break;
	default:
		RZ_LOG_ERROR("core: See /? for help.\n");
		break;
	}
	rz_config_set_i(core->config, "search.kwidx", search->n_kws);
	if (dosearch) {
		do_string_search(core, search_itv, &param);
	}
beach:
	core->num->value = search->nhits;
	core->in_search = false;
	rz_flag_space_pop(core->flags);
	if (param.outmode == RZ_OUTPUT_MODE_JSON) {
		rz_cons_println(pj_string(param.pj));
	}
	pj_free(param.pj);
	rz_list_free(param.boundaries);
	rz_search_kw_reset(search);
	return ret;
}

static int pass_to_legacy_api(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	rz_return_val_if_fail(core && argv, RZ_CMD_STATUS_ERROR);
	// The +1 strips the '/', because the legacy handler expect it this way.
	const char *cmd = argv[0] + 1;
	RzStrBuf *legacy_input = rz_strbuf_new(cmd);
	if (!legacy_input) {
		rz_warn_if_reached();
		return RZ_CMD_STATUS_ERROR;
	}
	// Append arguments
	for (size_t i = 1; i < argc; i++) {
		rz_strbuf_appendf(legacy_input, " %s", argv[i]);
	}
	bool succeeded = cmd_search_legacy_handler(core, rz_strbuf_drain(legacy_input));
	return succeeded ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// New search

#define CMD_SEARCH_BEGIN() \
	if (core->in_search) { \
		RZ_LOG_ERROR("core: recursive search is forbidden.\n"); \
		return RZ_CMD_STATUS_ERROR; \
	} \
	rz_cons_break_push(NULL, NULL); \
	core->in_search = true;

#define CMD_SEARCH_END() \
	do { \
		rz_cons_break_pop(); \
		core->in_search = false; \
	} while (0)

static bool cmd_search_progress_cancel(void *user, size_t n_hits, RzSearchCancelReason invoke_reason) {
	if (user) {
		// we have RzCmdStateOutput state
		eprintf("Searching... hits: %" PFMTSZu "\r", n_hits);
	}
	return rz_cons_is_breaked();
}

static void cmd_search_output_to_state(RzCmdStateOutput *state, RzSearchHit *hit, const char *flag_name, const char *detail) {
	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_printf("0x%08" PFMT64x "\n", hit->address);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("0x%08" PFMT64x " %" PFMTSZu " %s", hit->address, hit->size, flag_name);
		if (detail) {
			rz_cons_printf(" %s", detail);
		}
		rz_cons_newline();
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		pj_kn(state->d.pj, "address", hit->address);
		pj_kn(state->d.pj, "size", hit->size);
		pj_ks(state->d.pj, "flag", flag_name);
		rz_search_hit_detail_as_json(hit, state->d.pj);
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(state->d.t, "xXss", hit->address, hit->size, flag_name, rz_str_get(detail));
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

static void cmd_search_call_command(RzCore *core, RzSearchHit *hit, const char *command) {
	ut64 old_offset = core->offset;
	rz_core_seek(core, hit->address, true);
	rz_core_cmd(core, command, false);
	rz_core_seek(core, old_offset, true);
}

static RzCmdStatus cmd_core_handle_search_hits(RzCore *core, RzCmdStateOutput *state, RZ_OWN RzList /*<RzSearchHit *>*/ *hits) {
	if (!hits) {
		core->num->value = 0;
		return RZ_CMD_STATUS_ERROR;
	}

	if (!rz_str_is_false(rz_config_get(core->config, "search.show_progress"))) {
		// clear last progress notification, if any
		rz_cons_clear_line(stderr);
	}

	RzListIter *it = NULL;
	RzSearchHit *hit = NULL;
	const char *cmd_hit = NULL;
	const char *search_prefix = NULL;

	cmd_hit = rz_config_get(core->config, "cmd.hit");
	search_prefix = rz_config_get(core->config, "search.prefix");
	if (RZ_STR_ISEMPTY(search_prefix)) {
		search_prefix = "hit";
	}

	if (RZ_STR_ISEMPTY(cmd_hit)) {
		// Setup output and flag space.
		rz_cmd_state_output_array_start(state);
		rz_cmd_state_output_set_columnsf(state, "xXss", "offset", "size", "flag", "detail");
		rz_flag_space_push(core->flags, "search");
	}

	size_t i = 0;
	rz_list_foreach_enum (hits, it, hit, i) {
		if (RZ_STR_ISNOTEMPTY(cmd_hit)) {
			cmd_search_call_command(core, hit, cmd_hit);
			continue;
		}

		// Only output & add flag when cmd.hit is not set.
		char *flag = rz_search_hit_flag_name(hit, i, search_prefix);
		RzFlagItem *fitem = rz_flag_set(core->flags, flag, hit->address, hit->size);
		char *detail = rz_search_hit_detail_as_string(hit);
		if (detail) {
			rz_flag_item_set_comment(fitem, detail);
		}
		cmd_search_output_to_state(state, hit, flag, detail);
		free(detail);
		free(flag);
	}

	if (RZ_STR_ISEMPTY(cmd_hit)) {
		// terminating output and flag space
		rz_flag_space_pop(core->flags);
		rz_cmd_state_output_array_end(state);
	}

	// set return value to the number of hits before returning
	core->num->value = rz_list_length(hits);
	rz_list_free(hits);
	return RZ_CMD_STATUS_OK;
}

static RzSearchOpt *setup_search_options(RzCore *core) {
	RzSearchOpt *search_opts = rz_search_opt_new();
	ut32 max_threads = rz_th_max_threads(rz_config_get_i(core->config, "search.max_threads"));
	ut32 max_hits = rz_config_get_i(core->config, "search.maxhits");
	ut32 search_chunk = rz_config_get_i(core->config, "search.chunk");
	const char *show_progress = rz_config_get(core->config, "search.show_progress");
	if (!(rz_search_opt_set_max_threads(search_opts, max_threads) &&
		    rz_search_opt_set_max_hits(search_opts, max_hits) &&
		    rz_search_opt_set_show_progress_from_str(search_opts, show_progress))) {
		RZ_LOG_ERROR("Failed setup find options.\n");
		rz_search_opt_free(search_opts);
		return NULL;
	}

	if (search_chunk && !rz_search_opt_set_chunk_size(search_opts, search_chunk)) {
		RZ_LOG_ERROR("Failed setup find options.\n");
		rz_search_opt_free(search_opts);
		return NULL;
	}

	RzSearchFindOpt *fopts = rz_core_setup_default_search_find_opts(core);
	if (!fopts) {
		RZ_LOG_ERROR("Failed init find options.\n");
		rz_search_opt_free(search_opts);
		return NULL;
	}
	if (!rz_search_opt_set_find_options(search_opts, fopts)) {
		RZ_LOG_ERROR("Failed add find options to the search optoins.\n");
		rz_search_find_opt_free(fopts);
		rz_search_opt_free(search_opts);
		return NULL;
	}
	return search_opts;
}

static RzCmdStatus byte_pattern_search(RzCore *core, RZ_OWN RzSearchBytesPattern *pattern, RzCmdStateOutput *state) {
	RzSearchOpt *search_opts = setup_search_options(core);
	RzList *hits = NULL;
	if (!search_opts) {
		rz_search_bytes_pattern_free(pattern);
		goto error;
	}

	CMD_SEARCH_BEGIN();

	if (!pattern) {
		RZ_LOG_ERROR("Failed to parse given pattern.\n");
		goto error;
	}

	bool progress = rz_search_opt_get_show_progress(search_opts) != RZ_SEARCH_PROGRESS_DISABLED;
	if (!rz_search_opt_set_cancel_cb(search_opts, cmd_search_progress_cancel, progress ? state : NULL)) {
		RZ_LOG_ERROR("code: Failed to setup default search options.\n");
		rz_search_bytes_pattern_free(pattern);
		goto error;
	}
	hits = rz_core_search_bytes(core, search_opts, pattern);
	if (!hits) {
		RZ_LOG_ERROR("Failed to perform search.\n");
		goto error;
	}

	CMD_SEARCH_END();
	rz_search_opt_free(search_opts);
	return cmd_core_handle_search_hits(core, state, hits);

error:
	rz_search_bytes_pattern_free(pattern);
	rz_list_free(hits);
	rz_search_opt_free(search_opts);
	CMD_SEARCH_END();
	return RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus value_range_search(RzCore *core, RZ_OWN RzVector /*<RzSearchValueRange>*/ *ranges, RzCmdStateOutput *state) {
	RzSearchOpt *search_opts = setup_search_options(core);
	RzList *hits = NULL;
	if (!search_opts) {
		rz_vector_free(ranges);
		goto error;
	}

	CMD_SEARCH_BEGIN();

	bool progress = !rz_str_is_false(rz_config_get(core->config, "search.show_progress"));
	if (!rz_search_opt_set_cancel_cb(search_opts, cmd_search_progress_cancel, progress ? state : NULL)) {
		RZ_LOG_ERROR("code: Failed to setup default search options.\n");
		rz_vector_free(ranges);
		goto error;
	}
	hits = rz_core_search_values(core, search_opts, ranges);
	if (!hits) {
		RZ_LOG_ERROR("Failed to perform search.\n");
		goto error;
	}

	CMD_SEARCH_END();
	rz_search_opt_free(search_opts);
	return cmd_core_handle_search_hits(core, state, hits);

error:
	rz_list_free(hits);
	rz_search_opt_free(search_opts);
	CMD_SEARCH_END();
	return RZ_CMD_STATUS_ERROR;
}

// "/+"
RZ_IPI RzCmdStatus rz_cmd_search_str_chunk_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/a"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && core->rasm, RZ_CMD_STATUS_ERROR);
	if (!core->rasm->cur) {
		RZ_LOG_ERROR("Not RzArch plugin set up.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	RzAsmCode *acode;
	if (!(acode = rz_asm_massemble(core->rasm, argv[1]))) {
		RZ_LOG_ERROR("Failed to assemble '%s'\n", argv[1]);
		RZ_LOG_ERROR("Consider using \"/ar\" instead.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	size_t len = acode->len;
	ut8 *bytes = rz_mem_dup(acode->bytes, len);
	rz_asm_code_free(acode);

	RzSearchBytesPattern *pattern = rz_search_bytes_pattern_new(bytes, NULL, len, "asm_text", false);
	return byte_pattern_search(core, pattern, state);
}

// "/a1"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_1_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/aI"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_I_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/aa"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_a_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return pass_to_legacy_api(core, argc, argv, mode);
}

// "/ac"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_c_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return pass_to_legacy_api(core, argc, argv, mode);
}

// "/ad"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_d_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return pass_to_legacy_api(core, argc, argv, mode);
}

// "/ad/"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_d_slash_handler(RzCore *core, int argc, const char **argv) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/ad/a"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_d_slasha_handler(RzCore *core, int argc, const char **argv) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/ae"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_e_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/af"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_f_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/afl"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_fl_handler(RzCore *core, int argc, const char **argv) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/ai"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_i_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return pass_to_legacy_api(core, argc, argv, mode);
}

// "/al"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_l_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/am"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_m_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/ao"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_o_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/as"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_s_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/asl"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_sl_handler(RzCore *core, int argc, const char **argv) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/at"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_t_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/atl"
RZ_IPI RzCmdStatus rz_cmd_search_assemble_tl_handler(RzCore *core, int argc, const char **argv) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/cm"
RZ_IPI RzCmdStatus rz_cmd_search_cryptographic_material_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core, RZ_CMD_STATUS_ERROR);
	if (argc < 2 || RZ_STR_ISEMPTY(argv[1])) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	bool is_all = !strcmp(argv[1], "all");
	RzSearchCollectionCryptographicType type = RZ_SEARCH_COLLECTION_CRYPTOGRAPHIC_ALL;

	if (!is_all && !rz_search_collection_cryptographic_name_to_type(argv[1], &type)) {
		RZ_LOG_ERROR("Failed to parse given type (%s).\n", argv[1]);
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzSearchOpt *search_opts = setup_search_options(core);
	RzList *hits = NULL;
	if (!search_opts) {
		return RZ_CMD_STATUS_ERROR;
	}

	CMD_SEARCH_BEGIN();

	bool progress = rz_config_get_b(core->config, "search.show_progress");
	if (!rz_search_opt_set_cancel_cb(search_opts, cmd_search_progress_cancel, progress ? state : NULL)) {
		RZ_LOG_ERROR("code: Failed to setup default search options.\n");
		goto error;
	}

	hits = rz_core_search_cryptographic_material(core, search_opts, type);
	if (!hits) {
		RZ_LOG_ERROR("Failed to perform search.\n");
		goto error;
	}

	CMD_SEARCH_END();
	rz_search_opt_free(search_opts);
	return cmd_core_handle_search_hits(core, state, hits);

error:
	rz_list_free(hits);
	rz_search_opt_free(search_opts);
	CMD_SEARCH_END();
	return RZ_CMD_STATUS_ERROR;
}

// "/ch"
RZ_IPI RzCmdStatus rz_cmd_search_hash_block_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core, RZ_CMD_STATUS_ERROR);
	RzSearchOpt *search_opts = setup_search_options(core);
	RzList *hits = NULL;
	if (!search_opts) {
		return RZ_CMD_STATUS_ERROR;
	}

	ut64 block_size = rz_num_get(NULL, argv[3]);
	if (block_size < 1) {
		RZ_LOG_ERROR("search: bad block size (%s).\n", argv[3]);
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	CMD_SEARCH_BEGIN();

	bool progress = rz_config_get_b(core->config, "search.show_progress");
	if (!rz_search_opt_set_cancel_cb(search_opts, cmd_search_progress_cancel, progress ? state : NULL)) {
		RZ_LOG_ERROR("search: Failed to setup default search options.\n");
		goto error;
	}

	hits = rz_core_search_hash(core, search_opts, argv[1], argv[2], block_size);
	if (!hits) {
		RZ_LOG_ERROR("Failed to perform search.\n");
		goto error;
	}

	CMD_SEARCH_END();
	rz_search_opt_free(search_opts);
	return cmd_core_handle_search_hits(core, state, hits);

error:
	rz_list_free(hits);
	rz_search_opt_free(search_opts);
	CMD_SEARCH_END();
	return RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus cmd_search_hash_entropy_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state, bool fractional) {
	rz_return_val_if_fail(core, RZ_CMD_STATUS_ERROR);
	RzSearchOpt *search_opts = setup_search_options(core);
	RzList *hits = NULL;
	if (!search_opts) {
		return RZ_CMD_STATUS_ERROR;
	}

	ut64 block_size = rz_num_get(NULL, argv[3]);
	if (block_size < 1) {
		RZ_LOG_ERROR("search: bad block size (%s).\n", argv[3]);
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	CMD_SEARCH_BEGIN();

	bool progress = rz_config_get_b(core->config, "search.show_progress");
	if (!rz_search_opt_set_cancel_cb(search_opts, cmd_search_progress_cancel, progress ? state : NULL)) {
		RZ_LOG_ERROR("search: Failed to setup default search options.\n");
		goto error;
	}

	double min_inclusive_limit = strtod(argv[1], NULL);
	double max_inclusive_limit = strtod(argv[2], NULL);

	hits = rz_core_search_entropy(core, search_opts, fractional, min_inclusive_limit, max_inclusive_limit, block_size);
	if (!hits) {
		RZ_LOG_ERROR("Failed to perform search.\n");
		goto error;
	}

	CMD_SEARCH_END();
	rz_search_opt_free(search_opts);
	return cmd_core_handle_search_hits(core, state, hits);

error:
	rz_list_free(hits);
	rz_search_opt_free(search_opts);
	CMD_SEARCH_END();
	return RZ_CMD_STATUS_ERROR;
}

// "/ce"
RZ_IPI RzCmdStatus rz_cmd_search_hash_entropy_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return cmd_search_hash_entropy_handler(core, argc, argv, state, false);
}

// "/cef"
RZ_IPI RzCmdStatus rz_cmd_search_hash_entropy_fractional_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return cmd_search_hash_entropy_handler(core, argc, argv, state, true);
}

// "/d"
RZ_IPI RzCmdStatus rz_cmd_search_deltified_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

static void legacy_param_setup(RzCore *core, struct search_parameters *param, size_t mode) {
	param->mode = rz_config_get(core->config, "search.in");
	param->core = core;
	param->cmd_hit = rz_config_get(core->config, "cmd.hit");
	if (!param->cmd_hit) {
		param->cmd_hit = "";
	}
	param->hit_prefix = rz_config_get(core->config, "search.prefix");
	param->outmode = mode;
	param->searchshow = rz_config_get_i(core->config, "search.show");
	param->searchflags = rz_config_get_i(core->config, "search.flags");
	param->boundaries = rz_core_get_boundaries_select(core, "search.from", "search.to", "search.in");
	if (param->outmode == RZ_OUTPUT_MODE_JSON) {
		param->pj = pj_new();
	}
}

// "/F"
RZ_IPI RzCmdStatus rz_cmd_search_file_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	const char *keyword_file = argv[1];
	ut64 offset = argc > 2 ? rz_num_get(core->num, argv[2]) : 0;
	ut64 len = argc > 3 ? rz_num_get(core->num, argv[3]) : 0;
	if (!rz_file_exists(keyword_file)) {
		RZ_LOG_ERROR("File '%s' does not exist.\n", keyword_file);
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 file_size = rz_file_size(keyword_file);
	if (len > INT_MAX || (len == 0 && file_size > INT_MAX)) {
		RZ_LOG_ERROR("File sizes larger than INT_MAX are not supported currently.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (offset >= file_size) {
		RZ_LOG_ERROR("Given offset %" PFMT64u " exceeds file size %" PFMT64u ".\n", offset, file_size);
		return RZ_CMD_STATUS_ERROR;
	}
	int bytes_read;
	ut8 *file_content = (ut8 *)rz_file_slurp_range(keyword_file, offset, len == 0 ? file_size : len, &bytes_read);
	if (!file_content) {
		RZ_LOG_ERROR("Failed to read file: '%s'.\n", keyword_file);
		return RZ_CMD_STATUS_ERROR;
	}
	RzSearchBytesPattern *pattern = rz_search_bytes_pattern_new(file_content, NULL, bytes_read, "keyword_file", false);
	return byte_pattern_search(core, pattern, state);
}

// "/g"
RZ_IPI RzCmdStatus rz_cmd_search_graph_path_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	ut64 from = rz_num_get(NULL, argv[1]);
	ut64 to = rz_num_get(NULL, argv[2]);
	const int depth = rz_config_get_i(core->config, "analysis.depth");
	rz_core_analysis_paths(core, from, to, false, depth, state->mode == RZ_OUTPUT_MODE_JSON);
	return RZ_CMD_STATUS_OK;
}

// "/gg"
RZ_IPI RzCmdStatus rz_cmd_search_graph_path_follow_calls_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	ut64 from = rz_num_get(NULL, argv[1]);
	ut64 to = rz_num_get(NULL, argv[2]);
	const int depth = rz_config_get_i(core->config, "analysis.depth");
	rz_core_analysis_paths(core, from, to, true, depth, state->mode == RZ_OUTPUT_MODE_JSON);
	return RZ_CMD_STATUS_OK;
}

// "/m"
RZ_IPI RzCmdStatus rz_cmd_search_magic_const_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzList *hits = NULL;
	CMD_SEARCH_BEGIN();
	hits = rz_core_search_magic(core, NULL, argc > 1 ? argv[1] : NULL);
	CMD_SEARCH_END();
	return cmd_core_handle_search_hits(core, state, hits);
}

// "/mb"
RZ_IPI RzCmdStatus rz_cmd_search_magic_bin_headers_handler(RzCore *core, int argc, const char **argv) {
	RzInterval itv = { 0 };
	itv.addr = rz_config_get_i(core->config, "search.from");
	itv.size = rz_config_get_i(core->config, "search.to") - itv.addr;
	CMD_SEARCH_BEGIN();
	// This does not really searches magics.
	// It just opens the buffer with rz_bin_open_io().
	cmd_search_bin(core, itv);
	CMD_SEARCH_END();
	return RZ_CMD_STATUS_OK;
}

// "/o"
RZ_IPI RzCmdStatus rz_cmd_search_insn_offset_backwards_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	ut64 addr, n = rz_num_math(core->num, argv[1]);
	n = rz_num_abs((st64)n);
	if (((st64)n) < 1) {
		n = 1;
	}
	if (!rz_core_prevop_addr(core, core->offset, n, &addr)) {
		addr = UT64_MAX;
		(void)rz_core_asm_bwdis_len(core, NULL, &addr, n);
	}
	if (mode == RZ_OUTPUT_MODE_JSON) {
		rz_cons_printf("[%" PFMT64u "]", addr);
	} else {
		rz_cons_printf("0x%08" PFMT64x "\n", addr);
	}
	return RZ_CMD_STATUS_OK;
}

// "/O"
RZ_IPI RzCmdStatus rz_cmd_search_insn_offset_backwards_fallback_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	ut64 addr, n = rz_num_math(core->num, argv[1]);
	if (!n) {
		n = 1;
	}
	addr = rz_core_prevop_addr_force(core, core->offset, n);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		rz_cons_printf("[%" PFMT64u "]", addr);
	} else {
		rz_cons_printf("0x%08" PFMT64x "\n", addr);
	}
	return RZ_CMD_STATUS_OK;
}

// "/p"
RZ_IPI RzCmdStatus rz_cmd_search_pattern_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	ut64 ps = rz_num_get(NULL, argv[1]);
	if (ps <= 1) {
		RZ_LOG_ERROR("Pattern size must be greater than 1.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	CMD_SEARCH_BEGIN();
	struct search_parameters param = { 0 };
	legacy_param_setup(core, &param, RZ_OUTPUT_MODE_STANDARD);
	RzListIter *iter;
	RzIOMap *map;
	rz_list_foreach (param.boundaries, iter, map) {
		eprintf("-- %llx %llx\n", map->itv.addr, rz_itv_end(map->itv));
		rz_cons_break_push(NULL, NULL);
		rz_search_pattern_size(core->search, ps);
		if (!rz_search_pattern(core->search, map->itv.addr, rz_itv_end(map->itv))) {
			RZ_LOG_ERROR("Pattern search failed.\n");
			rz_cons_break_pop();
			CMD_SEARCH_END();
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_break_pop();
	}
	CMD_SEARCH_END();
	return RZ_CMD_STATUS_OK;
}

// "/P"
RZ_IPI RzCmdStatus rz_cmd_search_blocks_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	CMD_SEARCH_BEGIN();
	struct search_parameters param = { 0 };
	legacy_param_setup(core, &param, RZ_OUTPUT_MODE_STANDARD);
	search_similar_pattern(core, rz_num_get(NULL, argv[1]), &param);
	CMD_SEARCH_END();
	return RZ_CMD_STATUS_OK;
}

// "/r"
RZ_IPI RzCmdStatus rz_cmd_search_reference_handler(RzCore *core, int argc, const char **argv) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/ra"
RZ_IPI RzCmdStatus rz_cmd_search_reference_all_handler(RzCore *core, int argc, const char **argv) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/rc"
RZ_IPI RzCmdStatus rz_cmd_search_reference_call_handler(RzCore *core, int argc, const char **argv) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/rr"
RZ_IPI RzCmdStatus rz_cmd_search_reference_read_handler(RzCore *core, int argc, const char **argv) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/rw"
RZ_IPI RzCmdStatus rz_cmd_search_reference_write_handler(RzCore *core, int argc, const char **argv) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

// "/rx"
RZ_IPI RzCmdStatus rz_cmd_search_reference_execute_handler(RzCore *core, int argc, const char **argv) {
	return pass_to_legacy_api(core, argc, argv, RZ_OUTPUT_MODE_STANDARD);
}

static void set_byte_properties(RzCore *core, RzSearchValueRange *range, const char *byte_arg) {
	switch (byte_arg[0]) {
	default:
		rz_warn_if_reached();
		return;
	case '1':
		range->width = 1;
		break;
	case '2':
		range->width = 2;
		break;
	case '4':
		range->width = 4;
		break;
	case '8':
		range->width = 8;
		break;
	}

	switch (byte_arg[1]) {
	default:
		// NUL case of "1"
		return;
	case 'b':
		range->big_endian = true;
		break;
	case 'l':
		range->big_endian = false;
		break;
	case 'a':
		range->big_endian = rz_config_get_b(core->config, "cfg.bigendian");
		break;
	}
}

// "/v"
RZ_IPI RzCmdStatus rz_cmd_search_value_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzSearchValueRange range_template = { 0 };

	set_byte_properties(core, &range_template, argv[1]);
	RzVector *ranges = rz_vector_new(sizeof(RzSearchValueRange), NULL, NULL);
	for (size_t i = 2; i < argc; ++i) {
		RzIntervalBoundedUt64 itv = { 0 };
		if (!rz_itv_str_to_bounded_itv_ut64(argv[i], &itv)) {
			RZ_LOG_ERROR("Failed to parse interval: '%s'.\n", argv[i]);
			rz_vector_free(ranges);
			return RZ_CMD_STATUS_ERROR;
		}
		range_template.itv = itv;
		rz_vector_push(ranges, &range_template);
	}
	return value_range_search(core, ranges, state);
}

static RzCmdStatus v_alias(RzCore *core, size_t width, const char *min, const char *max, RzCmdStateOutput *state) {
	RzSearchValueRange range_template = { 0 };
	range_template.width = width;
	range_template.big_endian = rz_config_get_b(core->config, "cfg.bigendian");
	RzVector *ranges = rz_vector_new(sizeof(RzSearchValueRange), NULL, NULL);
	range_template.itv.bound = RZ_INTERVAL_BOUND_CLOSED;
	range_template.itv.a = rz_num_math(NULL, min);
	range_template.itv.b = rz_num_math(NULL, max);
	rz_vector_push(ranges, &range_template);
	return value_range_search(core, ranges, state);
}

// "/v1"
RZ_IPI RzCmdStatus rz_cmd_search_value_alias_v1_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return v_alias(core, 1, argv[1], argv[1], state);
}

// "/v2"
RZ_IPI RzCmdStatus rz_cmd_search_value_alias_v2_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return v_alias(core, 2, argv[1], argv[1], state);
}

// "/v4"
RZ_IPI RzCmdStatus rz_cmd_search_value_alias_v4_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return v_alias(core, 4, argv[1], argv[1], state);
}

// "/v8"
RZ_IPI RzCmdStatus rz_cmd_search_value_alias_v8_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return v_alias(core, 8, argv[1], argv[1], state);
}

// "/V1"
RZ_IPI RzCmdStatus rz_cmd_search_value_alias_v1_range_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return v_alias(core, 1, argv[1], argv[2], state);
}

// "/V2"
RZ_IPI RzCmdStatus rz_cmd_search_value_alias_v2_range_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return v_alias(core, 2, argv[1], argv[2], state);
}

// "/V4"
RZ_IPI RzCmdStatus rz_cmd_search_value_alias_v4_range_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return v_alias(core, 4, argv[1], argv[2], state);
}

// "/V8"
RZ_IPI RzCmdStatus rz_cmd_search_value_alias_v8_range_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return v_alias(core, 8, argv[1], argv[2], state);
}

// "/x"
RZ_IPI RzCmdStatus rz_cmd_search_hex_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	const char *arg = argv[1];
	RzSearchBytesPattern *pattern = rz_search_parse_byte_pattern(arg, "bytes");
	return byte_pattern_search(core, pattern, state);
}

static bool parse_pattern_arg(const char *arg, RZ_OUT ut8 *re, RZ_OUT size_t *len) {
	*len = 0;
	size_t arg_len = strlen(arg);
	// Convert to real bytes.
	for (size_t i = 0; i < arg_len;) {
		if (arg[i] == 'x') {
			if (i + 2 >= arg_len) {
				RZ_LOG_ERROR("'x' in the pattern must be followed by two hexadecimal nibbles (N = [a-fA-F0-9]): xNN.\n");
				return false;
			}
			if (!IS_HEXCHAR(arg[i + 1]) || !IS_HEXCHAR(arg[i + 2])) {
				RZ_LOG_ERROR("Bytes with non-hexadecimal nibbles are not allowed. Got: 'x%c%c'.\n", arg[i + 1], arg[i + 2]);
				return false;
			}
			ut16 byte = rz_hex_digit_pair_to_byte(arg + i + 1);
			re[*len] = byte;
			i += 3;
		} else {
			// Just copy normal character.
			re[*len] = arg[i];
			i++;
		}
		*len += 1;
	}
	return true;
}

// "/xr"
RZ_IPI RzCmdStatus rz_cmd_search_hex_regex_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && state && argv, RZ_CMD_STATUS_ERROR);
	ut8 *re = RZ_NEWS0(ut8, strlen(argv[1]));
	RzSearchOpt *search_opts = setup_search_options(core);
	RzList *hits = NULL;
	if (!search_opts) {
		goto error;
	}

	CMD_SEARCH_BEGIN();

	const char *arg = argv[1];
	size_t r = 0;
	if (!parse_pattern_arg(arg, re, &r)) {
		goto error;
	}
	RzSearchBytesPattern *pattern = rz_search_bytes_pattern_new(rz_new_copy(r, re), NULL, r, "bytes", true);

	if (!pattern) {
		RZ_LOG_ERROR("Failed to parse given pattern.\n");
		goto error;
	}

	bool progress = rz_search_opt_get_show_progress(search_opts) != RZ_SEARCH_PROGRESS_DISABLED;
	if (!rz_search_opt_set_cancel_cb(search_opts, cmd_search_progress_cancel, progress ? state : NULL)) {
		RZ_LOG_ERROR("code: Failed to setup default search options.\n");
		goto error;
	}
	hits = rz_core_search_bytes(core, search_opts, pattern);
	if (!hits) {
		RZ_LOG_ERROR("Failed to perform search.\n");
		goto error;
	}

	CMD_SEARCH_END();
	free(re);
	rz_search_opt_free(search_opts);
	return cmd_core_handle_search_hits(core, state, hits);

error:
	free(re);
	rz_list_free(hits);
	rz_search_opt_free(search_opts);
	CMD_SEARCH_END();
	return RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus cmd_string_search_generic(RzCore *core, const char *string, const char *encoding, RzRegexFlags flags, RzCmdStateOutput *state) {
	RzSearchOpt *search_opts = setup_search_options(core);
	if (!search_opts) {
		return RZ_CMD_STATUS_ERROR;
	}
	bool memset_ff = rz_config_get_b(core->config, "io.ff");
	// Disable memset of IO memory at read to be way faster.
	rz_config_set_b(core->config, "io.ff", false);

	CMD_SEARCH_BEGIN();

	RzStrEnc expected = RZ_STRING_ENC_GUESS;
	char *search_str = rz_str_dup(string);
	if (RZ_STR_ISEMPTY(search_str)) {
		RZ_LOG_ERROR("core: invalid string: empty string.\n");
		goto invalid_args;
	}
	if (RZ_STR_ISEMPTY(encoding)) {
		RZ_LOG_ERROR("core: invalid encoding: empty encoding.\n");
		goto invalid_args;
	}
	if (rz_str_unescape(search_str) < 1) {
		RZ_LOG_ERROR("core: invalid string: failed to unescape.\n");
		goto invalid_args;
	}
	size_t search_str_len = 0; // Not set if not literal.
	if (flags & RZ_REGEX_LITERAL) {
		search_str_len = rz_utf8_strlen((const ut8 *)search_str);
		if (search_str_len < core->bin->str_search_cfg.min_length) {
			RZ_LOG_WARN_AFTER(core, "|%s| < search.str.min_length so some search hits may be hidden."
						" Set search.str.min_length to %" PFMTSZu " to see them.\n",
				search_str, search_str_len);
		}
	}

	expected = rz_str_enc_string_as_type(encoding);
	if (expected == RZ_STRING_ENC_SETTINGS) {
		expected = rz_str_enc_string_as_type(rz_config_get(core->config, "str.encoding"));
	}
	if (!RZ_STR_EQ(encoding, "guess") && expected == RZ_STRING_ENC_GUESS) {
		if (!RZ_STR_EQ(encoding, "settings")) {
			RZ_LOG_ERROR("core: invalid encoding '%s'.\n", encoding);
			goto invalid_args;
		}
		// Else we are fine, since the encoding in the settings is set to 'guess'.
	}

	bool progress = rz_search_opt_get_show_progress(search_opts) != RZ_SEARCH_PROGRESS_DISABLED;
	if (!rz_search_opt_set_cancel_cb(search_opts, cmd_search_progress_cancel, progress ? state : NULL)) {
		RZ_LOG_ERROR("code: Failed to setup default search options.\n");
		free(search_str);
		rz_search_opt_free(search_opts);
		rz_config_set_b(core->config, "io.ff", memset_ff);
		CMD_SEARCH_END();
		return RZ_CMD_STATUS_ERROR;
	}
	RzList *hits = rz_core_search_string(core, search_opts, search_str, search_str_len, flags, expected);

	rz_config_set_b(core->config, "io.ff", memset_ff);
	free(search_str);
	rz_search_opt_free(search_opts);
	CMD_SEARCH_END();
	return cmd_core_handle_search_hits(core, state, hits);

invalid_args:
	rz_config_set_b(core->config, "io.ff", memset_ff);
	free(search_str);
	rz_search_opt_free(search_opts);
	CMD_SEARCH_END();
	return RZ_CMD_STATUS_ERROR;
}

// "/z"
RZ_IPI RzCmdStatus rz_cmd_search_string_sensitive_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzRegexFlags flags = rz_regex_parse_flag_desc(argv[2]);
	if (flags == ~RZ_REGEX_DEFAULT) {
		RZ_LOG_ERROR("Regex flags are invalid: '%s'\n", argv[2]);
		return RZ_CMD_STATUS_ERROR;
	}
	RzCmdStatus res = cmd_string_search_generic(core, argv[1], argv[3], flags, state);
	return res;
}
