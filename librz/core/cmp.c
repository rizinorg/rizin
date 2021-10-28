// SPDX-FileCopyrightText: 2021 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmp.h>
#include <rz_asm.h>
#include <rz_list.h>

RZ_API int rz_cmp_compare(RzCore *core, const ut8 *addr, int len, RzCompareOutputMode mode) {
	int i, eq = 0;
	PJ *pj = NULL;
	if (len < 1) {
		return 0;
	}
	if (mode == RZ_COMPARE_MODE_JSON) {
		pj = pj_new();
		if (!pj) {
			return -1;
		}
		pj_o(pj);
		pj_k(pj, "diff_bytes");
		pj_a(pj);
	}
	for (i = 0; i < len; i++) {
		if (core->block[i] == addr[i]) {
			eq++;
			continue;
		}
		switch (mode) {
		case RZ_COMPARE_MODE_DEFAULT:
			rz_cons_printf("0x%08" PFMT64x " (byte=%.2d)   %02x '%c'  ->  %02x '%c'\n",
				core->offset + i, i + 1,
				core->block[i], (IS_PRINTABLE(core->block[i])) ? core->block[i] : ' ',
				addr[i], (IS_PRINTABLE(addr[i])) ? addr[i] : ' ');
			break;
		case RZ_COMPARE_MODE_RIZIN:
			rz_cons_printf("wx %02x @ 0x%08" PFMT64x "\n",
				addr[i],
				core->offset + i);
			break;
		case RZ_COMPARE_MODE_JSON:
			pj_o(pj);
			pj_kn(pj, "offset", core->offset + i);
			pj_ki(pj, "rel_offset", i);
			pj_ki(pj, "value", (int)core->block[i]);
			pj_ki(pj, "cmp_value", (int)addr[i]);
			pj_end(pj);
			break;
		default:
			rz_warn_if_reached();
		}
	}
	if (mode == RZ_COMPARE_MODE_DEFAULT) {
		eprintf("Compare %d/%d equal bytes (%d%%)\n", eq, len, (eq / len) * 100);
	} else if (mode == RZ_COMPARE_MODE_JSON) {
		pj_end(pj);
		pj_ki(pj, "equal_bytes", eq);
		pj_ki(pj, "total_bytes", len);
		pj_end(pj); // End array
		pj_end(pj); // End object
		rz_cons_println(pj_string(pj));
	}
	return len - eq;
}

RZ_API RZ_OWN RzList /*<RzCompareData>*/ *rz_cmp_disasm(RZ_NONNULL RzCore *core, RZ_NONNULL const char *input) {
	rz_return_val_if_fail(core && input, false);

	RzList *cmp_list = rz_list_new();
	if (!cmp_list) {
		goto error_goto;
	}
	RzAsmOp op, op2;
	int i, j;
	ut64 off = rz_num_math(core->num, input);
	ut8 *buf = calloc(core->blocksize + 32, 1);
	if (!buf) {
		goto error_goto;
	}
	rz_io_read_at(core->io, off, buf, core->blocksize + 32);
	RzCompareData *comp;

	for (i = j = 0; i < core->blocksize && j < core->blocksize;) {
		comp = RZ_NEW0(RzCompareData);
		if (!comp) {
			continue;
		}

		// dis A
		rz_asm_set_pc(core->rasm, core->offset + i);
		(void)rz_asm_disassemble(core->rasm, &op,
			core->block + i, core->blocksize - i);

		// dis B
		rz_asm_set_pc(core->rasm, off + i);
		(void)rz_asm_disassemble(core->rasm, &op2,
			buf + j, core->blocksize - j);

		comp->same = rz_strbuf_equals(&op.buf_asm, &op2.buf_asm);
		comp->data1 = (ut8 *)strdup(rz_strbuf_get(&op.buf_asm));
		comp->addr1 = core->offset + i;
		comp->data2 = (ut8 *)strdup(rz_strbuf_get(&op2.buf_asm));
		comp->addr2 = off + j;
		rz_list_append(cmp_list, comp);

		if (op.size < 1) {
			op.size = 1;
		}
		i += op.size;
		if (op2.size < 1) {
			op2.size = 1;
		}
		j += op2.size;
	}

	return cmp_list;

error_goto:
	rz_list_free(cmp_list);
	return NULL;
}

RZ_API bool rz_cmp_disasm_print(RzCore *core, const RzList /*<RzCompareData>*/ *compare, bool unified) {
	rz_return_val_if_fail(core && compare, false);
	char colpad[80];
	int hascolor = rz_config_get_i(core->config, "scr.color");
	int cols = rz_config_get_i(core->config, "hex.cols") * 2;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	RzListIter *it;
	RzCompareData *cmp;

	if (unified) {
		rz_list_foreach (compare, it, cmp) {
			if (cmp->same) {
				rz_cons_printf(" 0x%08" PFMT64x "  %s\n",
					cmp->addr1, cmp->data1);
			} else {
				if (hascolor) {
					rz_cons_print(pal->graph_false);
				}
				rz_cons_printf("-0x%08" PFMT64x "  %s\n",
					cmp->addr1, cmp->data1);
				if (hascolor) {
					rz_cons_print(pal->graph_true);
				}
				rz_cons_printf("+0x%08" PFMT64x "  %s\n",
					cmp->addr2, cmp->data2);
				if (hascolor) {
					rz_cons_print(Color_RESET);
				}
			}
		}
	} else {
		rz_list_foreach (compare, it, cmp) {
			memset(colpad, ' ', sizeof(colpad));
			int pos = strlen((char *)cmp->data1);
			pos = (pos > cols) ? 0 : cols - pos;
			colpad[pos] = 0;
			if (hascolor) {
				rz_cons_print(cmp->same ? pal->graph_true : pal->graph_false);
			}
			rz_cons_printf(" 0x%08" PFMT64x "  %s %s",
				cmp->addr1, cmp->data1, colpad);
			rz_cons_printf("%c 0x%08" PFMT64x "  %s\n",
				cmp->same ? '=' : '!', cmp->addr2, cmp->data2);
			if (hascolor) {
				rz_cons_print(Color_RESET);
			}
		}
	}

	return true;
}

/* cmpwatch API */
RZ_API void rz_core_cmpwatch_free(RzCoreCmpWatcher *w) {
	free(w->ndata);
	free(w->odata);
	free(w);
}

RZ_API RzCoreCmpWatcher *rz_core_cmpwatch_get(RzCore *core, ut64 addr) {
	RzListIter *iter;
	RzCoreCmpWatcher *w;
	rz_list_foreach (core->watchers, iter, w) {
		if (addr == w->addr) {
			return w;
		}
	}
	return NULL;
}

RZ_API bool rz_core_cmpwatch_add(RzCore *core, ut64 addr, int size, const char *cmd) {
	RzCoreCmpWatcher *cmpw;
	if (size < 1) {
		return false;
	}
	cmpw = rz_core_cmpwatch_get(core, addr);
	if (!cmpw) {
		cmpw = RZ_NEW(RzCoreCmpWatcher);
		if (!cmpw) {
			return false;
		}
		cmpw->addr = addr;
	}
	cmpw->size = size;
	snprintf(cmpw->cmd, sizeof(cmpw->cmd), "%s", cmd);
	cmpw->odata = NULL;
	cmpw->ndata = malloc(size);
	if (!cmpw->ndata) {
		free(cmpw);
		return false;
	}
	rz_io_read_at(core->io, addr, cmpw->ndata, size);
	rz_list_append(core->watchers, cmpw);
	return true;
}

RZ_API int rz_core_cmpwatch_del(RzCore *core, ut64 addr) {
	int ret = false;
	RzCoreCmpWatcher *w;
	RzListIter *iter, *iter2;
	rz_list_foreach_safe (core->watchers, iter, iter2, w) {
		if (w->addr == addr || addr == UT64_MAX) {
			rz_list_delete(core->watchers, iter);
			ret = true;
		}
	}
	return ret;
}

RZ_API void rz_core_cmpwatch_show(RzCore *core, ut64 addr, RzCompareOutputMode mode) {
	char cmd[128];
	RzListIter *iter;
	RzCoreCmpWatcher *w;
	rz_list_foreach (core->watchers, iter, w) {
		int is_diff = w->odata ? memcmp(w->odata, w->ndata, w->size) : 0;
		switch (mode) {
		case RZ_COMPARE_MODE_RIZIN:
			rz_cons_printf("cw 0x%08" PFMT64x " %d %s%s\n",
				w->addr, w->size, w->cmd, is_diff ? " # differs" : "");
			break;
		case RZ_COMPARE_MODE_DIFF: // diff
			if (is_diff) {
				rz_cons_printf("0x%08" PFMT64x " has changed\n", w->addr);
			}
		case RZ_COMPARE_MODE_DEFAULT:
			rz_cons_printf("0x%08" PFMT64x "%s\n", w->addr, is_diff ? " modified" : "");
			snprintf(cmd, sizeof(cmd), "%s@%" PFMT64d "!%d",
				w->cmd, w->addr, w->size);
			rz_core_cmd0(core, cmd);
			break;
		default:
			rz_warn_if_reached();
		}
	}
}

RZ_API bool rz_core_cmpwatch_update(RzCore *core, ut64 addr) {
	RzCoreCmpWatcher *w;
	RzListIter *iter;
	rz_list_foreach (core->watchers, iter, w) {
		free(w->odata);
		w->odata = w->ndata;
		w->ndata = malloc(w->size);
		if (!w->ndata) {
			return false;
		}
		rz_io_read_at(core->io, w->addr, w->ndata, w->size);
	}
	return !rz_list_empty(core->watchers);
}

RZ_API bool rz_core_cmpwatch_revert(RzCore *core, ut64 addr) {
	RzCoreCmpWatcher *w;
	int ret = false;
	RzListIter *iter;
	rz_list_foreach (core->watchers, iter, w) {
		if (w->addr == addr || addr == UT64_MAX) {
			if (w->odata) {
				free(w->ndata);
				w->ndata = w->odata;
				w->odata = NULL;
				ret = true;
			}
		}
	}
	return ret;
}
