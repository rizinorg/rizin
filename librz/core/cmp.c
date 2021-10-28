// SPDX-FileCopyrightText: 2021 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmp.h>
#include <rz_asm.h>
#include <rz_list.h>

RZ_API RZ_OWN RzCompareData *rz_cmp_data_data(RZ_NONNULL RzCore *core, ut64 addr1, ut64 addr2, ut64 len) {
	rz_return_val_if_fail(core, NULL);

	ut8 *buf1 = malloc(len * sizeof(ut8));
	ut8 *buf2 = malloc(len * sizeof(ut8));
	if (!buf1 || !buf2) {
		goto error_goto;
	}
	if (!rz_io_read_at(core->io, addr1, buf1, len) || !rz_io_read_at(core->io, addr2, buf2, len)) {
		RZ_LOG_ERROR("Cannot read at provided addresses: 0x%" PFMT64x " 0x%" PFMT64x "\n", addr1, addr2);
		goto error_goto;
	}
	RzCompareData *cmp = RZ_NEW0(RzCompareData);
	if (!cmp) {
		goto error_goto;
	}
	cmp->len = len;
	cmp->data1 = buf1;
	cmp->addr1 = addr1;
	cmp->data2 = buf2;
	cmp->addr2 = addr2;
	cmp->same = rz_mem_eq(cmp->data1, cmp->data2, len);
	return cmp;

error_goto:
	free(buf1);
	free(buf2);
	return NULL;
}

RZ_API RZ_OWN RzCompareData *rz_cmp_data_str(RZ_NONNULL RzCore *core, ut64 addr1, RZ_NONNULL const ut8 *str, ut64 len) {
	rz_return_val_if_fail(core && str, NULL);

	ut8 *buf1 = malloc(len * sizeof(ut8));
	if (!buf1) {
		RZ_LOG_ERROR("Cannot read at address: 0x%" PFMT64x "\n", addr1);
		goto error_goto;
	}
	if (!rz_io_read_at(core->io, addr1, buf1, len)) {
		goto error_goto;
	}
	RzCompareData *cmp = RZ_NEW0(RzCompareData);
	if (!cmp) {
		goto error_goto;
	}
	cmp->len = len;
	cmp->data1 = buf1;
	cmp->addr1 = addr1;
	cmp->data2 = rz_mem_dup(str, len);
	cmp->addr2 = UT64_MAX;
	cmp->same = rz_mem_eq(cmp->data1, cmp->data2, len);
	return cmp;

error_goto:
	free(buf1);
	return NULL;
}

RZ_API int rz_cmp_print(RZ_NONNULL RzCore *core, RZ_NONNULL const RzCompareData *cmp, RzCompareOutputMode mode) {
	rz_return_val_if_fail(core && cmp, 0);

	int i, eq = 0;
	bool data_str = cmp->addr2 == UT64_MAX;
	PJ *pj = NULL;
	if (cmp->len == UT8_MAX) {
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
	for (i = 0; i < cmp->len; i++) {
		if (cmp->data1[i] == cmp->data2[i]) {
			eq++;
			continue;
		}
		switch (mode) {
		case RZ_COMPARE_MODE_DEFAULT:
			rz_cons_printf("0x%08" PFMT64x, cmp->addr1 + i);
			if (!data_str) {
				rz_cons_printf("  ->  0x%08" PFMT64x, cmp->addr2 + i);
			}
			rz_cons_printf(" (byte=%.2d)   %02x '%c'  ->  %02x '%c'\n", i + 1,
				cmp->data1[i], (IS_PRINTABLE(cmp->data1[i])) ? cmp->data1[i] : ' ',
				cmp->data2[i], (IS_PRINTABLE(cmp->data2[i])) ? cmp->data2[i] : ' ');
			break;
		case RZ_COMPARE_MODE_RIZIN:
			rz_cons_printf("wx %02x @ 0x%08" PFMT64x "\n",
				cmp->data2[i],
				cmp->addr1 + i);
			break;
		case RZ_COMPARE_MODE_JSON:
			pj_o(pj);
			pj_kn(pj, "offset1", cmp->addr1 + i);
			pj_kn(pj, "offset2", data_str ? i : cmp->addr2 + i);
			pj_ki(pj, "rel_offset", i);
			pj_ki(pj, "value1", (int)cmp->data1[i]);
			pj_ki(pj, "value2", (int)cmp->data2[i]);
			pj_end(pj);
			break;
		default:
			rz_warn_if_reached();
		}
	}
	if (mode == RZ_COMPARE_MODE_DEFAULT) {
		rz_cons_printf("Compare %d/%d equal bytes (%d%%)\n", eq, cmp->len, (int)(100.0 * eq / cmp->len));
	} else if (mode == RZ_COMPARE_MODE_JSON) {
		pj_end(pj);
		pj_ki(pj, "equal_bytes", eq);
		pj_ki(pj, "total_bytes", cmp->len);
		pj_end(pj); // End array
		pj_end(pj); // End object
		rz_cons_println(pj_string(pj));
	}
	return cmp->len - eq;
}

RZ_API RZ_OWN RzList /*<RzCompareData>*/ *rz_cmp_disasm(RZ_NONNULL RzCore *core, RZ_NONNULL const char *input) {
	rz_return_val_if_fail(core && input, NULL);

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

		comp->len = UT8_MAX;
		comp->data1 = (ut8 *)strdup(rz_strbuf_get(&op.buf_asm));
		comp->addr1 = core->offset + i;
		comp->data2 = (ut8 *)strdup(rz_strbuf_get(&op2.buf_asm));
		comp->addr2 = off + j;
		comp->same = rz_mem_eq(comp->data1, comp->data2, comp->len);
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
RZ_API void rz_core_cmpwatch_free(RZ_NONNULL RzCoreCmpWatcher *w) {
	rz_return_if_fail(w);
	free(w->ndata);
	free(w->odata);
	free(w);
}

RZ_API RzCoreCmpWatcher *rz_core_cmpwatch_get(RZ_NONNULL RzCore *core, ut64 addr) {
	rz_return_val_if_fail(core, NULL);
	RzListIter *iter;
	RzCoreCmpWatcher *w;
	rz_list_foreach (core->watchers, iter, w) {
		if (addr == w->addr) {
			return w;
		}
	}
	return NULL;
}

RZ_API bool rz_core_cmpwatch_add(RZ_NONNULL RzCore *core, ut64 addr, int size, const char *cmd) {
	rz_return_val_if_fail(core, false);
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

RZ_API bool rz_core_cmpwatch_del(RZ_NONNULL RzCore *core, ut64 addr) {
	rz_return_val_if_fail(core, false);
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

RZ_API void rz_core_cmpwatch_show(RZ_NONNULL RzCore *core, ut64 addr, RzCompareOutputMode mode) {
	rz_return_if_fail(core);
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

RZ_API bool rz_core_cmpwatch_update(RZ_NONNULL RzCore *core, ut64 addr) {
	rz_return_val_if_fail(core, false);
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

RZ_API bool rz_core_cmpwatch_revert(RZ_NONNULL RzCore *core, ut64 addr) {
	rz_return_val_if_fail(core, false);
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
