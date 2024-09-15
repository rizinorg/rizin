// SPDX-FileCopyrightText: 2021 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmp.h>
#include <rz_asm.h>
#include <rz_list.h>

/**
 * \brief Compare memory at \p addr1 with the memory at \p addr2
 *
 * \param core Current RzCore instance
 * \param addr1 address to read data from
 * \param addr2 address to read data from
 * \param len Number of bytes to compare
 * \return RzCompareData* A pointer to RzCompareData comparison
 */
RZ_API RZ_OWN RzCompareData *rz_core_cmp_mem_mem(RzCore *core, ut64 addr1, ut64 addr2, ut32 len) {
	rz_return_val_if_fail(core, NULL);

	ut8 *buf1 = malloc(len * sizeof(ut8));
	ut8 *buf2 = malloc(len * sizeof(ut8));
	if (!buf1 || !buf2) {
		goto error_goto;
	}
	if (!(rz_io_nread_at(core->io, addr1, buf1, len) == len && rz_io_nread_at(core->io, addr2, buf2, len) == len)) {
		RZ_LOG_ERROR("Cannot read %u bytes at provided addresses: 0x%" PFMT64x " 0x%" PFMT64x "\n", len, addr1, addr2);
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

/**
 * \brief Compare mem at \p addr with data \p data
 *
 * \param core Current RzCore instance
 * \param addr address to read data from
 * \param data Data to be compared
 * \param len Number of bytes to compare
 * \return RzCompareData* A pointer to RzCompareData comparison (the data1 corresponds to the data at addr (and addr1 = addr) and data2 is the str data (and addr2 = UT32_MAX))
 */
RZ_API RZ_OWN RzCompareData *rz_core_cmp_mem_data(RzCore *core, ut64 addr, RZ_NONNULL const ut8 *data, ut32 len) {
	rz_return_val_if_fail(core && data, NULL);

	ut8 *buf1 = malloc(len * sizeof(ut8));
	if (!buf1) {
		RZ_LOG_ERROR("Cannot read at address: 0x%" PFMT64x "\n", addr);
		goto error_goto;
	}
	if (rz_io_nread_at(core->io, addr, buf1, len) != len) {
		RZ_LOG_ERROR("Cannot read %u bytes at provided address: 0x%" PFMT64x "\n", len, addr);
		goto error_goto;
	}
	RzCompareData *cmp = RZ_NEW0(RzCompareData);
	if (!cmp) {
		goto error_goto;
	}
	cmp->len = len;
	cmp->data1 = buf1;
	cmp->addr1 = addr;
	cmp->data2 = rz_mem_dup(data, len);
	cmp->addr2 = UT64_MAX;
	cmp->same = rz_mem_eq(cmp->data1, cmp->data2, len);
	return cmp;

error_goto:
	free(buf1);
	return NULL;
}

/**
 * \brief Print a comparison \p cmp according to the print mode \p mode
 *
 * \param core Current RzCore instance
 * \param cmp RzCompareData instance to be printed
 * \param state RzCmdStateOutput to be used (options: standard, json) (NULL means standard)
 * \return int Number of lines/diffs printed (-1 if failed)
 */
RZ_API int rz_core_cmp_print(RzCore *core, RZ_NONNULL const RzCompareData *cmp, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && cmp, -1);

	int i, eq = 0;
	bool data_str = cmp->addr2 == UT64_MAX;
	if (cmp->len == UT8_MAX) {
		return -1;
	}
	RzOutputMode mode = RZ_OUTPUT_MODE_STANDARD;
	PJ *pj = NULL;
	if (state) {
		mode = state->mode;
		pj = state->d.pj;
	}
	if (mode == RZ_OUTPUT_MODE_JSON) {
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
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("0x%08" PFMT64x, cmp->addr1 + i);
			if (!data_str) {
				rz_cons_printf("  ->  0x%08" PFMT64x, cmp->addr2 + i);
			}
			rz_cons_printf(" (byte=%.2d)   %02x '%c'  ->  %02x '%c'\n", i + 1,
				cmp->data1[i], (IS_PRINTABLE(cmp->data1[i])) ? cmp->data1[i] : ' ',
				cmp->data2[i], (IS_PRINTABLE(cmp->data2[i])) ? cmp->data2[i] : ' ');
			break;
		case RZ_OUTPUT_MODE_JSON:
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
	if (mode == RZ_OUTPUT_MODE_STANDARD) {
		rz_cons_printf("Compare %d/%d equal bytes (%d%%)\n", eq, cmp->len, (int)(100.0 * eq / cmp->len));
	} else if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		pj_ki(pj, "equal_bytes", eq);
		pj_ki(pj, "total_bytes", cmp->len);
		pj_end(pj); // End array
		pj_end(pj); // End object
	}
	return cmp->len - eq;
}

/**
 * \brief Compare the instructions at \p addr1 and \p addr2
 *
 * \param core Current RzCore instance
 * \param addr1 address to read instructions from
 * \param addr2 address to read instructions from
 * \param len number of bytes to read instructions from
 * \return RzList<RzCompareData>* List of comparison data
 */
RZ_API RZ_OWN RzList /*<RzCompareData *>*/ *rz_core_cmp_disasm(RzCore *core, ut64 addr1, ut64 addr2, ut32 len) {
	rz_return_val_if_fail(core, NULL);

	RzList *cmp_list = rz_list_new();
	if (!cmp_list) {
		goto error_goto;
	}
	cmp_list->free = (RzListFree)&rz_core_cmp_free;
	RzAsmOp op, op2;
	int i, j;
	ut8 *buf = calloc(len + 32, 1);
	if (!buf) {
		goto error_goto;
	}
	rz_io_nread_at(core->io, addr2, buf, len + 32);
	RzCompareData *comp;

	for (i = j = 0; i < len && j < len;) {
		comp = RZ_NEW0(RzCompareData);
		if (!comp) {
			continue;
		}

		// dis A
		rz_asm_set_pc(core->rasm, addr1 + i);
		(void)rz_asm_disassemble(core->rasm, &op,
			core->block + i, len - i);

		// dis B
		rz_asm_set_pc(core->rasm, addr2 + i);
		(void)rz_asm_disassemble(core->rasm, &op2,
			buf + j, len - j);

		comp->len = UT8_MAX;
		comp->data1 = (ut8 *)rz_str_dup(rz_strbuf_get(&op.buf_asm));
		comp->addr1 = addr1 + i;
		comp->data2 = (ut8 *)rz_str_dup(rz_strbuf_get(&op2.buf_asm));
		comp->addr2 = addr2 + j;
		comp->same = !strcmp((char *)comp->data1, (char *)comp->data2); // we can assume that instructions can be represented as plain chars
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

	free(buf);
	return cmp_list;

error_goto:
	rz_list_free(cmp_list);
	return NULL;
}

/**
 * \brief Free RzCompareData object
 *
 * \param cmp RzCompareData object to be freed
 * \return void
 */
RZ_API void rz_core_cmp_free(RzCompareData *cmp) {
	if (!cmp) {
		return;
	}
	RZ_FREE(cmp->data1);
	RZ_FREE(cmp->data2);
	free(cmp);
}

/**
 * \brief Print the instruction comparison data \p compare
 *
 * \param core Current RzCore instance
 * \param compare list of RzCompareData of instructions
 * \param unified print in unified form
 * \return bool true if successfull
 */
RZ_API bool rz_core_cmp_disasm_print(RzCore *core, const RzList /*<RzCompareData *>*/ *compare, bool unified) {
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

/**
 * \defgroup cmpwatch Memory watcher functions API
 * API for memory watcher functions
 * \{
 */
RZ_API void rz_core_cmpwatch_free(RzCoreCmpWatcher *w) {
	if (!w) {
		return;
	}
	free(w->ndata);
	free(w->odata);
	free(w);
}

/**
 * \brief Get the memory watcher at address \p addr
 *
 * \param core Current RzCore instance
 * \param addr Expected address for the memory watcher to be found
 * \return RzCoreCmpWatcher* Pointer to the found memory watcher; NULL if not found
 */
RZ_API RzCoreCmpWatcher *rz_core_cmpwatch_get(RzCore *core, ut64 addr) {
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

/**
 * \brief Add a memory watcher at address \p addr od size \p size and command \p cmd
 *
 * \param core Current RzCore instance
 * \param addr Address where to add the new memory watcher
 * \param size Size of the memory watcher to be addded
 * \param cmd Command to be associated with the memory watcher
 * \return bool true if successful, false otherwise
 */
RZ_API bool rz_core_cmpwatch_add(RzCore *core, ut64 addr, int size, const char *cmd) {
	rz_return_val_if_fail(core, false);
	RzCoreCmpWatcher *cmpw;
	bool to_add = false;
	if (size < 1) {
		return false;
	}
	cmpw = rz_core_cmpwatch_get(core, addr);
	if (!cmpw) {
		to_add = true;
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
	rz_io_nread_at(core->io, addr, cmpw->ndata, size);
	if (to_add) {
		rz_list_append(core->watchers, cmpw);
	}
	return true;
}

/**
 * \brief Delete a memory watcher at address \p addr
 *
 * \param core Current RzCore instance
 * \param addr Address of the memory watcher to be deleted (if UT64_MAX, then all memory watchers will be deleted)
 * \return bool true if found and deleted; false otherwise
 */
RZ_API bool rz_core_cmpwatch_del(RzCore *core, ut64 addr) {
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

/**
 * \brief Show/print the memory watcher present at address \p addr
 *
 * \param core Current RzCore instance
 * \param addr Address of the memory watcher to be printed (if UT64_MAX, then all memory watchers will be printed)
 * \param mode Output mode
 * \return void Print nothing if no memory watcher found at \p addr
 */
RZ_API void rz_core_cmpwatch_show(RzCore *core, ut64 addr, RzOutputMode mode) {
	rz_return_if_fail(core);
	char cmd[128];
	RzListIter *iter;
	RzCoreCmpWatcher *w;
	rz_list_foreach (core->watchers, iter, w) {
		if (addr != UT64_MAX && w->addr != addr) {
			continue;
		}
		int is_diff = w->odata ? memcmp(w->odata, w->ndata, w->size) : 0;
		switch (mode) {
		case RZ_OUTPUT_MODE_RIZIN:
			rz_cons_printf("cw %d '%s' @  0x%08" PFMT64x "%s\n",
				w->size, w->cmd, w->addr, is_diff ? " # differs" : "");
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("0x%08" PFMT64x "%s\n", w->addr, is_diff ? " modified" : "");
			snprintf(cmd, sizeof(cmd), "%s @ %" PFMT64d " @!%d", w->cmd, w->addr, w->size);
			rz_core_cmd0(core, cmd);
			break;
		default:
			rz_warn_if_reached();
		}
	}
}

/**
 * \brief Update the memory watcher at address \p addr
 *
 * \param core Current RzCore instance
 * \param addr Address of the memory watcher to be updated (if UT64_MAX, then all memory watchers will be updated)
 * \return bool true if any memory watcher was updated; false otherwise
 */
RZ_API bool rz_core_cmpwatch_update(RzCore *core, ut64 addr) {
	rz_return_val_if_fail(core, false);
	RzCoreCmpWatcher *w;
	RzListIter *iter;
	bool ret = false;
	rz_list_foreach (core->watchers, iter, w) {
		if (addr != UT64_MAX && w->addr != addr) {
			continue;
		}
		free(w->odata);
		w->odata = w->ndata;
		w->ndata = malloc(w->size);
		if (!w->ndata) {
			return false;
		}
		rz_io_nread_at(core->io, w->addr, w->ndata, w->size);
		ret = true;
	}
	return ret;
}

/**
 * \brief Revert/reset a memory watcher at address \p addr
 *
 * \param core Current RzCore instance
 * \param addr Address of the memory watcher to be reset (if UT64_MAX, then all memory watchers will be reset)
 * \return bool true if the memory watcher was resetted; false otherwise
 */
RZ_API bool rz_core_cmpwatch_revert(RzCore *core, ut64 addr) {
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
/** \} */
