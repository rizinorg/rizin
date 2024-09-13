// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>

/* Old debug trace implementation */
RZ_API RzDebugTrace *rz_debug_trace_new(void) {
	RzDebugTrace *t = RZ_NEW0(RzDebugTrace);
	if (!t) {
		return NULL;
	}
	t->tag = 1; // UT32_MAX;
	t->addresses = NULL;
	t->enabled = false;
	t->traces = rz_list_new();
	if (!t->traces) {
		rz_debug_trace_free(t);
		return NULL;
	}
	t->traces->free = free;
	t->ht = ht_sp_new(HT_STR_DUP, NULL, NULL);
	if (!t->ht) {
		rz_debug_trace_free(t);
		return NULL;
	}
	return t;
}

RZ_API void rz_debug_trace_free(RzDebugTrace *trace) {
	if (!trace) {
		return;
	}
	rz_list_purge(trace->traces);
	free(trace->traces);
	ht_sp_free(trace->ht);
	RZ_FREE(trace);
}

// TODO: added overlap/mask support here...
// TODO: think about tagged traces
RZ_API int rz_debug_trace_tag(RzDebug *dbg, int tag) {
	// if (tag>0 && tag<31) core->dbg->trace->tag = 1<<(sz-1);
	return (dbg->trace->tag = (tag > 0) ? tag : UT32_MAX);
}

RZ_API bool rz_debug_trace_ins_before(RzDebug *dbg) {
	RzListIter *it, *it_tmp;
	RzAnalysisValue *val;
	ut8 buf_pc[32];

	// Analyze current instruction
	ut64 pc = rz_debug_reg_get(dbg, dbg->reg->name[RZ_REG_NAME_PC]);
	if (!dbg->iob.read_at) {
		RZ_LOG_ERROR("dbg->iob.read_at missing\n");
		return false;
	}
	if (!dbg->iob.read_at(dbg->iob.io, pc, buf_pc, sizeof(buf_pc))) {
		RZ_LOG_ERROR("dbg->iob.read_at failure -- pc 0x%" PFMT64x "\n", pc);
		return false;
	}
	dbg->cur_op = rz_analysis_op_new();
	if (!dbg->cur_op) {
		RZ_LOG_ERROR("rz_analysis_op_new failure\n");
		return false;
	}
	if (rz_analysis_op(dbg->analysis, dbg->cur_op, pc, buf_pc, sizeof(buf_pc), RZ_ANALYSIS_OP_MASK_VAL) < 1) {
		RZ_LOG_ERROR("rz_analysis_op failure -- pc 0x%" PFMT64x "\n", pc);
		rz_analysis_op_free(dbg->cur_op);
		dbg->cur_op = NULL;
		return false;
	}

	// resolve mem write address
	rz_list_foreach_safe (dbg->cur_op->access, it, it_tmp, val) {
		switch (val->type) {
		case RZ_ANALYSIS_VAL_REG:
			if (!(val->access & RZ_ANALYSIS_ACC_W)) {
				rz_list_delete(dbg->cur_op->access, it);
			}
			break;
		case RZ_ANALYSIS_VAL_MEM:
			if (val->memref > 32) {
				eprintf("Error: adding changes to %d bytes in memory.\n", val->memref);
				rz_list_delete(dbg->cur_op->access, it);
				break;
			}

			if (val->access & RZ_ANALYSIS_ACC_W) {
				// resolve memory address
				ut64 addr = 0;
				addr += val->delta;
				if (val->seg) {
					addr += rz_reg_get_value(dbg->reg, val->seg);
				}
				if (val->reg) {
					addr += rz_reg_get_value(dbg->reg, val->reg);
				}
				if (val->regdelta) {
					int mul = val->mul ? val->mul : 1;
					addr += mul * rz_reg_get_value(dbg->reg, val->regdelta);
				}
				// resolve address into base for ins_after
				val->base = addr;
			} else {
				rz_list_delete(dbg->cur_op->access, it);
			}
		default:
			break;
		}
	}
	return true;
}

/**
 * \brief Add register/memory changes to the debug session.
 *
 * \param dbg RzDebug instance containing the session.
 * \return false The current instruction is not known so no changes can be recorded.
 * \return true Otherwise.
 */
RZ_API bool rz_debug_trace_ins_after(RZ_NONNULL RzDebug *dbg) {
	rz_return_val_if_fail(dbg, false);
	if (!dbg->cur_op) { // Can happen if hard stepping is available and code is unknown to Rizin
		return false;
	}
	RzListIter *it;
	RzAnalysisValue *val;

	// Add reg/mem write change
	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, false);
	rz_list_foreach (dbg->cur_op->access, it, val) {
		if (!(val->access & RZ_ANALYSIS_ACC_W)) {
			continue;
		}

		switch (val->type) {
		case RZ_ANALYSIS_VAL_REG: {
			if (!val->reg) {
				RZ_LOG_ERROR("invalid register, unable to trace register state\n");
				continue;
			}
			ut64 data = rz_reg_get_value(dbg->reg, val->reg);

			// add reg write
			rz_debug_session_add_reg_change(dbg->session, val->reg->arena, val->reg->offset, data);
			break;
		}
		case RZ_ANALYSIS_VAL_MEM: {
			ut8 buf[32] = { 0 };
			if (!dbg->iob.read_at(dbg->iob.io, val->base, buf, val->memref)) {
				eprintf("Error reading memory at 0x%" PFMT64x "\n", val->base);
				break;
			}

			// add mem write
			size_t i;
			for (i = 0; i < val->memref; i++) {
				rz_debug_session_add_mem_change(dbg->session, val->base + i, buf[i]);
			}
			break;
		}
		default:
			break;
		}
	}
	rz_analysis_op_free(dbg->cur_op);
	dbg->cur_op = NULL;
	return true;
}

/*
 * something happened at the given pc that we need to trace
 */
RZ_API int rz_debug_trace_pc(RzDebug *dbg, ut64 pc) {
	ut8 buf[32];
	RzAnalysisOp op = { 0 };
	if (!dbg->iob.is_valid_offset(dbg->iob.io, pc, 0)) {
		eprintf("trace_pc: cannot read memory at 0x%" PFMT64x "\n", pc);
		return false;
	}
	(void)dbg->iob.read_at(dbg->iob.io, pc, buf, sizeof(buf));
	if (rz_analysis_op(dbg->analysis, &op, pc, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_ESIL) < 1) {
		eprintf("trace_pc: cannot get opcode size at 0x%" PFMT64x "\n", pc);
		return false;
	}
	rz_debug_trace_op(dbg, &op);
	rz_analysis_op_fini(&op);
	return true;
}

RZ_API void rz_debug_trace_op(RzDebug *dbg, RzAnalysisOp *op) {
	static ut64 oldpc = UT64_MAX; // Must trace the previously traced instruction
	if (dbg->trace->enabled) {
		if (dbg->analysis->esil) {
			rz_analysis_esil_trace_op(dbg->analysis->esil, op);
		} else {
			if (dbg->verbose) {
				eprintf("Run aeim to get dbg->analysis->esil initialized\n");
			}
		}
	}
	if (oldpc != UT64_MAX) {
		rz_debug_trace_add(dbg, oldpc, op->size); // XXX review what this line really do
	}
	oldpc = op->addr;
}

RZ_API void rz_debug_trace_at(RzDebug *dbg, const char *str) {
	// TODO: parse offsets and so use ut64 instead of strstr()
	free(dbg->trace->addresses);
	dbg->trace->addresses = (str && *str) ? rz_str_dup(str) : NULL;
}

RZ_API RzDebugTracepoint *rz_debug_trace_get(RzDebug *dbg, ut64 addr) {
	char tmpbuf[64];
	int tag = dbg->trace->tag;
	return ht_sp_find(dbg->trace->ht,
		rz_strf(tmpbuf, "trace.%d.%" PFMT64x, tag, addr), NULL);
}

static int cmpaddr(const void *_a, const void *_b, void *user) {
	const RzListInfo *a = _a, *b = _b;
	return (rz_itv_begin(a->pitv) > rz_itv_begin(b->pitv)) ? 1 : (rz_itv_begin(a->pitv) < rz_itv_begin(b->pitv)) ? -1
														     : 0;
}

/***
 * Get all trace info
 * @param dbg core->dbg
 * @param offset offset of address
 * @return a RzList of RzListInfo
 */
RZ_API RZ_OWN RzList /*<RzListInfo *>*/ *rz_debug_traces_info(RzDebug *dbg, ut64 offset) {
	rz_return_val_if_fail(dbg, NULL);
	int tag = dbg->trace->tag;
	RzListIter *iter;
	RzList *info_list = rz_list_new();
	if (!info_list) {
		return NULL;
	}

	RzDebugTracepoint *trace;
	rz_list_foreach (dbg->trace->traces, iter, trace) {
		if (trace->tag && !(tag & trace->tag)) {
			continue;
		}
		RzListInfo *info = RZ_NEW0(RzListInfo);
		if (!info) {
			rz_list_free(info_list);
			return NULL;
		}
		info->pitv = (RzInterval){ trace->addr, trace->size };
		info->vitv = info->pitv;
		info->perm = -1;
		info->name = rz_str_newf("%d", trace->times);
		info->extra = rz_str_newf("%d", trace->count);
		rz_list_append(info_list, info);
	}

	rz_list_sort(info_list, cmpaddr, NULL);
	return info_list;
}

// XXX: find better name, make it public?
static int rz_debug_trace_is_traceable(RzDebug *dbg, ut64 addr) {
	if (dbg->trace->addresses) {
		char addr_str[32];
		snprintf(addr_str, sizeof(addr_str), "0x%08" PFMT64x, addr);
		if (!strstr(dbg->trace->addresses, addr_str)) {
			return false;
		}
	}
	return true;
}

RZ_API RzDebugTracepoint *rz_debug_trace_add(RzDebug *dbg, ut64 addr, int size) {
	RzDebugTracepoint *tp;
	char tmpbuf[64];
	int tag = dbg->trace->tag;
	if (!rz_debug_trace_is_traceable(dbg, addr)) {
		return NULL;
	}
	rz_analysis_trace_bb(dbg->analysis, addr);
	tp = RZ_NEW0(RzDebugTracepoint);
	if (!tp) {
		return NULL;
	}
	tp->stamp = rz_time_now_mono();
	tp->addr = addr;
	tp->tags = tag;
	tp->size = size;
	tp->count = ++dbg->trace->count;
	tp->times = 1;
	rz_list_append(dbg->trace->traces, tp);
	ht_sp_update(dbg->trace->ht,
		rz_strf(tmpbuf, "trace.%d.%" PFMT64x, tag, addr), tp);
	return tp;
}

RZ_API void rz_debug_trace_reset(RzDebug *dbg) {
	RzDebugTrace *t = dbg->trace;
	rz_list_purge(t->traces);
	ht_sp_free(t->ht);
	t->ht = ht_sp_new(HT_STR_DUP, NULL, NULL);
	t->traces = rz_list_new();
	t->traces->free = free;
}
