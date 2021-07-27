#include <rz_analysis.h>

#define DB                   rzil->trace->db
#define KEY(x)               sdb_fmt("%d." x, rzil->trace->idx)
#define KEYAT(x, y)          sdb_fmt("%d." x ".0x%" PFMT64x, rzil->trace->idx, y)
#define KEYREG(x, y)         sdb_fmt("%d." x ".%s", rzil->trace->idx, y)
#define CMP_REG_CHANGE(x, y) ((x) - ((RzAnalysisRzilRegChange *)(y))->idx)
#define CMP_MEM_CHANGE(x, y) ((x) - ((RzAnalysisRzilMemChange *)(y))->idx)

static int ocbs_set = false;
static RzAnalysisRzilCallbacks ocbs = { 0 };

static void htup_vector_free(HtUPKv *kv) {
	rz_vector_free(kv->value);
}

RZ_API RzAnalysisRzilTrace *rz_analysis_rzil_trace_new(RzAnalysis *analysis, RzAnalysisRzil *rzil) {
	rz_return_val_if_fail(rzil && rzil->stack_addr && rzil->stack_size, NULL);
	size_t i;
	RzAnalysisRzilTrace *trace = RZ_NEW0(RzAnalysisRzilTrace);
	if (!trace) {
		return NULL;
	}
	trace->registers = ht_up_new(NULL, htup_vector_free, NULL);
	if (!trace->registers) {
		goto error;
	}
	trace->memory = ht_up_new(NULL, htup_vector_free, NULL);
	if (!trace->memory) {
		goto error;
	}
	trace->db = sdb_new0();
	if (!trace->db) {
		goto error;
	}
	// Save initial ESIL stack memory
	trace->stack_addr = rzil->stack_addr;
	trace->stack_size = rzil->stack_size;
	trace->stack_data = malloc(rzil->stack_size);
	if (!trace->stack_data) {
		goto error;
	}
	analysis->iob.read_at(analysis->iob.io, trace->stack_addr,
		trace->stack_data, trace->stack_size);
	// Save initial registers arenas
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		RzRegArena *a = analysis->reg->regset[i].arena;
		RzRegArena *b = rz_reg_arena_new(a->size);
		if (!b) {
			goto error;
		}
		if (b->bytes && a->bytes && b->size > 0) {
			memcpy(b->bytes, a->bytes, b->size);
		}
		trace->arena[i] = b;
	}
	return trace;
error:
	eprintf("error\n");
	rz_analysis_rzil_trace_free(trace);
	return NULL;
}

RZ_API void rz_analysis_rzil_trace_free(RzAnalysisRzilTrace *trace) {
	size_t i;
	if (trace) {
		ht_up_free(trace->registers);
		ht_up_free(trace->memory);
		for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
			rz_reg_arena_free(trace->arena[i]);
		}
		free(trace->stack_data);
		sdb_free(trace->db);
		RZ_FREE(trace);
	}
}

static void add_reg_change(RzAnalysisRzilTrace *trace, int idx, RzRegItem *ri, ut64 data) {
	ut64 addr = ri->offset | (ri->arena << 16);
	RzVector *vreg = ht_up_find(trace->registers, addr, NULL);
	if (!vreg) {
		vreg = rz_vector_new(sizeof(RzAnalysisEsilRegChange), NULL, NULL);
		if (!vreg) {
			eprintf("Error: creating a register vector.\n");
			return;
		}
		ht_up_insert(trace->registers, addr, vreg);
	}
	RzAnalysisEsilRegChange reg = { idx, data };
	rz_vector_push(vreg, &reg);
}

static void add_mem_change(RzAnalysisRzilTrace *trace, int idx, ut64 addr, ut8 data) {
	RzVector *vmem = ht_up_find(trace->memory, addr, NULL);
	if (!vmem) {
		vmem = rz_vector_new(sizeof(RzAnalysisEsilMemChange), NULL, NULL);
		if (!vmem) {
			eprintf("Error: creating a memory vector.\n");
			return;
		}
		ht_up_insert(trace->memory, addr, vmem);
	}
	RzAnalysisEsilMemChange mem = { idx, data };
	rz_vector_push(vmem, &mem);
}

static int trace_hook_reg_read(RzAnalysisRzil *rzil, const char *name, ut64 *res, int *size, RzAnalysis *analysis) {
	int ret = 0;
	if (*name == '0') {
		//eprintf ("Register not found in profile\n");
		return 0;
	}
	if (ocbs.hook_reg_read) {
		RzAnalysisRzilCallbacks cbs = rzil->cb;
		rzil->cb = ocbs;
		ret = ocbs.hook_reg_read(rzil, name, res, size, analysis);
		rzil->cb = cbs;
	}
	if (!ret && rzil->cb.reg_read) {
		ret = rzil->cb.reg_read(rzil, name, res, size, analysis);
	}
	if (ret) {
		ut64 val = *res;
		//eprintf ("[ESIL] REG READ %s 0x%08"PFMT64x"\n", name, val);
		sdb_array_add(DB, KEY("reg.read"), name, 0);
		sdb_num_set(DB, KEYREG("reg.read", name), val, 0);
	} //else {
	//eprintf ("[ESIL] REG READ %s FAILED\n", name);
	//}
	return ret;
}

static int trace_hook_reg_write(RzAnalysisRzil *rzil, const char *name, ut64 *val, RzAnalysis *analysis) {
	int ret = 0;
	//eprintf ("[ESIL] REG WRITE %s 0x%08"PFMT64x"\n", name, *val);
	sdb_array_add(DB, KEY("reg.write"), name, 0);
	sdb_num_set(DB, KEYREG("reg.write", name), *val, 0);
	RzRegItem *ri = rz_reg_get(analysis->reg, name, -1);
	add_reg_change(rzil->trace, rzil->trace->idx + 1, ri, *val);
	if (ocbs.hook_reg_write) {
		RzAnalysisRzilCallbacks cbs = rzil->cb;
		rzil->cb = ocbs;
		ret = ocbs.hook_reg_write(rzil, name, val, analysis);
		rzil->cb = cbs;
	}
	return ret;
}

static int trace_hook_mem_read(RzAnalysisRzil *rzil, ut64 addr, ut8 *buf, int len, RzAnalysis *analysis) {
	char *hexbuf = calloc((1 + len), 4);
	int ret = 0;
	if (rzil->cb.mem_read) {
		ret = rzil->cb.mem_read(rzil, addr, buf, len, analysis);
	}
	sdb_array_add_num(DB, KEY("mem.read"), addr, 0);
	rz_hex_bin2str(buf, len, hexbuf);
	sdb_set(DB, KEYAT("mem.read.data", addr), hexbuf, 0);
	//eprintf ("[ESIL] MEM READ 0x%08"PFMT64x" %s\n", addr, hexbuf);
	free(hexbuf);

	if (ocbs.hook_mem_read) {
		RzAnalysisRzilCallbacks cbs = rzil->cb;
		rzil->cb = ocbs;
		ret = ocbs.hook_mem_read(rzil, addr, buf, len, analysis);
		rzil->cb = cbs;
	}
	return ret;
}

static int trace_hook_mem_write(RzAnalysisRzil *rzil, ut64 addr, const ut8 *buf, int len, RzAnalysis *analysis) {
	size_t i;
	int ret = 0;
	char *hexbuf = malloc((1 + len) * 3);
	sdb_array_add_num(DB, KEY("mem.write"), addr, 0);
	rz_hex_bin2str(buf, len, hexbuf);
	sdb_set(DB, KEYAT("mem.write.data", addr), hexbuf, 0);
	//eprintf ("[ESIL] MEM WRITE 0x%08"PFMT64x" %s\n", addr, hexbuf);
	free(hexbuf);
	for (i = 0; i < len; i++) {
		add_mem_change(rzil->trace, rzil->trace->idx + 1, addr + i, buf[i]);
	}

	if (ocbs.hook_mem_write) {
		RzAnalysisRzilCallbacks cbs = rzil->cb;
		rzil->cb = ocbs;
		ret = ocbs.hook_mem_write(rzil, addr, buf, len, analysis);
		rzil->cb = cbs;
	}
	return ret;
}

RZ_API void rz_analysis_rzil_trace_op(RzAnalysis *analysis, RzAnalysisRzil *rzil, RzAnalysisOp *op) {
	// TODO : refactorr some here
	rz_return_if_fail(rzil && op);
	const char *expr = rz_strbuf_get(&op->esil);
	if (RZ_STR_ISEMPTY(expr)) {
		// do nothing
		return;
	}
	if (!rzil->trace) {
		rzil->trace = rz_analysis_rzil_trace_new(analysis, rzil);
		if (!rzil->trace) {
			return;
		}
	}
	/* restore from trace when `idx` is not at the end */
	if (rzil->trace->idx != rzil->trace->end_idx) {
		rz_analysis_rzil_trace_restore(analysis, rzil, rzil->trace->idx + 1);
		return;
	}
	/* save old callbacks */
	int verbose = rzil->verbose;
	if (ocbs_set) {
		eprintf("cannot call recursively\n");
	}
	ocbs = rzil->cb;
	ocbs_set = true;
	sdb_num_set(DB, "idx", rzil->trace->idx, 0);
	sdb_num_set(DB, KEY("addr"), op->addr, 0);
	RzRegItem *pc_ri = rz_reg_get(analysis->reg, "PC", -1);
	add_reg_change(rzil->trace, rzil->trace->idx, pc_ri, op->addr);
	//	sdb_set (DB, KEY ("opcode"), op->mnemonic, 0);
	//	sdb_set (DB, KEY ("addr"), expr, 0);
	//eprintf ("[ESIL] ADDR 0x%08"PFMT64x"\n", op->addr);
	//eprintf ("[ESIL] OPCODE %s\n", op->mnemonic);
	//eprintf ("[ESIL] EXPR = %s\n", expr);
	/* set hooks */
	rzil->verbose = 0;
	rzil->cb.hook_reg_read = trace_hook_reg_read;
	rzil->cb.hook_reg_write = trace_hook_reg_write;
	rzil->cb.hook_mem_read = trace_hook_mem_read;
	rzil->cb.hook_mem_write = trace_hook_mem_write;

	/* evaluate esil expression */
	// TODO : implement rzil_parse rzil_free
	// rz_analysis_rzil_parse(rzil, expr);
	// rz_analysis_rzil_stack_free();

	/* restore hooks */
	rzil->cb = ocbs;
	ocbs_set = false;
	rzil->verbose = verbose;
	/* increment idx */
	rzil->trace->idx++;
	rzil->trace->end_idx++;
}

static bool restore_memory_cb(void *user, const ut64 key, const void *value, RzAnalysis *analysis) {
	size_t index;
	RzAnalysisRzil *rzil = user;
	RzVector *vmem = (RzVector *)value;

	rz_vector_upper_bound(vmem, rzil->trace->idx, index, CMP_MEM_CHANGE);
	if (index > 0 && index <= vmem->len) {
		RzAnalysisRzilMemChange *c = rz_vector_index_ptr(vmem, index - 1);
		analysis->iob.write_at(analysis->iob.io, key, &c->data, 1);
	}
	return true;
}

static bool restore_register(RzAnalysisRzil *rzil, RzRegItem *ri, int idx, RzAnalysis *analysis) {
	size_t index;
	RzVector *vreg = ht_up_find(rzil->trace->registers, ri->offset | (ri->arena << 16), NULL);
	if (vreg) {
		rz_vector_upper_bound(vreg, idx, index, CMP_REG_CHANGE);
		if (index > 0 && index <= vreg->len) {
			RzAnalysisRzilRegChange *c = rz_vector_index_ptr(vreg, index - 1);
			rz_reg_set_value(analysis->reg, ri, c->data);
		}
	}
	return true;
}

RZ_API void rz_analysis_rzil_trace_restore(RzAnalysis *analysis, RzAnalysisRzil *rzil, int idx) {
	size_t i;
	RzAnalysisRzilTrace *trace = rzil->trace;
	// Restore initial state when going backward
	if (idx < rzil->trace->idx) {
		// Restore initial registers value
		for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
			RzRegArena *a = analysis->reg->regset[i].arena;
			RzRegArena *b = trace->arena[i];
			if (a && b) {
				memcpy(a->bytes, b->bytes, a->size);
			}
		}
		// Restore initial stack memory
		analysis->iob.write_at(analysis->iob.io, trace->stack_addr,
			trace->stack_data, trace->stack_size);
	}
	// Apply latest changes to registers and memory
	rzil->trace->idx = idx;
	RzListIter *iter;
	RzRegItem *ri;
	rz_list_foreach (analysis->reg->allregs, iter, ri) {
		restore_register(rzil, ri, idx, analysis);
	}
	// TODO : restore_memory_cb requires analysis as argument
	//      : while foreach support *user only
	// ht_up_foreach(trace->memory, restore_memory_cb, rzil);
}

static int cmp_strings_by_leading_number(void *data1, void *data2) {
	const char *a = sdbkv_key((const SdbKv *)data1);
	const char *b = sdbkv_key((const SdbKv *)data2);
	int i = 0;
	int j = 0;
	int k = 0;
	while (a[i] >= '0' && a[i] <= '9') {
		i++;
	}
	while (b[j] >= '0' && b[j] <= '9') {
		j++;
	}
	if (!i) {
		return 1;
	}
	if (!j) {
		return -1;
	}
	i--;
	j--;
	if (i > j) {
		return 1;
	}
	if (j > i) {
		return -1;
	}
	while (k <= i) {
		if (a[k] < b[k]) {
			return -1;
		}
		if (a[k] > b[k]) {
			return 1;
		}
		k++;
	}
	for (; a[i] && b[i]; i++) {
		if (a[i] > b[i]) {
			return 1;
		}
		if (a[i] < b[i]) {
			return -1;
		}
	}
	if (!a[i] && b[i]) {
		return -1;
	}
	if (!b[i] && a[i]) {
		return 1;
	}
	return 0;
}

RZ_API void rz_analysis_rzil_trace_list(RzAnalysis *analysis, RzAnalysisRzil *rzil) {
	if (!rzil->trace) {
		return;
	}

	PrintfCallback p = analysis->cb_printf;
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *list = sdb_foreach_list(rzil->trace->db, true);
	ls_sort(list, (SdbListComparator)cmp_strings_by_leading_number);
	ls_foreach (list, iter, kv) {
		p("%s=%s\n", sdbkv_key(kv), sdbkv_value(kv));
	}
	ls_free(list);
}

RZ_API void rz_analysis_rzil_trace_show(RzAnalysis *analysis, RzAnalysisRzil *rzil, int idx) {
	if (!rzil->trace) {
		return;
	}

	PrintfCallback p = analysis->cb_printf;
	const char *str2;
	const char *str;
	int trace_idx = rzil->trace->idx;
	rzil->trace->idx = idx;

	str2 = sdb_const_get(DB, KEY("addr"), 0);
	if (!str2) {
		return;
	}
	p("ar PC = %s\n", str2);
	/* registers */
	str = sdb_const_get(DB, KEY("reg.read"), 0);
	if (str) {
		char regname[32];
		const char *next, *ptr = str;
		if (ptr && *ptr) {
			do {
				next = sdb_const_anext(ptr);
				int len = next ? (int)(size_t)(next - ptr) - 1 : strlen(ptr);
				if (len < sizeof(regname)) {
					memcpy(regname, ptr, len);
					regname[len] = 0;
					str2 = sdb_const_get(DB, KEYREG("reg.read", regname), 0);
					p("ar %s = %s\n", regname, str2);
				} else {
					eprintf("Invalid entry in reg.read\n");
				}
				ptr = next;
			} while (next);
		}
	}
	/* memory */
	str = sdb_const_get(DB, KEY("mem.read"), 0);
	if (str) {
		char addr[64];
		const char *next, *ptr = str;
		if (ptr && *ptr) {
			do {
				next = sdb_const_anext(ptr);
				int len = next ? (int)(size_t)(next - ptr) - 1 : strlen(ptr);
				if (len < sizeof(addr)) {
					memcpy(addr, ptr, len);
					addr[len] = 0;
					str2 = sdb_const_get(DB, KEYAT("mem.read.data", rz_num_get(NULL, addr)), 0);
					p("wx %s @ %s\n", str2, addr);
				} else {
					eprintf("Invalid entry in reg.read\n");
				}
				ptr = next;
			} while (next);
		}
	}

	rzil->trace->idx = trace_idx;
}