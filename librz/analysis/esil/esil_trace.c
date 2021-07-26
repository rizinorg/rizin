// SPDX-FileCopyrightText: 2015-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2015-2020 rkx1209 <rkx1209dev@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

#define DB                   esil->trace->db
#define KEY(x)               sdb_fmt("%d." x, esil->trace->idx)
#define KEYAT(x, y)          sdb_fmt("%d." x ".0x%" PFMT64x, esil->trace->idx, y)
#define KEYREG(x, y)         sdb_fmt("%d." x ".%s", esil->trace->idx, y)
#define CMP_REG_CHANGE(x, y) ((x) - ((RzAnalysisEsilRegChange *)y)->idx)
#define CMP_MEM_CHANGE(x, y) ((x) - ((RzAnalysisEsilMemChange *)y)->idx)

static int ocbs_set = false;
static RzAnalysisEsilCallbacks ocbs = { 0 };

static void htup_vector_free(HtUPKv *kv) {
	rz_vector_free(kv->value);
}

RZ_API RzAnalysisEsilTrace *rz_analysis_esil_trace_new(RzAnalysisEsil *esil) {
	rz_return_val_if_fail(esil && esil->stack_addr && esil->stack_size, NULL);
	size_t i;
	RzAnalysisEsilTrace *trace = RZ_NEW0(RzAnalysisEsilTrace);
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
	trace->stack_addr = esil->stack_addr;
	trace->stack_size = esil->stack_size;
	trace->stack_data = malloc(esil->stack_size);
	if (!trace->stack_data) {
		goto error;
	}
	esil->analysis->iob.read_at(esil->analysis->iob.io, trace->stack_addr,
		trace->stack_data, trace->stack_size);
	// Save initial registers arenas
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		RzRegArena *a = esil->analysis->reg->regset[i].arena;
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
	rz_analysis_esil_trace_free(trace);
	return NULL;
}

RZ_API void rz_analysis_esil_trace_free(RzAnalysisEsilTrace *trace) {
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

static void add_reg_change(RzAnalysisEsilTrace *trace, int idx, RzRegItem *ri, ut64 data) {
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

static void add_mem_change(RzAnalysisEsilTrace *trace, int idx, ut64 addr, ut8 data) {
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

static int trace_hook_reg_read(RzAnalysisEsil *esil, const char *name, ut64 *res, int *size) {
	int ret = 0;
	if (*name == '0') {
		//eprintf ("Register not found in profile\n");
		return 0;
	}
	if (ocbs.hook_reg_read) {
		RzAnalysisEsilCallbacks cbs = esil->cb;
		esil->cb = ocbs;
		ret = ocbs.hook_reg_read(esil, name, res, size);
		esil->cb = cbs;
	}
	if (!ret && esil->cb.reg_read) {
		ret = esil->cb.reg_read(esil, name, res, size);
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

static int trace_hook_reg_write(RzAnalysisEsil *esil, const char *name, ut64 *val) {
	int ret = 0;
	//eprintf ("[ESIL] REG WRITE %s 0x%08"PFMT64x"\n", name, *val);
	sdb_array_add(DB, KEY("reg.write"), name, 0);
	sdb_num_set(DB, KEYREG("reg.write", name), *val, 0);
	RzRegItem *ri = rz_reg_get(esil->analysis->reg, name, -1);
	add_reg_change(esil->trace, esil->trace->idx + 1, ri, *val);
	if (ocbs.hook_reg_write) {
		RzAnalysisEsilCallbacks cbs = esil->cb;
		esil->cb = ocbs;
		ret = ocbs.hook_reg_write(esil, name, val);
		esil->cb = cbs;
	}
	return ret;
}

static int trace_hook_mem_read(RzAnalysisEsil *esil, ut64 addr, ut8 *buf, int len) {
	char *hexbuf = calloc((1 + len), 4);
	int ret = 0;
	if (esil->cb.mem_read) {
		ret = esil->cb.mem_read(esil, addr, buf, len);
	}
	sdb_array_add_num(DB, KEY("mem.read"), addr, 0);
	rz_hex_bin2str(buf, len, hexbuf);
	sdb_set(DB, KEYAT("mem.read.data", addr), hexbuf, 0);
	//eprintf ("[ESIL] MEM READ 0x%08"PFMT64x" %s\n", addr, hexbuf);
	free(hexbuf);

	if (ocbs.hook_mem_read) {
		RzAnalysisEsilCallbacks cbs = esil->cb;
		esil->cb = ocbs;
		ret = ocbs.hook_mem_read(esil, addr, buf, len);
		esil->cb = cbs;
	}
	return ret;
}

static int trace_hook_mem_write(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len) {
	size_t i;
	int ret = 0;
	char *hexbuf = malloc((1 + len) * 3);
	sdb_array_add_num(DB, KEY("mem.write"), addr, 0);
	rz_hex_bin2str(buf, len, hexbuf);
	sdb_set(DB, KEYAT("mem.write.data", addr), hexbuf, 0);
	//eprintf ("[ESIL] MEM WRITE 0x%08"PFMT64x" %s\n", addr, hexbuf);
	free(hexbuf);
	for (i = 0; i < len; i++) {
		add_mem_change(esil->trace, esil->trace->idx + 1, addr + i, buf[i]);
	}

	if (ocbs.hook_mem_write) {
		RzAnalysisEsilCallbacks cbs = esil->cb;
		esil->cb = ocbs;
		ret = ocbs.hook_mem_write(esil, addr, buf, len);
		esil->cb = cbs;
	}
	return ret;
}

RZ_API void rz_analysis_esil_trace_op(RzAnalysisEsil *esil, RzAnalysisOp *op) {
	rz_return_if_fail(esil && op);
	const char *expr = rz_strbuf_get(&op->esil);
	if (RZ_STR_ISEMPTY(expr)) {
		// do nothing
		return;
	}
	if (!esil->trace) {
		esil->trace = rz_analysis_esil_trace_new(esil);
		if (!esil->trace) {
			return;
		}
	}
	/* restore from trace when `idx` is not at the end */
	if (esil->trace->idx != esil->trace->end_idx) {
		rz_analysis_esil_trace_restore(esil, esil->trace->idx + 1);
		return;
	}
	/* save old callbacks */
	int esil_verbose = esil->verbose;
	if (ocbs_set) {
		eprintf("cannot call recursively\n");
	}
	ocbs = esil->cb;
	ocbs_set = true;
	sdb_num_set(DB, "idx", esil->trace->idx, 0);
	sdb_num_set(DB, KEY("addr"), op->addr, 0);
	RzRegItem *pc_ri = rz_reg_get(esil->analysis->reg, "PC", -1);
	add_reg_change(esil->trace, esil->trace->idx, pc_ri, op->addr);
	//	sdb_set (DB, KEY ("opcode"), op->mnemonic, 0);
	//	sdb_set (DB, KEY ("addr"), expr, 0);
	//eprintf ("[ESIL] ADDR 0x%08"PFMT64x"\n", op->addr);
	//eprintf ("[ESIL] OPCODE %s\n", op->mnemonic);
	//eprintf ("[ESIL] EXPR = %s\n", expr);
	/* set hooks */
	esil->verbose = 0;
	esil->cb.hook_reg_read = trace_hook_reg_read;
	esil->cb.hook_reg_write = trace_hook_reg_write;
	esil->cb.hook_mem_read = trace_hook_mem_read;
	esil->cb.hook_mem_write = trace_hook_mem_write;
	/* evaluate esil expression */
	rz_analysis_esil_parse(esil, expr);
	rz_analysis_esil_stack_free(esil);
	/* restore hooks */
	esil->cb = ocbs;
	ocbs_set = false;
	esil->verbose = esil_verbose;
	/* increment idx */
	esil->trace->idx++;
	esil->trace->end_idx++;
}

static bool restore_memory_cb(void *user, const ut64 key, const void *value) {
	size_t index;
	RzAnalysisEsil *esil = user;
	RzVector *vmem = (RzVector *)value;

	rz_vector_upper_bound(vmem, esil->trace->idx, index, CMP_MEM_CHANGE);
	if (index > 0 && index <= vmem->len) {
		RzAnalysisEsilMemChange *c = rz_vector_index_ptr(vmem, index - 1);
		esil->analysis->iob.write_at(esil->analysis->iob.io, key, &c->data, 1);
	}
	return true;
}

static bool restore_register(RzAnalysisEsil *esil, RzRegItem *ri, int idx) {
	size_t index;
	RzVector *vreg = ht_up_find(esil->trace->registers, ri->offset | (ri->arena << 16), NULL);
	if (vreg) {
		rz_vector_upper_bound(vreg, idx, index, CMP_REG_CHANGE);
		if (index > 0 && index <= vreg->len) {
			RzAnalysisEsilRegChange *c = rz_vector_index_ptr(vreg, index - 1);
			rz_reg_set_value(esil->analysis->reg, ri, c->data);
		}
	}
	return true;
}

RZ_API void rz_analysis_esil_trace_restore(RzAnalysisEsil *esil, int idx) {
	size_t i;
	RzAnalysisEsilTrace *trace = esil->trace;
	// Restore initial state when going backward
	if (idx < esil->trace->idx) {
		// Restore initial registers value
		for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
			RzRegArena *a = esil->analysis->reg->regset[i].arena;
			RzRegArena *b = trace->arena[i];
			if (a && b) {
				memcpy(a->bytes, b->bytes, a->size);
			}
		}
		// Restore initial stack memory
		esil->analysis->iob.write_at(esil->analysis->iob.io, trace->stack_addr,
			trace->stack_data, trace->stack_size);
	}
	// Apply latest changes to registers and memory
	esil->trace->idx = idx;
	RzListIter *iter;
	RzRegItem *ri;
	rz_list_foreach (esil->analysis->reg->allregs, iter, ri) {
		restore_register(esil, ri, idx);
	}
	ht_up_foreach(trace->memory, restore_memory_cb, esil);
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

RZ_API void rz_analysis_esil_trace_list(RzAnalysisEsil *esil) {
	if (!esil->trace) {
		return;
	}

	PrintfCallback p = esil->analysis->cb_printf;
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *list = sdb_foreach_list(esil->trace->db, true);
	ls_sort(list, (SdbListComparator)cmp_strings_by_leading_number);
	ls_foreach (list, iter, kv) {
		p("%s=%s\n", sdbkv_key(kv), sdbkv_value(kv));
	}
	ls_free(list);
}

RZ_API void rz_analysis_esil_trace_show(RzAnalysisEsil *esil, int idx) {
	if (!esil->trace) {
		return;
	}

	PrintfCallback p = esil->analysis->cb_printf;
	const char *str2;
	const char *str;
	int trace_idx = esil->trace->idx;
	esil->trace->idx = idx;

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

	esil->trace->idx = trace_idx;
}
