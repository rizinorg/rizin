// SPDX-FileCopyrightText: 2013-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

// Common base-struct for hints which affect an entire range as opposed to only one single address
// They are saved in a RBTree per hint type.
// Each ranged record in a tree affects every address address greater or equal to its specified address until
// the next record or the end of the address space.
typedef struct rz_analysis_ranged_hint_record_base_t {
	RBNode rb;
	ut64 addr;
} RzAnalysisRangedHintRecordBase;

typedef struct rz_analysis_arch_hint_record_t {
	RzAnalysisRangedHintRecordBase base; // MUST be the first member!
	char *arch; // NULL => reset to global
} RzAnalysisArchHintRecord;

typedef struct rz_analysis_bits_hint_record_t {
	RzAnalysisRangedHintRecordBase base; // MUST be the first member!
	int bits; // 0 => reset to global
} RzAnalysisBitsHintRecord;

static int ranged_hint_record_cmp(const void *incoming, const RBNode *in_tree, void *user) {
	ut64 addr = *(const ut64 *)incoming;
	const RzAnalysisRangedHintRecordBase *in_tree_record = container_of(in_tree, const RzAnalysisRangedHintRecordBase, rb);
	if (addr < in_tree_record->addr) {
		return -1;
	} else if (addr > in_tree_record->addr) {
		return 1;
	}
	return 0;
}

static void addr_hint_record_fini(void *element, void *user) {
	(void)user;
	RzAnalysisAddrHintRecord *record = element;
	switch (record->type) {
	case RZ_ANALYSIS_ADDR_HINT_TYPE_TYPE_OFFSET:
		free(record->type_offset);
		break;
	case RZ_ANALYSIS_ADDR_HINT_TYPE_SYNTAX:
		free(record->syntax);
		break;
	case RZ_ANALYSIS_ADDR_HINT_TYPE_OPCODE:
		free(record->opcode);
		break;
	case RZ_ANALYSIS_ADDR_HINT_TYPE_ESIL:
		free(record->esil);
		break;
	default:
		break;
	}
}

static void bits_hint_record_free_rb(RBNode *node, void *user) {
	free(container_of(node, RzAnalysisRangedHintRecordBase, rb));
}

static void arch_hint_record_free_rb(RBNode *node, void *user) {
	RzAnalysisArchHintRecord *record = (RzAnalysisArchHintRecord *)container_of(node, RzAnalysisRangedHintRecordBase, rb);
	free(record->arch);
	free(record);
}

// used in analysis.c, but no API needed
void rz_analysis_hint_storage_init(RzAnalysis *a) {
	a->addr_hints = ht_up_new(NULL, (HtUPFreeValue)rz_vector_free);
	a->arch_hints = NULL;
	a->bits_hints = NULL;
}

// used in analysis.c, but no API needed
void rz_analysis_hint_storage_fini(RzAnalysis *a) {
	ht_up_free(a->addr_hints);
	rz_rbtree_free(a->arch_hints, arch_hint_record_free_rb, NULL);
	rz_rbtree_free(a->bits_hints, bits_hint_record_free_rb, NULL);
}

RZ_API void rz_analysis_hint_clear(RzAnalysis *a) {
	rz_analysis_hint_storage_fini(a);
	rz_analysis_hint_storage_init(a);
}

typedef struct {
	HtUP *ht;
	ut64 addr;
	ut64 size;
} DeleteRangeCtx;

static bool addr_hint_range_delete_cb(void *user, const ut64 key, const void *value) {
	DeleteRangeCtx *ctx = user;
	if (key < ctx->addr || key >= ctx->addr + ctx->size) {
		return true;
	}
	ht_up_delete(ctx->ht, key);
	return true;
}

RZ_API void rz_analysis_hint_del(RzAnalysis *a, ut64 addr, ut64 size) {
	if (size <= 1) {
		// only single address
		ht_up_delete(a->addr_hints, addr);
		rz_analysis_hint_unset_arch(a, addr);
		rz_analysis_hint_unset_bits(a, addr);
		return;
	}
	// ranged delete
	DeleteRangeCtx ctx = { a->addr_hints, addr, size };
	ht_up_foreach(a->addr_hints, addr_hint_range_delete_cb, &ctx);
	while (true) { // arch
		RBNode *node = rz_rbtree_lower_bound(a->arch_hints, &addr, ranged_hint_record_cmp, NULL);
		if (!node) {
			return;
		}
		RzAnalysisRangedHintRecordBase *base = container_of(node, RzAnalysisRangedHintRecordBase, rb);
		if (base->addr >= addr + size) {
			break;
		}
		rz_analysis_hint_unset_arch(a, base->addr);
	}
	while (true) { // bits
		RBNode *node = rz_rbtree_lower_bound(a->bits_hints, &addr, ranged_hint_record_cmp, NULL);
		if (!node) {
			return;
		}
		RzAnalysisRangedHintRecordBase *base = container_of(node, RzAnalysisRangedHintRecordBase, rb);
		if (base->addr >= addr + size) {
			break;
		}
		rz_analysis_hint_unset_bits(a, base->addr);
	}
}

static void unset_addr_hint_record(RzAnalysis *analysis, RzAnalysisAddrHintType type, ut64 addr) {
	RzVector *records = ht_up_find(analysis->addr_hints, addr, NULL);
	if (!records) {
		return;
	}
	size_t i;
	for (i = 0; i < records->len; i++) {
		RzAnalysisAddrHintRecord *record = rz_vector_index_ptr(records, i);
		if (record->type == type) {
			addr_hint_record_fini(record, NULL);
			rz_vector_remove_at(records, i, NULL);
			return;
		}
	}
}

// create or return the existing addr hint record of the given type at addr
static RzAnalysisAddrHintRecord *ensure_addr_hint_record(RzAnalysis *analysis, RzAnalysisAddrHintType type, ut64 addr) {
	RzVector *records = ht_up_find(analysis->addr_hints, addr, NULL);
	if (!records) {
		records = rz_vector_new(sizeof(RzAnalysisAddrHintRecord), addr_hint_record_fini, NULL);
		if (!records) {
			return NULL;
		}
		ht_up_insert(analysis->addr_hints, addr, records);
	}
	void *pos;
	rz_vector_foreach (records, pos) {
		RzAnalysisAddrHintRecord *record = pos;
		if (record->type == type) {
			return record;
		}
	}
	RzAnalysisAddrHintRecord *record = rz_vector_push(records, NULL);
	memset(record, 0, sizeof(*record));
	record->type = type;
	return record;
}

#define SET_HINT(type, setcode) \
	do { \
		RzAnalysisAddrHintRecord *r = ensure_addr_hint_record(a, type, addr); \
		if (!r) { \
			break; \
		} \
		setcode \
	} while (0)

static RzAnalysisRangedHintRecordBase *ensure_ranged_hint_record(RBTree *tree, ut64 addr, size_t sz) {
	RBNode *node = rz_rbtree_find(*tree, &addr, ranged_hint_record_cmp, NULL);
	if (node) {
		return container_of(node, RzAnalysisRangedHintRecordBase, rb);
	}
	RzAnalysisRangedHintRecordBase *record = malloc(sz);
	memset(record, 0, sz);
	if (!record) {
		return NULL;
	}
	record->addr = addr;
	rz_rbtree_insert(tree, &addr, &record->rb, ranged_hint_record_cmp, NULL);
	return record;
}

RZ_API void rz_analysis_hint_set_offset(RzAnalysis *a, ut64 addr, const char *typeoff) {
	SET_HINT(RZ_ANALYSIS_ADDR_HINT_TYPE_TYPE_OFFSET,
		 free(r->type_offset);
		 r->type_offset = strdup(typeoff););
}

RZ_API void rz_analysis_hint_set_nword(RzAnalysis *a, ut64 addr, int nword) {
	SET_HINT(RZ_ANALYSIS_ADDR_HINT_TYPE_NWORD, r->nword = nword;);
}

RZ_API void rz_analysis_hint_set_jump(RzAnalysis *a, ut64 addr, ut64 jump) {
	SET_HINT(RZ_ANALYSIS_ADDR_HINT_TYPE_JUMP, r->jump = jump;);
}

RZ_API void rz_analysis_hint_set_fail(RzAnalysis *a, ut64 addr, ut64 fail) {
	SET_HINT(RZ_ANALYSIS_ADDR_HINT_TYPE_FAIL, r->fail = fail;);
}

RZ_API void rz_analysis_hint_set_newbits(RzAnalysis *a, ut64 addr, int bits) {
	SET_HINT(RZ_ANALYSIS_ADDR_HINT_TYPE_NEW_BITS, r->newbits = bits;);
}

RZ_API void rz_analysis_hint_set_high(RzAnalysis *a, ut64 addr) {
	SET_HINT(RZ_ANALYSIS_ADDR_HINT_TYPE_HIGH, );
}

RZ_API void rz_analysis_hint_set_immbase(RzAnalysis *a, ut64 addr, int base) {
	if (base) {
		SET_HINT(RZ_ANALYSIS_ADDR_HINT_TYPE_IMMBASE, r->immbase = base;);
	} else {
		unset_addr_hint_record(a, RZ_ANALYSIS_ADDR_HINT_TYPE_IMMBASE, addr);
	}
}

RZ_API void rz_analysis_hint_set_pointer(RzAnalysis *a, ut64 addr, ut64 ptr) {
	SET_HINT(RZ_ANALYSIS_ADDR_HINT_TYPE_PTR, r->ptr = ptr;);
}

RZ_API void rz_analysis_hint_set_ret(RzAnalysis *a, ut64 addr, ut64 val) {
	SET_HINT(RZ_ANALYSIS_ADDR_HINT_TYPE_RET, r->retval = val;);
}

RZ_API void rz_analysis_hint_set_syntax(RzAnalysis *a, ut64 addr, const char *syn) {
	SET_HINT(RZ_ANALYSIS_ADDR_HINT_TYPE_SYNTAX,
		 free(r->syntax);
		 r->syntax = strdup(syn););
}

RZ_API void rz_analysis_hint_set_opcode(RzAnalysis *a, ut64 addr, const char *opcode) {
	SET_HINT(RZ_ANALYSIS_ADDR_HINT_TYPE_OPCODE,
		 free(r->opcode);
		 r->opcode = strdup(opcode););
}

RZ_API void rz_analysis_hint_set_esil(RzAnalysis *a, ut64 addr, const char *esil) {
	SET_HINT(RZ_ANALYSIS_ADDR_HINT_TYPE_ESIL,
		 free(r->esil);
		 r->esil = strdup(esil););
}

RZ_API void rz_analysis_hint_set_type(RzAnalysis *a, ut64 addr, int type) {
	SET_HINT(RZ_ANALYSIS_ADDR_HINT_TYPE_OPTYPE, r->optype = type;);
}

RZ_API void rz_analysis_hint_set_size(RzAnalysis *a, ut64 addr, ut64 size) {
	SET_HINT(RZ_ANALYSIS_ADDR_HINT_TYPE_SIZE, r->size = size;);
}

RZ_API void rz_analysis_hint_set_stackframe(RzAnalysis *a, ut64 addr, ut64 size) {
	SET_HINT(RZ_ANALYSIS_ADDR_HINT_TYPE_STACKFRAME, r->stackframe = size;);
}

RZ_API void rz_analysis_hint_set_val(RzAnalysis *a, ut64 addr, ut64 v) {
	SET_HINT(RZ_ANALYSIS_ADDR_HINT_TYPE_VAL, r->val = v;);
}

RZ_API void rz_analysis_hint_set_arch(RzAnalysis *a, ut64 addr, RZ_NULLABLE const char *arch) {
	RzAnalysisArchHintRecord *record = (RzAnalysisArchHintRecord *)ensure_ranged_hint_record(&a->arch_hints, addr, sizeof(RzAnalysisArchHintRecord));
	if (!record) {
		return;
	}
	free(record->arch);
	record->arch = arch ? strdup(arch) : NULL;
}

RZ_API void rz_analysis_hint_set_bits(RzAnalysis *a, ut64 addr, int bits) {
	RzAnalysisBitsHintRecord *record = (RzAnalysisBitsHintRecord *)ensure_ranged_hint_record(&a->bits_hints, addr, sizeof(RzAnalysisBitsHintRecord));
	if (!record) {
		return;
	}
	record->bits = bits;
	if (a->hint_cbs.on_bits) {
		a->hint_cbs.on_bits(a, addr, bits, true);
	}
}

RZ_API void rz_analysis_hint_unset_size(RzAnalysis *a, ut64 addr) {
	unset_addr_hint_record(a, RZ_ANALYSIS_ADDR_HINT_TYPE_SIZE, addr);
}

RZ_API void rz_analysis_hint_unset_esil(RzAnalysis *a, ut64 addr) {
	unset_addr_hint_record(a, RZ_ANALYSIS_ADDR_HINT_TYPE_ESIL, addr);
}

RZ_API void rz_analysis_hint_unset_opcode(RzAnalysis *a, ut64 addr) {
	unset_addr_hint_record(a, RZ_ANALYSIS_ADDR_HINT_TYPE_OPCODE, addr);
}

RZ_API void rz_analysis_hint_unset_high(RzAnalysis *a, ut64 addr) {
	unset_addr_hint_record(a, RZ_ANALYSIS_ADDR_HINT_TYPE_HIGH, addr);
}

RZ_API void rz_analysis_hint_unset_immbase(RzAnalysis *a, ut64 addr) {
	unset_addr_hint_record(a, RZ_ANALYSIS_ADDR_HINT_TYPE_IMMBASE, addr);
}

RZ_API void rz_analysis_hint_unset_nword(RzAnalysis *a, ut64 addr) {
	unset_addr_hint_record(a, RZ_ANALYSIS_ADDR_HINT_TYPE_NWORD, addr);
}

RZ_API void rz_analysis_hint_unset_syntax(RzAnalysis *a, ut64 addr) {
	unset_addr_hint_record(a, RZ_ANALYSIS_ADDR_HINT_TYPE_SYNTAX, addr);
}

RZ_API void rz_analysis_hint_unset_pointer(RzAnalysis *a, ut64 addr) {
	unset_addr_hint_record(a, RZ_ANALYSIS_ADDR_HINT_TYPE_PTR, addr);
}

RZ_API void rz_analysis_hint_unset_ret(RzAnalysis *a, ut64 addr) {
	unset_addr_hint_record(a, RZ_ANALYSIS_ADDR_HINT_TYPE_RET, addr);
}

RZ_API void rz_analysis_hint_unset_offset(RzAnalysis *a, ut64 addr) {
	unset_addr_hint_record(a, RZ_ANALYSIS_ADDR_HINT_TYPE_TYPE_OFFSET, addr);
}

RZ_API void rz_analysis_hint_unset_jump(RzAnalysis *a, ut64 addr) {
	unset_addr_hint_record(a, RZ_ANALYSIS_ADDR_HINT_TYPE_JUMP, addr);
}

RZ_API void rz_analysis_hint_unset_fail(RzAnalysis *a, ut64 addr) {
	unset_addr_hint_record(a, RZ_ANALYSIS_ADDR_HINT_TYPE_FAIL, addr);
}

RZ_API void rz_analysis_hint_unset_newbits(RzAnalysis *a, ut64 addr) {
	unset_addr_hint_record(a, RZ_ANALYSIS_ADDR_HINT_TYPE_NEW_BITS, addr);
}

RZ_API void rz_analysis_hint_unset_val(RzAnalysis *a, ut64 addr) {
	unset_addr_hint_record(a, RZ_ANALYSIS_ADDR_HINT_TYPE_VAL, addr);
}

RZ_API void rz_analysis_hint_unset_type(RzAnalysis *a, ut64 addr) {
	unset_addr_hint_record(a, RZ_ANALYSIS_ADDR_HINT_TYPE_OPTYPE, addr);
}

RZ_API void rz_analysis_hint_unset_stackframe(RzAnalysis *a, ut64 addr) {
	unset_addr_hint_record(a, RZ_ANALYSIS_ADDR_HINT_TYPE_STACKFRAME, addr);
}

RZ_API void rz_analysis_hint_unset_arch(RzAnalysis *a, ut64 addr) {
	rz_rbtree_delete(&a->arch_hints, &addr, ranged_hint_record_cmp, NULL, arch_hint_record_free_rb, NULL);
}

RZ_API void rz_analysis_hint_unset_bits(RzAnalysis *a, ut64 addr) {
	rz_rbtree_delete(&a->bits_hints, &addr, ranged_hint_record_cmp, NULL, bits_hint_record_free_rb, NULL);
}

RZ_API void rz_analysis_hint_free(RzAnalysisHint *h) {
	if (h) {
		free(h->arch);
		free(h->esil);
		free(h->opcode);
		free(h->syntax);
		free(h->offset);
		free(h);
	}
}

RZ_API RZ_NULLABLE RZ_BORROW const char *rz_analysis_hint_arch_at(RzAnalysis *analysis, ut64 addr, RZ_NULLABLE ut64 *hint_addr) {
	RBNode *node = rz_rbtree_upper_bound(analysis->arch_hints, &addr, ranged_hint_record_cmp, NULL);
	if (!node) {
		if (hint_addr) {
			*hint_addr = UT64_MAX;
		}
		return NULL;
	}
	RzAnalysisArchHintRecord *record = (RzAnalysisArchHintRecord *)container_of(node, RzAnalysisRangedHintRecordBase, rb);
	if (hint_addr) {
		*hint_addr = record->base.addr;
	}
	return record->arch;
}

RZ_API int rz_analysis_hint_bits_at(RzAnalysis *analysis, ut64 addr, RZ_NULLABLE ut64 *hint_addr) {
	RBNode *node = rz_rbtree_upper_bound(analysis->bits_hints, &addr, ranged_hint_record_cmp, NULL);
	if (!node) {
		if (hint_addr) {
			*hint_addr = UT64_MAX;
		}
		return 0;
	}
	RzAnalysisBitsHintRecord *record = (RzAnalysisBitsHintRecord *)container_of(node, RzAnalysisRangedHintRecordBase, rb);
	if (hint_addr) {
		*hint_addr = record->base.addr;
	}
	return record->bits;
}

RZ_API RZ_NULLABLE const RzVector /*<const RzAnalysisAddrHintRecord>*/ *rz_analysis_addr_hints_at(RzAnalysis *analysis, ut64 addr) {
	return ht_up_find(analysis->addr_hints, addr, NULL);
}

typedef struct {
	RzAnalysisAddrHintRecordsCb cb;
	void *user;
} AddrHintForeachCtx;

static bool addr_hint_foreach_cb(void *user, const ut64 key, const void *value) {
	AddrHintForeachCtx *ctx = user;
	return ctx->cb(key, value, ctx->user);
}

RZ_API void rz_analysis_addr_hints_foreach(RzAnalysis *analysis, RzAnalysisAddrHintRecordsCb cb, void *user) {
	AddrHintForeachCtx ctx = { cb, user };
	ht_up_foreach(analysis->addr_hints, addr_hint_foreach_cb, &ctx);
}

RZ_API void rz_analysis_arch_hints_foreach(RzAnalysis *analysis, RzAnalysisArchHintCb cb, void *user) {
	RBIter iter;
	RzAnalysisRangedHintRecordBase *record;
	rz_rbtree_foreach (analysis->arch_hints, iter, record, RzAnalysisRangedHintRecordBase, rb) {
		bool cont = cb(record->addr, ((RzAnalysisArchHintRecord *)record)->arch, user);
		if (!cont) {
			break;
		}
	}
}

RZ_API void rz_analysis_bits_hints_foreach(RzAnalysis *analysis, RzAnalysisBitsHintCb cb, void *user) {
	RBIter iter;
	RzAnalysisRangedHintRecordBase *record;
	rz_rbtree_foreach (analysis->bits_hints, iter, record, RzAnalysisRangedHintRecordBase, rb) {
		bool cont = cb(record->addr, ((RzAnalysisBitsHintRecord *)record)->bits, user);
		if (!cont) {
			break;
		}
	}
}

static void hint_merge(RzAnalysisHint *hint, RzAnalysisAddrHintRecord *record) {
	switch (record->type) {
	case RZ_ANALYSIS_ADDR_HINT_TYPE_IMMBASE:
		hint->immbase = record->immbase;
		break;
	case RZ_ANALYSIS_ADDR_HINT_TYPE_JUMP:
		hint->jump = record->jump;
		break;
	case RZ_ANALYSIS_ADDR_HINT_TYPE_FAIL:
		hint->fail = record->fail;
		break;
	case RZ_ANALYSIS_ADDR_HINT_TYPE_STACKFRAME:
		hint->stackframe = record->stackframe;
		break;
	case RZ_ANALYSIS_ADDR_HINT_TYPE_PTR:
		hint->ptr = record->ptr;
		break;
	case RZ_ANALYSIS_ADDR_HINT_TYPE_NWORD:
		hint->nword = record->nword;
		break;
	case RZ_ANALYSIS_ADDR_HINT_TYPE_RET:
		hint->ret = record->retval;
		break;
	case RZ_ANALYSIS_ADDR_HINT_TYPE_NEW_BITS:
		hint->new_bits = record->newbits;
		break;
	case RZ_ANALYSIS_ADDR_HINT_TYPE_SIZE:
		hint->size = record->size;
		break;
	case RZ_ANALYSIS_ADDR_HINT_TYPE_SYNTAX:
		hint->syntax = record->syntax ? strdup(record->syntax) : NULL;
		break;
	case RZ_ANALYSIS_ADDR_HINT_TYPE_OPTYPE:
		hint->type = record->optype;
		break;
	case RZ_ANALYSIS_ADDR_HINT_TYPE_OPCODE:
		hint->opcode = record->opcode ? strdup(record->opcode) : NULL;
		break;
	case RZ_ANALYSIS_ADDR_HINT_TYPE_TYPE_OFFSET:
		hint->offset = record->type_offset ? strdup(record->type_offset) : NULL;
		break;
	case RZ_ANALYSIS_ADDR_HINT_TYPE_ESIL:
		hint->esil = record->esil ? strdup(record->esil) : NULL;
		break;
	case RZ_ANALYSIS_ADDR_HINT_TYPE_HIGH:
		hint->high = true;
		break;
	case RZ_ANALYSIS_ADDR_HINT_TYPE_VAL:
		hint->val = record->val;
		break;
	}
}

RZ_API RzAnalysisHint *rz_analysis_hint_get(RzAnalysis *a, ut64 addr) {
	RzAnalysisHint *hint = RZ_NEW0(RzAnalysisHint);
	if (!hint) {
		return NULL;
	}
	hint->addr = addr;
	hint->jump = UT64_MAX;
	hint->fail = UT64_MAX;
	hint->ret = UT64_MAX;
	hint->val = UT64_MAX;
	hint->stackframe = UT64_MAX;
	const RzVector *records = rz_analysis_addr_hints_at(a, addr);
	if (records) {
		RzAnalysisAddrHintRecord *record;
		rz_vector_foreach (records, record) {
			hint_merge(hint, record);
		}
	}
	const char *arch = rz_analysis_hint_arch_at(a, addr, NULL);
	hint->arch = arch ? strdup(arch) : NULL;
	hint->bits = rz_analysis_hint_bits_at(a, addr, NULL);
	if ((!records || rz_vector_empty(records)) && !hint->arch && !hint->bits) {
		// no hints found
		free(hint);
		return NULL;
	}
	return hint;
}
