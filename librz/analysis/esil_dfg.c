// SPDX-FileCopyrightText: 2019 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

//#include <rz_util.h>
#include <rz_analysis.h>
//#include <rz_reg.h>
//#include <sdb.h>

typedef struct esil_dfg_reg_var_t {
	ut32 from;
	ut32 to;
	RzGraphNode *node;
} EsilDFGRegVar;

typedef struct rz_analysis_esil_dfg_filter_t {
	RzAnalysisEsilDFG *dfg;
	RContRBTree *tree;
	HtPP *results;
} RzAnalysisEsilDFGFilter;

// TODO: simple const propagation - use node->type of srcs to propagate consts of pushed vars

RZ_API RzAnalysisEsilDFGNode *rz_analysis_esil_dfg_node_new(RzAnalysisEsilDFG *edf, const char *c) {
	RzAnalysisEsilDFGNode *ret = RZ_NEW0(RzAnalysisEsilDFGNode);
	ret->content = rz_strbuf_new(c);
	ret->idx = edf->idx++;
	return ret;
}

static void _dfg_node_free(RzAnalysisEsilDFGNode *free_me) {
	if (free_me) {
		rz_strbuf_free(free_me->content);
		free(free_me);
	}
}

static int _rv_del_alloc_cmp(void *incoming, void *in, void *user) {
	EsilDFGRegVar *rv_incoming = (EsilDFGRegVar *)incoming;
	EsilDFGRegVar *rv_in = (EsilDFGRegVar *)in;
	RzAnalysisEsilDFG *dfg = (RzAnalysisEsilDFG *)user;

	if (dfg->malloc_failed) {
		return -1;
	}

	// first handle the simple cases without intersection
	if (rv_incoming->to < rv_in->from) {
		return -1;
	}
	if (rv_in->to < rv_incoming->from) {
		return 1;
	}
	if (rv_in->from == rv_incoming->from && rv_in->to == rv_incoming->to) {
		return 0;
	}

	/*
	the following cases are about intersection, here some ascii-art, so you understand what I do

	     =incoming=
	=========in=========

	split in into 2 and reinsert the second half (in2)
	shrink first half (in1)

	     =incoming=
	=in1=          =in2=
	*/

	if (rv_in->from < rv_incoming->from && rv_incoming->to < rv_in->to) {
		EsilDFGRegVar *rv = RZ_NEW(EsilDFGRegVar);
		if (!rv) {
			dfg->malloc_failed = true;
			return -1;
		}
		rv[0] = rv_in[0];
		rv_in->to = rv_incoming->from - 1;
		rv->from = rv_incoming->to + 1;
		dfg->insert = rv;
		return 1;
	}

	/*
	   =incoming=
	      =in=

	enqueue the non-intersecting ends in the todo-queue
	*/

	if (rv_incoming->from < rv_in->from && rv_in->to < rv_incoming->to) {
		// lower part
		EsilDFGRegVar *rv = RZ_NEW(EsilDFGRegVar);
		if (!rv) {
			dfg->malloc_failed = true;
			return -1;
		}
		rv[0] = rv_incoming[0];
		rv->to = rv_in->from - 1;
		rz_queue_enqueue(dfg->todo, rv);
		// upper part
		rv = RZ_NEW(EsilDFGRegVar);
		if (!rv) {
			dfg->malloc_failed = true;
			return -1;
		}
		rv[0] = rv_incoming[0];
		rv->from = rv_in->to + 1;
		rz_queue_enqueue(dfg->todo, rv);
		return 0;
	}

	/*
	   =incoming=
	   =in=

	similar to the previous case, but this time only enqueue 1 half
	*/

	if (rv_incoming->from == rv_in->from && rv_in->to < rv_incoming->to) {
		EsilDFGRegVar *rv = RZ_NEW(EsilDFGRegVar);
		if (!rv) {
			dfg->malloc_failed = true;
			return -1;
		}
		rv[0] = rv_incoming[0];
		rv->from = rv_in->to + 1;
		rz_queue_enqueue(dfg->todo, rv);
		return 0;
	}

	/*
	   =incoming=
	         =in=
	*/

	if (rv_incoming->from < rv_in->from && rv_in->to == rv_incoming->to) {
		EsilDFGRegVar *rv = RZ_NEW(EsilDFGRegVar);
		if (!rv) {
			dfg->malloc_failed = true;
			return -1;
		}
		rv[0] = rv_incoming[0];
		rv->to = rv_in->from - 1;
		rz_queue_enqueue(dfg->todo, rv);
		return 0;
	}

	/*
	    =incoming=
	===in===

	shrink in

	    =incoming=
	=in=
	*/

	if (rv_in->to <= rv_incoming->to) {
		rv_in->to = rv_incoming->from - 1;
		return 1;
	}

	/*
	  =incoming=
        ===in===

	up-shrink in

	  =incoming=
	  ==in==
	*/

	rv_in->from = rv_incoming->to + 1;
	return -1;
}

static int _rv_ins_cmp(void *incoming, void *in, void *user) {
	EsilDFGRegVar *rv_incoming = (EsilDFGRegVar *)incoming;
	EsilDFGRegVar *rv_in = (EsilDFGRegVar *)in;
	return rv_incoming->from - rv_in->from;
}

static EsilDFGRegVar *newEsilDFGRegVar(const RzRegItem *ri, RzGraphNode *node) {
	EsilDFGRegVar *rv = RZ_NEW0(EsilDFGRegVar);
	if (!rv) {
		return NULL;
	}
	rv->from = ri->offset;
	rv->to = rv->from + ri->size - 1;
	rv->node = node;
	return rv;
}

static bool _edf_reg_set(RzAnalysisEsilDFG *dfg, const char *reg, RzGraphNode *node) {
	rz_return_val_if_fail(dfg && !dfg->malloc_failed && reg, false);
	const RzRegItem *ri = ht_pp_find(dfg->reg_items_ht, reg, NULL);
	if (!ri) {
		//no assert to prevent memleaks
		return false;
	}
	EsilDFGRegVar *rv = newEsilDFGRegVar(ri, NULL);
	if (!rv) {
		return false;
	}
	rz_queue_enqueue(dfg->todo, rv);
	while (!rz_queue_is_empty(dfg->todo) && !dfg->malloc_failed) {
		// rbtree api does sadly not allow deleting multiple items at once :(
		rv = rz_queue_dequeue(dfg->todo);
		rz_rbtree_cont_delete(dfg->reg_vars, rv, _rv_del_alloc_cmp, dfg);
		if (dfg->insert && !dfg->malloc_failed) {
			rz_rbtree_cont_insert(dfg->reg_vars, dfg->insert, _rv_ins_cmp, NULL);
			dfg->insert = NULL;
		}
		free(rv);
	}
	if (dfg->malloc_failed) {
		while (!rz_queue_is_empty(dfg->todo)) {
			free(rz_queue_dequeue(dfg->todo));
		}
		return false;
	}
	rv = newEsilDFGRegVar(ri, node);
	rz_rbtree_cont_insert(dfg->reg_vars, rv, _rv_ins_cmp, NULL);
	return true;
}

static int _rv_find_cmp(void *incoming, void *in, void *user) {
	EsilDFGRegVar *rv_incoming = (EsilDFGRegVar *)incoming;
	EsilDFGRegVar *rv_in = (EsilDFGRegVar *)in;

	RzAnalysisEsilDFG *dfg = (RzAnalysisEsilDFG *)user;
	if (dfg->malloc_failed) {
		return -1;
	}

	// first handle the simple cases without intersection
	if (rv_incoming->to < rv_in->from) {
		return -1;
	}
	if (rv_in->to < rv_incoming->from) {
		return 1;
	}

	/*
	     =incoming=
	=========in=========
	*/
	if (rv_in->from <= rv_incoming->from && rv_incoming->to <= rv_in->to) {
		return 0;
	}

	/*
	   =incoming=
	      =in=

	enqueue the non-intersecting ends in the todo-queue
	*/
	if (rv_incoming->from < rv_in->from && rv_in->to < rv_incoming->to) {
		// lower part
		EsilDFGRegVar *rv = RZ_NEW(EsilDFGRegVar);
		if (!rv) {
			dfg->malloc_failed = true;
			return -1;
		}
		rv[0] = rv_incoming[0];
		rv->to = rv_in->from - 1;
		rz_queue_enqueue(dfg->todo, rv);
		// upper part
		rv = RZ_NEW(EsilDFGRegVar);
		if (!rv) {
			dfg->malloc_failed = true;
			return -1;
		}
		rv[0] = rv_incoming[0];
		rv->from = rv_in->to + 1;
		rz_queue_enqueue(dfg->todo, rv);
		return 0;
	}

	/*
	   =incoming=
	  =in=

	similar to the previous case, but this time only enqueue 1 half
	*/
	if (rv_in->from <= rv_incoming->from && rv_in->to < rv_incoming->to) {
		EsilDFGRegVar *rv = RZ_NEW(EsilDFGRegVar);
		if (!rv) {
			dfg->malloc_failed = true;
			return -1;
		}
		rv[0] = rv_incoming[0];
		rv->from = rv_in->to + 1;
		rz_queue_enqueue(dfg->todo, rv);
		return 0;
	}

	/*
	   =incoming=
	          =in=
	*/
	EsilDFGRegVar *rv = RZ_NEW(EsilDFGRegVar);
	if (!rv) {
		dfg->malloc_failed = true;
		return -1;
	}
	rv[0] = rv_incoming[0];
	rv->to = rv_in->from - 1;
	rz_queue_enqueue(dfg->todo, rv);
	return 0;
}

static RzGraphNode *_edf_origin_reg_get(RzAnalysisEsilDFG *dfg, const char *reg) {
	rz_return_val_if_fail(dfg && reg, NULL);
	if (!ht_pp_find(dfg->reg_items_ht, reg, NULL)) {
		return NULL;
	}
	RzGraphNode *origin_reg_node = ht_pp_find(dfg->reg_nodes_ht, reg, NULL);
	if (origin_reg_node) {
		return origin_reg_node;
	}
	RzGraphNode *reg_node = rz_graph_add_node(dfg->flow, rz_analysis_esil_dfg_node_new(dfg, reg));
	RzAnalysisEsilDFGNode *_origin_reg_node = rz_analysis_esil_dfg_node_new(dfg, reg);
	rz_strbuf_appendf(_origin_reg_node->content, ":var_%d", dfg->idx++);
	_origin_reg_node->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_VAR;
	origin_reg_node = rz_graph_add_node(dfg->flow, _origin_reg_node);
	rz_graph_add_edge(dfg->flow, reg_node, origin_reg_node);
	ht_pp_insert(dfg->reg_nodes_ht, reg, origin_reg_node);
	return origin_reg_node;
}

static RzGraphNode *_edf_reg_get(RzAnalysisEsilDFG *dfg, const char *reg) {
	rz_return_val_if_fail(dfg && reg, NULL);
	RzRegItem *ri = ht_pp_find(dfg->reg_items_ht, reg, NULL);
	if (!ri) {
		return NULL;
	}
	EsilDFGRegVar *rv = newEsilDFGRegVar(ri, NULL);
	if (!rv) {
		return NULL;
	}
	RQueue *parts = rz_queue_new(8);
	if (!parts) {
		free(rv);
		return NULL;
	}
	rz_queue_enqueue(dfg->todo, rv);

	// log2((search_rv.to + 1) - search_rv.from) maybe better?
	// wat du if this fails?

	RzGraphNode *reg_node = NULL;
	while (!rz_queue_is_empty(dfg->todo)) {
		rv = rz_queue_dequeue(dfg->todo);
		EsilDFGRegVar *part_rv = rz_rbtree_cont_find(dfg->reg_vars, rv, _rv_find_cmp, dfg);
		if (part_rv) {
			rz_queue_enqueue(parts, part_rv->node);
		} else if (!reg_node) {
			reg_node = _edf_origin_reg_get(dfg, reg);
			//insert in the gap
			part_rv = RZ_NEW(EsilDFGRegVar);
			if (!part_rv) {
				RZ_FREE(rv);
				dfg->malloc_failed = true;
				break;
			}
			part_rv[0] = rv[0];
			part_rv->node = reg_node;
			rz_rbtree_cont_insert(dfg->reg_vars, part_rv, _rv_ins_cmp, NULL);
			//enqueue for later merge
			rz_queue_enqueue(parts, reg_node);
		} else {
			//initial regnode was already created
			//only need to insert in the tree
			part_rv = RZ_NEW(EsilDFGRegVar);
			if (!part_rv) {
				RZ_FREE(part_rv);
				dfg->malloc_failed = true;
				break;
			}
			part_rv[0] = rv[0];
			part_rv->node = reg_node;
			rz_rbtree_cont_insert(dfg->reg_vars, part_rv, _rv_ins_cmp, NULL);
		}
		free(rv);
	}
	reg_node = NULL; // is this needed?
	if (dfg->malloc_failed) {
		while (!rz_queue_is_empty(dfg->todo)) {
			free(rz_queue_dequeue(dfg->todo));
			goto beach;
		}
	}
	switch (parts->size) {
	case 0:
		break;
	case 1:
		reg_node = rz_queue_dequeue(parts);
		break;
	default: {
		RzAnalysisEsilDFGNode *_reg_node = rz_analysis_esil_dfg_node_new(dfg, "merge to ");
		if (!_reg_node) {
			while (!rz_queue_is_empty(dfg->todo)) {
				free(rz_queue_dequeue(dfg->todo));
			}
			dfg->malloc_failed = true;
			goto beach;
		}

		rz_strbuf_appendf(_reg_node->content, "%s:var_%d", reg, dfg->idx++);
		reg_node = rz_graph_add_node(dfg->flow, _reg_node);
		if (!reg_node) {
			_dfg_node_free(_reg_node);
			while (!rz_queue_is_empty(dfg->todo)) {
				free(rz_queue_dequeue(dfg->todo));
			}
			dfg->malloc_failed = true;
			goto beach;
		}
	}
		do {
			rz_graph_add_edge(dfg->flow, rz_queue_dequeue(parts), reg_node);
		} while (!rz_queue_is_empty(parts));
		break;
	}
beach:
	rz_queue_free(parts);
	return reg_node;
}

static bool _edf_var_set(RzAnalysisEsilDFG *dfg, const char *var, RzGraphNode *node) {
	rz_return_val_if_fail(dfg && var, false);
	return ht_pp_update(dfg->var_nodes_ht, var, node);
}

static RzGraphNode *_edf_var_get(RzAnalysisEsilDFG *dfg, const char *var) {
	rz_return_val_if_fail(dfg && var, NULL);
	return ht_pp_find(dfg->var_nodes_ht, var, NULL);
}

static bool edf_consume_2_set_reg(RzAnalysisEsil *esil);
static bool edf_consume_2_push_1(RzAnalysisEsil *esil);
static bool edf_consume_1_push_1(RzAnalysisEsil *esil);
typedef void (*AddConstraintStringUseNewCB)(RzStrBuf *result, const char *new_node_str);
static bool edf_use_new_push_1(RzAnalysisEsil *esil, const char *op_string, AddConstraintStringUseNewCB cb);
typedef void (*AddConstraintStringConsume1UseOldNewCB)(RzStrBuf *result, const char *consume_str, const char *old_node_str, const char *new_node_str);
static bool edf_consume_1_use_old_new_push_1(RzAnalysisEsil *esil, const char *op_string, AddConstraintStringConsume1UseOldNewCB cb);

static bool edf_eq_weak(RzAnalysisEsil *esil) {
	RzAnalysisEsilDFG *edf = (RzAnalysisEsilDFG *)esil->user;
	RzGraphNode *o_old = edf->old; //node for esil->old
	RzGraphNode *o_new = edf->cur; //node for esil->cur
	if (!edf_consume_2_set_reg(esil)) {
		return false;
	}
	//work-around
	edf->old = o_old ? o_old : NULL;
	edf->cur = o_new ? o_new : NULL;
	return true;
}

static void edf_zf_constraint(RzStrBuf *result, const char *new_node_str) {
	rz_strbuf_appendf(result, ":(%s==0)", new_node_str);
}

static bool edf_zf(RzAnalysisEsil *esil) {
	return edf_use_new_push_1(esil, "$z", edf_zf_constraint);
}

static void edf_pf_constraint(RzStrBuf *result, const char *new_node_str) {
	rz_strbuf_appendf(result, ":parity_of(%s)", new_node_str);
}

static bool edf_pf(RzAnalysisEsil *esil) {
	return edf_use_new_push_1(esil, "$p", edf_pf_constraint);
}

static void edf_cf_constraint(RzStrBuf *result, const char *consume, const char *o, const char *n) {
	rz_strbuf_appendf(result, ":((%s&mask(%s&0x3f))<(%s&mask(%s&0x3f)))",
		n, consume, o, consume);
}

static bool edf_cf(RzAnalysisEsil *esil) {
	return edf_consume_1_use_old_new_push_1(esil, "$c", edf_cf_constraint);
}

static void edf_bf_constraint(RzStrBuf *result, const char *consume, const char *o, const char *n) {
	rz_strbuf_appendf(result, ":((%s&mask((%s+0x3f)&0x3f))<(%s& mask((%s+0x3f)&0x3f)))",
		o, consume, n, consume);
}

static bool edf_bf(RzAnalysisEsil *esil) {
	return edf_consume_1_use_old_new_push_1(esil, "$b", edf_bf_constraint);
}

static bool _edf_consume_2_set_reg(RzAnalysisEsil *esil, const bool use_origin) {
	const char *op_string = rz_strbuf_get(&esil->current_opstr);
	RzAnalysisEsilDFG *edf = (RzAnalysisEsilDFG *)esil->user;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);

	if (!src || !dst) {
		free(dst);
		free(src);
		return false;
	}

	int dst_type = rz_analysis_esil_get_parm_type(esil, dst);
	if (dst_type == RZ_ANALYSIS_ESIL_PARM_INVALID) {
		free(dst);
		free(src);
		return false;
	}

	const int src_type = rz_analysis_esil_get_parm_type(esil, src);
	RzGraphNode *src_node = NULL;
	if (src_type == RZ_ANALYSIS_ESIL_PARM_REG) {
		src_node = _edf_reg_get(edf, src);
	} else if (src_type == RZ_ANALYSIS_ESIL_PARM_NUM) {
		RzGraphNode *n_value = rz_graph_add_node(edf->flow, rz_analysis_esil_dfg_node_new(edf, src));
		RzAnalysisEsilDFGNode *ec_node = rz_analysis_esil_dfg_node_new(edf, src);
		ec_node->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_CONST;
		rz_strbuf_appendf(ec_node->content, ":const_%d", edf->idx++);
		src_node = rz_graph_add_node(edf->flow, ec_node);
		rz_graph_add_edge(edf->flow, n_value, src_node);
	} else {
		src_node = _edf_var_get(edf, src);
	}

	RzGraphNode *dst_node = use_origin ? _edf_origin_reg_get(edf, dst) : _edf_reg_get(edf, dst);
	RzGraphNode *old_dst_node = dst_node;

	if (!src_node || !dst_node) {
		free(src);
		free(dst);
		return false;
	}

	RzAnalysisEsilDFGNode *eop_node = rz_analysis_esil_dfg_node_new(edf, src);
	rz_strbuf_appendf(eop_node->content, ",%s,%s", dst, op_string);
	eop_node->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_GENERATIVE;
	free(src);

	RzGraphNode *op_node = rz_graph_add_node(edf->flow, eop_node);
	rz_graph_add_edge(edf->flow, dst_node, op_node);
	rz_graph_add_edge(edf->flow, src_node, op_node);
	edf->old = old_dst_node;
	RzAnalysisEsilDFGNode *result = rz_analysis_esil_dfg_node_new(edf, dst);
	result->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_RESULT | RZ_ANALYSIS_ESIL_DFG_BLOCK_VAR;

	rz_strbuf_appendf(result->content, ":var_%d", edf->idx++);
	dst_node = rz_graph_add_node(edf->flow, result);
	rz_graph_add_edge(edf->flow, op_node, dst_node);
	_edf_reg_set(edf, dst, dst_node);
	edf->cur = dst_node;
	free(dst);
	return true;
}

static bool edf_consume_2_use_set_reg(RzAnalysisEsil *esil) {
	return _edf_consume_2_set_reg(esil, false);
}

static bool edf_consume_2_set_reg(RzAnalysisEsil *esil) {
	return _edf_consume_2_set_reg(esil, true);
}

static bool edf_consume_2_push_1(RzAnalysisEsil *esil) {
	const char *op_string = rz_strbuf_get(&esil->current_opstr);
	RzAnalysisEsilDFG *edf = (RzAnalysisEsilDFG *)esil->user;
	char *src[2] = { rz_analysis_esil_pop(esil), rz_analysis_esil_pop(esil) };

	if (!src[0] || !src[1]) {
		free(src[0]);
		free(src[1]);
		return false;
	}
	RzAnalysisEsilDFGNode *eop_node = rz_analysis_esil_dfg_node_new(edf, src[1]);
	rz_strbuf_appendf(eop_node->content, ",%s,%s", src[0], op_string);
	eop_node->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_RESULT | RZ_ANALYSIS_ESIL_DFG_BLOCK_GENERATIVE;
	RzGraphNode *op_node = rz_graph_add_node(edf->flow, eop_node);
	RzGraphNode *src_node[2];
	ut32 i;
	for (i = 0; i < 2; i++) {
		const int src_type = rz_analysis_esil_get_parm_type(esil, src[i]);
		if (src_type == RZ_ANALYSIS_ESIL_PARM_REG) {
			src_node[i] = _edf_reg_get(edf, src[i]);
		} else if (src_type == RZ_ANALYSIS_ESIL_PARM_NUM) {
			RzGraphNode *n_value = rz_graph_add_node(edf->flow, rz_analysis_esil_dfg_node_new(edf, src[i]));
			RzAnalysisEsilDFGNode *ec_node = rz_analysis_esil_dfg_node_new(edf, src[i]);
			ec_node->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_CONST;
			rz_strbuf_appendf(ec_node->content, ":const_%d", edf->idx++);
			src_node[i] = rz_graph_add_node(edf->flow, ec_node);
			rz_graph_add_edge(edf->flow, n_value, src_node[i]);
		} else {
			src_node[i] = _edf_var_get(edf, src[i]);
		}
		rz_graph_add_edge(edf->flow, src_node[i], op_node);
	}

	free(src[0]);
	free(src[1]);

	RzAnalysisEsilDFGNode *result = rz_analysis_esil_dfg_node_new(edf, "result_");
	result->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_RESULT;
	rz_strbuf_appendf(result->content, "%d", edf->idx++);
	RzGraphNode *result_node = rz_graph_add_node(edf->flow, result);
	rz_graph_add_edge(edf->flow, op_node, result_node);
	_edf_var_set(edf, rz_strbuf_get(result->content), result_node);
	rz_analysis_esil_push(esil, rz_strbuf_get(result->content));
	return true;
}

static bool edf_consume_1_push_1(RzAnalysisEsil *esil) {
	const char *op_string = rz_strbuf_get(&esil->current_opstr);
	RzAnalysisEsilDFG *edf = (RzAnalysisEsilDFG *)esil->user;
	char *src = rz_analysis_esil_pop(esil);
	if (!src) {
		return false;
	}
	RzAnalysisEsilDFGNode *eop_node = rz_analysis_esil_dfg_node_new(edf, src);
	rz_strbuf_appendf(eop_node->content, ",%s", op_string);
	eop_node->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_RESULT | RZ_ANALYSIS_ESIL_DFG_BLOCK_GENERATIVE;
	RzGraphNode *op_node = rz_graph_add_node(edf->flow, eop_node);
	const int src_type = rz_analysis_esil_get_parm_type(esil, src);
	RzGraphNode *src_node = NULL;
	if (src_type == RZ_ANALYSIS_ESIL_PARM_REG) {
		src_node = _edf_reg_get(edf, src);
	} else if (src_type == RZ_ANALYSIS_ESIL_PARM_NUM) {
		RzGraphNode *n_value = rz_graph_add_node(edf->flow, rz_analysis_esil_dfg_node_new(edf, src));
		RzAnalysisEsilDFGNode *ec_node = rz_analysis_esil_dfg_node_new(edf, src);
		ec_node->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_CONST;
		rz_strbuf_appendf(ec_node->content, ":const_%d", edf->idx++);
		src_node = rz_graph_add_node(edf->flow, ec_node);
		rz_graph_add_edge(edf->flow, n_value, src_node);
	} else {
		src_node = _edf_var_get(edf, src);
	}

	free(src);

	rz_graph_add_edge(edf->flow, src_node, op_node);

	RzAnalysisEsilDFGNode *result = rz_analysis_esil_dfg_node_new(edf, "result_");
	result->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_RESULT; //TODO: propgate type from src here
	rz_strbuf_appendf(result->content, "%d", edf->idx++);
	RzGraphNode *result_node = rz_graph_add_node(edf->flow, result);
	rz_graph_add_edge(edf->flow, op_node, result_node);
	_edf_var_set(edf, rz_strbuf_get(result->content), result_node);
	rz_analysis_esil_push(esil, rz_strbuf_get(result->content));
	return true;
}

static bool edf_consume_2_set_mem(RzAnalysisEsil *esil) {
	const char *op_string = rz_strbuf_get(&esil->current_opstr);
	RzAnalysisEsilDFG *edf = (RzAnalysisEsilDFG *)esil->user;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);

	if (!src || !dst) {
		free(dst);
		free(src);
		return 0;
	}

	int dst_type = rz_analysis_esil_get_parm_type(esil, dst);

	const int src_type = rz_analysis_esil_get_parm_type(esil, src);
	RzGraphNode *src_node = NULL;
	if (src_type == RZ_ANALYSIS_ESIL_PARM_REG) {
		src_node = _edf_reg_get(edf, src);
	} else if (src_type == RZ_ANALYSIS_ESIL_PARM_NUM) {
		RzGraphNode *n_value = rz_graph_add_node(edf->flow, rz_analysis_esil_dfg_node_new(edf, src));
		RzAnalysisEsilDFGNode *ec_node = rz_analysis_esil_dfg_node_new(edf, src);
		ec_node->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_CONST;
		rz_strbuf_appendf(ec_node->content, ":const_%d", edf->idx++);
		src_node = rz_graph_add_node(edf->flow, ec_node);
		rz_graph_add_edge(edf->flow, n_value, src_node);
	} else {
		src_node = _edf_var_get(edf, src);
	}

	RzGraphNode *dst_node = _edf_reg_get(edf, dst);
	if (!dst_node) {
		dst_node = _edf_var_get(edf, dst);
	}
	//probably dead code
	if (!dst_node) {
		if (dst_type == RZ_ANALYSIS_ESIL_PARM_REG) {
			RzGraphNode *n_reg = rz_graph_add_node(edf->flow, rz_analysis_esil_dfg_node_new(edf, dst));
			RzAnalysisEsilDFGNode *ev_node = rz_analysis_esil_dfg_node_new(edf, dst);
			ev_node->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_VAR | RZ_ANALYSIS_ESIL_DFG_BLOCK_PTR;
			rz_strbuf_appendf(ev_node->content, ":var_ptr_%d", edf->idx++);
			dst_node = rz_graph_add_node(edf->flow, ev_node);
			//			_edf_reg_set (edf, dst, ev_node);
			rz_graph_add_edge(edf->flow, n_reg, dst_node);
		}
		// TODO: const pointers
	}

	if (!src_node || !dst_node) {
		free(src);
		free(dst);
		return false;
	}

	RzAnalysisEsilDFGNode *eop_node = rz_analysis_esil_dfg_node_new(edf, src);
	rz_strbuf_appendf(eop_node->content, ",%s,%s", dst, op_string);
	eop_node->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_GENERATIVE;
	free(src);

	RzGraphNode *op_node = rz_graph_add_node(edf->flow, eop_node);
	rz_graph_add_edge(edf->flow, dst_node, op_node);
	rz_graph_add_edge(edf->flow, src_node, op_node);
	RzAnalysisEsilDFGNode *result = rz_analysis_esil_dfg_node_new(edf, dst);
	//	result->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_RESULT | RZ_ANALYSIS_ESIL_DFG_BLOCK_GENERATIVE;
	result->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_VAR;
	rz_strbuf_appendf(result->content, ":var_mem_%d", edf->idx++);
	dst_node = rz_graph_add_node(edf->flow, result);
	rz_graph_add_edge(edf->flow, op_node, dst_node);
	free(dst);
	return true;
}

static bool edf_use_new_push_1(RzAnalysisEsil *esil, const char *op_string, AddConstraintStringUseNewCB cb) {
	RzAnalysisEsilDFG *edf = (RzAnalysisEsilDFG *)esil->user;
	RzGraphNode *op_node = rz_graph_add_node(edf->flow, rz_analysis_esil_dfg_node_new(edf, op_string));
	RzGraphNode *latest_new = edf->cur;
	if (!latest_new) {
		return 0;
	}
	RzAnalysisEsilDFGNode *result = rz_analysis_esil_dfg_node_new(edf, "result_");
	result->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_RESULT; // is this generative?
	rz_strbuf_appendf(result->content, "%d", edf->idx++);
	if (cb) {
		RzAnalysisEsilDFGNode *e_new_node = (RzAnalysisEsilDFGNode *)latest_new->data;
		cb(result->content, rz_strbuf_get(e_new_node->content));
	}
	RzGraphNode *result_node = rz_graph_add_node(edf->flow, result);
	_edf_var_set(edf, rz_strbuf_get(result->content), result_node);
	rz_graph_add_edge(edf->flow, latest_new, op_node);
	rz_graph_add_edge(edf->flow, op_node, result_node);
	return rz_analysis_esil_push(esil, rz_strbuf_get(result->content));
}

static bool edf_consume_1_use_old_new_push_1(RzAnalysisEsil *esil, const char *op_string, AddConstraintStringConsume1UseOldNewCB cb) {
	RzAnalysisEsilDFG *edf = (RzAnalysisEsilDFG *)esil->user;
	char *src = rz_analysis_esil_pop(esil);

	if (!src) {
		return false;
	}
	RzAnalysisEsilDFGNode *eop_node = rz_analysis_esil_dfg_node_new(edf, src);
#if 0
	eop_node->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_GENERATIVE;
#endif
	rz_strbuf_appendf(eop_node->content, ",%s", op_string);
	RzGraphNode *op_node = rz_graph_add_node(edf->flow, eop_node);
	const int src_type = rz_analysis_esil_get_parm_type(esil, src);
	RzGraphNode *src_node = NULL;
	if (src_type == RZ_ANALYSIS_ESIL_PARM_REG) {
		src_node = _edf_reg_get(edf, src);
	} else if (src_type == RZ_ANALYSIS_ESIL_PARM_NUM) {
		RzGraphNode *n_value = rz_graph_add_node(edf->flow, rz_analysis_esil_dfg_node_new(edf, src));
		RzAnalysisEsilDFGNode *ec_node = rz_analysis_esil_dfg_node_new(edf, src);
		ec_node->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_CONST;
		rz_strbuf_appendf(ec_node->content, ":const_%d", edf->idx++);
		src_node = rz_graph_add_node(edf->flow, ec_node);
		rz_graph_add_edge(edf->flow, n_value, src_node);
	} else {
		src_node = _edf_var_get(edf, src);
	}
	free(src);

	rz_graph_add_edge(edf->flow, src_node, op_node);

	RzGraphNode *latest_new = edf->cur;
	RzGraphNode *latest_old = edf->old;
	RzAnalysisEsilDFGNode *result = rz_analysis_esil_dfg_node_new(edf, "result_");
	result->type = RZ_ANALYSIS_ESIL_DFG_BLOCK_RESULT; // propagate type here
	rz_strbuf_appendf(result->content, "%d", edf->idx++);
	if (cb) {
		RzAnalysisEsilDFGNode *e_src_node = (RzAnalysisEsilDFGNode *)src_node->data;
		RzAnalysisEsilDFGNode *e_new_node = (RzAnalysisEsilDFGNode *)latest_new->data;
		RzAnalysisEsilDFGNode *e_old_node = (RzAnalysisEsilDFGNode *)latest_old->data;
		cb(result->content, rz_strbuf_get(e_src_node->content),
			rz_strbuf_get(e_new_node->content), rz_strbuf_get(e_old_node->content));
	}
	RzGraphNode *result_node = rz_graph_add_node(edf->flow, result);
	_edf_var_set(edf, rz_strbuf_get(result->content), result_node);
	rz_graph_add_edge(edf->flow, latest_new, op_node);
	rz_graph_add_edge(edf->flow, latest_old, op_node);
	rz_graph_add_edge(edf->flow, op_node, result_node);
	return rz_analysis_esil_push(esil, rz_strbuf_get(result->content));
}

RZ_API RzAnalysisEsilDFG *rz_analysis_esil_dfg_new(RzReg *regs) {
	rz_return_val_if_fail(regs, NULL);
	RzAnalysisEsilDFG *dfg = RZ_NEW0(RzAnalysisEsilDFG);
	if (!dfg) {
		return NULL;
	}
	dfg->flow = rz_graph_new();
	// rax, eax, ax, ah, al	=> 8 should be enough
	dfg->todo = rz_queue_new(8);
	dfg->reg_vars = rz_rbtree_cont_newf(free);
	if (!dfg->flow || !dfg->todo || !dfg->reg_vars) {
		rz_analysis_esil_dfg_free(dfg);
		return NULL;
	}
	dfg->reg_items_ht = ht_pp_new0();
	dfg->reg_nodes_ht = ht_pp_new0();
	dfg->var_nodes_ht = ht_pp_new0();
	if (!dfg->reg_items_ht || !dfg->reg_items_ht || !dfg->var_nodes_ht) {
		rz_analysis_esil_dfg_free(dfg);
		return NULL;
	}

	// this is not exactly necessary
	// could use RzReg-API directly in the dfg gen,
	// but HT as transition table is probably faster
	RzRegItem *ri;
	RzListIter *ator;
	rz_list_foreach (regs->allregs, ator, ri) {
		ht_pp_insert(dfg->reg_items_ht, ri->name, ri);
	}
	return dfg;
}

RZ_API void rz_analysis_esil_dfg_free(RzAnalysisEsilDFG *dfg) {
	if (dfg) {
		if (dfg->flow) {
			RzGraphNode *n;
			RzListIter *iter;
			rz_list_foreach (rz_graph_get_nodes(dfg->flow), iter, n) {
				n->free = (RzListFree)_dfg_node_free;
			}
			rz_graph_free(dfg->flow);
		}
		ht_pp_free(dfg->reg_items_ht);
		ht_pp_free(dfg->reg_nodes_ht);
		ht_pp_free(dfg->var_nodes_ht);
		rz_rbtree_cont_free(dfg->reg_vars);
		rz_queue_free(dfg->todo);
		free(dfg);
	}
}

RZ_API RzAnalysisEsilDFG *rz_analysis_esil_dfg_expr(RzAnalysis *analysis, RzAnalysisEsilDFG *dfg, const char *expr) {
	if (!expr) {
		return NULL;
	}
	RzAnalysisEsil *esil = rz_analysis_esil_new(4096, 0, 1);
	if (!esil) {
		return NULL;
	}
	esil->analysis = analysis;

	RzAnalysisEsilDFG *edf = dfg ? dfg : rz_analysis_esil_dfg_new(analysis->reg);
	if (!edf) {
		rz_analysis_esil_free(esil);
		return NULL;
	}

	rz_analysis_esil_set_op(esil, "=", edf_consume_2_set_reg, 0, 2, RZ_ANALYSIS_ESIL_OP_TYPE_REG_WRITE);
	rz_analysis_esil_set_op(esil, ":=", edf_eq_weak, 0, 2, RZ_ANALYSIS_ESIL_OP_TYPE_REG_WRITE);
	rz_analysis_esil_set_op(esil, "$z", edf_zf, 1, 0, RZ_ANALYSIS_ESIL_OP_TYPE_UNKNOWN);
	rz_analysis_esil_set_op(esil, "$p", edf_pf, 1, 0, RZ_ANALYSIS_ESIL_OP_TYPE_UNKNOWN);
	rz_analysis_esil_set_op(esil, "$c", edf_cf, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_UNKNOWN);
	rz_analysis_esil_set_op(esil, "$b", edf_bf, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_UNKNOWN);
	rz_analysis_esil_set_op(esil, "^=", edf_consume_2_use_set_reg, 0, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH | RZ_ANALYSIS_ESIL_OP_TYPE_REG_WRITE);
	rz_analysis_esil_set_op(esil, "-=", edf_consume_2_use_set_reg, 0, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH | RZ_ANALYSIS_ESIL_OP_TYPE_REG_WRITE);
	rz_analysis_esil_set_op(esil, "+=", edf_consume_2_use_set_reg, 0, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH | RZ_ANALYSIS_ESIL_OP_TYPE_REG_WRITE);
	rz_analysis_esil_set_op(esil, "*=", edf_consume_2_use_set_reg, 0, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH | RZ_ANALYSIS_ESIL_OP_TYPE_REG_WRITE);
	rz_analysis_esil_set_op(esil, "/=", edf_consume_2_use_set_reg, 0, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH | RZ_ANALYSIS_ESIL_OP_TYPE_REG_WRITE);
	rz_analysis_esil_set_op(esil, "&=", edf_consume_2_use_set_reg, 0, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH | RZ_ANALYSIS_ESIL_OP_TYPE_REG_WRITE);
	rz_analysis_esil_set_op(esil, "|=", edf_consume_2_use_set_reg, 0, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH | RZ_ANALYSIS_ESIL_OP_TYPE_REG_WRITE);
	rz_analysis_esil_set_op(esil, "^=", edf_consume_2_use_set_reg, 0, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH | RZ_ANALYSIS_ESIL_OP_TYPE_REG_WRITE);
	rz_analysis_esil_set_op(esil, "+", edf_consume_2_push_1, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH);
	rz_analysis_esil_set_op(esil, "-", edf_consume_2_push_1, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH);
	rz_analysis_esil_set_op(esil, "&", edf_consume_2_push_1, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH);
	rz_analysis_esil_set_op(esil, "|", edf_consume_2_push_1, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH);
	rz_analysis_esil_set_op(esil, "^", edf_consume_2_push_1, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH);
	rz_analysis_esil_set_op(esil, "%", edf_consume_2_push_1, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH);
	rz_analysis_esil_set_op(esil, "*", edf_consume_2_push_1, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH);
	rz_analysis_esil_set_op(esil, "/", edf_consume_2_push_1, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH);
	rz_analysis_esil_set_op(esil, ">>", edf_consume_2_push_1, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH);
	rz_analysis_esil_set_op(esil, "<<", edf_consume_2_push_1, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH);
	rz_analysis_esil_set_op(esil, ">>>", edf_consume_2_push_1, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH);
	rz_analysis_esil_set_op(esil, ">>>", edf_consume_2_push_1, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MATH);
	rz_analysis_esil_set_op(esil, "!", edf_consume_1_push_1, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_MATH);
	rz_analysis_esil_set_op(esil, "[1]", edf_consume_1_push_1, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_MEM_READ);
	rz_analysis_esil_set_op(esil, "[2]", edf_consume_1_push_1, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_MEM_READ);
	rz_analysis_esil_set_op(esil, "[4]", edf_consume_1_push_1, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_MEM_READ);
	rz_analysis_esil_set_op(esil, "[8]", edf_consume_1_push_1, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_MEM_READ);
	rz_analysis_esil_set_op(esil, "[16]", edf_consume_1_push_1, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_MEM_READ);
	rz_analysis_esil_set_op(esil, "=[1]", edf_consume_2_set_mem, 0, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MEM_WRITE);
	rz_analysis_esil_set_op(esil, "=[2]", edf_consume_2_set_mem, 0, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MEM_WRITE);
	rz_analysis_esil_set_op(esil, "=[4]", edf_consume_2_set_mem, 0, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MEM_WRITE);
	rz_analysis_esil_set_op(esil, "=[8]", edf_consume_2_set_mem, 0, 2, RZ_ANALYSIS_ESIL_OP_TYPE_MEM_WRITE);

	esil->user = edf;

	rz_analysis_esil_parse(esil, expr);
	rz_analysis_esil_free(esil);
	return edf;
}

static int _dfg_node_filter_insert_cmp(void *incoming, void *in, void *user) {
	RzAnalysisEsilDFGNode *incoming_node = (RzAnalysisEsilDFGNode *)incoming;
	RzAnalysisEsilDFGNode *in_node = (RzAnalysisEsilDFGNode *)in;
	return incoming_node->idx - in_node->idx;
}

static void _dfg_rev_dfs_cb(RzGraphNode *n, RzGraphVisitor *vi) {
	RzAnalysisEsilDFGNode *node = (RzAnalysisEsilDFGNode *)n->data;
	RzAnalysisEsilDFGFilter *filter = (RzAnalysisEsilDFGFilter *)vi->data;
	switch (node->type) {
	case RZ_ANALYSIS_ESIL_DFG_BLOCK_CONST:
	case RZ_ANALYSIS_ESIL_DFG_BLOCK_VAR:
	case RZ_ANALYSIS_ESIL_DFG_BLOCK_PTR:
		break;
	case RZ_ANALYSIS_ESIL_DFG_BLOCK_GENERATIVE:
		rz_rbtree_cont_insert(filter->tree, node, _dfg_node_filter_insert_cmp, NULL);
		break;
	case RZ_ANALYSIS_ESIL_DFG_BLOCK_RESULT: // outnode must be result generator here
	{
		RzGraphNode *previous = (RzGraphNode *)rz_list_get_top(n->in_nodes);
		if (previous) {
			ht_pp_update(filter->results, rz_strbuf_get(node->content), previous);
		}
	} break;
	}
}

// There is an exact copy of this function in esil_cfg.c
static char *internal_esil_strchrtok(char *str, const char tok) {
	if (!str) {
		return NULL;
	}
	ut32 i;
	for (i = 0; str[i]; i++) {
		if (str[i] == tok) {
			str[i] = '\0';
			return &str[i + 1];
		}
	}
	return NULL;
}

static RzStrBuf *get_resolved_expr(RzAnalysisEsilDFGFilter *filter, RzAnalysisEsilDFGNode *node) {
	char *expr = strdup(rz_strbuf_get(node->content));
	RzStrBuf *res = rz_strbuf_new("");
	if (!expr) { //empty expressions. can this happen?
		return res;
	}
	char *p, *q;
	// we can do this bc every generative node MUST end with an operator
	for (p = expr; (q = internal_esil_strchrtok(p, ',')); p = q) {
		RzGraphNode *gn = ht_pp_find(filter->results, p, NULL);
		if (!gn) {
			rz_strbuf_appendf(res, ",%s,", p);
		} else {
			RzStrBuf *r = get_resolved_expr(filter, (RzAnalysisEsilDFGNode *)gn->data);
			rz_strbuf_appendf(res, ",%s,", rz_strbuf_get(r));
			rz_strbuf_free(r);
		}
	}
	rz_strbuf_appendf(res, "%s", p);
	free(expr);
	return res;
}

RZ_API RzStrBuf *rz_analysis_esil_dfg_filter(RzAnalysisEsilDFG *dfg, const char *reg) {
	if (!dfg || !reg) {
		return NULL;
	}
	RzGraphNode *resolve_me = _edf_reg_get(dfg, reg);
	if (!resolve_me) {
		return NULL;
	}

	// allocate stuff
	RzAnalysisEsilDFGFilter filter = { dfg, rz_rbtree_cont_new(), ht_pp_new0() };
	RzStrBuf *filtered = rz_strbuf_new("");
	RzGraphVisitor vi = { _dfg_rev_dfs_cb, NULL, NULL, NULL, NULL, &filter };

	// dfs the graph starting at node of esp-register
	rz_graph_dfs_node_reverse(dfg->flow, resolve_me, &vi);

	RBIter ator;
	RzAnalysisEsilDFGNode *node;
	rz_rbtree_cont_foreach(filter.tree, ator, node) {
		// resolve results to opstr here
		RzStrBuf *resolved = get_resolved_expr(&filter, node);
		rz_strbuf_append(filtered, rz_strbuf_get(resolved));
		rz_strbuf_free(resolved);
	}
	{
		char *sanitized = rz_str_replace(rz_str_replace(strdup(rz_strbuf_get(filtered)), ",,", ",", 1), ",,", ",", 1);
		rz_strbuf_set(filtered, (sanitized[0] == ',') ? &sanitized[1] : sanitized);
		free(sanitized);
	}
	rz_rbtree_cont_free(filter.tree);
	ht_pp_free(filter.results);
	return filtered;
}

RZ_API RzStrBuf *rz_analysis_esil_dfg_filter_expr(RzAnalysis *analysis, const char *expr, const char *reg) {
	if (!reg) {
		return NULL;
	}
	RzAnalysisEsilDFG *dfg = rz_analysis_esil_dfg_expr(analysis, NULL, expr);
	if (!dfg) {
		return NULL;
	}
	RzStrBuf *filtered = rz_analysis_esil_dfg_filter(dfg, reg);
	rz_analysis_esil_dfg_free(dfg);
	return filtered;
}
