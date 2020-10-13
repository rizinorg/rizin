/* radare - LGPL - Copyright 2019 - condret */

//#include <rz_util.h>
#include <rz_anal.h>
//#include <rz_reg.h>
//#include <sdb.h>

typedef struct esil_dfg_reg_var_t {
	ut32 from;
	ut32 to;
	RzGraphNode *node;
} EsilDFGRegVar;

typedef struct rz_anal_esil_dfg_filter_t {
	RzAnalEsilDFG *dfg;
	RContRBTree *tree;
	Sdb *results;
} RzAnalEsilDFGFilter;

// TODO: simple const propagation - use node->type of srcs to propagate consts of pushed vars

RZ_API RzAnalEsilDFGNode *rz_anal_esil_dfg_node_new(RzAnalEsilDFG *edf, const char *c) {
	RzAnalEsilDFGNode *ret = RZ_NEW0 (RzAnalEsilDFGNode);
	ret->content = rz_strbuf_new (c);
	ret->idx = edf->idx++;
	return ret;
}

static void _dfg_node_free (RzAnalEsilDFGNode *free_me) {
	if (free_me) {
		rz_strbuf_free (free_me->content);
		free (free_me);
	}
}

static int _rv_del_alloc_cmp (void *incoming, void *in, void *user) {
	EsilDFGRegVar *rv_incoming = (EsilDFGRegVar *)incoming;
	EsilDFGRegVar *rv_in = (EsilDFGRegVar *)in;
	RzAnalEsilDFG *dfg = (RzAnalEsilDFG *)user;

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
		EsilDFGRegVar *rv = RZ_NEW (EsilDFGRegVar);
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
		EsilDFGRegVar *rv = RZ_NEW (EsilDFGRegVar);
		if (!rv) {
			dfg->malloc_failed = true;
			return -1;
		}
		rv[0] = rv_incoming[0];
		rv->to = rv_in->from - 1;
		rz_queue_enqueue (dfg->todo, rv);
		// upper part
		rv = RZ_NEW (EsilDFGRegVar);
		if (!rv) {
			dfg->malloc_failed = true;
			return -1;
		}
		rv[0] = rv_incoming[0];
		rv->from = rv_in->to + 1;
		rz_queue_enqueue (dfg->todo, rv);
		return 0;
	}

	/*
	   =incoming=
	   =in=

	similar to the previous case, but this time only enqueue 1 half
	*/

	if (rv_incoming->from == rv_in->from && rv_in->to < rv_incoming->to) {
		EsilDFGRegVar *rv = RZ_NEW (EsilDFGRegVar);
		if (!rv) {
			dfg->malloc_failed = true;
			return -1;
		}
		rv[0] = rv_incoming[0];
		rv->from = rv_in->to + 1;
		rz_queue_enqueue (dfg->todo, rv);
		return 0;
	}

	/*
	   =incoming=
	         =in=
	*/

	if (rv_incoming->from < rv_in->from && rv_in->to == rv_incoming->to) {
		EsilDFGRegVar *rv = RZ_NEW (EsilDFGRegVar);
		if (!rv) {
			dfg->malloc_failed = true;
			return -1;
		}
		rv[0] = rv_incoming[0];
		rv->to = rv_in->from - 1;
		rz_queue_enqueue (dfg->todo, rv);
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

static int _rv_ins_cmp (void *incoming, void *in, void *user) {
	EsilDFGRegVar *rv_incoming = (EsilDFGRegVar *)incoming;
	EsilDFGRegVar *rv_in = (EsilDFGRegVar *)in;
	return rv_incoming->from - rv_in->from;
}

static bool _edf_reg_set (RzAnalEsilDFG *dfg, const char *reg, RzGraphNode *node) {
	rz_return_val_if_fail (dfg && !dfg->malloc_failed && reg, false);
	const ut32 _reg_strlen = 4 + strlen (reg);
	char *_reg = RZ_NEWS0 (char, _reg_strlen + 1);
	if (!_reg) {
		// no need for assert here, it's not a bug if malloc fails
		return false;
	}
	strncat (_reg, "reg.", _reg_strlen);
	strncat (_reg, reg, _reg_strlen);
	if (!sdb_num_exists (dfg->regs, _reg)) {
		//no assert to prevent memleaks
		free (_reg);
		return false;
	}
	EsilDFGRegVar *rv = RZ_NEW0 (EsilDFGRegVar);
	if (!rv) {
		free (_reg);
		return false;
	}

	const ut64 v = sdb_num_get (dfg->regs, _reg, NULL);
	free (_reg);
	rv->from = (v & (UT64_MAX ^ UT32_MAX)) >> 32;
	rv->to = v & UT32_MAX;
	rz_queue_enqueue (dfg->todo, rv);
	while (!rz_queue_is_empty (dfg->todo) && !dfg->malloc_failed) {
		// rbtree api does sadly not allow deleting multiple items at once :(
		rv = rz_queue_dequeue (dfg->todo);
		rz_rbtree_cont_delete (dfg->reg_vars, rv, _rv_del_alloc_cmp, dfg);
		if (dfg->insert && !dfg->malloc_failed) {
			rz_rbtree_cont_insert (dfg->reg_vars, dfg->insert, _rv_ins_cmp, NULL);
			dfg->insert = NULL;
		}
		free (rv);
	}
	if (dfg->malloc_failed) {
		while (!rz_queue_is_empty (dfg->todo)) {
			free (rz_queue_dequeue (dfg->todo));
		}
		return false;
	}
	rv = RZ_NEW0 (EsilDFGRegVar);
	rv->from = (v & (UT64_MAX ^ UT32_MAX)) >> 32;
	rv->to = v & UT32_MAX;
	rv->node = node;
	rz_rbtree_cont_insert (dfg->reg_vars, rv, _rv_ins_cmp, NULL);
	return true;
}

static int _rv_find_cmp (void *incoming, void *in, void *user) {
	EsilDFGRegVar *rv_incoming = (EsilDFGRegVar *)incoming;
	EsilDFGRegVar *rv_in = (EsilDFGRegVar *)in;

	RzAnalEsilDFG *dfg = (RzAnalEsilDFG *)user;
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
		EsilDFGRegVar *rv = RZ_NEW (EsilDFGRegVar);
		if (!rv) {
			dfg->malloc_failed = true;
			return -1;
		}
		rv[0] = rv_incoming[0];
		rv->to = rv_in->from - 1;
		rz_queue_enqueue (dfg->todo, rv);
		// upper part
		rv = RZ_NEW (EsilDFGRegVar);
		if (!rv) {
			dfg->malloc_failed = true;
			return -1;
		}
		rv[0] = rv_incoming[0];
		rv->from = rv_in->to + 1;
		rz_queue_enqueue (dfg->todo, rv);
		return 0;
	}

	/*
	   =incoming=
	  =in=

	similar to the previous case, but this time only enqueue 1 half
	*/
	if (rv_in->from <= rv_incoming->from && rv_in->to < rv_incoming->to) {
		EsilDFGRegVar *rv = RZ_NEW (EsilDFGRegVar);
		if (!rv) {
			dfg->malloc_failed = true;
			return -1;
		}
		rv[0] = rv_incoming[0];
		rv->from = rv_in->to + 1;
		rz_queue_enqueue (dfg->todo, rv);
		return 0;
	}

	/*
	   =incoming=
	          =in=
	*/
	EsilDFGRegVar *rv = RZ_NEW (EsilDFGRegVar);
	if (!rv) {
		dfg->malloc_failed = true;
		return -1;
	}
	rv[0] = rv_incoming[0];
	rv->to = rv_in->from - 1;
	rz_queue_enqueue (dfg->todo, rv);
	return 0;
}

static RzGraphNode *_edf_origin_reg_get(RzAnalEsilDFG *dfg, const char *reg) {
	rz_return_val_if_fail (dfg && reg, NULL);
	const ut32 _reg_strlen = 4 + strlen (reg);
	char *_reg = RZ_NEWS0 (char, _reg_strlen + 1);
	if (!_reg) {
		return NULL;
	}
	strncat (_reg, "reg.", _reg_strlen);
	strncat (_reg, reg, _reg_strlen);
	if (!sdb_num_exists (dfg->regs, _reg)) {
		free (_reg);
		return NULL;
	}
	free (_reg);
	const ut32 origin_reg_strlen = 4 + strlen (reg);
	char *origin_reg = RZ_NEWS0 (char, origin_reg_strlen + 1);
	if (!origin_reg) {
		return NULL;
	}
	strncat (origin_reg, "ori.", origin_reg_strlen);
	strncat (origin_reg, reg, origin_reg_strlen);
	RzGraphNode *origin_reg_node = sdb_ptr_get (dfg->regs, origin_reg, 0);
	if (origin_reg_node) {
		free (origin_reg);
		return origin_reg_node;
	}
	RzGraphNode *reg_node = rz_graph_add_node (dfg->flow, rz_anal_esil_dfg_node_new (dfg, reg));
	RzAnalEsilDFGNode *_origin_reg_node = rz_anal_esil_dfg_node_new (dfg, reg);
	rz_strbuf_appendf (_origin_reg_node->content, ":var_%d", dfg->idx++);
	_origin_reg_node->type = RZ_ANAL_ESIL_DFG_BLOCK_VAR;
	origin_reg_node = rz_graph_add_node (dfg->flow, _origin_reg_node);
	rz_graph_add_edge (dfg->flow, reg_node, origin_reg_node);
	sdb_ptr_set (dfg->regs, origin_reg, origin_reg_node, 0);
	free (origin_reg);
	return origin_reg_node;
}


static RzGraphNode *_edf_reg_get(RzAnalEsilDFG *dfg, const char *reg) {
	rz_return_val_if_fail (dfg && reg, NULL);
	const ut32 _reg_strlen = 4 + strlen (reg);
	char *_reg = RZ_NEWS0 (char, _reg_strlen + 1);
	if (!_reg) {
		return NULL;
	}
	strncat (_reg, "reg.", _reg_strlen);
	strncat (_reg, reg, _reg_strlen);
	if (!sdb_num_exists (dfg->regs, _reg)) {
		free (_reg);
		return NULL;
	}
	EsilDFGRegVar *rv = RZ_NEW0 (EsilDFGRegVar);
	if (!rv) {
		free (_reg);
		return NULL;
	}
	const ut64 v = sdb_num_get (dfg->regs, _reg, NULL);
	free (_reg);
	rv->from = (v & (UT64_MAX ^ UT32_MAX)) >> 32;
	rv->to = v & UT32_MAX;
	RQueue *parts = rz_queue_new (8);
	if (!parts) {
		free (rv);
		return NULL;
	}
	rz_queue_enqueue (dfg->todo, rv);

	// log2((search_rv.to + 1) - search_rv.from) maybe better?
	// wat du if this fails?

	RzGraphNode *reg_node = NULL;
	while (!rz_queue_is_empty (dfg->todo)) {
		rv = rz_queue_dequeue (dfg->todo);
		EsilDFGRegVar *part_rv = rz_rbtree_cont_find (dfg->reg_vars, rv, _rv_find_cmp, dfg);
		if (part_rv) {
			rz_queue_enqueue (parts, part_rv->node);
		} else if (!reg_node) {
			reg_node = _edf_origin_reg_get (dfg, reg);
			//insert in the gap
			part_rv = RZ_NEW (EsilDFGRegVar);
			if (!part_rv) {
				RZ_FREE (rv);
				dfg->malloc_failed = true;
				break;
			}
			part_rv[0] = rv[0];
			part_rv->node = reg_node;
			rz_rbtree_cont_insert (dfg->reg_vars, part_rv, _rv_ins_cmp, NULL);
			//enqueue for later merge
			rz_queue_enqueue (parts, reg_node);
		} else {
			//initial regnode was already created
			//only need to insert in the tree
			part_rv = RZ_NEW (EsilDFGRegVar);
			if (!part_rv) {
				RZ_FREE (part_rv);
				dfg->malloc_failed = true;
				break;
			}
			part_rv[0] = rv[0];
			part_rv->node = reg_node;
			rz_rbtree_cont_insert (dfg->reg_vars, part_rv, _rv_ins_cmp, NULL);
		}
		free (rv);
	}
	reg_node = NULL;	// is this needed?
	if (dfg->malloc_failed) {
		while (!rz_queue_is_empty(dfg->todo)) {
			free (rz_queue_dequeue (dfg->todo));
			goto beach;
		}
	}
	switch (parts->size) {
	case 0:
		break;
	case 1:
		reg_node = rz_queue_dequeue (parts);
		break;
	default:
		{
			RzAnalEsilDFGNode *_reg_node = rz_anal_esil_dfg_node_new (dfg, "merge to ");
			if (!_reg_node) {
				while (!rz_queue_is_empty (dfg->todo)) {
					free (rz_queue_dequeue (dfg->todo));
				}
				dfg->malloc_failed = true;
				goto beach;
			}

			rz_strbuf_appendf (_reg_node->content, "%s:var_%d", reg, dfg->idx++);
			reg_node = rz_graph_add_node (dfg->flow, _reg_node);
			if (!reg_node) {
				_dfg_node_free (_reg_node);
				while (!rz_queue_is_empty (dfg->todo)) {
					free (rz_queue_dequeue (dfg->todo));
				}
				dfg->malloc_failed = true;
				goto beach;
			}
		}
		do {
			rz_graph_add_edge (dfg->flow, rz_queue_dequeue(parts), reg_node);
		} while (!rz_queue_is_empty (parts));
		break;
	}
beach:
	rz_queue_free (parts);
	return reg_node;
}


static bool _edf_var_set (RzAnalEsilDFG *dfg, const char *var, RzGraphNode *node) {
	rz_return_val_if_fail (dfg && var, false);
	const ut32 _var_strlen = 4 + strlen (var);
	char *_var = RZ_NEWS0 (char, _var_strlen + 1);
	if (!_var) {
		return false;
	}
	strncat (_var, "var.", _var_strlen);
	strncat (_var, var, _var_strlen);
	const bool ret = !sdb_ptr_set (dfg->regs, _var, node, 0);
	free (_var);
	return ret;
}


static RzGraphNode *_edf_var_get (RzAnalEsilDFG *dfg, const char *var) {
	rz_return_val_if_fail (dfg && var, NULL);
	const ut32 _var_strlen = 4 + strlen (var);
	char *_var = RZ_NEWS0 (char, _var_strlen + 1);
	if (!_var) {
		return NULL;
	}
	strncat (_var, "var.", _var_strlen);
	strncat (_var, var, _var_strlen);
	RzGraphNode *ret = sdb_ptr_get (dfg->regs, _var, NULL);
	free (_var);
	return ret;
}

static bool edf_consume_2_set_reg(RzAnalEsil *esil);
static bool edf_consume_2_push_1(RzAnalEsil *esil);
static bool edf_consume_1_push_1(RzAnalEsil *esil);
typedef void (*AddConstraintStringUseNewCB) (RzStrBuf *result, const char *new_node_str);
static bool edf_use_new_push_1(RzAnalEsil *esil, const char *op_string, AddConstraintStringUseNewCB cb);
typedef void (*AddConstraintStringConsume1UseOldNewCB) (RzStrBuf *result, const char *consume_str, const char *old_node_str, const char *new_node_str);
static bool edf_consume_1_use_old_new_push_1(RzAnalEsil *esil, const char *op_string, AddConstraintStringConsume1UseOldNewCB cb);

static bool edf_eq_weak(RzAnalEsil *esil) {
	RzAnalEsilDFG *edf = (RzAnalEsilDFG *)esil->user;
	RzGraphNode *o_old = edf->old; //node for esil->old
	RzGraphNode *o_new = edf->cur; //node for esil->cur
	if (!edf_consume_2_set_reg (esil)) {
		return false;
	}
	//work-around
	edf->old = o_old ? o_old : NULL;
	edf->cur = o_new ? o_new : NULL;
	return true;
}

static void edf_zf_constraint(RzStrBuf *result, const char *new_node_str) {
	rz_strbuf_appendf (result, ":(%s==0)", new_node_str);
}

static bool edf_zf(RzAnalEsil *esil) {
	return edf_use_new_push_1 (esil, "$z", edf_zf_constraint);
}

static void edf_pf_constraint(RzStrBuf *result, const char *new_node_str) {
	rz_strbuf_appendf (result, ":parity_of(%s)", new_node_str);
}

static bool edf_pf(RzAnalEsil *esil) {
	return edf_use_new_push_1 (esil, "$p", edf_pf_constraint);
}

static void edf_cf_constraint(RzStrBuf *result, const char *consume, const char *o, const char *n) {
	rz_strbuf_appendf (result, ":((%s&mask(%s&0x3f))<(%s&mask(%s&0x3f)))",
		n, consume, o, consume);
}

static bool edf_cf(RzAnalEsil *esil) {
	return edf_consume_1_use_old_new_push_1 (esil, "$c", edf_cf_constraint);
}

static void edf_bf_constraint(RzStrBuf *result, const char *consume, const char *o, const char *n) {
	rz_strbuf_appendf (result, ":((%s&mask((%s+0x3f)&0x3f))<(%s& mask((%s+0x3f)&0x3f)))",
		o, consume, n, consume);
}

static bool edf_bf(RzAnalEsil *esil) {
	return edf_consume_1_use_old_new_push_1 (esil, "$b", edf_bf_constraint);
}

static bool _edf_consume_2_set_reg(RzAnalEsil *esil, const bool use_origin) {
	const char *op_string = esil->current_opstr;
	RzAnalEsilDFG *edf = (RzAnalEsilDFG *)esil->user;
	char *dst = rz_anal_esil_pop (esil);
	char *src = rz_anal_esil_pop (esil);

	if (!src || !dst) {
		free (dst);
		free (src);
		return false;
	}

	int dst_type = rz_anal_esil_get_parm_type (esil, dst);
	if (dst_type == RZ_ANAL_ESIL_PARM_INVALID) {
		free (dst);
		free (src);
		return false;
	}

	const int src_type = rz_anal_esil_get_parm_type (esil, src);
	RzGraphNode *src_node = NULL;
	if (src_type == RZ_ANAL_ESIL_PARM_REG) {
		src_node = _edf_reg_get (edf, src);
	} else if (src_type == RZ_ANAL_ESIL_PARM_NUM) {
		RzGraphNode *n_value = rz_graph_add_node (edf->flow, rz_anal_esil_dfg_node_new (edf, src));
		RzAnalEsilDFGNode *ec_node = rz_anal_esil_dfg_node_new (edf, src);
		ec_node->type = RZ_ANAL_ESIL_DFG_BLOCK_CONST;
		rz_strbuf_appendf (ec_node->content, ":const_%d", edf->idx++);
		src_node = rz_graph_add_node (edf->flow, ec_node);
		rz_graph_add_edge (edf->flow, n_value, src_node);
	} else {
		src_node = _edf_var_get (edf, src);
	}

	RzGraphNode *dst_node = use_origin ? _edf_origin_reg_get (edf, dst) : _edf_reg_get (edf, dst);
	RzGraphNode *old_dst_node = dst_node;

	if (!src_node || !dst_node) {
		free (src);
		free (dst);
		return false;
	}

	RzAnalEsilDFGNode *eop_node = rz_anal_esil_dfg_node_new (edf, src);
	rz_strbuf_appendf (eop_node->content, ",%s,%s", dst, op_string);
	eop_node->type = RZ_ANAL_ESIL_DFG_BLOCK_GENERATIVE;
	free (src);

	RzGraphNode *op_node = rz_graph_add_node (edf->flow, eop_node);
	rz_graph_add_edge (edf->flow, dst_node, op_node);
	rz_graph_add_edge (edf->flow, src_node, op_node);
	edf->old = old_dst_node;
	RzAnalEsilDFGNode *result = rz_anal_esil_dfg_node_new (edf, dst);
	result->type = RZ_ANAL_ESIL_DFG_BLOCK_RESULT | RZ_ANAL_ESIL_DFG_BLOCK_VAR;

	rz_strbuf_appendf (result->content, ":var_%d", edf->idx++);
	dst_node = rz_graph_add_node (edf->flow, result);
	rz_graph_add_edge (edf->flow, op_node, dst_node);
	_edf_reg_set (edf, dst, dst_node);
	edf->cur = dst_node;
	free (dst);
	return true;
}

static bool edf_consume_2_use_set_reg(RzAnalEsil *esil) {
	return _edf_consume_2_set_reg (esil, false);
}

static bool edf_consume_2_set_reg(RzAnalEsil *esil) {
	return _edf_consume_2_set_reg (esil, true);
}

static bool edf_consume_2_push_1(RzAnalEsil *esil) {
	const char *op_string = esil->current_opstr;
	RzAnalEsilDFG *edf = (RzAnalEsilDFG *)esil->user;
	char *src[2] = { rz_anal_esil_pop (esil), rz_anal_esil_pop (esil) };

	if (!src[0] || !src[1]) {
		free (src[0]);
		free (src[1]);
		return false;
	}
	RzAnalEsilDFGNode *eop_node = rz_anal_esil_dfg_node_new (edf, src[1]);
	rz_strbuf_appendf (eop_node->content, ",%s,%s", src[0], op_string);
	eop_node->type = RZ_ANAL_ESIL_DFG_BLOCK_RESULT | RZ_ANAL_ESIL_DFG_BLOCK_GENERATIVE;
	RzGraphNode *op_node = rz_graph_add_node (edf->flow, eop_node);
	RzGraphNode *src_node[2];
	ut32 i;
	for (i = 0; i < 2; i++) {
		const int src_type = rz_anal_esil_get_parm_type (esil, src[i]);
		if (src_type == RZ_ANAL_ESIL_PARM_REG) {
			src_node[i] = _edf_reg_get (edf, src[i]);
		} else if (src_type == RZ_ANAL_ESIL_PARM_NUM) {
			RzGraphNode *n_value = rz_graph_add_node (edf->flow, rz_anal_esil_dfg_node_new (edf, src[i]));
			RzAnalEsilDFGNode *ec_node = rz_anal_esil_dfg_node_new (edf, src[i]);
			ec_node->type = RZ_ANAL_ESIL_DFG_BLOCK_CONST;
			rz_strbuf_appendf (ec_node->content, ":const_%d", edf->idx++);
			src_node[i] = rz_graph_add_node (edf->flow, ec_node);
			rz_graph_add_edge (edf->flow, n_value, src_node[i]);
		} else {
			src_node[i] = _edf_var_get (edf, src[i]);
		}
		rz_graph_add_edge (edf->flow, src_node[i], op_node);
	}

	free (src[0]);
	free (src[1]);

	RzAnalEsilDFGNode *result = rz_anal_esil_dfg_node_new (edf, "result_");
	result->type = RZ_ANAL_ESIL_DFG_BLOCK_RESULT;
	rz_strbuf_appendf (result->content, "%d", edf->idx++);
	RzGraphNode *result_node = rz_graph_add_node (edf->flow, result);
	rz_graph_add_edge (edf->flow, op_node, result_node);
	_edf_var_set (edf, rz_strbuf_get (result->content), result_node);
	rz_anal_esil_push (esil, rz_strbuf_get (result->content));
	return true;
}

static bool edf_consume_1_push_1(RzAnalEsil *esil) {
	const char *op_string = esil->current_opstr;
	RzAnalEsilDFG *edf = (RzAnalEsilDFG *)esil->user;
	char *src = rz_anal_esil_pop (esil);
	if (!src) {
		return false;
	}
	RzAnalEsilDFGNode *eop_node = rz_anal_esil_dfg_node_new (edf, src);
	rz_strbuf_appendf (eop_node->content, ",%s", op_string);
	eop_node->type = RZ_ANAL_ESIL_DFG_BLOCK_RESULT | RZ_ANAL_ESIL_DFG_BLOCK_GENERATIVE;
	RzGraphNode *op_node = rz_graph_add_node (edf->flow, eop_node);
	const int src_type = rz_anal_esil_get_parm_type (esil, src);
	RzGraphNode *src_node = NULL;
	if (src_type == RZ_ANAL_ESIL_PARM_REG) {
		src_node = _edf_reg_get (edf, src);
	} else if (src_type == RZ_ANAL_ESIL_PARM_NUM) {
		RzGraphNode *n_value = rz_graph_add_node (edf->flow, rz_anal_esil_dfg_node_new (edf, src));
		RzAnalEsilDFGNode *ec_node = rz_anal_esil_dfg_node_new (edf, src);
		ec_node->type = RZ_ANAL_ESIL_DFG_BLOCK_CONST;
		rz_strbuf_appendf (ec_node->content, ":const_%d", edf->idx++);
		src_node = rz_graph_add_node (edf->flow, ec_node);
		rz_graph_add_edge (edf->flow, n_value, src_node);
	} else {
		src_node = _edf_var_get (edf, src);
	}

	free (src);

	rz_graph_add_edge (edf->flow, src_node, op_node);

	RzAnalEsilDFGNode *result = rz_anal_esil_dfg_node_new (edf, "result_");
	result->type = RZ_ANAL_ESIL_DFG_BLOCK_RESULT; //TODO: propgate type from src here
	rz_strbuf_appendf (result->content, "%d", edf->idx++);
	RzGraphNode *result_node = rz_graph_add_node (edf->flow, result);
	rz_graph_add_edge (edf->flow, op_node, result_node);
	_edf_var_set (edf, rz_strbuf_get (result->content), result_node);
	rz_anal_esil_push (esil, rz_strbuf_get (result->content));
	return true;
}

static bool edf_consume_2_set_mem(RzAnalEsil *esil) {
	const char *op_string = esil->current_opstr;
	RzAnalEsilDFG *edf = (RzAnalEsilDFG *)esil->user;
	char *dst = rz_anal_esil_pop (esil);
	char *src = rz_anal_esil_pop (esil);

	if (!src || !dst) {
		free (dst);
		free (src);
		return 0;
	}

	int dst_type = rz_anal_esil_get_parm_type (esil, dst);

	const int src_type = rz_anal_esil_get_parm_type (esil, src);
	RzGraphNode *src_node = NULL;
	if (src_type == RZ_ANAL_ESIL_PARM_REG) {
		src_node = _edf_reg_get (edf, src);
	} else if (src_type == RZ_ANAL_ESIL_PARM_NUM) {
		RzGraphNode *n_value = rz_graph_add_node (edf->flow, rz_anal_esil_dfg_node_new (edf, src));
		RzAnalEsilDFGNode *ec_node = rz_anal_esil_dfg_node_new (edf, src);
		ec_node->type = RZ_ANAL_ESIL_DFG_BLOCK_CONST;
		rz_strbuf_appendf (ec_node->content, ":const_%d", edf->idx++);
		src_node = rz_graph_add_node (edf->flow, ec_node);
		rz_graph_add_edge (edf->flow, n_value, src_node);
	} else {
		src_node = _edf_var_get (edf, src);
	}

	RzGraphNode *dst_node = _edf_reg_get (edf, dst);
	if (!dst_node) {
		dst_node = _edf_var_get (edf, dst);
	}
//probably dead code
	if (!dst_node) {
		if (dst_type == RZ_ANAL_ESIL_PARM_REG) {
			RzGraphNode *n_reg = rz_graph_add_node (edf->flow, rz_anal_esil_dfg_node_new (edf, dst));
			RzAnalEsilDFGNode *ev_node = rz_anal_esil_dfg_node_new (edf, dst);
			ev_node->type = RZ_ANAL_ESIL_DFG_BLOCK_VAR | RZ_ANAL_ESIL_DFG_BLOCK_PTR;
			rz_strbuf_appendf (ev_node->content, ":var_ptr_%d", edf->idx++);
			dst_node = rz_graph_add_node (edf->flow, ev_node);
			//			_edf_reg_set (edf, dst, ev_node);
			rz_graph_add_edge (edf->flow, n_reg, dst_node);
		}
		// TODO: const pointers
	}

	if (!src_node || !dst_node) {
		free (src);
		free (dst);
		return false;
	}

	RzAnalEsilDFGNode *eop_node = rz_anal_esil_dfg_node_new (edf, src);
	rz_strbuf_appendf (eop_node->content, ",%s,%s", dst, op_string);
	eop_node->type = RZ_ANAL_ESIL_DFG_BLOCK_GENERATIVE;
	free (src);

	RzGraphNode *op_node = rz_graph_add_node (edf->flow, eop_node);
	rz_graph_add_edge (edf->flow, dst_node, op_node);
	rz_graph_add_edge (edf->flow, src_node, op_node);
	RzAnalEsilDFGNode *result = rz_anal_esil_dfg_node_new (edf, dst);
	//	result->type = RZ_ANAL_ESIL_DFG_BLOCK_RESULT | RZ_ANAL_ESIL_DFG_BLOCK_GENERATIVE;
	result->type = RZ_ANAL_ESIL_DFG_BLOCK_VAR;
	rz_strbuf_appendf (result->content, ":var_mem_%d", edf->idx++);
	dst_node = rz_graph_add_node (edf->flow, result);
	rz_graph_add_edge (edf->flow, op_node, dst_node);
	free (dst);
	return true;
}

static bool edf_use_new_push_1(RzAnalEsil *esil, const char *op_string, AddConstraintStringUseNewCB cb) {
	RzAnalEsilDFG *edf = (RzAnalEsilDFG *)esil->user;
	RzGraphNode *op_node = rz_graph_add_node (edf->flow, rz_anal_esil_dfg_node_new (edf, op_string));
	RzGraphNode *latest_new = edf->cur;
	if (!latest_new) {
		return 0;
	}
	RzAnalEsilDFGNode *result = rz_anal_esil_dfg_node_new (edf, "result_");
	result->type = RZ_ANAL_ESIL_DFG_BLOCK_RESULT; // is this generative?
	rz_strbuf_appendf (result->content, "%d", edf->idx++);
	if (cb) {
		RzAnalEsilDFGNode *e_new_node = (RzAnalEsilDFGNode *)latest_new->data;
		cb (result->content, rz_strbuf_get (e_new_node->content));
	}
	RzGraphNode *result_node = rz_graph_add_node (edf->flow, result);
	_edf_var_set (edf, rz_strbuf_get (result->content), result_node);
	rz_graph_add_edge (edf->flow, latest_new, op_node);
	rz_graph_add_edge (edf->flow, op_node, result_node);
	return rz_anal_esil_push (esil, rz_strbuf_get (result->content));
}

static bool edf_consume_1_use_old_new_push_1(RzAnalEsil *esil, const char *op_string, AddConstraintStringConsume1UseOldNewCB cb) {
	RzAnalEsilDFG *edf = (RzAnalEsilDFG *)esil->user;
	char *src = rz_anal_esil_pop (esil);

	if (!src) {
		return false;
	}
	RzAnalEsilDFGNode *eop_node = rz_anal_esil_dfg_node_new (edf, src);
#if 0
	eop_node->type = RZ_ANAL_ESIL_DFG_BLOCK_GENERATIVE;
#endif
	rz_strbuf_appendf (eop_node->content, ",%s", op_string);
	RzGraphNode *op_node = rz_graph_add_node (edf->flow, eop_node);
	const int src_type = rz_anal_esil_get_parm_type (esil, src);
	RzGraphNode *src_node = NULL;
	if (src_type == RZ_ANAL_ESIL_PARM_REG) {
		src_node = _edf_reg_get (edf, src);
	} else if (src_type == RZ_ANAL_ESIL_PARM_NUM) {
		RzGraphNode *n_value = rz_graph_add_node (edf->flow, rz_anal_esil_dfg_node_new (edf, src));
		RzAnalEsilDFGNode *ec_node = rz_anal_esil_dfg_node_new (edf, src);
		ec_node->type = RZ_ANAL_ESIL_DFG_BLOCK_CONST;
		rz_strbuf_appendf (ec_node->content, ":const_%d", edf->idx++);
		src_node = rz_graph_add_node (edf->flow, ec_node);
		rz_graph_add_edge (edf->flow, n_value, src_node);
	} else {
		src_node = _edf_var_get (edf, src);
	}
	free (src);

	rz_graph_add_edge (edf->flow, src_node, op_node);

	RzGraphNode *latest_new = edf->cur;
	RzGraphNode *latest_old = edf->old;
	RzAnalEsilDFGNode *result = rz_anal_esil_dfg_node_new (edf, "result_");
	result->type = RZ_ANAL_ESIL_DFG_BLOCK_RESULT; // propagate type here
	rz_strbuf_appendf (result->content, "%d", edf->idx++);
	if (cb) {
		RzAnalEsilDFGNode *e_src_node = (RzAnalEsilDFGNode *)src_node->data;
		RzAnalEsilDFGNode *e_new_node = (RzAnalEsilDFGNode *)latest_new->data;
		RzAnalEsilDFGNode *e_old_node = (RzAnalEsilDFGNode *)latest_old->data;
		cb (result->content, rz_strbuf_get (e_src_node->content),
			rz_strbuf_get (e_new_node->content), rz_strbuf_get (e_old_node->content));
	}
	RzGraphNode *result_node = rz_graph_add_node (edf->flow, result);
	_edf_var_set (edf, rz_strbuf_get (result->content), result_node);
	rz_graph_add_edge (edf->flow, latest_new, op_node);
	rz_graph_add_edge (edf->flow, latest_old, op_node);
	rz_graph_add_edge (edf->flow, op_node, result_node);
	return rz_anal_esil_push (esil, rz_strbuf_get (result->content));
}

RZ_API RzAnalEsilDFG *rz_anal_esil_dfg_new(RzReg *regs) {
	if (!regs) {
		return NULL;
	}
	RzAnalEsilDFG *dfg = RZ_NEW0 (RzAnalEsilDFG);
	if (!dfg) {
		return NULL;
	}
	dfg->flow = rz_graph_new ();
	if (!dfg->flow) {
		free (dfg);
		return NULL;
	}
	dfg->regs = sdb_new0 ();
	if (!dfg->regs) {
		rz_graph_free (dfg->flow);
		free (dfg);
		return NULL;
	}
	// rax, eax, ax, ah, al	=> 8 should be enough
	dfg->todo = rz_queue_new (8);
	if (!dfg->todo) {
		sdb_free (dfg->regs);
		rz_graph_free (dfg->flow);
		free (dfg);
		return NULL;
	}
	dfg->reg_vars = rz_rbtree_cont_newf (free);
	if (!dfg->reg_vars) {
		rz_queue_free (dfg->todo);
		sdb_free (dfg->regs);
		rz_graph_free (dfg->flow);
		free (dfg);
		return NULL;
	}

// this is not exactly necessary
// could use RzReg-API directly in the dfg gen,
// but sdb as transition table is probably faster
	RzRegItem *ri;
	RzListIter *ator;
	rz_list_foreach (regs->allregs, ator, ri) {
		const ut32 from = ri->offset;
		const ut32 to = from + ri->size - 1;	// closed intervals because of FUCK YOU
		const ut64 v = to | (((ut64)from) << 32);
		const ut32 reg_strlen = 4 + strlen (ri->name) + 1;
		char *reg = RZ_NEWS0 (char, reg_strlen);
		strncat (reg, "reg.", reg_strlen);
		strncat (reg, ri->name, reg_strlen);
		sdb_num_set (dfg->regs, reg, v, 0);
		free (reg);
	}
	return dfg;
}

RZ_API void rz_anal_esil_dfg_free(RzAnalEsilDFG *dfg) {
	if (dfg) {
		if (dfg->flow) {
			RzGraphNode *n;
			RzListIter *iter;
			rz_list_foreach (rz_graph_get_nodes (dfg->flow), iter, n) {
				n->free = (RzListFree)_dfg_node_free;
			}
			rz_graph_free (dfg->flow);
		}
		sdb_free (dfg->regs);
		rz_rbtree_cont_free (dfg->reg_vars);
		rz_queue_free (dfg->todo);
		free (dfg);
	}
}

RZ_API RzAnalEsilDFG *rz_anal_esil_dfg_expr(RzAnal *anal, RzAnalEsilDFG *dfg, const char *expr) {
	if (!expr) {
		return NULL;
	}
	RzAnalEsil *esil = rz_anal_esil_new (4096, 0, 1);
	if (!esil) {
		return NULL;
	}
	esil->anal = anal;

	RzAnalEsilDFG *edf = dfg ? dfg : rz_anal_esil_dfg_new (anal->reg);
	if (!edf) {
		rz_anal_esil_free (esil);
		return NULL;
	}

	rz_anal_esil_set_op (esil, "=", edf_consume_2_set_reg, 0, 2, RZ_ANAL_ESIL_OP_TYPE_REG_WRITE);
	rz_anal_esil_set_op (esil, ":=", edf_eq_weak, 0, 2, RZ_ANAL_ESIL_OP_TYPE_REG_WRITE);
	rz_anal_esil_set_op (esil, "$z", edf_zf, 1, 0, RZ_ANAL_ESIL_OP_TYPE_UNKNOWN);
	rz_anal_esil_set_op (esil, "$p", edf_pf, 1, 0, RZ_ANAL_ESIL_OP_TYPE_UNKNOWN);
	rz_anal_esil_set_op (esil, "$c", edf_cf, 1, 1, RZ_ANAL_ESIL_OP_TYPE_UNKNOWN);
	rz_anal_esil_set_op (esil, "$b", edf_bf, 1, 1, RZ_ANAL_ESIL_OP_TYPE_UNKNOWN);
	rz_anal_esil_set_op (esil, "^=", edf_consume_2_use_set_reg, 0, 2, RZ_ANAL_ESIL_OP_TYPE_MATH | RZ_ANAL_ESIL_OP_TYPE_REG_WRITE);
	rz_anal_esil_set_op (esil, "-=", edf_consume_2_use_set_reg, 0, 2, RZ_ANAL_ESIL_OP_TYPE_MATH | RZ_ANAL_ESIL_OP_TYPE_REG_WRITE);
	rz_anal_esil_set_op (esil, "+=", edf_consume_2_use_set_reg, 0, 2, RZ_ANAL_ESIL_OP_TYPE_MATH | RZ_ANAL_ESIL_OP_TYPE_REG_WRITE);
	rz_anal_esil_set_op (esil, "*=", edf_consume_2_use_set_reg, 0, 2, RZ_ANAL_ESIL_OP_TYPE_MATH | RZ_ANAL_ESIL_OP_TYPE_REG_WRITE);
	rz_anal_esil_set_op (esil, "/=", edf_consume_2_use_set_reg, 0, 2, RZ_ANAL_ESIL_OP_TYPE_MATH | RZ_ANAL_ESIL_OP_TYPE_REG_WRITE);
	rz_anal_esil_set_op (esil, "&=", edf_consume_2_use_set_reg, 0, 2, RZ_ANAL_ESIL_OP_TYPE_MATH | RZ_ANAL_ESIL_OP_TYPE_REG_WRITE);
	rz_anal_esil_set_op (esil, "|=", edf_consume_2_use_set_reg, 0, 2, RZ_ANAL_ESIL_OP_TYPE_MATH | RZ_ANAL_ESIL_OP_TYPE_REG_WRITE);
	rz_anal_esil_set_op (esil, "^=", edf_consume_2_use_set_reg, 0, 2, RZ_ANAL_ESIL_OP_TYPE_MATH | RZ_ANAL_ESIL_OP_TYPE_REG_WRITE);
	rz_anal_esil_set_op (esil, "+", edf_consume_2_push_1, 1, 2, RZ_ANAL_ESIL_OP_TYPE_MATH);
	rz_anal_esil_set_op (esil, "-", edf_consume_2_push_1, 1, 2, RZ_ANAL_ESIL_OP_TYPE_MATH);
	rz_anal_esil_set_op (esil, "&", edf_consume_2_push_1, 1, 2, RZ_ANAL_ESIL_OP_TYPE_MATH);
	rz_anal_esil_set_op (esil, "|", edf_consume_2_push_1, 1, 2, RZ_ANAL_ESIL_OP_TYPE_MATH);
	rz_anal_esil_set_op (esil, "^", edf_consume_2_push_1, 1, 2, RZ_ANAL_ESIL_OP_TYPE_MATH);
	rz_anal_esil_set_op (esil, "%", edf_consume_2_push_1, 1, 2, RZ_ANAL_ESIL_OP_TYPE_MATH);
	rz_anal_esil_set_op (esil, "*", edf_consume_2_push_1, 1, 2, RZ_ANAL_ESIL_OP_TYPE_MATH);
	rz_anal_esil_set_op (esil, "/", edf_consume_2_push_1, 1, 2, RZ_ANAL_ESIL_OP_TYPE_MATH);
	rz_anal_esil_set_op (esil, ">>", edf_consume_2_push_1, 1, 2, RZ_ANAL_ESIL_OP_TYPE_MATH);
	rz_anal_esil_set_op (esil, "<<", edf_consume_2_push_1, 1, 2, RZ_ANAL_ESIL_OP_TYPE_MATH);
	rz_anal_esil_set_op (esil, ">>>", edf_consume_2_push_1, 1, 2, RZ_ANAL_ESIL_OP_TYPE_MATH);
	rz_anal_esil_set_op (esil, ">>>", edf_consume_2_push_1, 1, 2, RZ_ANAL_ESIL_OP_TYPE_MATH);
	rz_anal_esil_set_op (esil, "!", edf_consume_1_push_1, 1, 1, RZ_ANAL_ESIL_OP_TYPE_MATH);
	rz_anal_esil_set_op (esil, "[1]", edf_consume_1_push_1, 1, 1, RZ_ANAL_ESIL_OP_TYPE_MEM_READ);
	rz_anal_esil_set_op (esil, "[2]", edf_consume_1_push_1, 1, 1, RZ_ANAL_ESIL_OP_TYPE_MEM_READ);
	rz_anal_esil_set_op (esil, "[4]", edf_consume_1_push_1, 1, 1, RZ_ANAL_ESIL_OP_TYPE_MEM_READ);
	rz_anal_esil_set_op (esil, "[8]", edf_consume_1_push_1, 1, 1, RZ_ANAL_ESIL_OP_TYPE_MEM_READ);
	rz_anal_esil_set_op (esil, "[16]", edf_consume_1_push_1, 1, 1, RZ_ANAL_ESIL_OP_TYPE_MEM_READ);
	rz_anal_esil_set_op (esil, "=[1]", edf_consume_2_set_mem, 0, 2, RZ_ANAL_ESIL_OP_TYPE_MEM_WRITE);
	rz_anal_esil_set_op (esil, "=[2]", edf_consume_2_set_mem, 0, 2, RZ_ANAL_ESIL_OP_TYPE_MEM_WRITE);
	rz_anal_esil_set_op (esil, "=[4]", edf_consume_2_set_mem, 0, 2, RZ_ANAL_ESIL_OP_TYPE_MEM_WRITE);
	rz_anal_esil_set_op (esil, "=[8]", edf_consume_2_set_mem, 0, 2, RZ_ANAL_ESIL_OP_TYPE_MEM_WRITE);

	esil->user = edf;

	rz_anal_esil_parse (esil, expr);
	rz_anal_esil_free (esil);
	return edf;
}

static int _dfg_node_filter_insert_cmp(void *incoming, void *in, void *user) {
	RzAnalEsilDFGNode *incoming_node = (RzAnalEsilDFGNode *)incoming;
	RzAnalEsilDFGNode *in_node = (RzAnalEsilDFGNode *)in;
	return incoming_node->idx - in_node->idx;
}

static void _dfg_rev_dfs_cb(RzGraphNode *n, RzGraphVisitor *vi) {
	RzAnalEsilDFGNode *node = (RzAnalEsilDFGNode *)n->data;
	RzAnalEsilDFGFilter *filter = (RzAnalEsilDFGFilter *)vi->data;
	switch (node->type) {
	case RZ_ANAL_ESIL_DFG_BLOCK_CONST:
	case RZ_ANAL_ESIL_DFG_BLOCK_VAR:
	case RZ_ANAL_ESIL_DFG_BLOCK_PTR:
		break;
	case RZ_ANAL_ESIL_DFG_BLOCK_GENERATIVE:
		rz_rbtree_cont_insert (filter->tree, node, _dfg_node_filter_insert_cmp, NULL);
		break;
	case RZ_ANAL_ESIL_DFG_BLOCK_RESULT: // outnode must be result generator here
	{
		RzGraphNode *previous = (RzGraphNode *)rz_list_get_top (n->in_nodes);
		if (previous) {
			sdb_ptr_set (filter->results, rz_strbuf_get (node->content), previous, 0);
		}
	} break;
	}
}

static char *condrets_strtok(char *str, const char tok) {
	if (!str) {
		return NULL;
	}
	ut32 i = 0;
	while (1 == 1) {
		if (!str[i]) {
			break;
		}
		if (str[i] == tok) {
			str[i] = '\0';
			return &str[i + 1];
		}
		i++;
	}
	return NULL;
}

static RzStrBuf *get_resolved_expr(RzAnalEsilDFGFilter *filter, RzAnalEsilDFGNode *node) {
	char *expr = strdup (rz_strbuf_get (node->content));
	RzStrBuf *res = rz_strbuf_new ("");
	if (!expr) { //empty expressions. can this happen?
		return res;
	}
	char *p, *q;
	// we can do this bc every generative node MUST end with an operator
	for (p = expr; (q = condrets_strtok (p, ',')); p = q) {
		RzGraphNode *gn = sdb_ptr_get (filter->results, p, 0);
		if (!gn) {
			rz_strbuf_appendf (res, ",%s,", p);
		} else {
			RzStrBuf *r = get_resolved_expr (filter, (RzAnalEsilDFGNode *)gn->data);
			rz_strbuf_appendf (res, ",%s,", rz_strbuf_get (r));
			rz_strbuf_free (r);
		}
	}
	rz_strbuf_appendf (res, "%s", p);
	free (expr);
	return res;
}

RZ_API RzStrBuf *rz_anal_esil_dfg_filter(RzAnalEsilDFG *dfg, const char *reg) {
	if (!dfg || !reg) {
		return NULL;
	}
	RzGraphNode *resolve_me = _edf_reg_get (dfg, reg);
	if (!resolve_me) {
		return NULL;
	}

	// allocate stuff
	RzAnalEsilDFGFilter filter = { dfg, rz_rbtree_cont_new (), sdb_new0 () };
	RzStrBuf *filtered = rz_strbuf_new ("");
	RzGraphVisitor vi = { _dfg_rev_dfs_cb, NULL, NULL, NULL, NULL, &filter };

	// dfs the graph starting at node of esp-register
	rz_graph_dfs_node_reverse (dfg->flow, resolve_me, &vi);

	RBIter ator;
	RzAnalEsilDFGNode *node;
	rz_rbtree_cont_foreach (filter.tree, ator, node) {
		// resolve results to opstr here
		RzStrBuf *resolved = get_resolved_expr (&filter, node);
		rz_strbuf_append (filtered, rz_strbuf_get (resolved));
		rz_strbuf_free (resolved);
	}
	{
		char *sanitized = rz_str_replace (rz_str_replace (strdup (rz_strbuf_get (filtered)), ",,", ",", 1), ",,", ",", 1);
		rz_strbuf_set (filtered, (sanitized[0] == ',') ? &sanitized[1] : sanitized);
		free (sanitized);
	}
	rz_rbtree_cont_free (filter.tree);
	sdb_free (filter.results);
	return filtered;
}

RZ_API RzStrBuf *rz_anal_esil_dfg_filter_expr(RzAnal *anal, const char *expr, const char *reg) {
	if (!reg) {
		return NULL;
	}
	RzAnalEsilDFG *dfg = rz_anal_esil_dfg_expr (anal, NULL, expr);
	if (!dfg) {
		return NULL;
	}
	RzStrBuf *filtered = rz_anal_esil_dfg_filter (dfg, reg);
	rz_anal_esil_dfg_free (dfg);
	return filtered;
}
