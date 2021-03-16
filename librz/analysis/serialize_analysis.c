// SPDX-FileCopyrightText: 2020-2021 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_serialize.h>
#include <rz_analysis.h>

#include <errno.h>

/*
 *
 * SDB Format:
 *
 * /
 *   /blocks
 *     0x<addr>={size:<ut64>, jump?:<ut64>, fail?:<ut64>, traced?:true, colorize?:<ut32>,
 *               fingerprint?:"<base64>", diff?: <RzAnalysisDiff>, switch_op?:<RzAnalysisSwitchOp>,
 *               ninstr:<int>, op_pos?:[<ut16>], stackptr:<int>, parent_stackptr:<int>,
 *               cmpval:<ut64>, cmpreg?:<str>}
 *   /functions
 *     0x<addr>={name:<str>, bits?:<int>, type:<int>, cc?:<str>, stack:<int>, maxstack:<int>,
 *               ninstr:<int>, pure?:<bool>, bp_frame?:<bool>, bp_off?:<st64>, noreturn?:<bool>,
 *               fingerprint?:"<base64>", diff?:<RzAnalysisDiff>, bbs:[<ut64>], imports?:[<str>], vars?:[<RzAnalysisVar>],
 *               labels?: {<str>:<ut64>}}
 *   /xrefs
 *     0x<addr>=[{to:<ut64>, type?:"c"|"C"|"d"|"s"}]
 *
 *   /meta
 *     0x<addr>=[{size?:<ut64, interpreted as 1 if not present>, type:<str>, subtype?:<int>, str?:<str>, space?:<str>}]
 *     /spaces
 *       see spaces.c
 *
 *   /hints
 *     0x<addr>={arch?:<str|null>,bits?:<int|null>,toff?:<string>,nword?:<int>,jump?:<ut64>,fail?:<ut64>,newbits?:<int>,
 *               immbase?:<int>,ptr?:<ut64>,ret?:<ut64>,syntax?:<str>,opcode?:<str>,esil?:<str>,optype?:<int>,
 *               size?:<ut64>,frame?:<ut64>,val?:<ut64>,high?:<bool>}
 *   /classes
 *     <direct dump of RzAnalysis.sdb_classes>
 *     /attrs
 *       <direct dump of RzAnalysis.sdb_classes_attrs>
 *
 *   /zigns
 *     <direct dump of RzAnalysis.sdb_zigns>
 *     /spaces
 *       see spaces.c
 *
 *   /imports
 *     <str>=i
 *
 * RzAnalysisDiff JSON:
 * {type?:"m"|"u", addr:<ut64>, dist:<double>, name?:<str>, size:<ut32>}
 *
 * RzAnalysisSwitchOp JSON:
 * {addr:<ut64>, min:<ut64>, max:<ut64>, def:<ut64>, cases:[<RzAnalysisCaseOp>]}
 *
 * RzAnalysisCaseOp JSON:
 * {addr:<ut64>, jump:<ut64>, value:<ut64>}
 *
 * RzAnalysisVar JSON:
 * {name:<str>, type:<str>, kind:"s|b|r", arg?:<bool>, delta?:<st64>, reg?:<str>, cmt?:<str>,
 *   accs?: [{off:<st64>, type:"r|w|rw", reg:<str>, sp?:<st64>}], constrs?:[<int>,<ut64>,...]}
 *
 */

RZ_API void rz_serialize_analysis_diff_save(RZ_NONNULL PJ *j, RZ_NONNULL RzAnalysisDiff *diff) {
	pj_o(j);
	switch (diff->type) {
	case RZ_ANALYSIS_DIFF_TYPE_MATCH:
		pj_ks(j, "type", "m");
		break;
	case RZ_ANALYSIS_DIFF_TYPE_UNMATCH:
		pj_ks(j, "type", "u");
		break;
	}
	if (diff->addr != UT64_MAX) {
		pj_kn(j, "addr", diff->addr);
	}
	if (diff->dist != 0.0) {
		pj_kd(j, "dist", diff->dist);
	}
	if (diff->name) {
		pj_ks(j, "name", diff->name);
	}
	if (diff->size) {
		pj_kn(j, "size", (ut64)diff->size);
	}
	pj_end(j);
}

enum {
	DIFF_FIELD_TYPE,
	DIFF_FIELD_ADDR,
	DIFF_FIELD_DIST,
	DIFF_FIELD_NAME,
	DIFF_FIELD_SIZE
};

RZ_API RzSerializeAnalDiffParser rz_serialize_analysis_diff_parser_new(void) {
	RzSerializeAnalDiffParser parser = rz_key_parser_new();
	if (!parser) {
		return NULL;
	}
	rz_key_parser_add(parser, "type", DIFF_FIELD_TYPE);
	rz_key_parser_add(parser, "addr", DIFF_FIELD_ADDR);
	rz_key_parser_add(parser, "dist", DIFF_FIELD_DIST);
	rz_key_parser_add(parser, "name", DIFF_FIELD_NAME);
	rz_key_parser_add(parser, "size", DIFF_FIELD_SIZE);
	return parser;
}

RZ_API void rz_serialize_analysis_diff_parser_free(RzSerializeAnalDiffParser parser) {
	rz_key_parser_free(parser);
}

RZ_API RZ_NULLABLE RzAnalysisDiff *rz_serialize_analysis_diff_load(RZ_NONNULL RzSerializeAnalDiffParser parser, RZ_NONNULL const RzJson *json) {
	if (json->type != RZ_JSON_OBJECT) {
		return NULL;
	}
	RzAnalysisDiff *diff = rz_analysis_diff_new();
	if (!diff) {
		return NULL;
	}
	RZ_KEY_PARSER_JSON(parser, json, child, {
		case DIFF_FIELD_TYPE:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			if (strcmp(child->str_value, "m") == 0) {
				diff->type = RZ_ANALYSIS_DIFF_TYPE_MATCH;
			} else if (strcmp(child->str_value, "u") == 0) {
				diff->type = RZ_ANALYSIS_DIFF_TYPE_UNMATCH;
			}
			break;
		case DIFF_FIELD_ADDR:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			diff->addr = child->num.u_value;
			break;
		case DIFF_FIELD_DIST:
			if (child->type == RZ_JSON_INTEGER) {
				diff->dist = child->num.u_value;
			} else if (child->type == RZ_JSON_DOUBLE) {
				diff->dist = child->num.dbl_value;
			}
			break;
		case DIFF_FIELD_NAME:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			free(diff->name);
			diff->name = strdup(child->str_value);
			break;
		case DIFF_FIELD_SIZE:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			diff->size = child->num.u_value;
			break;
		default:
			break;
	})
	return diff;
}

RZ_API void rz_serialize_analysis_case_op_save(RZ_NONNULL PJ *j, RZ_NONNULL RzAnalysisCaseOp *op) {
	pj_o(j);
	pj_kn(j, "addr", op->addr);
	pj_kn(j, "jump", op->jump);
	pj_kn(j, "value", op->value);
	pj_end(j);
}

RZ_API void rz_serialize_analysis_switch_op_save(RZ_NONNULL PJ *j, RZ_NONNULL RzAnalysisSwitchOp *op) {
	pj_o(j);
	pj_kn(j, "addr", op->addr);
	pj_kn(j, "min", op->min_val);
	pj_kn(j, "max", op->max_val);
	pj_kn(j, "def", op->def_val);
	pj_k(j, "cases");
	pj_a(j);
	RzListIter *it;
	RzAnalysisCaseOp *cop;
	rz_list_foreach (op->cases, it, cop) {
		rz_serialize_analysis_case_op_save(j, cop);
	}
	pj_end(j);
	pj_end(j);
}

RZ_API RzAnalysisSwitchOp *rz_serialize_analysis_switch_op_load(RZ_NONNULL const RzJson *json) {
	if (json->type != RZ_JSON_OBJECT) {
		return NULL;
	}
	RzAnalysisSwitchOp *sop = rz_analysis_switch_op_new(0, 0, 0, 0);
	if (!sop) {
		return NULL;
	}
	RzJson *child;
	for (child = json->children.first; child; child = child->next) {
		if (child->type == RZ_JSON_INTEGER) {
			if (strcmp(child->key, "addr") == 0) {
				sop->addr = child->num.u_value;
			} else if (strcmp(child->key, "min") == 0) {
				sop->min_val = child->num.u_value;
			} else if (strcmp(child->key, "max") == 0) {
				sop->max_val = child->num.u_value;
			} else if (strcmp(child->key, "def") == 0) {
				sop->def_val = child->num.u_value;
			}
		} else if (child->type == RZ_JSON_ARRAY && strcmp(child->key, "cases") == 0) {
			RzJson *obj;
			for (obj = child->children.first; obj; obj = obj->next) {
				if (obj->type != RZ_JSON_OBJECT) {
					continue;
				}
				ut64 addr = UT64_MAX;
				ut64 jump = UT64_MAX;
				ut64 value = UT64_MAX;
				RzJson *cases;
				for (cases = obj->children.first; cases; cases = cases->next) {
					if (cases->type != RZ_JSON_INTEGER) {
						continue;
					}
					if (strcmp(cases->key, "addr") == 0) {
						addr = cases->num.u_value;
					} else if (strcmp(cases->key, "jump") == 0) {
						jump = cases->num.u_value;
					} else if (strcmp(cases->key, "value") == 0) {
						value = cases->num.u_value;
					}
				}
				rz_analysis_switch_op_add_case(sop, addr, value, jump);
			}
		}
	}
	return sop;
}

static void block_store(RZ_NONNULL Sdb *db, const char *key, RzAnalysisBlock *block) {
	PJ *j = pj_new();
	if (!j) {
		return;
	}
	pj_o(j);

	pj_kn(j, "size", block->size);
	if (block->jump != UT64_MAX) {
		pj_kn(j, "jump", block->jump);
	}
	if (block->fail != UT64_MAX) {
		pj_kn(j, "fail", block->fail);
	}
	if (block->traced) {
		pj_kb(j, "traced", true);
	}
	if (block->colorize) {
		pj_kn(j, "colorize", (ut64)block->colorize);
	}
	if (block->fingerprint) {
		char *b64 = rz_base64_encode_dyn(block->fingerprint, block->size);
		if (b64) {
			pj_ks(j, "fingerprint", b64);
			free(b64);
		}
	}
	if (block->diff) {
		pj_k(j, "diff");
		rz_serialize_analysis_diff_save(j, block->diff);
	}

	// TODO: cond? It's used nowhere...

	if (block->switch_op) {
		pj_k(j, "switch_op");
		rz_serialize_analysis_switch_op_save(j, block->switch_op);
	}

	if (block->ninstr) {
		pj_ki(j, "ninstr", block->ninstr);
	}
	if (block->op_pos && block->ninstr > 1) {
		pj_k(j, "op_pos");
		pj_a(j);
		size_t i;
		for (i = 0; i < block->ninstr - 1; i++) {
			pj_n(j, block->op_pos[i]);
		}
		pj_end(j);
	}

	// op_bytes is only java, never set
	// parent_reg_arena is never set

	if (block->stackptr) {
		pj_ki(j, "stackptr", block->stackptr);
	}
	if (block->parent_stackptr != INT_MAX) {
		pj_ki(j, "parent_stackptr", block->parent_stackptr);
	}
	if (block->cmpval != UT64_MAX) {
		pj_kn(j, "cmpval", block->cmpval);
	}
	if (block->cmpreg) {
		pj_ks(j, "cmpreg", block->cmpreg);
	}

	pj_end(j);
	sdb_set(db, key, pj_string(j), 0);
	pj_free(j);
}

RZ_API void rz_serialize_analysis_blocks_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis) {
	RBIter iter;
	RzAnalysisBlock *block;
	RzStrBuf key = { 0 };
	rz_rbtree_foreach (analysis->bb_tree, iter, block, RzAnalysisBlock, _rb) {
		rz_strbuf_setf(&key, "0x%" PFMT64x, block->addr);
		block_store(db, rz_strbuf_get(&key), block);
	}
	rz_strbuf_fini(&key);
}

enum {
	BLOCK_FIELD_SIZE,
	BLOCK_FIELD_JUMP,
	BLOCK_FIELD_FAIL,
	BLOCK_FIELD_TRACED,
	BLOCK_FIELD_COLORIZE,
	BLOCK_FIELD_FINGERPRINT,
	BLOCK_FIELD_DIFF,
	BLOCK_FIELD_SWITCH_OP,
	BLOCK_FIELD_NINSTR,
	BLOCK_FIELD_OP_POS,
	BLOCK_FIELD_STACKPTR,
	BLOCK_FIELD_PARENT_STACKPTR,
	BLOCK_FIELD_CMPVAL,
	BLOCK_FIELD_CMPREG
};

typedef struct {
	RzAnalysis *analysis;
	RzKeyParser *parser;
	RzSerializeAnalDiffParser diff_parser;
} BlockLoadCtx;

static bool block_load_cb(void *user, const char *k, const char *v) {
	BlockLoadCtx *ctx = user;

	char *json_str = strdup(v);
	if (!json_str) {
		return true;
	}
	RzJson *json = rz_json_parse(json_str);
	if (!json || json->type != RZ_JSON_OBJECT) {
		free(json_str);
		return false;
	}

	RzAnalysisBlock proto = { 0 };
	proto.jump = UT64_MAX;
	proto.fail = UT64_MAX;
	proto.size = UT64_MAX;
	proto.parent_stackptr = INT_MAX;
	proto.cmpval = UT64_MAX;
	size_t fingerprint_size = SIZE_MAX;
	RZ_KEY_PARSER_JSON(ctx->parser, json, child, {
		case BLOCK_FIELD_SIZE:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			proto.size = child->num.u_value;
			break;
		case BLOCK_FIELD_JUMP:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			proto.jump = child->num.u_value;
			break;
		case BLOCK_FIELD_FAIL:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			proto.fail = child->num.u_value;
			break;
		case BLOCK_FIELD_TRACED:
			if (child->type != RZ_JSON_BOOLEAN) {
				break;
			}
			proto.traced = child->num.u_value;
			break;
		case BLOCK_FIELD_COLORIZE:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			proto.colorize = (ut32)child->num.u_value;
			break;
		case BLOCK_FIELD_FINGERPRINT: {
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			if (proto.fingerprint) {
				free(proto.fingerprint);
				proto.fingerprint = NULL;
			}
			fingerprint_size = strlen(child->str_value);
			if (!fingerprint_size) {
				break;
			}
			proto.fingerprint = malloc(fingerprint_size);
			if (!proto.fingerprint) {
				break;
			}
			int decsz = rz_base64_decode(proto.fingerprint, child->str_value, fingerprint_size);
			if (decsz <= 0) {
				free(proto.fingerprint);
				proto.fingerprint = NULL;
				fingerprint_size = 0;
			} else if (decsz < fingerprint_size) {
				ut8 *n = realloc(proto.fingerprint, (size_t)decsz);
				if (n) {
					proto.fingerprint = n;
					fingerprint_size = decsz;
				}
			}
			break;
		}
		case BLOCK_FIELD_DIFF:
			rz_analysis_diff_free(proto.diff);
			proto.diff = rz_serialize_analysis_diff_load(ctx->diff_parser, child);
			break;
		case BLOCK_FIELD_SWITCH_OP:
			rz_analysis_switch_op_free(proto.switch_op);
			proto.switch_op = rz_serialize_analysis_switch_op_load(child);
			break;
		case BLOCK_FIELD_NINSTR:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			proto.ninstr = (int)child->num.s_value;
			break;
		case BLOCK_FIELD_OP_POS: {
			if (child->type != RZ_JSON_ARRAY) {
				break;
			}
			if (proto.op_pos) {
				free(proto.op_pos);
				proto.op_pos = NULL;
			}
			proto.op_pos = calloc(child->children.count, sizeof(ut16));
			proto.op_pos_size = 0;
			RzJson *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != RZ_JSON_INTEGER) {
					free(proto.op_pos);
					proto.op_pos = NULL;
					proto.op_pos_size = 0;
					break;
				}
				proto.op_pos[proto.op_pos_size++] = (ut16)baby->num.u_value;
			}
			break;
		}
		case BLOCK_FIELD_STACKPTR:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			proto.stackptr = (int)child->num.s_value;
			break;
		case BLOCK_FIELD_PARENT_STACKPTR:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			proto.parent_stackptr = (int)child->num.s_value;
			break;
		case BLOCK_FIELD_CMPVAL:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			proto.cmpval = child->num.u_value;
			break;
		case BLOCK_FIELD_CMPREG:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			proto.cmpreg = rz_str_constpool_get(&ctx->analysis->constpool, child->str_value);
			break;
		default:
			break;
	})
	rz_json_free(json);
	free(json_str);

	errno = 0;
	ut64 addr = strtoull(k, NULL, 0);
	if (errno || proto.size == UT64_MAX || (fingerprint_size != SIZE_MAX && fingerprint_size != proto.size) || (proto.op_pos && proto.op_pos_size != proto.ninstr - 1)) { // op_pos_size > ninstr - 1 is legal but we require the format to be like this.
		goto error;
	}

	RzAnalysisBlock *block = rz_analysis_create_block(ctx->analysis, addr, proto.size);
	if (!block) {
		goto error;
	}
	block->jump = proto.jump;
	block->fail = proto.fail;
	block->traced = proto.traced;
	block->colorize = proto.colorize;
	block->fingerprint = proto.fingerprint;
	block->diff = proto.diff;
	block->switch_op = proto.switch_op;
	block->ninstr = proto.ninstr;
	if (proto.op_pos) {
		free(block->op_pos);
		block->op_pos = proto.op_pos;
		block->op_pos_size = proto.op_pos_size;
	}
	block->stackptr = proto.stackptr;
	block->parent_stackptr = proto.parent_stackptr;
	block->cmpval = proto.cmpval;
	block->cmpreg = proto.cmpreg;

	return true;
error:
	free(proto.fingerprint);
	rz_analysis_diff_free(proto.diff);
	rz_analysis_switch_op_free(proto.switch_op);
	free(proto.op_pos);
	return false;
}

RZ_API bool rz_serialize_analysis_blocks_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RzSerializeAnalDiffParser diff_parser, RZ_NULLABLE RzSerializeResultInfo *res) {
	BlockLoadCtx ctx = { analysis, rz_key_parser_new(), diff_parser };
	if (!ctx.parser) {
		RZ_SERIALIZE_ERR(res, "parser init failed");
		return false;
	}
	rz_key_parser_add(ctx.parser, "size", BLOCK_FIELD_SIZE);
	rz_key_parser_add(ctx.parser, "jump", BLOCK_FIELD_JUMP);
	rz_key_parser_add(ctx.parser, "fail", BLOCK_FIELD_FAIL);
	rz_key_parser_add(ctx.parser, "traced", BLOCK_FIELD_TRACED);
	rz_key_parser_add(ctx.parser, "colorize", BLOCK_FIELD_COLORIZE);
	rz_key_parser_add(ctx.parser, "fingerprint", BLOCK_FIELD_FINGERPRINT);
	rz_key_parser_add(ctx.parser, "diff", BLOCK_FIELD_DIFF);
	rz_key_parser_add(ctx.parser, "switch_op", BLOCK_FIELD_SWITCH_OP);
	rz_key_parser_add(ctx.parser, "ninstr", BLOCK_FIELD_NINSTR);
	rz_key_parser_add(ctx.parser, "op_pos", BLOCK_FIELD_OP_POS);
	rz_key_parser_add(ctx.parser, "stackptr", BLOCK_FIELD_STACKPTR);
	rz_key_parser_add(ctx.parser, "parent_stackptr", BLOCK_FIELD_PARENT_STACKPTR);
	rz_key_parser_add(ctx.parser, "cmpval", BLOCK_FIELD_CMPVAL);
	rz_key_parser_add(ctx.parser, "cmpreg", BLOCK_FIELD_CMPREG);
	bool ret = sdb_foreach(db, block_load_cb, &ctx);
	rz_key_parser_free(ctx.parser);
	if (!ret) {
		RZ_SERIALIZE_ERR(res, "basic blocks parsing failed");
	}
	return ret;
}

RZ_API void rz_serialize_analysis_var_save(RZ_NONNULL PJ *j, RZ_NONNULL RzAnalysisVar *var) {
	pj_o(j);
	pj_ks(j, "name", var->name);
	pj_ks(j, "type", var->type);
	switch (var->kind) {
	case RZ_ANALYSIS_VAR_KIND_REG:
		pj_ks(j, "kind", "r");
		break;
	case RZ_ANALYSIS_VAR_KIND_SPV:
		pj_ks(j, "kind", "s");
		break;
	case RZ_ANALYSIS_VAR_KIND_BPV:
		pj_ks(j, "kind", "b");
		break;
	}
	if (var->kind != RZ_ANALYSIS_VAR_KIND_REG) {
		pj_kN(j, "delta", var->delta);
	}
	if (var->regname) {
		pj_ks(j, "reg", var->regname);
	}
	if (var->isarg) {
		pj_kb(j, "arg", true);
	}
	if (var->comment) {
		pj_ks(j, "cmt", var->comment);
	}
	if (!rz_vector_empty(&var->accesses)) {
		pj_ka(j, "accs");
		RzAnalysisVarAccess *acc;
		rz_vector_foreach(&var->accesses, acc) {
			pj_o(j);
			pj_kn(j, "off", acc->offset);
			switch (acc->type) {
			case RZ_ANALYSIS_VAR_ACCESS_TYPE_READ:
				pj_ks(j, "type", "r");
				break;
			case RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE:
				pj_ks(j, "type", "w");
				break;
			case RZ_ANALYSIS_VAR_ACCESS_TYPE_READ | RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE:
				pj_ks(j, "type", "rw");
				break;
			}
			if (acc->stackptr) {
				pj_kn(j, "sp", acc->stackptr);
			}
			if (acc->reg) {
				pj_ks(j, "reg", acc->reg);
			} else {
				rz_warn_if_reached();
			}
			pj_end(j);
		}
		pj_end(j);
	}
	if (!rz_vector_empty(&var->constraints)) {
		pj_ka(j, "constrs");
		RzAnalysisVarConstraint *constr;
		rz_vector_foreach(&var->constraints, constr) {
			pj_i(j, (int)constr->cond);
			pj_n(j, constr->val);
		}
		pj_end(j);
	}
	pj_end(j);
}

enum {
	VAR_FIELD_NAME,
	VAR_FIELD_TYPE,
	VAR_FIELD_KIND,
	VAR_FIELD_ARG,
	VAR_FIELD_DELTA,
	VAR_FIELD_REG,
	VAR_FIELD_COMMENT,
	VAR_FIELD_ACCS,
	VAR_FIELD_CONSTRS
};

RZ_API RzSerializeAnalVarParser rz_serialize_analysis_var_parser_new(void) {
	RzSerializeAnalDiffParser parser = rz_key_parser_new();
	if (!parser) {
		return NULL;
	}
	rz_key_parser_add(parser, "name", VAR_FIELD_NAME);
	rz_key_parser_add(parser, "type", VAR_FIELD_TYPE);
	rz_key_parser_add(parser, "kind", VAR_FIELD_KIND);
	rz_key_parser_add(parser, "arg", VAR_FIELD_ARG);
	rz_key_parser_add(parser, "delta", VAR_FIELD_DELTA);
	rz_key_parser_add(parser, "reg", VAR_FIELD_REG);
	rz_key_parser_add(parser, "cmt", VAR_FIELD_COMMENT);
	rz_key_parser_add(parser, "accs", VAR_FIELD_ACCS);
	rz_key_parser_add(parser, "constrs", VAR_FIELD_CONSTRS);
	return parser;
}

RZ_API void rz_serialize_analysis_var_parser_free(RzSerializeAnalVarParser parser) {
	rz_key_parser_free(parser);
}

RZ_API RZ_NULLABLE RzAnalysisVar *rz_serialize_analysis_var_load(RZ_NONNULL RzAnalysisFunction *fcn, RZ_NONNULL RzSerializeAnalVarParser parser, RZ_NONNULL const RzJson *json) {
	if (json->type != RZ_JSON_OBJECT) {
		return NULL;
	}
	const char *name = NULL;
	const char *type = NULL;
	RzAnalysisVarKind kind = -1;
	bool arg = false;
	st64 delta = ST64_MAX;
	const char *regname = NULL;
	const char *comment = NULL;
	RzVector accesses;
	rz_vector_init(&accesses, sizeof(RzAnalysisVarAccess), NULL, NULL);
	RzVector constraints;
	rz_vector_init(&constraints, sizeof(RzAnalysisVarConstraint), NULL, NULL);

	RzAnalysisVar *ret = NULL;

	RZ_KEY_PARSER_JSON(parser, json, child, {
		case VAR_FIELD_NAME:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			name = child->str_value;
			break;
		case VAR_FIELD_TYPE:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			type = child->str_value;
			break;
		case VAR_FIELD_KIND:
			if (child->type != RZ_JSON_STRING || !*child->str_value || child->str_value[1]) {
				// must be a string of exactly 1 char
				break;
			}
			switch (*child->str_value) {
			case 'r':
				kind = RZ_ANALYSIS_VAR_KIND_REG;
				break;
			case 's':
				kind = RZ_ANALYSIS_VAR_KIND_SPV;
				break;
			case 'b':
				kind = RZ_ANALYSIS_VAR_KIND_BPV;
				break;
			default:
				break;
			}
			break;
		case VAR_FIELD_ARG:
			if (child->type != RZ_JSON_BOOLEAN) {
				break;
			}
			arg = child->num.u_value ? true : false;
			break;
		case VAR_FIELD_DELTA:
			if (child->type != RZ_JSON_INTEGER) {
				eprintf("delta nop\n");
				break;
			}
			delta = child->num.s_value;
			break;
		case VAR_FIELD_REG:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			regname = child->str_value;
			break;
		case VAR_FIELD_COMMENT:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			comment = child->str_value;
			break;
		case VAR_FIELD_ACCS: {
			if (child->type != RZ_JSON_ARRAY) {
				break;
			}
			RzJson *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != RZ_JSON_OBJECT) {
					continue;
				}
				// {off:<st64>, type:"r|w|rw", sp?:<st64>}
				const RzJson *offv = rz_json_get(baby, "off");
				if (!offv || offv->type != RZ_JSON_INTEGER) {
					continue;
				}
				const RzJson *typev = rz_json_get(baby, "type");
				if (!typev || typev->type != RZ_JSON_STRING) {
					continue;
				}
				const char *acctype_str = typev->str_value;
				const RzJson *spv = rz_json_get(baby, "sp");
				if (spv && spv->type != RZ_JSON_INTEGER) {
					continue;
				}
				const RzJson *regv = rz_json_get(baby, "reg");
				if (!regv || regv->type != RZ_JSON_STRING) {
					continue;
				}

				ut64 acctype;
				// parse "r", "w" or "rw" and reject everything else
				if (acctype_str[0] == 'r') {
					if (acctype_str[1] == 'w') {
						acctype = RZ_ANALYSIS_VAR_ACCESS_TYPE_READ | RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE;
					} else if (!acctype_str[1]) {
						acctype = RZ_ANALYSIS_VAR_ACCESS_TYPE_READ;
					} else {
						continue;
					}
				} else if (acctype_str[0] == 'w' && !acctype_str[1]) {
					acctype = RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE;
				} else {
					continue;
				}

				RzAnalysisVarAccess *acc = rz_vector_push(&accesses, NULL);
				acc->offset = offv->num.s_value;
				acc->type = acctype;
				acc->stackptr = spv ? spv->num.s_value : 0;
				acc->reg = regv->str_value;
			}
			break;
		}
		case VAR_FIELD_CONSTRS: {
			if (child->type != RZ_JSON_ARRAY) {
				break;
			}
			RzJson *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != RZ_JSON_INTEGER) {
					break;
				}
				RzJson *sibling = baby->next;
				if (!sibling || sibling->type != RZ_JSON_INTEGER) {
					break;
				}
				RzAnalysisVarConstraint constr;
				constr.cond = (_RzAnalysisCond)baby->num.s_value;
				constr.val = sibling->num.u_value;
				if (constr.cond < RZ_ANALYSIS_COND_AL || constr.cond > RZ_ANALYSIS_COND_LS) {
					baby = sibling;
					continue;
				}
				rz_vector_push(&constraints, &constr);
				baby = sibling;
			}
			break;
		}
		default:
			break;
	})

	if (kind == RZ_ANALYSIS_VAR_KIND_REG) {
		if (!regname) {
			goto beach;
		}
		RzRegItem *reg = rz_reg_get(fcn->analysis->reg, regname, -1);
		if (!reg) {
			goto beach;
		}
		delta = reg->index;
	}
	if (!name || !type || kind == -1 || delta == ST64_MAX) {
		goto beach;
	}
	ret = rz_analysis_function_set_var(fcn, delta, kind, type, 0, arg, name);
	if (!ret) {
		goto beach;
	}
	if (comment) {
		free(ret->comment);
		ret->comment = strdup(comment);
	}
	RzAnalysisVarAccess *acc;
	rz_vector_foreach(&accesses, acc) {
		rz_analysis_var_set_access(ret, acc->reg, fcn->addr + acc->offset, acc->type, acc->stackptr);
	}
	RzAnalysisVarConstraint *constr;
	rz_vector_foreach(&constraints, constr) {
		rz_analysis_var_add_constraint(ret, constr);
	}

beach:
	rz_vector_fini(&accesses);
	rz_vector_fini(&constraints);
	return ret;
}

static bool store_label_cb(void *j, const ut64 k, const void *v) {
	pj_kn(j, v, k);
	return true;
}

static void function_store(RZ_NONNULL Sdb *db, const char *key, RzAnalysisFunction *function) {
	PJ *j = pj_new();
	if (!j) {
		return;
	}
	pj_o(j);

	pj_ks(j, "name", function->name);
	if (function->bits) {
		pj_ki(j, "bits", function->bits);
	}
	pj_ki(j, "type", function->type);
	if (function->cc) {
		pj_ks(j, "cc", function->cc);
	}
	pj_ki(j, "stack", function->stack);
	pj_ki(j, "maxstack", function->maxstack);
	pj_ki(j, "ninstr", function->ninstr);
	if (function->bp_frame) {
		pj_kb(j, "bp_frame", true);
	}
	if (function->bp_off) {
		pj_kN(j, "bp_off", function->bp_off);
	}
	if (function->is_pure) {
		pj_kb(j, "pure", true);
	}
	if (function->is_noreturn) {
		pj_kb(j, "noreturn", true);
	}
	if (function->fingerprint) {
		char *b64 = rz_base64_encode_dyn(function->fingerprint, function->fingerprint_size);
		if (b64) {
			pj_ks(j, "fingerprint", b64);
			free(b64);
		}
	}
	if (function->diff) {
		pj_k(j, "diff");
		rz_serialize_analysis_diff_save(j, function->diff);
	}

	pj_ka(j, "bbs");
	RzListIter *it;
	RzAnalysisBlock *block;
	rz_list_foreach (function->bbs, it, block) {
		pj_n(j, block->addr);
	}
	pj_end(j);

	if (!rz_list_empty(function->imports)) {
		pj_ka(j, "imports");
		const char *import;
		rz_list_foreach (function->imports, it, import) {
			pj_s(j, import);
		}
		pj_end(j);
	}

	if (!rz_pvector_empty(&function->vars)) {
		pj_ka(j, "vars");
		void **vit;
		rz_pvector_foreach (&function->vars, vit) {
			RzAnalysisVar *var = *vit;
			rz_serialize_analysis_var_save(j, var);
		}
		pj_end(j);
	}

	if (function->labels->count) {
		pj_ko(j, "labels");
		ht_up_foreach(function->labels, store_label_cb, j);
		pj_end(j);
	}

	pj_end(j);
	sdb_set(db, key, pj_string(j), 0);
	pj_free(j);
}

RZ_API void rz_serialize_analysis_functions_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis) {
	RzListIter *it;
	RzAnalysisFunction *function;
	RzStrBuf key;
	rz_strbuf_init(&key);
	rz_list_foreach (analysis->fcns, it, function) {
		rz_strbuf_setf(&key, "0x%" PFMT64x, function->addr);
		function_store(db, rz_strbuf_get(&key), function);
	}
	rz_strbuf_fini(&key);
}

enum {
	FUNCTION_FIELD_NAME,
	FUNCTION_FIELD_BITS,
	FUNCTION_FIELD_TYPE,
	FUNCTION_FIELD_CC,
	FUNCTION_FIELD_STACK,
	FUNCTION_FIELD_MAXSTACK,
	FUNCTION_FIELD_NINSTR,
	FUNCTION_FIELD_PURE,
	FUNCTION_FIELD_BP_FRAME,
	FUNCTION_FIELD_BP_OFF,
	FUNCTION_FIELD_NORETURN,
	FUNCTION_FIELD_FINGERPRINT,
	FUNCTION_FIELD_DIFF,
	FUNCTION_FIELD_BBS,
	FUNCTION_FIELD_IMPORTS,
	FUNCTION_FIELD_VARS,
	FUNCTION_FIELD_LABELS
};

typedef struct {
	RzAnalysis *analysis;
	RzKeyParser *parser;
	RzSerializeAnalDiffParser diff_parser;
	RzSerializeAnalVarParser var_parser;
} FunctionLoadCtx;

static bool function_load_cb(void *user, const char *k, const char *v) {
	FunctionLoadCtx *ctx = user;

	char *json_str = strdup(v);
	if (!json_str) {
		return true;
	}
	RzJson *json = rz_json_parse(json_str);
	if (!json || json->type != RZ_JSON_OBJECT) {
		free(json_str);
		return false;
	}

	RzAnalysisFunction *function = rz_analysis_function_new(ctx->analysis);
	function->bits = 0; // should be 0 if not specified
	function->bp_frame = false; // should be false if not specified
	function->bp_off = 0; // 0 if not specified
	bool noreturn = false;
	RzJson *vars_json = NULL;
	RZ_KEY_PARSER_JSON(ctx->parser, json, child, {
		case FUNCTION_FIELD_NAME:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			if (function->name) {
				free(function->name);
			}
			function->name = strdup(child->str_value);
			break;
		case FUNCTION_FIELD_BITS:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			function->bits = (int)child->num.s_value;
			break;
		case FUNCTION_FIELD_TYPE:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			function->type = (int)child->num.s_value;
			break;
		case FUNCTION_FIELD_CC:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			function->cc = rz_str_constpool_get(&ctx->analysis->constpool, child->str_value);
			break;
		case FUNCTION_FIELD_STACK:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			function->stack = (int)child->num.s_value;
			break;
		case FUNCTION_FIELD_MAXSTACK:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			function->maxstack = (int)child->num.s_value;
			break;
		case FUNCTION_FIELD_NINSTR:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			function->ninstr = (int)child->num.s_value;
			break;
		case FUNCTION_FIELD_PURE:
			if (child->type != RZ_JSON_BOOLEAN) {
				break;
			}
			function->is_pure = child->num.u_value ? true : false;
			break;
		case FUNCTION_FIELD_BP_FRAME:
			if (child->type != RZ_JSON_BOOLEAN) {
				break;
			}
			function->bp_frame = child->num.u_value ? true : false;
			break;
		case FUNCTION_FIELD_BP_OFF:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			function->bp_off = child->num.s_value;
			break;
		case FUNCTION_FIELD_NORETURN:
			if (child->type != RZ_JSON_BOOLEAN) {
				break;
			}
			noreturn = child->num.u_value ? true : false;
			break;
		case FUNCTION_FIELD_FINGERPRINT:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			if (function->fingerprint) {
				free(function->fingerprint);
				function->fingerprint = NULL;
			}
			function->fingerprint_size = strlen(child->str_value);
			if (!function->fingerprint_size) {
				break;
			}
			function->fingerprint = malloc(function->fingerprint_size);
			if (!function->fingerprint) {
				function->fingerprint_size = 0;
				break;
			}
			int decsz = rz_base64_decode(function->fingerprint, child->str_value, function->fingerprint_size);
			if (decsz <= 0) {
				free(function->fingerprint);
				function->fingerprint = NULL;
				function->fingerprint_size = 0;
			} else if (decsz < function->fingerprint_size) {
				ut8 *n = realloc(function->fingerprint, (size_t)decsz);
				if (!n) {
					free(function->fingerprint);
					function->fingerprint = NULL;
					function->fingerprint_size = 0;
				}
				function->fingerprint = n;
				function->fingerprint_size = (size_t)decsz;
			}
			break;
		case FUNCTION_FIELD_DIFF:
			rz_analysis_diff_free(function->diff);
			function->diff = rz_serialize_analysis_diff_load(ctx->diff_parser, child);
			break;
		case FUNCTION_FIELD_BBS: {
			if (child->type != RZ_JSON_ARRAY) {
				break;
			}
			RzJson *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != RZ_JSON_INTEGER) {
					continue;
				}
				RzAnalysisBlock *block = rz_analysis_get_block_at(ctx->analysis, baby->num.u_value);
				if (!block) {
					continue;
				}
				rz_analysis_function_add_block(function, block);
			}
			break;
		}
		case FUNCTION_FIELD_IMPORTS: {
			if (child->type != RZ_JSON_ARRAY) {
				break;
			}
			RzJson *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != RZ_JSON_STRING) {
					continue;
				}
				char *import = strdup(baby->str_value);
				if (!import) {
					break;
				}
				if (!function->imports) {
					function->imports = rz_list_newf((RzListFree)free);
					if (!function->imports) {
						free(import);
						break;
					}
				}
				rz_list_push(function->imports, import);
			}
			break;
		}
		case FUNCTION_FIELD_VARS: {
			if (child->type != RZ_JSON_ARRAY) {
				break;
			}
			vars_json = child;
			break;
		}
		case FUNCTION_FIELD_LABELS: {
			if (child->type != RZ_JSON_OBJECT) {
				break;
			}
			RzJson *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != RZ_JSON_INTEGER) {
					continue;
				}
				rz_analysis_function_set_label(function, baby->key, baby->num.u_value);
			}
			break;
		}
		default:
			break;
	})

	bool ret = true;
	errno = 0;
	function->addr = strtoull(k, NULL, 0);
	if (errno || !function->name || !rz_analysis_add_function(ctx->analysis, function)) {
		rz_analysis_function_free(function);
		ret = false;
		goto beach;
	}
	function->is_noreturn = noreturn; // Can't set directly, rz_analysis_add_function() overwrites it

	if (vars_json) {
		RzJson *baby;
		for (baby = vars_json->children.first; baby; baby = baby->next) {
			rz_serialize_analysis_var_load(function, ctx->var_parser, baby);
		}
	}

beach:
	rz_json_free(json);
	free(json_str);
	return ret;
}

RZ_API bool rz_serialize_analysis_functions_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RzSerializeAnalDiffParser diff_parser, RZ_NULLABLE RzSerializeResultInfo *res) {
	FunctionLoadCtx ctx = {
		.analysis = analysis,
		.parser = rz_key_parser_new(),
		.diff_parser = diff_parser,
		.var_parser = rz_serialize_analysis_var_parser_new()
	};
	bool ret;
	if (!ctx.parser || !ctx.var_parser) {
		RZ_SERIALIZE_ERR(res, "parser init failed");
		ret = false;
		goto beach;
	}
	rz_key_parser_add(ctx.parser, "name", FUNCTION_FIELD_NAME);
	rz_key_parser_add(ctx.parser, "bits", FUNCTION_FIELD_BITS);
	rz_key_parser_add(ctx.parser, "type", FUNCTION_FIELD_TYPE);
	rz_key_parser_add(ctx.parser, "cc", FUNCTION_FIELD_CC);
	rz_key_parser_add(ctx.parser, "stack", FUNCTION_FIELD_STACK);
	rz_key_parser_add(ctx.parser, "maxstack", FUNCTION_FIELD_MAXSTACK);
	rz_key_parser_add(ctx.parser, "ninstr", FUNCTION_FIELD_NINSTR);
	rz_key_parser_add(ctx.parser, "pure", FUNCTION_FIELD_PURE);
	rz_key_parser_add(ctx.parser, "bp_frame", FUNCTION_FIELD_BP_FRAME);
	rz_key_parser_add(ctx.parser, "bp_off", FUNCTION_FIELD_BP_OFF);
	rz_key_parser_add(ctx.parser, "noreturn", FUNCTION_FIELD_NORETURN);
	rz_key_parser_add(ctx.parser, "fingerprint", FUNCTION_FIELD_FINGERPRINT);
	rz_key_parser_add(ctx.parser, "diff", FUNCTION_FIELD_DIFF);
	rz_key_parser_add(ctx.parser, "bbs", FUNCTION_FIELD_BBS);
	rz_key_parser_add(ctx.parser, "imports", FUNCTION_FIELD_IMPORTS);
	rz_key_parser_add(ctx.parser, "vars", FUNCTION_FIELD_VARS);
	rz_key_parser_add(ctx.parser, "labels", FUNCTION_FIELD_LABELS);
	ret = sdb_foreach(db, function_load_cb, &ctx);
	if (!ret) {
		RZ_SERIALIZE_ERR(res, "functions parsing failed");
	}
beach:
	rz_key_parser_free(ctx.parser);
	rz_serialize_analysis_var_parser_free(ctx.var_parser);
	return ret;
}

static bool store_xref_cb(void *j, const ut64 k, const void *v) {
	const RzAnalysisRef *xref = v;
	pj_o(j);
	pj_kn(j, "to", k);
	if (xref->type != RZ_ANALYSIS_REF_TYPE_NULL) {
		char type[2] = { xref->type, '\0' };
		pj_ks(j, "type", type);
	}
	pj_end(j);
	return true;
}

static bool store_xrefs_list_cb(void *db, const ut64 k, const void *v) {
	char key[0x20];
	if (snprintf(key, sizeof(key), "0x%" PFMT64x, k) < 0) {
		return false;
	}
	PJ *j = pj_new();
	if (!j) {
		return false;
	}
	pj_a(j);
	HtUP *ht = (HtUP *)v;
	ht_up_foreach(ht, store_xref_cb, j);
	pj_end(j);
	sdb_set(db, key, pj_string(j), 0);
	pj_free(j);
	return true;
}

RZ_API void rz_serialize_analysis_xrefs_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis) {
	ht_up_foreach(analysis->dict_refs, store_xrefs_list_cb, db);
}

static bool xrefs_load_cb(void *user, const char *k, const char *v) {
	RzAnalysis *analysis = user;

	errno = 0;
	ut64 from = strtoull(k, NULL, 0);
	if (errno) {
		return false;
	}

	char *json_str = strdup(v);
	if (!json_str) {
		return true;
	}
	RzJson *json = rz_json_parse(json_str);
	if (!json || json->type != RZ_JSON_ARRAY) {
		free(json_str);
		return false;
	}

	const RzJson *child;
	for (child = json->children.first; child; child = child->next) {
		if (child->type != RZ_JSON_OBJECT) {
			goto error;
		}
		const RzJson *baby = rz_json_get(child, "to");
		if (!baby || baby->type != RZ_JSON_INTEGER) {
			goto error;
		}
		ut64 to = baby->num.u_value;

		RzAnalysisRefType type = RZ_ANALYSIS_REF_TYPE_NULL;
		baby = rz_json_get(child, "type");
		if (baby) {
			// must be a 1-char string
			if (baby->type != RZ_JSON_STRING || !baby->str_value[0] || baby->str_value[1]) {
				goto error;
			}
			switch (baby->str_value[0]) {
			case RZ_ANALYSIS_REF_TYPE_CODE:
			case RZ_ANALYSIS_REF_TYPE_CALL:
			case RZ_ANALYSIS_REF_TYPE_DATA:
			case RZ_ANALYSIS_REF_TYPE_STRING:
				type = baby->str_value[0];
				break;
			default:
				goto error;
			}
		}

		rz_analysis_xrefs_set(analysis, from, to, type);
	}

	rz_json_free(json);
	free(json_str);

	return true;
error:
	rz_json_free(json);
	free(json_str);
	return false;
}

RZ_API bool rz_serialize_analysis_xrefs_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	bool ret = sdb_foreach(db, xrefs_load_cb, analysis);
	if (!ret) {
		RZ_SERIALIZE_ERR(res, "xrefs parsing failed");
	}
	return ret;
}

RZ_API void rz_serialize_analysis_meta_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis) {
	rz_serialize_spaces_save(sdb_ns(db, "spaces", true), &analysis->meta_spaces);

	PJ *j = pj_new();
	if (!j) {
		return;
	}
	char key[0x20];
	RzIntervalTreeIter it;
	RzAnalysisMetaItem *meta;
	ut64 addr = 0;
	size_t count = 0;
#define FLUSH \
	pj_end(j); \
	if (snprintf(key, sizeof(key), "0x%" PFMT64x, addr) >= 0) { \
		sdb_set(db, key, pj_string(j), 0); \
	}
	rz_interval_tree_foreach (&analysis->meta, it, meta) {
		RzIntervalNode *node = rz_interval_tree_iter_get(&it);
		if (count && node->start != addr) {
			// new address
			FLUSH
			pj_reset(j);
			pj_a(j);
			count = 0;
		} else if (!count) {
			// first address
			pj_a(j);
		}
		count++;
		addr = node->start;
		pj_o(j);
		ut64 size = rz_meta_node_size(node);
		if (size != 1) {
			pj_kn(j, "size", size);
		}
		char type_str[2] = { 0 };
		switch (meta->type) {
		case RZ_META_TYPE_DATA:
			type_str[0] = 'd';
			break;
		case RZ_META_TYPE_CODE:
			type_str[0] = 'c';
			break;
		case RZ_META_TYPE_STRING:
			type_str[0] = 's';
			break;
		case RZ_META_TYPE_FORMAT:
			type_str[0] = 'f';
			break;
		case RZ_META_TYPE_MAGIC:
			type_str[0] = 'm';
			break;
		case RZ_META_TYPE_HIDE:
			type_str[0] = 'h';
			break;
		case RZ_META_TYPE_COMMENT:
			type_str[0] = 'C';
			break;
		case RZ_META_TYPE_RUN:
			type_str[0] = 'r';
			break;
		case RZ_META_TYPE_HIGHLIGHT:
			type_str[0] = 'H';
			break;
		case RZ_META_TYPE_VARTYPE:
			type_str[0] = 't';
			break;
		default:
			break;
		}
		pj_ks(j, "type", type_str);
		if (meta->subtype) {
			pj_ki(j, "subtype", meta->subtype);
		}
		if (meta->str) {
			pj_ks(j, "str", meta->str);
		}
		if (meta->space) {
			pj_ks(j, "space", meta->space->name);
		}
		pj_end(j);
	}
	if (count) {
		FLUSH
	}
#undef FLUSH
	pj_free(j);
}

static bool meta_load_cb(void *user, const char *k, const char *v) {
	RzAnalysis *analysis = user;

	errno = 0;
	ut64 addr = strtoull(k, NULL, 0);
	if (errno) {
		return false;
	}

	char *json_str = strdup(v);
	if (!json_str) {
		return true;
	}
	RzJson *json = rz_json_parse(json_str);
	if (!json || json->type != RZ_JSON_ARRAY) {
		free(json_str);
		return false;
	}

	const RzJson *child;
	for (child = json->children.first; child; child = child->next) {
		if (child->type != RZ_JSON_OBJECT) {
			goto error;
		}

		ut64 size = 1;
		RzAnalysisMetaType type = RZ_META_TYPE_ANY;
		const char *str = NULL;
		int subtype = 0;
		const char *space_name = NULL;

		const RzJson *baby;
		for (baby = child->children.first; baby; baby = baby->next) {
			if (!strcmp(baby->key, "size")) {
				if (baby->type == RZ_JSON_INTEGER) {
					size = baby->num.u_value;
				}
				continue;
			}
			if (!strcmp(baby->key, "type")) {
				// only single-char strings accepted
				if (baby->type == RZ_JSON_STRING && baby->str_value[0] && !baby->str_value[1]) {
					switch (baby->str_value[0]) {
					case 'd':
						type = RZ_META_TYPE_DATA;
						break;
					case 'c':
						type = RZ_META_TYPE_CODE;
						break;
					case 's':
						type = RZ_META_TYPE_STRING;
						break;
					case 'f':
						type = RZ_META_TYPE_FORMAT;
						break;
					case 'm':
						type = RZ_META_TYPE_MAGIC;
						break;
					case 'h':
						type = RZ_META_TYPE_HIDE;
						break;
					case 'C':
						type = RZ_META_TYPE_COMMENT;
						break;
					case 'r':
						type = RZ_META_TYPE_RUN;
						break;
					case 'H':
						type = RZ_META_TYPE_HIGHLIGHT;
						break;
					case 't':
						type = RZ_META_TYPE_VARTYPE;
						break;
					default:
						break;
					}
				}
				continue;
			}
			if (!strcmp(baby->key, "str")) {
				if (baby->type == RZ_JSON_STRING) {
					str = baby->str_value;
				}
				continue;
			}
			if (!strcmp(baby->key, "subtype")) {
				if (baby->type == RZ_JSON_INTEGER) {
					subtype = (int)baby->num.s_value;
				}
				continue;
			}
			if (!strcmp(baby->key, "space")) {
				if (baby->type == RZ_JSON_STRING) {
					space_name = baby->str_value;
				}
				continue;
			}
		}

		if (type == RZ_META_TYPE_ANY || (type == RZ_META_TYPE_COMMENT && !str)) {
			continue;
		}

		RzAnalysisMetaItem *item = RZ_NEW0(RzAnalysisMetaItem);
		if (!item) {
			break;
		}
		item->type = type;
		item->subtype = subtype;
		item->space = space_name ? rz_spaces_get(&analysis->meta_spaces, space_name) : NULL;
		item->str = str ? strdup(str) : NULL;
		if (str && !item->str) {
			free(item);
			continue;
		}
		ut64 end = addr + size - 1;
		if (end < addr) {
			end = UT64_MAX;
		}
		rz_interval_tree_insert(&analysis->meta, addr, end, item);
	}

	rz_json_free(json);
	free(json_str);

	return true;
error:
	rz_json_free(json);
	free(json_str);
	return false;
}

RZ_API bool rz_serialize_analysis_meta_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	Sdb *spaces_db = sdb_ns(db, "spaces", false);
	if (!spaces_db) {
		RZ_SERIALIZE_ERR(res, "missing meta spaces namespace");
		return false;
	}
	if (!rz_serialize_spaces_load(spaces_db, &analysis->meta_spaces, false, res)) {
		return false;
	}
	bool ret = sdb_foreach(db, meta_load_cb, analysis);
	if (!ret) {
		RZ_SERIALIZE_ERR(res, "meta parsing failed");
	}
	return ret;
}

typedef struct {
	const RzVector /*<const RzAnalysisAddrHintRecord>*/ *addr_hints;
	const char *arch;
	int bits;
	bool arch_set;
	bool bits_set;
} HintsAtAddr;

static void hints_at_addr_kv_free(HtUPKv *kv) {
	free(kv->value);
}

static HintsAtAddr *hints_at_addr(HtUP *acc, ut64 addr) {
	HintsAtAddr *h = ht_up_find(acc, addr, NULL);
	if (h) {
		return h;
	}
	h = RZ_NEW0(HintsAtAddr);
	if (!h) {
		return NULL;
	}
	ht_up_insert(acc, addr, h);
	return h;
}

static bool addr_hint_acc_cb(ut64 addr, const RzVector /*<const RzAnalysisAddrHintRecord>*/ *records, void *user) {
	HintsAtAddr *h = hints_at_addr(user, addr);
	if (!h) {
		return false;
	}
	h->addr_hints = records;
	return true;
}

static bool arch_hint_acc_cb(ut64 addr, RZ_NULLABLE const char *arch, void *user) {
	HintsAtAddr *h = hints_at_addr(user, addr);
	if (!h) {
		return false;
	}
	h->arch = arch;
	h->arch_set = true;
	return true;
}

static bool bits_hint_acc_cb(ut64 addr, int bits, void *user) {
	HintsAtAddr *h = hints_at_addr(user, addr);
	if (!h) {
		return false;
	}
	h->bits = bits;
	h->bits_set = true;
	return true;
}

static bool hints_acc_store_cb(void *user, const ut64 addr, const void *v) {
	const HintsAtAddr *h = v;
	char key[0x20];
	if (snprintf(key, sizeof(key), "0x%" PFMT64x, addr) < 0) {
		return false;
	}
	Sdb *db = user;
	PJ *j = pj_new();
	if (!j) {
		return false;
	}
	pj_o(j);
	if (h->arch_set) {
		pj_k(j, "arch");
		if (h->arch) {
			pj_s(j, h->arch);
		} else {
			pj_null(j);
		}
	}
	if (h->bits_set) {
		pj_ki(j, "bits", h->bits);
	}
	if (h->addr_hints) {
		RzAnalysisAddrHintRecord *record;
		rz_vector_foreach(h->addr_hints, record) {
			switch (record->type) {
			case RZ_ANALYSIS_ADDR_HINT_TYPE_IMMBASE:
				pj_ki(j, "immbase", record->immbase);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_JUMP:
				pj_kn(j, "jump", record->jump);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_FAIL:
				pj_kn(j, "fail", record->fail);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_STACKFRAME:
				pj_kn(j, "frame", record->stackframe);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_PTR:
				pj_kn(j, "ptr", record->ptr);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_NWORD:
				pj_ki(j, "nword", record->nword);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_RET:
				pj_kn(j, "ret", record->retval);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_NEW_BITS:
				pj_ki(j, "newbits", record->newbits);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_SIZE:
				pj_kn(j, "size", record->size);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_SYNTAX:
				pj_ks(j, "syntax", record->syntax);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_OPTYPE:
				pj_ki(j, "optype", record->optype);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_OPCODE:
				pj_ks(j, "opcode", record->opcode);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_TYPE_OFFSET:
				pj_ks(j, "toff", record->type_offset);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_ESIL:
				pj_ks(j, "esil", record->esil);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_HIGH:
				pj_kb(j, "high", true);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_VAL:
				pj_kn(j, "val", record->val);
				break;
			}
		}
	}
	pj_end(j);
	sdb_set(db, key, pj_string(j), 0);
	pj_free(j);
	return true;
}

RZ_API void rz_serialize_analysis_hints_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis) {
	HtUP /*<HintsAtAddr *>*/ *acc = ht_up_new(NULL, hints_at_addr_kv_free, NULL);
	rz_analysis_addr_hints_foreach(analysis, addr_hint_acc_cb, acc);
	rz_analysis_arch_hints_foreach(analysis, arch_hint_acc_cb, acc);
	rz_analysis_bits_hints_foreach(analysis, bits_hint_acc_cb, acc);
	ht_up_foreach(acc, hints_acc_store_cb, db);
	ht_up_free(acc);
}

enum {
	HINTS_FIELD_ARCH,
	HINTS_FIELD_BITS,
	HINTS_FIELD_IMMBASE,
	HINTS_FIELD_JUMP,
	HINTS_FIELD_FAIL,
	HINTS_FIELD_STACKFRAME,
	HINTS_FIELD_PTR,
	HINTS_FIELD_NWORD,
	HINTS_FIELD_RET,
	HINTS_FIELD_NEW_BITS,
	HINTS_FIELD_SIZE,
	HINTS_FIELD_SYNTAX,
	HINTS_FIELD_OPTYPE,
	HINTS_FIELD_OPCODE,
	HINTS_FIELD_TYPE_OFFSET,
	HINTS_FIELD_ESIL,
	HINTS_FIELD_HIGH,
	HINTS_FIELD_VAL
};

typedef struct {
	RzAnalysis *analysis;
	RzKeyParser *parser;
} HintsLoadCtx;

static bool hints_load_cb(void *user, const char *k, const char *v) {
	HintsLoadCtx *ctx = user;
	RzAnalysis *analysis = ctx->analysis;

	errno = 0;
	ut64 addr = strtoull(k, NULL, 0);
	if (errno) {
		return false;
	}

	char *json_str = strdup(v);
	if (!json_str) {
		return true;
	}
	RzJson *json = rz_json_parse(json_str);
	if (!json || json->type != RZ_JSON_OBJECT) {
		free(json_str);
		return false;
	}

	RZ_KEY_PARSER_JSON(ctx->parser, json, child, {
		case HINTS_FIELD_ARCH:
			rz_analysis_hint_set_arch(analysis, addr, child->type == RZ_JSON_STRING ? child->str_value : NULL);
			break;
		case HINTS_FIELD_BITS:
			rz_analysis_hint_set_bits(analysis, addr, child->type == RZ_JSON_INTEGER ? (int)child->num.s_value : 0);
			break;
		case HINTS_FIELD_IMMBASE:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			rz_analysis_hint_set_immbase(analysis, addr, (int)child->num.s_value);
			break;
		case HINTS_FIELD_JUMP:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			rz_analysis_hint_set_jump(analysis, addr, child->num.u_value);
			break;
		case HINTS_FIELD_FAIL:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			rz_analysis_hint_set_fail(analysis, addr, child->num.u_value);
			break;
		case HINTS_FIELD_STACKFRAME:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			rz_analysis_hint_set_stackframe(analysis, addr, child->num.u_value);
			break;
		case HINTS_FIELD_PTR:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			rz_analysis_hint_set_pointer(analysis, addr, child->num.u_value);
			break;
		case HINTS_FIELD_NWORD:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			rz_analysis_hint_set_nword(analysis, addr, (int)child->num.s_value);
			break;
		case HINTS_FIELD_RET:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			rz_analysis_hint_set_ret(analysis, addr, child->num.u_value);
			break;
		case HINTS_FIELD_NEW_BITS:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			rz_analysis_hint_set_newbits(analysis, addr, (int)child->num.s_value);
			break;
		case HINTS_FIELD_SIZE:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			rz_analysis_hint_set_size(analysis, addr, child->num.u_value);
			break;
		case HINTS_FIELD_SYNTAX:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			rz_analysis_hint_set_syntax(analysis, addr, child->str_value);
			break;
		case HINTS_FIELD_OPTYPE:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			rz_analysis_hint_set_type(analysis, addr, (int)child->num.s_value);
			break;
		case HINTS_FIELD_OPCODE:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			rz_analysis_hint_set_opcode(analysis, addr, child->str_value);
			break;
		case HINTS_FIELD_TYPE_OFFSET:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			rz_analysis_hint_set_offset(analysis, addr, child->str_value);
			break;
		case HINTS_FIELD_ESIL:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			rz_analysis_hint_set_esil(analysis, addr, child->str_value);
			break;
		case HINTS_FIELD_HIGH:
			if (child->type != RZ_JSON_BOOLEAN || !child->num.u_value) {
				break;
			}
			rz_analysis_hint_set_high(analysis, addr);
			break;
		case HINTS_FIELD_VAL:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			rz_analysis_hint_set_val(analysis, addr, child->num.u_value);
			break;
		default:
			break;
	})

	rz_json_free(json);
	free(json_str);

	return true;
}

RZ_API bool rz_serialize_analysis_hints_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	HintsLoadCtx ctx = {
		.analysis = analysis,
		.parser = rz_key_parser_new(),
	};
	bool ret;
	if (!ctx.parser) {
		RZ_SERIALIZE_ERR(res, "parser init failed");
		ret = false;
		goto beach;
	}
	rz_key_parser_add(ctx.parser, "arch", HINTS_FIELD_ARCH);
	rz_key_parser_add(ctx.parser, "bits", HINTS_FIELD_BITS);
	rz_key_parser_add(ctx.parser, "immbase", HINTS_FIELD_IMMBASE);
	rz_key_parser_add(ctx.parser, "jump", HINTS_FIELD_JUMP);
	rz_key_parser_add(ctx.parser, "fail", HINTS_FIELD_FAIL);
	rz_key_parser_add(ctx.parser, "frame", HINTS_FIELD_STACKFRAME);
	rz_key_parser_add(ctx.parser, "ptr", HINTS_FIELD_PTR);
	rz_key_parser_add(ctx.parser, "nword", HINTS_FIELD_NWORD);
	rz_key_parser_add(ctx.parser, "ret", HINTS_FIELD_RET);
	rz_key_parser_add(ctx.parser, "newbits", HINTS_FIELD_NEW_BITS);
	rz_key_parser_add(ctx.parser, "size", HINTS_FIELD_SIZE);
	rz_key_parser_add(ctx.parser, "syntax", HINTS_FIELD_SYNTAX);
	rz_key_parser_add(ctx.parser, "optype", HINTS_FIELD_OPTYPE);
	rz_key_parser_add(ctx.parser, "opcode", HINTS_FIELD_OPCODE);
	rz_key_parser_add(ctx.parser, "toff", HINTS_FIELD_TYPE_OFFSET);
	rz_key_parser_add(ctx.parser, "esil", HINTS_FIELD_ESIL);
	rz_key_parser_add(ctx.parser, "high", HINTS_FIELD_HIGH);
	rz_key_parser_add(ctx.parser, "val", HINTS_FIELD_VAL);
	ret = sdb_foreach(db, hints_load_cb, &ctx);
	if (!ret) {
		RZ_SERIALIZE_ERR(res, "hints parsing failed");
	}
beach:
	rz_key_parser_free(ctx.parser);
	return ret;
}

RZ_API void rz_serialize_analysis_classes_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis) {
	sdb_copy(analysis->sdb_classes, db);
}

RZ_API bool rz_serialize_analysis_classes_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	if (!sdb_ns(db, "attrs", false)) {
		RZ_SERIALIZE_ERR(res, "missing attrs namespace");
		return false;
	}
	sdb_reset(analysis->sdb_classes);
	sdb_reset(analysis->sdb_classes_attrs);
	sdb_copy(db, analysis->sdb_classes);
	return true;
}

RZ_API void rz_serialize_analysis_types_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis) {
	sdb_copy(analysis->sdb_types, db);
}

RZ_API bool rz_serialize_analysis_types_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	sdb_reset(analysis->sdb_types);
	sdb_copy(db, analysis->sdb_types);
	return true;
}

RZ_API void rz_serialize_analysis_sign_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis) {
	sdb_copy(analysis->sdb_zigns, db);
	rz_serialize_spaces_save(sdb_ns(db, "spaces", true), &analysis->zign_spaces);
}

RZ_API bool rz_serialize_analysis_sign_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	sdb_reset(analysis->sdb_zigns);
	sdb_copy(db, analysis->sdb_zigns);
	Sdb *spaces_db = sdb_ns(db, "spaces", false);
	if (!spaces_db) {
		RZ_SERIALIZE_ERR(res, "missing spaces namespace");
		return false;
	}
	if (!rz_serialize_spaces_load(spaces_db, &analysis->zign_spaces, false, res)) {
		return false;
	}
	return true;
}

RZ_API void rz_serialize_analysis_imports_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis) {
	RzListIter *it;
	const char *imp;
	rz_list_foreach (analysis->imports, it, imp) {
		sdb_set(db, imp, "i", 0);
	}
}

static bool import_load_cb(void *user, const char *k, const char *v) {
	rz_analysis_add_import(user, k);
	return true;
}

RZ_API bool rz_serialize_analysis_imports_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	return sdb_foreach(db, import_load_cb, analysis);
}

RZ_API void rz_serialize_analysis_pin_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis) {
	sdb_copy(analysis->sdb_pins, db);
}

RZ_API bool rz_serialize_analysis_pin_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	sdb_copy(db, analysis->sdb_pins);
	return true;
}

RZ_API void rz_serialize_analysis_cc_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis) {
	sdb_copy(analysis->sdb_cc, db);
}

RZ_API bool rz_serialize_analysis_cc_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	sdb_copy(db, analysis->sdb_cc);
	return true;
}

RZ_API void rz_serialize_analysis_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis) {
	rz_serialize_analysis_xrefs_save(sdb_ns(db, "xrefs", true), analysis);
	rz_serialize_analysis_blocks_save(sdb_ns(db, "blocks", true), analysis);
	rz_serialize_analysis_functions_save(sdb_ns(db, "functions", true), analysis);
	rz_serialize_analysis_meta_save(sdb_ns(db, "meta", true), analysis);
	rz_serialize_analysis_hints_save(sdb_ns(db, "hints", true), analysis);
	rz_serialize_analysis_classes_save(sdb_ns(db, "classes", true), analysis);
	rz_serialize_analysis_types_save(sdb_ns(db, "types", true), analysis);
	rz_serialize_analysis_sign_save(sdb_ns(db, "zigns", true), analysis);
	rz_serialize_analysis_imports_save(sdb_ns(db, "imports", true), analysis);
	rz_serialize_analysis_pin_save(sdb_ns(db, "pins", true), analysis);
	rz_serialize_analysis_cc_save(sdb_ns(db, "cc", true), analysis);
}

RZ_API bool rz_serialize_analysis_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	bool ret = false;
	RzSerializeAnalDiffParser diff_parser = rz_serialize_analysis_diff_parser_new();
	if (!diff_parser) {
		goto beach;
	}

	rz_analysis_purge(analysis);

	Sdb *subdb;
#define SUB(ns, call) RZ_SERIALIZE_SUB_DO(db, subdb, res, ns, call, goto beach;)
	SUB("xrefs", rz_serialize_analysis_xrefs_load(subdb, analysis, res));

	SUB("blocks", rz_serialize_analysis_blocks_load(subdb, analysis, diff_parser, res));
	// All bbs have ref=1 now
	SUB("functions", rz_serialize_analysis_functions_load(subdb, analysis, diff_parser, res));
	// BB's refs have increased if they are part of a function.
	// We must subtract from each to hold our invariant again.
	// If any block has ref=0 then, it should be deleted. But we can't do this while
	// iterating the RBTree, otherwise this will become a segfault cacophony, so we cache them.
	RzPVector orphaned_bbs;
	rz_pvector_init(&orphaned_bbs, (RzPVectorFree)rz_analysis_block_unref);
	RBIter iter;
	RzAnalysisBlock *block;
	rz_rbtree_foreach (analysis->bb_tree, iter, block, RzAnalysisBlock, _rb) {
		if (block->ref <= 1) {
			rz_pvector_push(&orphaned_bbs, block);
			continue;
		}
		rz_analysis_block_unref(block);
	}
	rz_pvector_clear(&orphaned_bbs); // unrefs all

	SUB("meta", rz_serialize_analysis_meta_load(subdb, analysis, res));
	SUB("hints", rz_serialize_analysis_hints_load(subdb, analysis, res));
	SUB("classes", rz_serialize_analysis_classes_load(subdb, analysis, res));
	SUB("types", rz_serialize_analysis_types_load(subdb, analysis, res));
	SUB("zigns", rz_serialize_analysis_sign_load(subdb, analysis, res));
	SUB("imports", rz_serialize_analysis_imports_load(subdb, analysis, res));
	SUB("pins", rz_serialize_analysis_pin_load(subdb, analysis, res));
	SUB("cc", rz_serialize_analysis_cc_load(subdb, analysis, res));

	ret = true;
beach:
	rz_serialize_analysis_diff_parser_free(diff_parser);
	return ret;
}
