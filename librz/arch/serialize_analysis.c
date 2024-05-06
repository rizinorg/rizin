// SPDX-FileCopyrightText: 2020-2021 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_serialize.h>
#include <rz_util/rz_num.h>
#include <rz_vector.h>
#include <rz_type.h>
#include <rz_analysis.h>
#include <rz_core.h>

#include <errno.h>

/*
 *
 * SDB Format:
 *
 * /
 *   /blocks
 *     0x<addr>={size:<ut64>, jump?:<ut64>, fail?:<ut64>, traced?:true, colorize?:<ut32>,
 *               switch_op?:<RzAnalysisSwitchOp>, ninstr:<int>, op_pos?:[<ut16>], sp?:<st64>,
 *               sp_delta?:[<st16>], cmpval:<ut64>, cmpreg?:<str>}
 *   /functions
 *     0x<addr>={name:<str>, bits?:<int>, type:<int>, cc?:<str>, stack:<int>, maxstack:<int>,
 *               ninstr:<int>, pure?:<bool>, bp_frame?:<bool>, bp_off?:<st64>, noreturn?:<bool>,
 *               bbs:[<ut64>], imports?:[<str>], vars?:[<RzAnalysisVar>], labels?: {<str>:<ut64>}}
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
 *   /imports
 *     <str>=i
 *
 * RzAnalysisSwitchOp JSON:
 * {addr:<ut64>, min:<ut64>, max:<ut64>, def:<ut64>, cases:[<RzAnalysisCaseOp>]}
 *
 * RzAnalysisCaseOp JSON:
 * {addr:<ut64>, jump:<ut64>, value:<ut64>}
 *
 * RzAnalysisVar JSON:
 * {name:<str>, type:<str>, stack?:<st64>, reg?:<str>, cmt?:<str>,
 *   accs?: [{off:<st64>, type:"r|w|rw", reg:<str>, sp?:<st64>}], constrs?:[<int>,<ut64>,...]}
 *
 */

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

	// TODO: cond? It's used nowhere...

	if (block->switch_op) {
		pj_k(j, "switch_op");
		rz_serialize_analysis_switch_op_save(j, block->switch_op);
	}

	if (block->ninstr) {
		pj_ki(j, "ninstr", block->ninstr);
	}
	if (block->ninstr > 1) {
		if (block->op_pos) {
			pj_k(j, "op_pos");
			pj_a(j);
			for (size_t i = 0; i < block->ninstr - 1; i++) {
				pj_n(j, block->op_pos[i]);
			}
			pj_end(j);
		}
		if (rz_vector_len(&block->sp_delta)) {
			pj_k(j, "sp_delta");
			pj_a(j);
			for (size_t i = 0; i < block->ninstr; i++) {
				if (i >= rz_vector_len(&block->sp_delta)) {
					break;
				}
				// We save this negated, because most practical sp_delta vals are negative
				// and so we can spare the '-' char.
				pj_N(j, -*(st16 *)rz_vector_index_ptr(&block->sp_delta, i));
			}
			pj_end(j);
		}
	}

	// op_bytes is only java, never set
	// parent_reg_arena is never set

	if (block->sp_entry != RZ_STACK_ADDR_INVALID) {
		// We save this negated, because most practical sp_entry vals are negative
		// and so we can spare the '-' char.
		pj_kN(j, "sp", -block->sp_entry);
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
	BLOCK_FIELD_SWITCH_OP,
	BLOCK_FIELD_NINSTR,
	BLOCK_FIELD_OP_POS,
	BLOCK_FIELD_SP_ENTRY,
	BLOCK_FIELD_SP_DELTA,
	BLOCK_FIELD_CMPVAL,
	BLOCK_FIELD_CMPREG
};

typedef struct {
	RzAnalysis *analysis;
	RzKeyParser *parser;
} BlockLoadCtx;

static bool block_load_cb(void *user, const SdbKv *kv) {
	BlockLoadCtx *ctx = user;

	char *json_str = sdbkv_dup_value(kv);
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
	proto.sp_entry = RZ_STACK_ADDR_INVALID;
	proto.cmpval = UT64_MAX;
	rz_vector_init(&proto.sp_delta, sizeof(st16), NULL, NULL);
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
		case BLOCK_FIELD_SP_ENTRY:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			proto.sp_entry = -child->num.s_value;
			break;
		case BLOCK_FIELD_SP_DELTA: {
			if (child->type != RZ_JSON_ARRAY) {
				break;
			}
			rz_vector_clear(&proto.sp_delta);
			rz_vector_reserve(&proto.sp_delta, child->children.count);
			RzJson *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != RZ_JSON_INTEGER) {
					break;
				}
				st16 val = -baby->num.s_value;
				rz_vector_push(&proto.sp_delta, &val);
			}
			break;
		}
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
	ut64 addr = strtoull(sdbkv_key(kv), NULL, 0);
	if (errno || proto.size == UT64_MAX || (proto.op_pos && proto.op_pos_size != proto.ninstr - 1)) { // op_pos_size > ninstr - 1 is legal but we require the format to be like this.
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
	block->switch_op = proto.switch_op;
	block->ninstr = proto.ninstr;
	if (proto.op_pos) {
		free(block->op_pos);
		block->op_pos = proto.op_pos;
		block->op_pos_size = proto.op_pos_size;
	}
	block->sp_entry = proto.sp_entry;
	rz_vector_fini(&block->sp_delta); // This should be a nop with a new block, but let's be safe
	block->sp_delta = proto.sp_delta;
	block->cmpval = proto.cmpval;
	block->cmpreg = proto.cmpreg;

	return true;
error:
	rz_analysis_switch_op_free(proto.switch_op);
	free(proto.op_pos);
	rz_vector_fini(&proto.sp_delta);
	return false;
}

RZ_API bool rz_serialize_analysis_blocks_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	BlockLoadCtx ctx = { analysis, rz_key_parser_new() };
	if (!ctx.parser) {
		RZ_SERIALIZE_ERR(res, "parser init failed");
		return false;
	}
	rz_key_parser_add(ctx.parser, "size", BLOCK_FIELD_SIZE);
	rz_key_parser_add(ctx.parser, "jump", BLOCK_FIELD_JUMP);
	rz_key_parser_add(ctx.parser, "fail", BLOCK_FIELD_FAIL);
	rz_key_parser_add(ctx.parser, "traced", BLOCK_FIELD_TRACED);
	rz_key_parser_add(ctx.parser, "colorize", BLOCK_FIELD_COLORIZE);
	rz_key_parser_add(ctx.parser, "switch_op", BLOCK_FIELD_SWITCH_OP);
	rz_key_parser_add(ctx.parser, "ninstr", BLOCK_FIELD_NINSTR);
	rz_key_parser_add(ctx.parser, "op_pos", BLOCK_FIELD_OP_POS);
	rz_key_parser_add(ctx.parser, "sp", BLOCK_FIELD_SP_ENTRY);
	rz_key_parser_add(ctx.parser, "sp_delta", BLOCK_FIELD_SP_DELTA);
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
	rz_return_if_fail(j && var);
	char *vartype = rz_type_as_string(var->fcn->analysis->typedb, var->type);
	if (!vartype) {
		RZ_LOG_ERROR("Variable \"%s\" has undefined type\n", var->name);
		return;
	}
	pj_o(j);
	pj_ks(j, "name", var->name);
	// TODO: Save it properly instead of using the C representation
	pj_ks(j, "type", vartype);
	free(vartype);

	if (var->kind != RZ_ANALYSIS_VAR_KIND_INVALID) {
		pj_ks(j, "kind", rz_analysis_var_kind_as_string(var->kind));
	}
	rz_analysis_var_storage_dump_pj(j, var, &var->storage);

	if (var->origin.kind != RZ_ANALYSIS_VAR_ORIGIN_NONE) {
		pj_ks(j, "origin", rz_analysis_var_origin_kind_as_string(var->origin.kind));
		if (var->origin.kind == RZ_ANALYSIS_VAR_ORIGIN_DWARF) {
			pj_kn(j, "dw_var", var->origin.dw_var->offset);
		}
	}

	if (var->comment) {
		pj_ks(j, "cmt", var->comment);
	}
	if (!rz_vector_empty(&var->accesses)) {
		pj_ka(j, "accs");
		RzAnalysisVarAccess *acc;
		rz_vector_foreach (&var->accesses, acc) {
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
			if (acc->reg_addend) {
				pj_kN(j, "sp", acc->reg_addend);
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
		RzTypeConstraint *constr;
		rz_vector_foreach (&var->constraints, constr) {
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
	VAR_FIELD_STACK,
	VAR_FIELD_REG,
	VAR_FIELD_COMMENT,
	VAR_FIELD_ACCS,
	VAR_FIELD_CONSTRS,
	VAR_FIELD_STORAGE,
	VAR_FIELD_KIND,
	VAR_FIELD_ORIGIN,
	VAR_FIELD_DW_VAR,
};

RZ_API RzSerializeAnalysisVarParser rz_serialize_analysis_var_parser_new(void) {
	RzKeyParser *parser = rz_key_parser_new();
	if (!parser) {
		return NULL;
	}
	rz_key_parser_add(parser, "name", VAR_FIELD_NAME);
	rz_key_parser_add(parser, "type", VAR_FIELD_TYPE);
	rz_key_parser_add(parser, "stack", VAR_FIELD_STACK);
	rz_key_parser_add(parser, "reg", VAR_FIELD_REG);
	rz_key_parser_add(parser, "storage", VAR_FIELD_STORAGE);
	rz_key_parser_add(parser, "cmt", VAR_FIELD_COMMENT);
	rz_key_parser_add(parser, "accs", VAR_FIELD_ACCS);
	rz_key_parser_add(parser, "constrs", VAR_FIELD_CONSTRS);
	rz_key_parser_add(parser, "kind", VAR_FIELD_KIND);
	rz_key_parser_add(parser, "origin", VAR_FIELD_ORIGIN);
	rz_key_parser_add(parser, "dw_var", VAR_FIELD_DW_VAR);
	return parser;
}

RZ_API void rz_serialize_analysis_var_parser_free(RzSerializeAnalysisVarParser parser) {
	rz_key_parser_free(parser);
}

RZ_API RZ_OWN RzAnalysisVar *rz_serialize_analysis_var_load(
	RZ_NONNULL RzSerializeAnalysisFunctionLoadCtx *ctx,
	RZ_NONNULL RzAnalysisFunction *fcn,
	RZ_NONNULL const RzJson *json) {
	if (json->type != RZ_JSON_OBJECT) {
		return NULL;
	}
	const char *name = NULL;
	const char *type = NULL;
	bool have_storage = false;
	RzAnalysisVarStorage storage = { 0 };
	const char *comment = NULL;
	RzVector accesses;
	rz_vector_init(&accesses, sizeof(RzAnalysisVarAccess), NULL, NULL);
	RzVector constraints;
	rz_vector_init(&constraints, sizeof(RzTypeConstraint), NULL, NULL);

	RzAnalysisVar *ret = NULL;
	RzAnalysisVarKind k = RZ_ANALYSIS_VAR_KIND_INVALID;
	RzAnalysisVarOriginKind origin_kind = RZ_ANALYSIS_VAR_ORIGIN_NONE;
	ut64 dw_var = UT64_MAX;

	RZ_KEY_PARSER_JSON(ctx->var_parser, json, child, {
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
		case VAR_FIELD_STACK:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			storage.type = RZ_ANALYSIS_VAR_STORAGE_STACK;
			storage.stack_off = child->num.s_value;
			have_storage = true;
			break;
		case VAR_FIELD_REG:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			storage.type = RZ_ANALYSIS_VAR_STORAGE_REG;
			storage.reg = child->str_value;
			have_storage = true;
			break;
		case VAR_FIELD_STORAGE:
			if (child->type != RZ_JSON_OBJECT) {
				break;
			}
			if (!rz_serialize_analysis_var_storage_load(ctx, child, &storage)) {
				break;
			}
			have_storage = true;
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
				acc->reg_addend = spv ? spv->num.s_value : 0;
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
				RzTypeConstraint constr;
				constr.cond = (RzTypeCond)baby->num.s_value;
				constr.val = sibling->num.u_value;
				if (constr.cond < RZ_TYPE_COND_AL || constr.cond > RZ_TYPE_COND_LS) {
					baby = sibling;
					continue;
				}
				rz_vector_push(&constraints, &constr);
				baby = sibling;
			}
			break;
		}
		case VAR_FIELD_KIND: {
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			k = rz_analysis_var_kind_from_string(child->str_value);
			break;
		}
		case VAR_FIELD_ORIGIN:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			origin_kind = rz_analysis_var_origin_kind_from_string(child->str_value);
			break;
		case VAR_FIELD_DW_VAR:
			if (child->type != RZ_JSON_INTEGER || origin_kind != RZ_ANALYSIS_VAR_ORIGIN_DWARF) {
				break;
			}
			dw_var = child->num.u_value;
			break;
		default:
			break;
	})

	if (!name || !type || !have_storage) {
		goto beach;
	}
	char *error_msg = NULL;
	RzType *vartype = rz_type_parse_string_single(fcn->analysis->typedb->parser, type, &error_msg);
	if (!vartype || error_msg) {
		RZ_LOG_ERROR("Fail to parse the function variable (\"%s\") type: %s\n", name, type);
		free(error_msg);
		goto beach;
	}

	if (origin_kind == RZ_ANALYSIS_VAR_ORIGIN_NONE) {
		ret = rz_analysis_function_set_var(fcn, &storage, vartype, 0, name);
		rz_type_free(vartype);
	} else {
		ret = RZ_NEW0(RzAnalysisVar);
		if (!ret) {
			goto beach;
		}
		ret->name = strdup(name);
		ret->type = vartype;
		ret->fcn = fcn;
		rz_mem_copy(&ret->storage, sizeof(RzAnalysisVarStorage), &storage, sizeof(RzAnalysisVarStorage));
		ret->origin.kind = origin_kind;
		if (origin_kind == RZ_ANALYSIS_VAR_ORIGIN_DWARF) {
			ret->origin.dw_var = ht_up_find(ctx->analysis->debug_info->variable_by_offset, dw_var, NULL);
		}
		ret = rz_analysis_function_add_var(fcn, ret);
	}
	if (!ret) {
		goto beach;
	}

	ret->kind = k;
	if (comment) {
		free(ret->comment);
		ret->comment = strdup(comment);
	}
	RzAnalysisVarAccess *acc;
	rz_vector_foreach (&accesses, acc) {
		rz_analysis_var_set_access(ret, acc->reg, fcn->addr + acc->offset, acc->type, acc->reg_addend);
	}
	RzTypeConstraint *constr;
	rz_vector_foreach (&constraints, constr) {
		rz_analysis_var_add_constraint(ret, constr);
	}

beach:
	rz_vector_fini(&accesses);
	rz_vector_fini(&constraints);
	return ret;
}

enum {
	VAR_STORAGE_FIELD_TYPE,
	VAR_STORAGE_FIELD_STACK,
	VAR_STORAGE_FIELD_REG,
	VAR_STORAGE_FIELD_COMPOSITE,
	VAR_STORAGE_FIELD_EVAL_PENDING,
};

RZ_API RzSerializeAnalysisVarParser rz_serialize_analysis_var_storage_parser_new(void) {
	RzKeyParser *parser = rz_key_parser_new();
	if (!parser) {
		return NULL;
	}
	rz_key_parser_add(parser, "type", VAR_STORAGE_FIELD_TYPE);
	rz_key_parser_add(parser, "stack", VAR_STORAGE_FIELD_STACK);
	rz_key_parser_add(parser, "reg", VAR_STORAGE_FIELD_REG);
	rz_key_parser_add(parser, "composite", VAR_STORAGE_FIELD_COMPOSITE);
	rz_key_parser_add(parser, "eval_pending", VAR_STORAGE_FIELD_EVAL_PENDING);
	return parser;
}

enum {
	VAR_STORAGE_PIECE_FIELD_OFFSET,
	VAR_STORAGE_PIECE_FIELD_SIZE,
	VAR_STORAGE_PIECE_FIELD_STORAGE,
};

RzKeyParser *rz_serialize_analysis_var_piece_parser_new() {
	RzKeyParser *parser = rz_key_parser_new();
	if (!parser) {
		return NULL;
	}
	rz_key_parser_add(parser, "offset_in_bits", VAR_STORAGE_PIECE_FIELD_OFFSET);
	rz_key_parser_add(parser, "size_in_bits", VAR_STORAGE_PIECE_FIELD_SIZE);
	rz_key_parser_add(parser, "storage", VAR_STORAGE_PIECE_FIELD_STORAGE);
	return parser;
}

static bool piece_load(
	RZ_NONNULL RzSerializeAnalysisFunctionLoadCtx *ctx,
	RZ_NONNULL const RzJson *json,
	RzAnalysisVarStoragePiece *p) {
	RZ_KEY_PARSER_JSON(ctx->piece_parser, json, child, {
		case VAR_STORAGE_PIECE_FIELD_OFFSET:
			if (child->type != RZ_JSON_INTEGER) {
				return false;
			}
			p->offset_in_bits = child->num.u_value;
			break;
		case VAR_STORAGE_PIECE_FIELD_SIZE:
			if (child->type != RZ_JSON_INTEGER) {
				return false;
			}
			p->size_in_bits = child->num.u_value;
			break;
		case VAR_STORAGE_PIECE_FIELD_STORAGE:
			if (child->type != RZ_JSON_OBJECT) {
				return false;
			}
			p->storage = RZ_NEW0(RzAnalysisVarStorage);
			if (!rz_serialize_analysis_var_storage_load(ctx, child, p->storage)) {
				return false;
			}
			break;
		default:
			rz_warn_if_reached();
			break;
	});
	return true;
}

/**
 * \brief Load variable storage from a JSON object
 * \param parser RzKeyParser to parse the storage JSON object
 * \param json JSON object to parse
 * \param storage Output variable storage
 * \return true if the storage was successfully loaded, false otherwise
 */
RZ_API bool rz_serialize_analysis_var_storage_load(
	RZ_NONNULL RzSerializeAnalysisFunctionLoadCtx *ctx,
	RZ_NONNULL const RzJson *json,
	RZ_NONNULL RZ_BORROW RZ_OUT RzAnalysisVarStorage *storage) {
	RZ_KEY_PARSER_JSON(ctx->storage_parser, json, child, {
		case VAR_STORAGE_FIELD_TYPE: {
			if (child->type != RZ_JSON_STRING) {
				return false;
			}
			const char *type = child->str_value;
			if (!rz_analysis_var_storage_type_from_string(type, &storage->type)) {
				return false;
			}
			break;
		}
		case VAR_STORAGE_FIELD_STACK:
			if (child->type != RZ_JSON_INTEGER || storage->type != RZ_ANALYSIS_VAR_STORAGE_STACK) {
				return false;
			}
			storage->stack_off = child->num.s_value;
			break;
		case VAR_STORAGE_FIELD_REG:
			if (child->type != RZ_JSON_STRING || !(storage->type == RZ_ANALYSIS_VAR_STORAGE_REG)) {
				return false;
			}
			storage->reg = child->str_value;
			break;
		case VAR_STORAGE_FIELD_COMPOSITE:
			if (child->type != RZ_JSON_ARRAY || storage->type != RZ_ANALYSIS_VAR_STORAGE_COMPOSITE) {
				return false;
			}
			rz_analysis_var_storage_init_composite(storage);
			RzJson *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != RZ_JSON_OBJECT) {
					RZ_LOG_WARN("Composite variable storage piece is not an object\n");
					return false;
				}
				RzAnalysisVarStoragePiece p = { 0 };
				if (!piece_load(ctx, baby, &p)) {
					RZ_LOG_WARN("Failed to load composite variable storage piece\n");
					rz_analysis_var_storage_piece_fini(&p);
					return false;
				}
				rz_vector_push(storage->composite, &p);
			}
			break;
		case VAR_STORAGE_FIELD_EVAL_PENDING:
			if (child->type != RZ_JSON_INTEGER || storage->type != RZ_ANALYSIS_VAR_STORAGE_EVAL_PENDING) {
				return false;
			}
			storage->dw_var_off = child->num.u_value;
			break;
		default:
			RZ_LOG_WARN("Unimplemented field \"%s\" in variable storage\n", child->key);
			break;
	});
	rz_analysis_var_storage_poolify(ctx->analysis, storage);
	return json->type == RZ_JSON_OBJECT && storage->type <= RZ_ANALYSIS_VAR_STORAGE_EVAL_PENDING;
}

RZ_API void rz_serialize_analysis_global_var_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *a) {
	rz_return_if_fail(db && a);

	PJ *j = pj_new();
	if (!j) {
		return;
	}
	RBIter it;
	RzAnalysisVarGlobal *var;
	char *vartype;
	rz_rbtree_foreach (a->global_var_tree, it, var, RzAnalysisVarGlobal, rb) {
		vartype = rz_type_as_string(a->typedb, var->type);
		if (!vartype) {
			RZ_LOG_ERROR("Global variable \"%s\" has undefined type\n", var->name);
			pj_free(j);
			return;
		}
		char addr[32];
		rz_strf(addr, "0x%" PFMT64x, var->addr);
		pj_o(j);
		pj_ks(j, "name", var->name);
		pj_ks(j, "addr", addr);
		// TODO: Save it properly instead of using the C representation
		pj_ks(j, "type", vartype);
		free(vartype);
		if (!rz_vector_empty(&var->constraints)) {
			pj_ka(j, "constrs");
			RzTypeConstraint *constr;
			rz_vector_foreach (&var->constraints, constr) {
				pj_i(j, (int)constr->cond);
				pj_n(j, constr->val);
			}
			pj_end(j);
		}
		pj_end(j);

		sdb_set(db, addr, pj_string(j), 0);
		pj_reset(j);
	}
	pj_free(j);
}

enum {
	GLOBAL_VAR_FIELD_NAME,
	GLOBAL_VAR_FIELD_ADDR,
	GLOBAL_VAR_FIELD_TYPE,
	GLOBAL_VAR_FIELD_CONSTRS
};

RZ_API RzSerializeAnalysisGlobalVarParser rz_serialize_analysis_global_var_parser_new(void) {
	RzKeyParser *parser = rz_key_parser_new();
	if (!parser) {
		return NULL;
	}
	rz_key_parser_add(parser, "name", GLOBAL_VAR_FIELD_NAME);
	rz_key_parser_add(parser, "addr", GLOBAL_VAR_FIELD_ADDR);
	rz_key_parser_add(parser, "type", GLOBAL_VAR_FIELD_TYPE);
	rz_key_parser_add(parser, "constrs", GLOBAL_VAR_FIELD_CONSTRS);
	return parser;
}

RZ_API void rz_serialize_analysis_global_var_parser_free(RzSerializeAnalysisGlobalVarParser parser) {
	rz_key_parser_free(parser);
}

typedef struct {
	RzAnalysis *analysis;
	RzKeyParser *parser;
} GlobalVarCtx;

static bool global_var_load_cb(void *user, const SdbKv *kv) {
	GlobalVarCtx *ctx = user;

	char *json_str = sdbkv_dup_value(kv);
	if (!json_str) {
		return true;
	}
	RzJson *json = rz_json_parse(json_str);
	if (!json || json->type != RZ_JSON_OBJECT) {
		free(json_str);
		return false;
	}

	const char *name = NULL;
	const char *type = NULL;
	const char *addr_s = NULL;
	ut64 addr = 0;
	RzVector constraints;
	rz_vector_init(&constraints, sizeof(RzTypeConstraint), NULL, NULL);

	RzAnalysisVarGlobal *glob = NULL;

	RZ_KEY_PARSER_JSON(ctx->parser, json, child, {
		case GLOBAL_VAR_FIELD_NAME:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			name = child->str_value;
			break;
		case GLOBAL_VAR_FIELD_ADDR:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			addr_s = child->str_value;
			break;
		case GLOBAL_VAR_FIELD_TYPE:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			type = child->str_value;
			break;
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
				RzTypeConstraint constr;
				constr.cond = (RzTypeCond)baby->num.s_value;
				constr.val = sibling->num.u_value;
				if (constr.cond < RZ_TYPE_COND_AL || constr.cond > RZ_TYPE_COND_LS) {
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

	if (!name || !type) {
		goto beach;
	}
	char *error_msg = NULL;
	RzType *vartype = rz_type_parse_string_single(ctx->analysis->typedb->parser, type, &error_msg);
	if (error_msg) {
		RZ_LOG_ERROR("Fail to parse the function variable (\"%s\") type: %s\n", name, type);
		RZ_FREE(error_msg);
		goto beach;
	}
	RzCore *core = ctx->analysis->core;
	addr = rz_num_math(core->num, addr_s);
	if (rz_analysis_var_global_get_byaddr_in(ctx->analysis, addr) ||
		rz_analysis_var_global_get_byname(ctx->analysis, name)) {
		return true;
	}

	glob = rz_analysis_var_global_new(name, addr);
	if (!glob) {
		goto beach;
	}
	rz_analysis_var_global_set_type(glob, vartype);

	RzTypeConstraint *constr;
	rz_vector_foreach (&constraints, constr) {
		rz_analysis_var_global_add_constraint(glob, constr);
	}
	return rz_analysis_var_global_add(ctx->analysis, glob);

beach:
	rz_vector_fini(&constraints);
	return false;
}

RZ_API bool rz_serialize_analysis_global_var_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	GlobalVarCtx ctx = {
		.analysis = analysis,
		.parser = rz_serialize_analysis_global_var_parser_new(),
	};
	bool ret;
	if (!ctx.parser) {
		RZ_SERIALIZE_ERR(res, "parser init failed");
		ret = false;
		goto beach;
	}
	ret = sdb_foreach(db, global_var_load_cb, &ctx);
	if (!ret) {
		RZ_SERIALIZE_ERR(res, "global var parsing failed");
	}
beach:
	rz_key_parser_free(ctx.parser);
	return ret;
}

static bool store_label_cb(void *j, const ut64 k, const void *v) {
	pj_kn(j, v, k);
	return true;
}

static void function_store(RZ_NONNULL Sdb *db, const char *key, RzAnalysisFunction *function) {
	RzAnalysisBlock *block;
	RzListIter *lit;
	void **vit;
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

	pj_ka(j, "bbs");
	rz_pvector_foreach (function->bbs, vit) {
		block = (RzAnalysisBlock *)*vit;
		pj_n(j, block->addr);
	}
	pj_end(j);

	if (!rz_list_empty(function->imports)) {
		pj_ka(j, "imports");
		const char *import;
		rz_list_foreach (function->imports, lit, import) {
			pj_s(j, import);
		}
		pj_end(j);
	}

	if (!rz_pvector_empty(&function->vars)) {
		pj_ka(j, "vars");
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
	FUNCTION_FIELD_BBS,
	FUNCTION_FIELD_IMPORTS,
	FUNCTION_FIELD_VARS,
	FUNCTION_FIELD_LABELS
};

static bool function_load_cb(void *user, const SdbKv *kv) {
	RzSerializeAnalysisFunctionLoadCtx *ctx = user;

	char *json_str = sdbkv_dup_value(kv);
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
	function->addr = strtoull(sdbkv_key(kv), NULL, 0);
	if (errno || !function->name || !rz_analysis_add_function(ctx->analysis, function)) {
		rz_analysis_function_free(function);
		ret = false;
		goto beach;
	}
	function->is_noreturn = noreturn; // Can't set directly, rz_analysis_add_function() overwrites it

	if (vars_json) {
		RzJson *baby;
		for (baby = vars_json->children.first; baby; baby = baby->next) {
			rz_serialize_analysis_var_load(ctx, function, baby);
		}
	}

beach:
	rz_json_free(json);
	free(json_str);
	return ret;
}

RZ_API bool rz_serialize_analysis_functions_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	RzSerializeAnalysisFunctionLoadCtx ctx = {
		.analysis = analysis,
		.parser = rz_key_parser_new(),
		.var_parser = rz_serialize_analysis_var_parser_new(),
		.storage_parser = rz_serialize_analysis_var_storage_parser_new(),
		.piece_parser = rz_serialize_analysis_var_piece_parser_new(),
	};
	bool ret;
	if (!(ctx.parser && ctx.var_parser && ctx.storage_parser)) {
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
	rz_key_parser_free(ctx.storage_parser);
	return ret;
}

RZ_API void rz_serialize_analysis_function_noreturn_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis) {
	sdb_copy(analysis->sdb_noret, db);
}

RZ_API bool rz_serialize_analysis_function_noreturn_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	sdb_reset(analysis->sdb_noret);
	sdb_copy(db, analysis->sdb_noret);
	return true;
}

static bool store_xref_cb(void *j, const ut64 k, const void *v) {
	const RzAnalysisXRef *xref = v;
	pj_o(j);
	pj_kn(j, "to", k);
	if (xref->type != RZ_ANALYSIS_XREF_TYPE_NULL) {
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
	ht_up_foreach(analysis->ht_xrefs_from, store_xrefs_list_cb, db);
}

static bool xrefs_load_cb(void *user, const SdbKv *kv) {
	RzAnalysis *analysis = user;

	errno = 0;
	ut64 from = strtoull(sdbkv_key(kv), NULL, 0);
	if (errno) {
		return false;
	}

	char *json_str = sdbkv_dup_value(kv);
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

		RzAnalysisXRefType type = RZ_ANALYSIS_XREF_TYPE_NULL;
		baby = rz_json_get(child, "type");
		if (baby) {
			// must be a 1-char string
			if (baby->type != RZ_JSON_STRING || !baby->str_value[0] || baby->str_value[1]) {
				goto error;
			}
			switch (baby->str_value[0]) {
			case RZ_ANALYSIS_XREF_TYPE_CODE:
			case RZ_ANALYSIS_XREF_TYPE_CALL:
			case RZ_ANALYSIS_XREF_TYPE_DATA:
			case RZ_ANALYSIS_XREF_TYPE_STRING:
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

	if (rz_interval_tree_empty(&analysis->meta)) {
		return;
	}

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

static bool meta_load_cb(void *user, const SdbKv *kv) {
	RzAnalysis *analysis = user;

	errno = 0;
	ut64 addr = strtoull(sdbkv_key(kv), NULL, 0);
	if (errno) {
		return false;
	}

	char *json_str = sdbkv_dup_value(kv);
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
		rz_vector_foreach (h->addr_hints, record) {
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
	HtUP /*<HintsAtAddr *>*/ *acc = ht_up_new(NULL, free);
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

static bool hints_load_cb(void *user, const SdbKv *kv) {
	HintsLoadCtx *ctx = user;
	RzAnalysis *analysis = ctx->analysis;

	errno = 0;
	ut64 addr = strtoull(sdbkv_key(kv), NULL, 0);
	if (errno) {
		return false;
	}

	char *json_str = sdbkv_dup_value(kv);
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
	rz_serialize_types_save(db, analysis->typedb);
}

RZ_API bool rz_serialize_analysis_types_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	return rz_serialize_types_load(db, analysis->typedb, res);
}

RZ_API void rz_serialize_analysis_callables_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis) {
	rz_serialize_callables_save(db, analysis->typedb);
}

RZ_API bool rz_serialize_analysis_callables_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	return rz_serialize_callables_load(db, analysis->typedb, res);
}

RZ_API void rz_serialize_analysis_imports_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis) {
	RzListIter *it;
	const char *imp;
	rz_list_foreach (analysis->imports, it, imp) {
		sdb_set(db, imp, "i", 0);
	}
}

static bool import_load_cb(void *user, const SdbKv *kv) {
	rz_analysis_add_import(user, sdbkv_key(kv));
	return true;
}

RZ_API bool rz_serialize_analysis_imports_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	return sdb_foreach(db, import_load_cb, analysis);
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
	rz_serialize_analysis_function_noreturn_save(sdb_ns(db, "noreturn", true), analysis);
	rz_serialize_analysis_meta_save(sdb_ns(db, "meta", true), analysis);
	rz_serialize_analysis_hints_save(sdb_ns(db, "hints", true), analysis);
	rz_serialize_analysis_classes_save(sdb_ns(db, "classes", true), analysis);
	rz_serialize_analysis_types_save(sdb_ns(db, "types", true), analysis);
	rz_serialize_analysis_callables_save(sdb_ns(db, "callables", true), analysis);
	rz_serialize_analysis_imports_save(sdb_ns(db, "imports", true), analysis);
	rz_serialize_analysis_cc_save(sdb_ns(db, "cc", true), analysis);
	rz_serialize_analysis_global_var_save(sdb_ns(db, "vars", true), analysis);
}

RZ_API bool rz_serialize_analysis_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzSerializeResultInfo *res) {
	bool ret = false;
	Sdb *subdb = NULL;

	rz_analysis_purge(analysis);

#define SUB(ns, call) RZ_SERIALIZE_SUB_DO(db, subdb, res, ns, call, goto beach;)
	SUB("xrefs", rz_serialize_analysis_xrefs_load(subdb, analysis, res));

	SUB("blocks", rz_serialize_analysis_blocks_load(subdb, analysis, res));

	SUB("classes", rz_serialize_analysis_classes_load(subdb, analysis, res));
	SUB("types", rz_serialize_analysis_types_load(subdb, analysis, res));
	SUB("callables", rz_serialize_analysis_callables_load(subdb, analysis, res));

	// All bbs have ref=1 now
	SUB("functions", rz_serialize_analysis_functions_load(subdb, analysis, res));
	SUB("noreturn", rz_serialize_analysis_function_noreturn_load(subdb, analysis, res));
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
	SUB("imports", rz_serialize_analysis_imports_load(subdb, analysis, res));
	SUB("cc", rz_serialize_analysis_cc_load(subdb, analysis, res));
	SUB("vars", rz_serialize_analysis_global_var_load(subdb, analysis, res));

	ret = true;
beach:
	return ret;
}
