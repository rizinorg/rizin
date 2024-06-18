// SPDX-FileCopyrightText: 2010-2021 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_asm.h>
#include <rz_util/rz_log.h>
#include <rz_util/rz_regex.h>
#include <rz_rop.h>

RzRopGadgetInfo *create_gadget_info(ut64 address);

RzRopGadgetInfo *create_gadget_info(ut64 address) {
	RzRopGadgetInfo *info = RZ_NEW0(RzRopGadgetInfo);
	if (!info) {
		return NULL;
	}
	info->address = address;
	info->stack_change = 0x8;
	info->modified_registers = rz_list_newf(free);
	info->memory_write.dependencies = rz_list_newf(free);
	info->memory_write.stored_in_regs = rz_list_newf(free);
	info->memory_read.dependencies = rz_list_newf(free);
	info->memory_read.stored_in_regs = rz_list_newf(free);
	return info;
}

void free_gadget_info(RzRopGadgetInfo *info) {
	if (!info) {
		return;
	}
	rz_list_free(info->modified_registers);
	rz_list_free(info->memory_write.dependencies);
	rz_list_free(info->memory_write.stored_in_regs);
	rz_list_free(info->memory_read.dependencies);
	rz_list_free(info->memory_read.stored_in_regs);

	free(info);
}

void merge_gadget_info(RzCore *core, RzRopGadgetInfo *dest, RzRopGadgetInfo *src) {
	RzListIter *iter;
	char *data;
	rz_list_foreach (src->modified_registers, iter, data) {
		add_reg_to_list(core, dest->modified_registers, data);
	}
	rz_list_foreach (src->memory_write.dependencies, iter, data) {
		add_reg_to_list(core, dest->memory_write.dependencies, data);
	}
	rz_list_foreach (src->memory_write.stored_in_regs, iter, data) {
		add_reg_to_list(core, dest->memory_write.stored_in_regs, data);
	}
	rz_list_foreach (src->memory_read.dependencies, iter, data) {
		add_reg_to_list(core, dest->memory_read.dependencies, data);
	}
	rz_list_foreach (src->memory_read.stored_in_regs, iter, data) {
		add_reg_to_list(core, dest->memory_read.stored_in_regs, data);
	}
	dest->stack_change += src->stack_change;
}

RZ_API void process_gadget(RzCore *core, RzRopGadgetInfo *gadget_info, RzILOpEffect *effects, ut64 addr) {
	RzRopGadgetInfo *temp_info = create_gadget_info(addr);
	populate_gadget_info(core, temp_info, effects);
	merge_gadget_info(core, gadget_info, temp_info);
	free_gadget_info(temp_info);
}

static bool is_end_gadget(const RzAnalysisOp *aop, const ut8 crop) {
	if (aop->family == RZ_ANALYSIS_OP_FAMILY_SECURITY) {
		return false;
	}
	switch (aop->type) {
	case RZ_ANALYSIS_OP_TYPE_TRAP:
	case RZ_ANALYSIS_OP_TYPE_RET:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
	case RZ_ANALYSIS_OP_TYPE_RCALL:
	case RZ_ANALYSIS_OP_TYPE_ICALL:
	case RZ_ANALYSIS_OP_TYPE_IRCALL:
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_RJMP:
	case RZ_ANALYSIS_OP_TYPE_IJMP:
	case RZ_ANALYSIS_OP_TYPE_IRJMP:
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_CALL:
		return true;
	}
	if (crop) { // if conditional jumps, calls and returns should be used for the gadget-search too
		switch (aop->type) {
		case RZ_ANALYSIS_OP_TYPE_CJMP:
		case RZ_ANALYSIS_OP_TYPE_UCJMP:
		case RZ_ANALYSIS_OP_TYPE_CCALL:
		case RZ_ANALYSIS_OP_TYPE_UCCALL:
		case RZ_ANALYSIS_OP_TYPE_CRET:
			return true;
		}
	}
	return false;
}

static int rz_rop_process_asm_op(RzCore *core, RzCoreAsmHit *hit, RzAsmOp *asmop, RzAnalysisOp *aop, unsigned int *size, char **asmop_str, char **asmop_hex_str) {
	ut8 *buf = malloc(hit->len);
	if (!buf) {
		return -1;
	}
	rz_io_read_at(core->io, hit->addr, buf, hit->len);
	rz_asm_set_pc(core->rasm, hit->addr);
	rz_asm_disassemble(core->rasm, asmop, buf, hit->len);
	rz_analysis_op_init(aop);
	rz_analysis_op(core->analysis, aop, hit->addr, buf, hit->len, RZ_ANALYSIS_OP_MASK_ESIL);
	*size += hit->len;

	// Append assembly operation string
	if (asmop_str) {
		*asmop_str = rz_str_append(*asmop_str, rz_asm_op_get_asm(asmop));
		*asmop_str = rz_str_append(*asmop_str, "; ");
	}

	// Append hex string of assembly operation
	if (asmop_hex_str) {
		char *asmop_hex = rz_asm_op_get_hex(asmop);
		*asmop_hex_str = rz_str_append(*asmop_hex_str, asmop_hex);
		free(asmop_hex);
	}

	free(buf);
	return 0;
}

static int rz_rop_print_table_mode(RzCore *core, RzCoreAsmHit *hit, RzList *hitlist, RzAsmOp *asmop, unsigned int *size, char **asmop_str, char **asmop_hex_str) {
	RzAnalysisOp aop = RZ_EMPTY;
	if (rz_rop_process_asm_op(core, hit, asmop, &aop, size, asmop_str, asmop_hex_str) != 0) {
		return -1;
	}
	const ut64 addr_last = ((RzCoreAsmHit *)rz_list_last(hitlist))->addr;
	if (addr_last != hit->addr) {
		*asmop_str = rz_str_append(*asmop_str, "; ");
	}
	rz_analysis_op_fini(&aop);
	return 0;
}

static int rz_rop_print_quiet_mode(RzCore *core, RzCoreAsmHit *hit, RzList *ropList, RzAsmOp *asmop, unsigned int *size, bool esil, bool colorize) {
	RzAnalysisOp aop = RZ_EMPTY;
	if (rz_rop_process_asm_op(core, hit, asmop, &aop, size, NULL, NULL) != 0) {
		return -1;
	}
	const char *opstr = RZ_STRBUF_SAFEGET(&aop.esil);
	if (aop.type != RZ_ANALYSIS_OP_TYPE_RET) {
		rz_list_append(ropList, rz_str_newf(" %s", opstr));
	}
	if (esil) {
		rz_cons_printf("%s\n", opstr);
	} else if (colorize) {
		RzStrBuf *bw_str = rz_strbuf_new(rz_asm_op_get_asm(asmop));
		RzAsmParseParam *param = rz_asm_get_parse_param(core->analysis->reg, aop.type);
		RzStrBuf *colored_asm = rz_asm_colorize_asm_str(bw_str, core->print, param, asmop->asm_toks);
		rz_asm_parse_param_free(param);
		rz_cons_printf(" %s%s;", colored_asm ? rz_strbuf_get(colored_asm) : "", Color_RESET);
		rz_strbuf_free(colored_asm);
		rz_strbuf_free(bw_str);
	} else {
		rz_cons_printf(" %s;", rz_asm_op_get_asm(asmop));
	}
	rz_analysis_op_fini(&aop);
	return 0;
}

static int rz_rop_print_standard_mode(RzCore *core, RzCoreAsmHit *hit, RzList *ropList, RzAsmOp *asmop, unsigned int *size, bool rop_comments, bool colorize) {
	RzAnalysisOp aop = RZ_EMPTY;
	if (rz_rop_process_asm_op(core, hit, asmop, &aop, size, NULL, NULL) != 0) {
		return -1;
	}
	const char *comment = rop_comments ? rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, hit->addr) : NULL;
	if (aop.type != RZ_ANALYSIS_OP_TYPE_RET) {
		char *opstr_n = rz_str_newf(" %s", RZ_STRBUF_SAFEGET(&aop.esil));
		rz_list_append(ropList, opstr_n);
	}
	char *asm_op_hex = rz_asm_op_get_hex(asmop);
	if (colorize) {
		RzStrBuf *bw_str = rz_strbuf_new(rz_asm_op_get_asm(asmop));
		RzAsmParseParam *param = rz_asm_get_parse_param(core->analysis->reg, aop.type);
		RzStrBuf *colored_asm = rz_asm_colorize_asm_str(bw_str, core->print, param, asmop->asm_toks);
		rz_asm_parse_param_free(param);
		if (comment) {
			rz_cons_printf("  0x%08" PFMT64x " %18s  %s%s ; %s\n",
				hit->addr, asm_op_hex, colored_asm ? rz_strbuf_get(colored_asm) : "", Color_RESET, comment);
		} else {
			rz_cons_printf("  0x%08" PFMT64x " %18s  %s%s\n",
				hit->addr, asm_op_hex, colored_asm ? rz_strbuf_get(colored_asm) : "", Color_RESET);
		}
		rz_strbuf_free(colored_asm);
		rz_strbuf_free(bw_str);
	} else {
		if (comment) {
			rz_cons_printf("  0x%08" PFMT64x " %18s  %s ; %s\n",
				hit->addr, asm_op_hex, rz_asm_op_get_asm(asmop), comment);
		} else {
			rz_cons_printf("  0x%08" PFMT64x " %18s  %s\n",
				hit->addr, asm_op_hex, rz_asm_op_get_asm(asmop));
		}
	}
	free(asm_op_hex);
	rz_analysis_op_fini(&aop);
	return 0;
}

static int rz_rop_print_json_mode(RzCore *core, RzCoreAsmHit *hit, RzList *ropList, RzCmdStateOutput *state, RzAsmOp *asmop, unsigned int *size) {
	RzAnalysisOp aop = RZ_EMPTY;

	if (rz_rop_process_asm_op(core, hit, asmop, &aop, size, NULL, NULL) != 0) {
		return -1;
	}

	if (aop.type != RZ_ANALYSIS_OP_TYPE_RET) {
		char *opstr_n = rz_str_newf(" %s", RZ_STRBUF_SAFEGET(&aop.esil));
		rz_list_append(ropList, opstr_n);
	}

	pj_o(state->d.pj);
	pj_kn(state->d.pj, "offset", hit->addr);
	pj_ki(state->d.pj, "size", hit->len);
	pj_ks(state->d.pj, "opcode", rz_asm_op_get_asm(asmop));
	pj_ks(state->d.pj, "type", rz_analysis_optype_to_string(aop.type));
	pj_end(state->d.pj);

	rz_analysis_op_fini(&aop);
	return 0;
}

static void print_rop(RzCore *core, RzList /*<RzCoreAsmHit *>*/ *hitlist, RzCmdStateOutput *state) {
	RzCoreAsmHit *hit = NULL;
	RzListIter *iter;
	unsigned int size = 0;
	RzList *ropList = NULL;
	char *asmop_str = NULL, *asmop_hex_str = NULL;
	Sdb *db = NULL;
	const bool colorize = rz_config_get_i(core->config, "scr.color");
	const bool rop_comments = rz_config_get_i(core->config, "rop.comments");
	const bool esil = rz_config_get_i(core->config, "asm.esil");
	const bool rop_db = rz_config_get_i(core->config, "rop.db");
	if (rop_db) {
		db = sdb_ns(core->sdb, "rop", true);
		ropList = rz_list_newf(free);
		if (!db) {
			RZ_LOG_ERROR("core: Could not create SDB 'rop' namespace\n");
			rz_list_free(ropList);
			return;
		}
	}

	rz_cmd_state_output_set_columnsf(state, "XXs", "addr", "bytes", "disasm");
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_o(state->d.pj);
		pj_ka(state->d.pj, "opcodes");
	} else if (state->mode == RZ_OUTPUT_MODE_QUIET) {
		rz_cons_printf("0x%08" PFMT64x ":", ((RzCoreAsmHit *)rz_list_first(hitlist))->addr);
	}
	const ut64 addr = ((RzCoreAsmHit *)rz_list_first(hitlist))->addr;

	rz_list_foreach (hitlist, iter, hit) {
		RzAsmOp *asmop = rz_asm_op_new();
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			if (rz_rop_print_json_mode(core, hit, ropList, state, asmop, &size) != 0) {
				goto cleanup;
			}
			break;
		case RZ_OUTPUT_MODE_QUIET:
			if (rz_rop_print_quiet_mode(core, hit, ropList, asmop, &size, esil, colorize) != 0) {
				goto cleanup;
			}
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			if (rz_rop_print_standard_mode(core, hit, ropList, asmop, &size, rop_comments, colorize) != 0) {
				goto cleanup;
			}
			break;
		case RZ_OUTPUT_MODE_TABLE:
			if (rz_rop_print_table_mode(core, hit, hitlist, asmop, &size, &asmop_str, &asmop_hex_str) != 0) {
				goto cleanup;
			}
			break;
		default:
			rz_warn_if_reached();
			break;
		}
		rz_asm_op_free(asmop);
	}
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		pj_end(state->d.pj);
		if (db && hit) {
			// const char *key = rz_strf(tmpbuf, "0x%08" PFMT64x, addr);
			// rop_classify(core, db, ropList, key, size);
		}
		if (hit) {
			pj_kn(state->d.pj, "retaddr", hit->addr);
			pj_ki(state->d.pj, "size", size);
		}
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_newline();
		break;
		// fallthrough
	case RZ_OUTPUT_MODE_STANDARD:
		if (db && hit) {
			rz_cons_printf("Gadget size: %d\n", (int)size);
			// rop_classify(core, db, ropList, key, size);
			ut8 *buf;
			RzAnalysisOp aop;
			buf = malloc(size + 1);
			hit = rz_list_first(hitlist);
			if (!buf) {
				goto cleanup;
			}
			RzAsmOp *asmop = rz_asm_op_new();
			buf[size] = 0;
			rz_io_read_at(core->io, hit->addr, buf, size);
			rz_asm_set_pc(core->rasm, hit->addr);
			rz_asm_disassemble(core->rasm, asmop, buf, size);
			rz_analysis_op_init(&aop);
			rz_analysis_op(core->analysis, &aop, hit->addr, buf, size, RZ_ANALYSIS_OP_MASK_IL);
			RzRopGadgetInfo *rop_gadget_info = create_gadget_info(hit->addr);
			// TODO: Remove this
			RzStrBuf sb = { 0 };
			rz_strbuf_init(&sb);
			rz_il_op_effect_stringify(aop.il_op, &sb, false);
			process_gadget(core, rop_gadget_info, aop.il_op, hit->addr);
			free_gadget_info(rop_gadget_info);
			rz_analysis_op_fini(&aop);
			rz_asm_op_free(asmop);
			rz_strbuf_fini(&sb);
			free(buf);
		}
		rz_cons_newline();
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(state->d.t, "Xss", addr, asmop_hex_str, asmop_str);
		free(asmop_str);
		free(asmop_hex_str);
		break;
	default:
		rz_warn_if_reached();
	}
cleanup:
	rz_list_free(ropList);
}

static bool insert_into(void *user, const ut64 k, const ut64 v) {
	HtUU *ht = (HtUU *)user;
	ht_uu_insert(ht, k, v);
	return true;
}

// TODO: follow unconditional jumps
static RzList /*<RzCoreAsmHit *>*/ *construct_rop_gadget(RzCore *core, ut64 addr, ut8 *buf, int buflen,
	int idx, const char *grep, int regex, RzList /*<char *>*/ *rx_list,
	RzRopEndListPair *end_gadget, HtUU *badstart, int delta) {
	int endaddr = end_gadget->instr_offset;
	int branch_delay = end_gadget->delay_size;
	RzAnalysisOp aop = { 0 };
	const char *start = NULL, *end = NULL;
	char *grep_str = NULL;
	RzCoreAsmHit *hit = NULL;
	RzList *hitlist = rz_core_asm_hit_list_new();
	ut8 nb_instr = 0;
	const ut8 max_instr = rz_config_get_i(core->config, "rop.len");
	bool valid = false;
	int grep_find;
	int search_hit;
	char *rx = NULL;
	HtUUOptions opt = { 0 };
	HtUU *localbadstart = ht_uu_new_opt(&opt);
	int count = 0;

	if (grep) {
		start = grep;
		end = strchr(grep, ';');
		if (!end) { // We filter on a single opcode, so no ";"
			end = start + strlen(grep);
		}
		grep_str = calloc(1, end - start + 1);
		strncpy(grep_str, start, end - start);
		if (regex) {
			// get the first regexp.
			if (rz_list_length(rx_list) > 0) {
				rx = rz_list_get_n(rx_list, count++);
			}
		}
	}

	bool found;
	ht_uu_find(badstart, idx, &found);
	if (found) {
		valid = false;
		goto ret;
	}
	while (nb_instr < max_instr) {
		ht_uu_insert(localbadstart, idx, 1);
		rz_analysis_op_init(&aop);
		if (idx >= delta) {
			valid = false;
			goto ret;
		}
		int error = rz_analysis_op(core->analysis, &aop, addr, buf + idx, buflen - idx, RZ_ANALYSIS_OP_MASK_DISASM);
		if (error < 0 || (nb_instr == 0 && (is_end_gadget(&aop, 0) || aop.type == RZ_ANALYSIS_OP_TYPE_NOP))) {
			valid = false;
			goto ret;
		}

		const int opsz = aop.size;
		// opsz = rz_strbuf_length (asmop.buf);
		char *opst = aop.mnemonic;
		if (!opst) {
			RZ_LOG_WARN("Analysis plugin %s did not return disassembly\n", core->analysis->cur->name);
			RzAsmOp asmop;
			rz_asm_set_pc(core->rasm, addr);
			if (rz_asm_disassemble(core->rasm, &asmop, buf + idx, buflen - idx) < 0) {
				valid = false;
				goto ret;
			}
			opst = strdup(rz_asm_op_get_asm(&asmop));
			rz_asm_op_fini(&asmop);
		}
		if (!rz_str_ncasecmp(opst, "invalid", strlen("invalid")) ||
			!rz_str_ncasecmp(opst, ".byte", strlen(".byte"))) {
			valid = false;
			goto ret;
		}

		hit = rz_core_asm_hit_new();
		if (hit) {
			hit->addr = addr;
			hit->len = opsz;
			rz_list_append(hitlist, hit);
		}

		// Move on to the next instruction
		idx += opsz;
		addr += opsz;
		if (rx) {
			grep_find = rz_regex_contains(rx, opst, RZ_REGEX_ZERO_TERMINATED, RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT);
			search_hit = (end && grep && grep_find);
		} else {
			search_hit = (end && grep && strstr(opst, grep_str));
		}

		// Handle (possible) grep
		if (search_hit) {
			if (end[0] == ';') { // fields are semicolon-separated
				start = end + 1; // skip the ;
				end = strchr(start, ';');
				end = end ? end : start + strlen(start); // latest field?
				free(grep_str);
				grep_str = calloc(1, end - start + 1);
				if (grep_str) {
					strncpy(grep_str, start, end - start);
				}
			} else {
				end = NULL;
			}
			if (regex) {
				rx = rz_list_get_n(rx_list, count++);
			}
		}
		if (endaddr <= (idx - opsz)) {
			valid = (endaddr == idx - opsz);
			goto ret;
		}
		rz_analysis_op_fini(&aop);
		nb_instr++;
	}
ret:
	rz_analysis_op_fini(&aop);
	free(grep_str);
	if (regex && rx) {
		rz_list_free(hitlist);
		ht_uu_free(localbadstart);
		return NULL;
	}
	if (!valid || (grep && end)) {
		rz_list_free(hitlist);
		ht_uu_free(localbadstart);
		return NULL;
	}
	ht_uu_foreach(localbadstart, insert_into, badstart);
	ht_uu_free(localbadstart);
	// If our arch has bds then we better be including them
	if (branch_delay && rz_list_length(hitlist) < (1 + branch_delay)) {
		rz_list_free(hitlist);
		return NULL;
	}
	return hitlist;
}

RZ_API int rz_core_search_rop(RzCore *core, const char *greparg, int regexp, RzCmdStateOutput *state) {
	const ut8 crop = rz_config_get_i(core->config, "rop.conditional"); // decide if cjmp, cret, and ccall should be used too for the gadget-search
	const ut8 subchain = rz_config_get_i(core->config, "rop.subchains");
	const ut8 max_instr = rz_config_get_i(core->config, "rop.len");
	const char *arch = rz_config_get(core->config, "asm.arch");
	int max_count = rz_config_get_i(core->config, "search.maxhits");
	int i = 0, end = 0, increment = 1, ret, result = true;
	RzList /*<endlist_pair>*/ *end_list = rz_list_newf(free);
	RzList /*<char *>*/ *rx_list = NULL;
	int align = core->search->align;
	RzListIter *itermap = NULL;
	char *grep_arg = NULL;
	char *tok, *gregexp = NULL;
	char *rx = NULL;
	RzAsmOp *asmop = NULL;
	RzList *boundaries = NULL;
	int delta = 0;
	ut8 *buf;
	RzIOMap *map;

	const ut64 search_from = rz_config_get_i(core->config, "search.from"),
		   search_to = rz_config_get_i(core->config, "search.to");
	if (search_from > search_to && search_to) {
		RZ_LOG_ERROR("core: search.from > search.to is not supported\n");
		ret = false;
		goto bad;
	}
	// {.addr = UT64_MAX, .size = 0} means search range is unspecified
	RzInterval search_itv = { search_from, search_to - search_from };
	bool empty_search_itv = search_from == search_to && search_from != UT64_MAX;
	if (empty_search_itv) {
		RZ_LOG_ERROR("core: `from` address is equal `to`\n");
		ret = false;
		goto bad;
	}
	// TODO full address cannot be represented, shrink 1 byte to [0, UT64_MAX)
	if (search_from == UT64_MAX && search_to == UT64_MAX) {
		search_itv.addr = 0;
		search_itv.size = UT64_MAX;
	}

	Sdb *gadgetSdb = NULL;
	if (rz_config_get_i(core->config, "rop.sdb")) {
		if (!(gadgetSdb = sdb_ns(core->sdb, "gadget_sdb", false))) {
			gadgetSdb = sdb_ns(core->sdb, "gadget_sdb", true);
		}
	}
	if (max_count == 0) {
		max_count = -1;
	}
	if (max_instr <= 1) {
		rz_list_free(end_list);
		RZ_LOG_ERROR("core: ROP length (rop.len) must be greater than 1.\n");
		if (max_instr == 1) {
			RZ_LOG_ERROR("core: For rop.len = 1, use /c to search for single "
				     "instructions. See /c? for help.\n");
		}
		return false;
	}

	if (!strcmp(arch, "mips")) { // MIPS has no jump-in-the-middle
		increment = 4;
	} else if (!strcmp(arch, "arm")) { // ARM has no jump-in-the-middle
		increment = rz_config_get_i(core->config, "asm.bits") == 16 ? 2 : 4;
	} else if (!strcmp(arch, "avr")) { // AVR is halfword aligned.
		increment = 2;
	}

	if (greparg) {
		grep_arg = strdup(greparg);
		grep_arg = rz_str_replace(grep_arg, ",,", ";", true);
	}

	// Deal with the grep guy.
	if (grep_arg && regexp) {
		if (!rx_list) {
			rx_list = rz_list_newf(free);
		}
		gregexp = strdup(grep_arg);
		tok = strtok(gregexp, ";");
		while (tok) {
			rx = strdup(tok);
			rz_list_append(rx_list, rx);
			tok = strtok(NULL, ";");
		}
	}
	rz_cmd_state_output_array_start(state);
	rz_cons_break_push(NULL, NULL);
	const char *mode_str = rz_config_get(core->config, "search.in");
	boundaries = rz_core_get_boundaries_prot(core, -1, mode_str, "search");
	if (!boundaries) {
		rz_cmd_state_output_array_end(state);
	}
	rz_list_foreach (boundaries, itermap, map) {
		HtUUOptions opt = { 0 };
		HtUU *badstart = ht_uu_new_opt(&opt);
		if (!rz_itv_overlap(search_itv, map->itv)) {
			continue;
		}
		RzInterval itv = rz_itv_intersect(search_itv, map->itv);
		ut64 from = itv.addr, to = rz_itv_end(itv);
		if (rz_cons_is_breaked()) {
			break;
		}
		delta = to - from;
		buf = calloc(1, delta);
		if (!buf) {
			result = false;
			goto bad;
		}
		(void)rz_io_read_at(core->io, from, buf, delta);

		// Find the end gadgets.
		for (i = 0; i < delta; i += increment) {
			RzAnalysisOp end_gadget = RZ_EMPTY;
			// Disassemble one.
			rz_analysis_op_init(&end_gadget);
			if (rz_analysis_op(core->analysis, &end_gadget, from + i, buf + i,
				    delta - i, RZ_ANALYSIS_OP_MASK_BASIC) < 1) {
				rz_analysis_op_fini(&end_gadget);
				continue;
			}
			if (is_end_gadget(&end_gadget, crop)) {
#if 0
				if (search->maxhits && rz_list_length (end_list) >= search->maxhits) {
					// limit number of high level rop gadget results
					rz_analysis_op_fini (&end_gadget);
					break;
				}
#endif
				RzRopEndListPair *epair = RZ_NEW0(RzRopEndListPair);
				if (epair) {
					// If this arch has branch delay slots, add the next instr as well
					if (end_gadget.delay) {
						epair->instr_offset = i + increment;
						epair->delay_size = end_gadget.delay;
					} else {
						epair->instr_offset = (intptr_t)i;
						epair->delay_size = end_gadget.delay;
					}
					rz_list_append(end_list, (void *)(intptr_t)epair);
				}
			}
			rz_analysis_op_fini(&end_gadget);
			if (rz_cons_is_breaked()) {
				break;
			}
			// Right now we have a list of all of the end/stop gadgets.
			// We can just construct gadgets from a little bit before them.
		}
		rz_list_reverse(end_list);
		// If we have no end gadgets, just skip all of this search nonsense.
		if (!rz_list_empty(end_list)) {
			int prev, next, ropdepth;
			const int max_inst_size_x86 = 15;
			// Get the depth of rop search, should just be max_instr
			// instructions, x86 and friends are weird length instructions, so
			// we'll just assume 15 byte instructions.
			ropdepth = increment == 1 ? max_instr * max_inst_size_x86 /* wow, x86 is long */ : max_instr * increment;
			if (rz_cons_is_breaked()) {
				break;
			}
			RzRopEndListPair *end_gadget = rz_list_pop(end_list);
			next = end_gadget->instr_offset;
			prev = 0;
			// Start at just before the first end gadget.
			for (i = 0; i < delta && max_count; i += increment) {
				if (increment == 1) {
					// give in-boundary instructions a shot
					if (i < prev - max_inst_size_x86) {
						i = prev - max_inst_size_x86;
					}
				} else {
					if (i < prev) {
						i = prev;
					}
				}
				if (i < 0) {
					i = 0;
				}
				if (rz_cons_is_breaked()) {
					break;
				}
				if (i >= next) {
					// We've exhausted the first end-gadget section,
					// move to the next one.
					free(end_gadget);
					if (rz_list_get_n(end_list, 0)) {
						prev = i;
						end_gadget = (RzRopEndListPair *)rz_list_pop(end_list);
						next = end_gadget->instr_offset;
						i = next - ropdepth;
						if (i < 0) {
							i = 0;
						}
					} else {
						end_gadget = NULL;
						break;
					}
				}
				if (i >= end) { // read by chunk of 4k
					rz_io_read_at(core->io, from + i, buf + i,
						RZ_MIN((delta - i), 4096));
					end = i + 2048;
				}
				asmop = rz_asm_op_new();
				ret = rz_asm_disassemble(core->rasm, asmop, buf + i, delta - i);
				if (ret) {
					rz_asm_set_pc(core->rasm, from + i);
					RzList *hitlist = construct_rop_gadget(core,
						from + i, buf, delta, i, greparg, regexp,
						rx_list, end_gadget, badstart, delta);
					if (!hitlist) {
						rz_asm_op_free(asmop);
						asmop = NULL;
						continue;
					}
					if (align && 0 != (from + i) % align) {
						rz_asm_op_free(asmop);
						asmop = NULL;
						continue;
					}
					if (gadgetSdb) {
						RzListIter *iter;

						RzCoreAsmHit *hit = rz_list_first(hitlist);
						char *headAddr = rz_str_newf("%" PFMT64x, hit->addr);
						if (!headAddr) {
							result = false;
							free(buf);
							ht_uu_free(badstart);
							goto bad;
						}

						rz_list_foreach (hitlist, iter, hit) {
							char *addr = rz_str_newf("%" PFMT64x "(%" PFMT32d ")", hit->addr, hit->len);
							if (!addr) {
								free(headAddr);
								result = false;
								free(buf);
								ht_uu_free(badstart);
								goto bad;
							}
							sdb_concat(gadgetSdb, headAddr, addr);
							free(addr);
						}
						free(headAddr);
					}

					if (subchain) {
						do {
							print_rop(core, hitlist, state);
							hitlist->head = hitlist->head->next;
						} while (hitlist->head->next);
					} else {
						print_rop(core, hitlist, state);
					}
					rz_list_free(hitlist);
					if (max_count > 0) {
						max_count--;
						if (max_count < 1) {
							break;
						}
					}
				}
				if (increment != 1) {
					i = next;
				}
				rz_asm_op_free(asmop);
				asmop = NULL;
			}
			free(end_gadget);
		}
		free(buf);
		ht_uu_free(badstart);
	}
	if (rz_cons_is_breaked()) {
		eprintf("\n");
	}

bad:
	rz_cmd_state_output_array_end(state);
	rz_cons_break_pop();
	rz_asm_op_free(asmop);
	rz_list_free(rx_list);
	rz_list_free(end_list);
	rz_list_free(boundaries);
	free(grep_arg);
	free(gregexp);
	return result;
}

RZ_API RzCmdStatus rz_core_rop_gadget_info(RzCore *core, const char *input, RzCmdStateOutput *state) {
	Sdb *gadgetSdb = sdb_ns(core->sdb, "gadget_sdb", false);

	if (!gadgetSdb) {
		rz_core_search_rop(core, input, 0, state);
		return RZ_CMD_STATUS_OK;
	}
	void **iter;
	RzPVector *items = sdb_get_items(gadgetSdb, true);

	rz_cmd_state_output_array_start(state);
	rz_pvector_foreach (items, iter) {
		SdbKv *kv = *iter;
		RzList *hitlist = rz_core_asm_hit_list_new();
		if (!hitlist) {
			break;
		}

		const char *s = sdbkv_value(kv);
		ut64 addr;
		int opsz;
		do {
			RzCoreAsmHit *hit = rz_core_asm_hit_new();
			if (!hit) {
				rz_list_free(hitlist);
				break;
			}
			sscanf(s, "%" PFMT64x "(%" PFMT32d ")", &addr, &opsz);
			hit->addr = addr;
			hit->len = opsz;
			rz_list_append(hitlist, hit);
		} while (*(s = strchr(s, ')') + 1) != '\0');

		print_rop(core, hitlist, state);
		rz_list_free(hitlist);
	}
	rz_pvector_free(items);
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}

RZ_API void rz_rop_constraint_free(RZ_NULLABLE void *data) {
	RzRopConstraint *constraint = data;
	if (!constraint) {
		return;
	}
	for (int i = 0; i < NUM_ARGS; i++) {
		if (constraint->args[i]) {
			free(constraint->args[i]);
		}
	}
	free(constraint);
}

RZ_API RzList /*<RzRopConstraint *>*/ *rz_rop_constraint_list_new(void) {
	RzList *list = rz_list_new();
	if (list) {
		list->free = &rz_rop_constraint_free;
	}
	return list;
}