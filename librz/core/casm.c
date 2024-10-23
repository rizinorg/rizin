// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_regex.h>
#include <rz_vector.h>
#include <rz_types.h>
#include <rz_core.h>
#include <rz_asm.h>

static RzCoreAsmHit *find_addr(RzList /*<RzCoreAsmHit *>*/ *hits, ut64 addr);
static int prune_hits_in_hit_range(RzList /*<RzCoreAsmHit *>*/ *hits, RzCoreAsmHit *hit);
static int is_hit_inrange(RzCoreAsmHit *hit, ut64 start_range, ut64 end_range);
static int is_addr_in_range(ut64 start, ut64 end, ut64 start_range, ut64 end_range);
static void add_hit_to_sorted_hits(RzList /*<RzCoreAsmHit *>*/ *hits, ut64 addr, int len, ut8 is_valid);
static int prune_hits_in_addr_range(RzList /*<RzCoreAsmHit *>*/ *hits, ut64 addr, ut64 len, ut8 is_valid);

static int coreasm_address_comparator(RzCoreAsmHit *a, RzCoreAsmHit *b, void *user) {
	if (a->addr == b->addr) {
		return 0;
	}
	if (a->addr < b->addr) {
		return -1;
	}
	return 1; /* a->addr > b->addr */
}

RZ_API RzCoreAsmHit *rz_core_asm_hit_new(void) {
	RzCoreAsmHit *hit = RZ_NEW0(RzCoreAsmHit);
	if (!hit) {
		return NULL;
	}
	hit->addr = -1;
	hit->valid = false;
	return hit;
}

RZ_API RzList /*<RzCoreAsmHit *>*/ *rz_core_asm_hit_list_new(void) {
	RzList *list = rz_list_new();
	if (list) {
		list->free = &rz_core_asm_hit_free;
	}
	return list;
}

RZ_API void rz_core_asm_hit_free(void *_hit) {
	RzCoreAsmHit *hit = _hit;
	if (hit) {
		if (hit->code) {
			free(hit->code);
		}
		free(hit);
	}
}

RZ_API char *rz_core_asm_search(RzCore *core, const char *input) {
	RzAsmCode *acode;
	char *ret;
	if (!(acode = rz_asm_massemble(core->rasm, input))) {
		return NULL;
	}
	ret = rz_asm_code_get_hex(acode);
	rz_asm_code_free(acode);
	return ret;
}

static const char *has_esil(RzCore *core, const char *name) {
	rz_return_val_if_fail(core && core->analysis && name, NULL);
	RzIterator *iter = ht_sp_as_iter(core->analysis->plugins);
	RzAnalysisPlugin **val;
	rz_iterator_foreach(iter, val) {
		RzAnalysisPlugin *h = *val;
		if (!h->name || strcmp(name, h->name)) {
			continue;
		}
		if (h->il_config && h->esil) {
			// Analysis with RzIL and ESIL
			rz_iterator_free(iter);
			return "AeI";
		} else if (h->il_config) {
			// Analysis with RzIL
			rz_iterator_free(iter);
			return "A_I";
		} else if (h->esil) {
			// Analysis with ESIL
			rz_iterator_free(iter);
			return "Ae_";
		}
		// Only the analysis plugin.
		rz_iterator_free(iter);
		return "A__";
	}
	rz_iterator_free(iter);
	return "___";
}

RZ_API RzCmdStatus rz_core_asm_plugin_print(RzCore *core, RzAsmPlugin *ap, const char *arch, RzCmdStateOutput *state, const char *license) {
	const char *feat2, *feat;
	char bits[32];
	PJ *pj = state->d.pj;
	bits[0] = 0;
	if (ap->bits == 27) {
		strcat(bits, "27");
	} else if (ap->bits == 0) {
		strcat(bits, "any");
	} else {
		if (ap->bits & 4) {
			strcat(bits, "4 ");
		}
		if (ap->bits & 8) {
			strcat(bits, "8 ");
		}
		if (ap->bits & 16) {
			strcat(bits, "16 ");
		}
		if (ap->bits & 32) {
			strcat(bits, "32 ");
		}
		if (ap->bits & 64) {
			strcat(bits, "64");
		}
	}
	feat = "__";
	if (ap->assemble && ap->disassemble) {
		feat = "ad";
	}
	if (ap->assemble && !ap->disassemble) {
		feat = "a_";
	}
	if (!ap->assemble && ap->disassemble) {
		feat = "_d";
	}
	feat2 = has_esil(core, ap->name);
	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET: {
		rz_cons_println(ap->name);
		break;
	}
	case RZ_OUTPUT_MODE_JSON: {
		pj_ko(pj, ap->name);
		pj_ks(pj, "bits", bits);
		pj_ks(pj, "license", license);
		pj_ks(pj, "description", ap->desc);
		pj_ks(pj, "features", feat);
		pj_end(pj);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD: {
		rz_cons_printf("%s%s %-10s %-11s %-7s %s",
			feat, feat2, bits, ap->name, license, ap->desc);
		if (ap->author) {
			rz_cons_printf(" (by %s)", ap->author);
		}
		if (ap->version) {
			rz_cons_printf(" v%s", ap->version);
		}
		rz_cons_newline();
		break;
	}
	default: {
		rz_warn_if_reached();
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_API RzCmdStatus rz_core_asm_plugins_print(RzCore *core, const char *arch, RzCmdStateOutput *state) {
	int i;
	RzAsm *a = core->rasm;
	RzIterator *iter = ht_sp_as_iter(a->plugins);
	RzList *plugin_list = rz_list_new_from_iterator(iter);
	rz_list_sort(plugin_list, (RzListComparator)rz_asm_plugin_cmp, NULL);
	RzListIter *it;
	RzAsmPlugin *ap;
	RzCmdStatus status;
	if (arch) {
		rz_list_foreach (plugin_list, it, ap) {
			if (ap->cpus && !strcmp(arch, ap->name)) {
				char *c = rz_str_dup(ap->cpus);
				int n = rz_str_split(c, ',');
				for (i = 0; i < n; i++) {
					rz_cons_println(rz_str_word_get0(c, i));
				}
				free(c);
				break;
			}
		}
	} else {
		rz_cmd_state_output_array_start(state);
		rz_list_foreach (plugin_list, it, ap) {
			const char *license = ap->license
				? ap->license
				: "unknown";
			status = rz_core_asm_plugin_print(core, ap, arch, state, license);
			if (status != RZ_CMD_STATUS_OK) {
				rz_iterator_free(iter);
				rz_list_free(plugin_list);
				return status;
			}
		}
		rz_cmd_state_output_array_end(state);
	}
	rz_list_free(plugin_list);
	rz_iterator_free(iter);
	return RZ_CMD_STATUS_OK;
}

// TODO: add support for byte-per-byte opcode search
RZ_API RzList /*<RzCoreAsmHit *>*/ *rz_core_asm_strsearch(RzCore *core, const char *input, ut64 from, ut64 to, int maxhits, int regexp, int everyByte, int mode) {
	RzCoreAsmHit *hit;
	RzAsmOp op;
	RzList *hits;
	ut64 at, toff = core->offset;
	ut8 *buf;
	int align = core->search->align;
	RzRegex *rx = NULL;
	char *tok, *tokens[1024], *code = NULL, *ptr;
	int idx, tidx = 0, len = 0;
	int tokcount, matchcount, count = 0;
	int matches = 0;
	const int addrbytes = core->io->addrbytes;

	if (!input || !*input) {
		return NULL;
	}

	char *inp = rz_str_trim_dup(input + 1);
	char *inp_arg = strchr(inp, ' ');
	if (inp_arg) {
		*inp_arg++ = 0;
	}
	ut64 usrimm = rz_num_math(core->num, inp);
	ut64 usrimm2 = inp_arg ? rz_num_math(core->num, inp_arg) : usrimm;
	if (usrimm > usrimm2) {
		RZ_LOG_ERROR("core: Invalid range [0x%08" PFMT64x ":0x%08" PFMT64x "]\n", usrimm, usrimm2);
		return NULL;
	}

	if (core->blocksize < 8) {
		RZ_LOG_ERROR("core: block size is too small\n");
		return NULL;
	}
	if (!(buf = (ut8 *)calloc(core->blocksize, 1))) {
		return NULL;
	}
	if (!(ptr = rz_str_dup(input))) {
		free(buf);
		return NULL;
	}
	if (!(hits = rz_core_asm_hit_list_new())) {
		free(buf);
		free(ptr);
		return NULL;
	}
	tokens[0] = NULL;
	for (tokcount = 0; tokcount < RZ_ARRAY_SIZE(tokens) - 1; tokcount++) {
		tok = strtok(tokcount ? NULL : ptr, ";");
		if (!tok) {
			break;
		}
		rz_str_trim(tok);
		tokens[tokcount] = tok;
	}
	tokens[tokcount] = NULL;
	rz_cons_break_push(NULL, NULL);
	char *opst = NULL;
	for (at = from; at < to; at += core->blocksize) {
		if (rz_cons_is_breaked()) {
			break;
		}
		if (!rz_io_is_valid_offset(core->io, at, 0)) {
			break;
		}
		(void)rz_io_read_at(core->io, at, buf, core->blocksize);
		idx = 0, matchcount = 0;
		while (addrbytes * (idx + 1) <= core->blocksize) {
			ut64 addr = at + idx;
			if (addr > to) {
				break;
			}
			rz_asm_set_pc(core->rasm, addr);
			if (mode == 'i') {
				RzAnalysisOp aop = { 0 };
				ut64 len = RZ_MIN(15, core->blocksize - idx);
				rz_analysis_op_init(&aop);
				if (rz_analysis_op(core->analysis, &aop, addr, buf + idx, len, RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_DISASM) < 1) {
					idx++; // TODO: honor mininstrsz
					rz_analysis_op_fini(&aop);
					continue;
				}
				ut64 val = aop.val; // Referenced value

				bool match = (val != UT64_MAX && val >= usrimm && val <= usrimm2);

				if (!match) {
					for (size_t i = 0; i < 6; ++i) {
						st64 v = aop.analysis_vals[i].imm;
						match = (v != ST64_MAX && v >= usrimm && v <= usrimm2);
						if (match) {
							break;
						}
					}
				}
				if (!match) {
					ut64 val = aop.disp;
					match = (val != UT64_MAX && val >= usrimm && val <= usrimm2);
				}
				if (!match) {
					st64 val = aop.ptr;
					match = (val != ST64_MAX && val >= usrimm && val <= usrimm2);
				}
				if (match) {
					if (!(hit = rz_core_asm_hit_new())) {
						rz_list_purge(hits);
						RZ_FREE(hits);
						rz_analysis_op_fini(&aop);
						goto beach;
					}
					hit->addr = addr;
					hit->len = aop.size; //  idx + len - tidx;
					if (hit->len == -1) {
						rz_core_asm_hit_free(hit);
						rz_analysis_op_fini(&aop);
						goto beach;
					}
					rz_asm_disassemble(core->rasm, &op, buf + addrbytes * idx,
						core->blocksize - addrbytes * idx);
					hit->code = rz_str_dup(rz_strbuf_get(&op.buf_asm));
					rz_asm_op_fini(&op);
					rz_analysis_op_fini(&aop);
					idx = (matchcount) ? tidx + 1 : idx + 1;
					matchcount = 0;
					rz_list_append(hits, hit);
					continue;
				}
				rz_analysis_op_fini(&aop);
				idx++; // TODO: honor mininstrsz
				continue;
			} else if (mode == 'e') {
				RzAnalysisOp aop = { 0 };
				rz_analysis_op_init(&aop);
				if (rz_analysis_op(core->analysis, &aop, addr, buf + idx, 15, RZ_ANALYSIS_OP_MASK_ESIL) < 1) {
					idx++; // TODO: honor mininstrsz
					rz_analysis_op_fini(&aop);
					continue;
				}
				// opsz = aop.size;
				opst = rz_str_dup(rz_strbuf_get(&aop.esil));
				rz_analysis_op_fini(&aop);
			} else {
				if (!(len = rz_asm_disassemble(
					      core->rasm, &op,
					      buf + addrbytes * idx,
					      core->blocksize - addrbytes * idx))) {
					idx = (matchcount) ? tidx + 1 : idx + 1;
					matchcount = 0;
					rz_asm_op_fini(&op);
					continue;
				}
				// opsz = op.size;
				opst = rz_str_dup(rz_strbuf_get(&op.buf_asm));
				rz_asm_op_fini(&op);
			}
			if (opst) {
				matches = strcmp(opst, "invalid") && strcmp(opst, "unaligned");
			}
			if (matches && tokens[matchcount]) {
				if (mode == 'a') { // check for case sensitive
					matches = !rz_str_ncasecmp(opst, tokens[matchcount], strlen(tokens[matchcount]));
				} else if (!regexp) {
					matches = strstr(opst, tokens[matchcount]) != NULL;
				} else {
					rx = rz_regex_new(tokens[matchcount], RZ_REGEX_EXTENDED, 0);
					RzPVector *tmp_m = rz_regex_match_first(rx, opst, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
					matches = (!rz_pvector_empty(tmp_m) && tmp_m != NULL) ? 1 : 0;
					rz_regex_free(rx);
					rz_pvector_free(tmp_m);
				}
			}
			if (align && align > 1) {
				if (addr % align) {
					matches = false;
				}
			}
			if (matches) {
				code = rz_str_appendf(code, "%s; ", opst);
				if (matchcount == tokcount - 1) {
					if (tokcount == 1) {
						tidx = idx;
					}
					if (!(hit = rz_core_asm_hit_new())) {
						rz_list_purge(hits);
						RZ_FREE(hits);
						goto beach;
					}
					hit->addr = addr;
					hit->len = idx + len - tidx;
					if (hit->len == -1) {
						rz_core_asm_hit_free(hit);
						goto beach;
					}
					code[strlen(code) - 2] = 0;
					hit->code = rz_str_dup(code);
					rz_list_append(hits, hit);
					RZ_FREE(code);
					matchcount = 0;
					idx = tidx + 1;
					if (maxhits) {
						count++;
						if (count >= maxhits) {
							// eprintf ("Error: search.maxhits reached\n");
							goto beach;
						}
					}
				} else if (!matchcount) {
					tidx = idx;
					matchcount++;
					idx += len;
				} else {
					matchcount++;
					idx += len;
				}
			} else {
				if (everyByte) {
					idx = matchcount ? tidx + 1 : idx + 1;
				} else {
					idx += RZ_MAX(1, len);
				}
				RZ_FREE(code);
				matchcount = 0;
			}
			RZ_FREE(opst);
		}
	}
	rz_cons_break_pop();
	rz_asm_set_pc(core->rasm, toff);
beach:
	free(buf);
	free(ptr);
	free(code);
	RZ_FREE(opst);
	rz_cons_break_pop();
	return hits;
}

static void add_hit_to_sorted_hits(RzList /*<RzCoreAsmHit *>*/ *hits, ut64 addr, int len, ut8 is_valid) {
	RzCoreAsmHit *hit = rz_core_asm_hit_new();
	if (hit) {
		RZ_LOG_DEBUG("*** Inserting instruction (valid?: %d): instr_addr: 0x%" PFMT64x " instr_len: %d\n", is_valid, addr, len);
		hit->addr = addr;
		hit->len = len;
		hit->valid = is_valid;
		hit->code = NULL;
		rz_list_add_sorted(hits, hit, ((RzListComparator)coreasm_address_comparator), NULL);
	}
}

static void add_hit_to_hits(RzList /*<RzCoreAsmHit *>*/ *hits, ut64 addr, int len, ut8 is_valid) {
	RzCoreAsmHit *hit = rz_core_asm_hit_new();
	if (hit) {
		RZ_LOG_DEBUG("*** Inserting instruction (valid?: %d): instr_addr: 0x%" PFMT64x " instr_len: %d\n", is_valid, addr, len);
		hit->addr = addr;
		hit->len = len;
		hit->valid = is_valid;
		hit->code = NULL;
		if (!rz_list_append(hits, hit)) {
			free(hit);
		}
	}
}

static int prune_hits_in_addr_range(RzList /*<RzCoreAsmHit *>*/ *hits, ut64 addr, ut64 len, ut8 is_valid) {
	RzCoreAsmHit hit = RZ_EMPTY;
	hit.addr = addr;
	hit.len = len;
	hit.valid = is_valid;
	return prune_hits_in_hit_range(hits, &hit);
}

static int prune_hits_in_hit_range(RzList /*<RzCoreAsmHit *>*/ *hits, RzCoreAsmHit *hit) {
	RzListIter *iter, *iter_tmp;
	RzCoreAsmHit *to_check_hit;
	int result = 0;
	ut64 start_range, end_range;
	if (!hit || !hits) {
		return 0;
	}
	start_range = hit->addr;
	end_range = hit->addr + hit->len;
	rz_list_foreach_safe (hits, iter, iter_tmp, to_check_hit) {
		if (to_check_hit && is_hit_inrange(to_check_hit, start_range, end_range)) {
			RZ_LOG_DEBUG("Found hit that clashed (start: 0x%" PFMT64x
				     " - end: 0x%" PFMT64x " ), 0x%" PFMT64x " len: %d (valid: %d 0x%" PFMT64x
				     " - 0x%" PFMT64x ")\n",
				start_range, end_range, to_check_hit->addr,
				to_check_hit->len, to_check_hit->valid, to_check_hit->addr,
				to_check_hit->addr + to_check_hit->len);
			// XXX - could this be a valid decode instruction we are deleting?
			rz_list_delete(hits, iter);
			// iter->data = NULL;
			to_check_hit = NULL;
			result++;
		}
	}
	return result;
}

static RzCoreAsmHit *find_addr(RzList /*<RzCoreAsmHit *>*/ *hits, ut64 addr) {
	// Find an address in the list of hits
	RzListIter *addr_iter = NULL;
	RzCoreAsmHit dummy_value;
	dummy_value.addr = addr;
	addr_iter = rz_list_find(hits, &dummy_value, ((RzListComparator)coreasm_address_comparator), NULL);
	return rz_list_iter_get_data(addr_iter);
}

static int handle_forward_disassemble(RzCore *core, RzList /*<RzCoreAsmHit *>*/ *hits, ut8 *buf, ut64 len, ut64 current_buf_pos, ut64 current_instr_addr, ut64 end_addr) {
	RzCoreAsmHit *hit = NULL, *found_addr = NULL;
	// forward disassemble from the current instruction up to the end address
	ut64 temp_instr_addr = current_instr_addr;
	ut64 tmp_current_buf_pos = current_buf_pos;
	ut64 start_range = current_instr_addr;
	ut64 end_range = end_addr;
	ut64 temp_instr_len = 0;
	ut64 start = 0, end = 0;
	ut8 is_valid = false;
	RzAsmOp op;

	if (end_addr < current_instr_addr) {
		return end_addr;
	}

	rz_asm_set_pc(core->rasm, current_instr_addr);
	while (tmp_current_buf_pos < len && temp_instr_addr < end_addr) {
		temp_instr_len = len - tmp_current_buf_pos;
		RZ_LOG_DEBUG("Current position: %" PFMT64d " instr_addr: 0x%" PFMT64x "\n", tmp_current_buf_pos, temp_instr_addr);
		temp_instr_len = rz_asm_disassemble(core->rasm, &op, buf + tmp_current_buf_pos, temp_instr_len);

		if (temp_instr_len == 0) {
			is_valid = false;
			temp_instr_len = 1;
		} else {
			is_valid = true;
		}

		// check to see if addr exits
		found_addr = find_addr(hits, temp_instr_addr);
		start = temp_instr_addr;
		end = temp_instr_addr + temp_instr_len;

		if (!found_addr) {
			add_hit_to_sorted_hits(hits, temp_instr_addr, temp_instr_len, is_valid);
		} else if (is_valid && !found_addr->valid && is_addr_in_range(start, end, start_range, end_range)) {
			ut32 prune_results = 0;
			prune_results = prune_hits_in_addr_range(hits, temp_instr_addr, temp_instr_len, is_valid);
			add_hit_to_sorted_hits(hits, temp_instr_addr, temp_instr_len, is_valid);
			if (prune_results) {
				rz_list_add_sorted(hits, hit, ((RzListComparator)coreasm_address_comparator), NULL);
				RZ_LOG_DEBUG("Pruned %u hits from list in fwd sweep.\n", prune_results);
			} else {
				RZ_FREE(hit);
			}
		}

		temp_instr_addr += temp_instr_len;
		tmp_current_buf_pos += temp_instr_len;
	}
	return temp_instr_addr;
}

static int is_addr_in_range(ut64 start, ut64 end, ut64 start_range, ut64 end_range) {
	int result = false;
	if (start == start_range) {
		return true;
	}
	if (start < end && start_range < end_range) {
		// ez cases
		if (start_range <= start && start < end_range) {
			result = true;
		} else if (start_range < end && end < end_range) {
			result = true;
		} else if (start <= start_range && end_range < end) {
			result = true;
		}
		// XXX - these cases need to be tested
		// (long long) start_range < 0 < end_range
	} else if (start_range > end_range) {
		if (start < end) {
			if (start < end_range) {
				result = true;
			} else if (end <= end_range) {
				result = true;
			} else if (start_range <= start) {
				result = true;
			} else if (start_range < end) {
				result = true;
			}
			// (long long) start < 0 < end
		} else {
			if (end < end_range) {
				result = true;
			} else if (end <= end_range) {
				result = true;
			} else if (start_range <= start) {
				result = true;
			}
		}
		// XXX - these cases need to be tested
		// (long long) start < 0 < end
	} else if (start_range < end_range) {
		if (start < end_range) {
			result = true;
		} else if (start <= start_range) {
			result = true;
		} else if (start_range < end) {
			result = true;
		}
	}
	return result;
}

static int is_hit_inrange(RzCoreAsmHit *hit, ut64 start_range, ut64 end_range) {
	int result = false;
	if (hit) {
		result = is_addr_in_range(hit->addr,
			hit->addr + hit->len,
			start_range, end_range);
	}
	return result;
}

RZ_API RzList /*<RzCoreAsmHit *>*/ *rz_core_asm_bwdisassemble(RzCore *core, ut64 addr, int n, int len) {
	RzAsmOp op;
	// if (n > core->blocksize) n = core->blocksize;
	ut64 at;
	ut32 idx = 0, hit_count;
	int numinstr, asmlen, ii;
	const int addrbytes = core->io->addrbytes;
	RzAsmCode *c;
	RzList *hits = rz_core_asm_hit_list_new();
	if (!hits) {
		return NULL;
	}

	len = RZ_MIN(len - len % addrbytes, addrbytes * addr);
	if (len < 1) {
		rz_list_free(hits);
		return NULL;
	}

	ut8 *buf = (ut8 *)malloc(len);
	if (!buf) {
		rz_list_free(hits);
		return NULL;
	} else if (!hits) {
		free(buf);
		return NULL;
	}
	if (!rz_io_read_at(core->io, addr - len / addrbytes, buf, len)) {
		rz_list_free(hits);
		free(buf);
		return NULL;
	}

	for (idx = addrbytes; idx < len; idx += addrbytes) {
		if (rz_cons_is_breaked()) {
			break;
		}
		c = rz_asm_mdisassemble(core->rasm, buf + len - idx, idx);
		if (strstr(c->assembly, "invalid") || strstr(c->assembly, ".byte")) {
			rz_asm_code_free(c);
			continue;
		}
		numinstr = 0;
		asmlen = strlen(c->assembly);
		for (ii = 0; ii < asmlen; ii++) {
			if (c->assembly[ii] == '\n') {
				++numinstr;
			}
		}
		rz_asm_code_free(c);
		if (numinstr >= n || idx > 16 * n) { // assume average instruction length <= 16
			break;
		}
	}
	at = addr - idx / addrbytes;
	rz_asm_set_pc(core->rasm, at);
	for (hit_count = 0; hit_count < n; hit_count++) {
		int instrlen = rz_asm_disassemble(core->rasm, &op,
			buf + len - addrbytes * (addr - at), addrbytes * (addr - at));
		add_hit_to_hits(hits, at, instrlen, true);
		at += instrlen;
	}
	free(buf);
	return hits;
}

static RzList /*<RzCoreAsmHit *>*/ *rz_core_asm_back_disassemble_all(RzCore *core, ut64 addr, ut64 len, ut64 max_hit_count, ut32 extra_padding) {
	RzList *hits = rz_core_asm_hit_list_new();
	RzCoreAsmHit dummy_value;
	RzCoreAsmHit *hit = NULL;
	RzAsmOp op;
	ut8 *buf = (ut8 *)malloc(len + extra_padding);
	int current_instr_len = 0;
	ut64 current_instr_addr = addr,
	     current_buf_pos = len - 1,
	     hit_count = 0;

	memset(&dummy_value, 0, sizeof(RzCoreAsmHit));

	if (!hits || !buf) {
		if (hits) {
			rz_list_purge(hits);
			free(hits);
		}
		free(buf);
		return NULL;
	}

	if (!rz_io_read_at(core->io, addr - (len + extra_padding), buf, len + extra_padding)) {
		rz_list_purge(hits);
		free(hits);
		free(buf);
		return NULL;
	}

	if (len == 0) {
		return hits;
	}

	do {
		if (rz_cons_is_breaked()) {
			break;
		}
		// reset assembler
		rz_asm_set_pc(core->rasm, current_instr_addr);
		current_instr_len = len - current_buf_pos + extra_padding;
		RZ_LOG_DEBUG("current_buf_pos: 0x%" PFMT64x ", current_instr_len: %d\n", current_buf_pos, current_instr_len);
		current_instr_len = rz_asm_disassemble(core->rasm, &op, buf + current_buf_pos, current_instr_len);
		hit = rz_core_asm_hit_new();
		hit->addr = current_instr_addr;
		hit->len = current_instr_len;
		hit->code = NULL;
		rz_list_add_sorted(hits, hit, ((RzListComparator)coreasm_address_comparator), NULL);

		current_buf_pos--;
		current_instr_addr--;
		hit_count++;
	} while (((int)current_buf_pos >= 0) && (int)(len - current_buf_pos) >= 0 && hit_count <= max_hit_count);

	free(buf);
	return hits;
}

static RzList /*<RzCoreAsmHit *>*/ *rz_core_asm_back_disassemble(RzCore *core, ut64 addr, int len, ut64 max_hit_count, ut8 disassmble_each_addr, ut32 extra_padding) {
	RzList *hits;
	RzAsmOp op;
	ut8 *buf = NULL;
	ut8 max_invalid_b4_exit = 4,
	    last_num_invalid = 0;
	int current_instr_len = 0;
	ut64 current_instr_addr = addr,
	     current_buf_pos = 0,
	     next_buf_pos = len;

	RzCoreAsmHit dummy_value;
	ut32 hit_count = 0;

	if (disassmble_each_addr) {
		return rz_core_asm_back_disassemble_all(core, addr, len, max_hit_count, extra_padding + 1);
	}

	hits = rz_core_asm_hit_list_new();
	buf = malloc(len + extra_padding);
	if (!hits || !buf) {
		if (hits) {
			rz_list_purge(hits);
			free(hits);
		}
		free(buf);
		return NULL;
	}

	if (!rz_io_read_at(core->io, (addr + extra_padding) - len, buf, len + extra_padding)) {
		rz_list_purge(hits);
		free(hits);
		free(buf);
		return NULL;
	}

	//
	// XXX - This is a heavy handed approach without a
	// 		an appropriate btree or hash table for storing
	//	 hits, because are using:
	//			1) Sorted RzList with many inserts and searches
	//			2) Pruning hits to find the most optimal disassembly

	// greedy approach
	// 1) Consume previous bytes
	// 1a) Instruction is invalid (incr current_instr_addr)
	// 1b) Disasm is perfect
	// 1c) Disasm is underlap (disasm(current_instr_addr, next_instr_addr - current_instr_addr) short some bytes)
	// 1d) Disasm is overlap (disasm(current_instr_addr, next_instr_addr - current_instr_addr) over some bytes)

	memset(&dummy_value, 0, sizeof(RzCoreAsmHit));
	// disassemble instructions previous to current address, extra_padding can move the location of addr
	// so we need to account for that with current_buf_pos
	current_buf_pos = len - extra_padding - 1;
	next_buf_pos = len + extra_padding - 1;
	current_instr_addr = addr - 1;
	do {
		if (rz_cons_is_breaked()) {
			break;
		}
		// reset assembler
		rz_asm_set_pc(core->rasm, current_instr_addr);
		current_instr_len = next_buf_pos - current_buf_pos;
		current_instr_len = rz_asm_disassemble(core->rasm, &op, buf + current_buf_pos, current_instr_len);
		// disassembly invalid
		if (current_instr_len == 0 || strstr(rz_strbuf_get(&op.buf_asm), "invalid")) {
			if (current_instr_len == 0) {
				current_instr_len = 1;
			}
			add_hit_to_sorted_hits(hits, current_instr_addr, current_instr_len, /* is_valid */ false);
			hit_count++;
			last_num_invalid++;
			// disassembly perfect
		} else if (current_buf_pos + current_instr_len == next_buf_pos) {
			// i think this may be the only case where an invalid instruction will be
			// added because handle_forward_disassemble and handle_disassembly_overlap
			// are only called in cases where a valid instruction has been found.
			// and they are lazy, since they purge the hit list
			ut32 purge_results = 0;
			ut8 is_valid = true;
			RZ_LOG_DEBUG(" handling underlap case: current_instr_addr: 0x%" PFMT64x ".\n", current_instr_addr);
			purge_results = prune_hits_in_addr_range(hits, current_instr_addr, current_instr_len, /* is_valid */ true);
			if (purge_results) {
				handle_forward_disassemble(core, hits, buf, len, current_buf_pos + current_instr_len, current_instr_addr + current_instr_len, addr);
				hit_count = rz_list_length(hits);
			}
			add_hit_to_sorted_hits(hits, current_instr_addr, current_instr_len, is_valid);
			// handle_forward_disassemble(core, hits, buf, len, current_buf_pos+current_instr_len, current_instr_addr+current_instr_len, addr/*end_addr*/);
			hit_count++;
			next_buf_pos = current_buf_pos;
			last_num_invalid = 0;
			// disassembly underlap
		} else if (current_buf_pos + current_instr_len < next_buf_pos) {
			prune_hits_in_addr_range(hits, current_instr_addr, current_instr_len, true);
			add_hit_to_sorted_hits(hits, current_instr_addr, current_instr_len, true);

			next_buf_pos = current_buf_pos;
			handle_forward_disassemble(core, hits, buf, len - extra_padding, current_buf_pos + current_instr_len, current_instr_addr + current_instr_len, addr);
			hit_count = rz_list_length(hits);
			last_num_invalid = 0;
			// disassembly overlap
		} else if (current_buf_pos + current_instr_len > next_buf_pos) {
			// ut64 value = handle_disassembly_overlap(core, hits, buf, len, current_buf_pos, current_instr_addr);
			next_buf_pos = current_buf_pos;
			hit_count = rz_list_length(hits);
			last_num_invalid = 0;
		}

		// walk backwards by one instruction
		RZ_LOG_DEBUG(" current_instr_addr: 0x%" PFMT64x " current_instr_len: %d next_instr_addr: 0x%04" PFMT64x "\n",
			current_instr_addr, current_instr_len, next_buf_pos);
		RZ_LOG_DEBUG(" hit count: %d \n", hit_count);
		current_instr_addr -= 1;
		current_buf_pos -= 1;

		if (hit_count >= max_hit_count &&
			(last_num_invalid >= max_invalid_b4_exit || last_num_invalid == 0)) {
			break;
		}
	} while (((int)current_buf_pos >= 0) && (int)(len - current_buf_pos) >= 0);

	rz_asm_set_pc(core->rasm, addr);
	free(buf);
	return hits;
}

RZ_API RzList /*<RzCoreAsmHit *>*/ *rz_core_asm_back_disassemble_instr(RzCore *core, ut64 addr, int len, ut32 hit_count, ut32 extra_padding) {
	// extra padding to allow for additional disassembly on border buffer cases
	ut8 disassmble_each_addr = false;
	return rz_core_asm_back_disassemble(core, addr, len, hit_count, disassmble_each_addr, extra_padding);
}

RZ_API RzList /*<RzCoreAsmHit *>*/ *rz_core_asm_back_disassemble_byte(RzCore *core, ut64 addr, int len, ut32 hit_count, ut32 extra_padding) {
	// extra padding to allow for additional disassembly on border buffer cases
	ut8 disassmble_each_addr = true;
	return rz_core_asm_back_disassemble(core, addr, len, hit_count, disassmble_each_addr, extra_padding);
}

/* Compute the len and the starting address
 * when disassembling `nb` opcodes backward. */
RZ_API ut32 rz_core_asm_bwdis_len(RzCore *core, int *instr_len, ut64 *start_addr, ut32 nb) {
	ut32 instr_run = 0;
	RzCoreAsmHit *hit;
	RzListIter *iter = NULL;
	// TODO if length of nb instructions is larger than blocksize
	RzList *hits = rz_core_asm_bwdisassemble(core, core->offset, nb, core->blocksize);
	if (instr_len) {
		*instr_len = 0;
	}
	if (hits && rz_list_length(hits) > 0) {
		hit = rz_list_first(hits);
		if (start_addr) {
			*start_addr = hit->addr;
		}
		rz_list_foreach (hits, iter, hit) {
			instr_run += hit->len;
		}
		if (instr_len) {
			*instr_len = instr_run;
		}
	}
	rz_list_free(hits);
	return instr_run;
}
