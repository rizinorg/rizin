static bool cmd_aea(RzCore *core, RzOutputMode output_mode, int behavior_flags, ut64 addr, int length_or_ops) {
	RzAnalysisEsil *esil;
	int ptr, ops, ops_end = 0, len, buf_sz, maxopsize;
	ut64 addr_end_bytes;
	AeaStats stats;
	const char *esilstr;
	RzAnalysisOp aop = RZ_EMPTY;
	ut8 *buf;
	RzList *regnow; // Registers read but not written (inputs)
	PJ *pj_local = NULL; // Local PJ for JSON output

	if (!core) {
		return false;
	}
	maxopsize = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE);
	if (maxopsize < 1) {
		maxopsize = 16;
	}

	if (behavior_flags & AEA_FLAG_NUM_IS_BYTES) {
		buf_sz = length_or_ops;
		addr_end_bytes = addr + buf_sz;
	} else {
		ops_end = length_or_ops;
		if (ops_end < 1) {
			ops_end = 1;
		}
		buf_sz = ops_end * maxopsize;
		addr_end_bytes = UT64_MAX; // Not directly used if ops_end is the limit
	}
	if (buf_sz < 1) {
		buf_sz = maxopsize;
	}

	buf = malloc(buf_sz);
	if (!buf) {
		return false;
	}
	(void)rz_io_read_at(core->io, addr, (ut8 *)buf, buf_sz);
	aea_stats_init(&stats);

	rz_reg_arena_push(core->analysis->reg);
	int stacksize = rz_config_get_i(core->config, "esil.stack.depth");
	bool iotrap = rz_config_get_i(core->config, "esil.iotrap");
	int romem = rz_config_get_i(core->config, "esil.romem");
	int stats1 = rz_config_get_i(core->config, "esil.stats");
	int noNULL = rz_config_get_i(core->config, "esil.noNULL");
	unsigned int esil_addrsize = rz_config_get_i(core->config, "esil.addr.size");
	esil = rz_analysis_esil_new(stacksize, iotrap, esil_addrsize);
	rz_analysis_esil_setup(esil, core->analysis, romem, stats1, noNULL);

#undef hasNext // Remove old definition if it was present from previous diff attempts
#define hasNextAEA() (behavior_flags & AEA_FLAG_NUM_IS_BYTES) ? (current_addr_for_loop < addr_end_bytes) : (ops < ops_end)
	ut64 current_addr_for_loop = addr;

	ESILISTATE->memreads = rz_list_newf(NULL);
	ESILISTATE->memwrites = rz_list_newf(NULL);
	esil->user = &stats;
	esil->cb.hook_reg_write = myregwrite;
	esil->cb.hook_reg_read = myregread;
	esil->cb.hook_mem_write = mymemwrite;
	esil->cb.hook_mem_read = mymemread;
	esil->nowrite = true;

	for (ops = ptr = 0; ptr < buf_sz && hasNextAEA(); ops++, ptr += len) {
		current_addr_for_loop = addr + ptr;
		rz_analysis_op_init(&aop);
		len = rz_analysis_op(core->analysis, &aop, addr + ptr, buf + ptr, buf_sz - ptr, RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_HINT);
		if (len < 1) {
			RZ_LOG_ERROR("core: Invalid 0x%08" PFMT64x " instruction %02x %02x\n",
				addr + ptr, buf[ptr], buf[ptr + 1]);
			rz_analysis_op_fini(&aop);
			break;
		}
		esilstr = RZ_STRBUF_SAFEGET(&aop.esil);
		if (RZ_STR_ISNOTEMPTY(esilstr)) {
			rz_analysis_esil_parse(esil, esilstr);
			rz_analysis_esil_stack_free(esil);
		}
		rz_analysis_op_fini(&aop);
	}
	esil->nowrite = false;
	esil->cb.hook_reg_write = NULL;
	esil->cb.hook_reg_read = NULL;
	rz_analysis_esil_free(esil);
	rz_reg_arena_pop(core->analysis->reg);

	regnow = rz_list_newf(free);
	if (regnow) {
		RzListIter *iter_reg;
		char *reg_name;
		rz_list_foreach (stats.regs, iter_reg, reg_name) {
			if (!contains(stats.regwrite, reg_name)) {
				rz_list_push(regnow, rz_str_dup(reg_name));
			}
		}
	}

	// Refactored output logic
	switch (output_mode) {
	case RZ_OUTPUT_MODE_JSON:
		pj_local = pj_new();
		if (!pj_local) {
			goto cleanup_error_no_pj;
		}
		pj_o(pj_local);
		bool regs_requested_for_json = behavior_flags & (AEA_SHOW_REG_READ | AEA_SHOW_REG_WRITE | AEA_SHOW_REG_INPUT | AEA_SHOW_REGS_ALL);
		if (regs_requested_for_json) {
			// For JSON, if any register category is specifically requested, show all available groups.
			// If AEA_SHOW_REGS_ALL is the only one, it also shows all.
			pj_k(pj_local, "all_touched_registers"); showregs_ng(stats.regs, output_mode, pj_local);
			pj_k(pj_local, "input_registers"); showregs_ng(stats.inputregs, output_mode, pj_local);
			pj_k(pj_local, "read_registers"); showregs_ng(stats.regread, output_mode, pj_local);
			pj_k(pj_local, "written_registers"); showregs_ng(stats.regwrite, output_mode, pj_local);
			if (!rz_list_empty(stats.regvalues)) { pj_k(pj_local, "register_values"); showregs_ng(stats.regvalues, output_mode, pj_local); }
			if (regnow && !rz_list_empty(regnow)) { pj_k(pj_local, "read_not_written_registers"); showregs_ng(regnow, output_mode, pj_local); }
		}
		if (!rz_list_empty(ESILISTATE->memreads))  { pj_k(pj_local, "memory_read"); showmem_ng(ESILISTATE->memreads, output_mode, pj_local, true); }
		if (!rz_list_empty(ESILISTATE->memwrites)) { pj_k(pj_local, "memory_write"); showmem_ng(ESILISTATE->memwrites, output_mode, pj_local, false); }
		pj_end(pj_local);
		rz_cons_println(pj_string(pj_local));
		pj_free(pj_local);
		break;

	case RZ_OUTPUT_MODE_RIZIN:
		// Rizin output primarily focuses on memory state changes
		showmem_ng(ESILISTATE->memreads, output_mode, NULL, true);
		showmem_ng(ESILISTATE->memwrites, output_mode, NULL, false);
		// Register changes could be printed as 'dr' commands if desired, based on behavior_flags
		break;

	case RZ_OUTPUT_MODE_STANDARD:
		if ((behavior_flags & AEA_SHOW_REG_INPUT) && regnow && !rz_list_empty(regnow)) {
			rz_cons_printf(" I: "); showregs_ng(regnow, output_mode, NULL);
		}
		if ((behavior_flags & AEA_SHOW_REG_READ) && !rz_list_empty(stats.regread)) {
			rz_cons_printf(" R: "); showregs_ng(stats.regread, output_mode, NULL);
		}
		if ((behavior_flags & AEA_SHOW_REG_WRITE) && !rz_list_empty(stats.regwrite)) {
			rz_cons_printf(" W: "); showregs_ng(stats.regwrite, output_mode, NULL);
		}
		// If no specific register group was requested by behavior_flags, but AEA_SHOW_REGS_ALL implies a default summary.
		// Or if no reg-related behavior_flags are set at all (plain 'aea d'), show default summary.
		if ( (behavior_flags & AEA_SHOW_REGS_ALL) || 
		     !(behavior_flags & (AEA_SHOW_REG_READ | AEA_SHOW_REG_WRITE | AEA_SHOW_REG_INPUT)) ) {
			if (!rz_list_empty(stats.regs))      { rz_cons_printf(" A: "); showregs_ng(stats.regs, output_mode, NULL); }
		}
		if (!rz_list_empty(ESILISTATE->memreads))  { rz_cons_printf("@R:"); showmem_ng(ESILISTATE->memreads, output_mode, NULL, true); }
		if (!rz_list_empty(ESILISTATE->memwrites)) { rz_cons_printf("@W:"); showmem_ng(ESILISTATE->memwrites, output_mode, NULL, false); }
		break;
	case RZ_OUTPUT_MODE_QUIET: // Fall-through
	case RZ_OUTPUT_MODE_QUIETEST:
		// No output by design for these modes in show*_ng helpers
		break;
	default:
		RZ_LOG_WARN("cmd_aea: Unhandled RzOutputMode\n"); // Optional warning
		break;
	}

cleanup_error_no_pj: 
	rz_list_free(ESILISTATE->memreads);
	rz_list_free(ESILISTATE->memwrites);
	ESILISTATE->memreads = NULL;
	ESILISTATE->memwrites = NULL;
	aea_stats_fini(&stats);
	free(buf);
	RZ_FREE(regnow);
	return true; 
}
#undef hasNextAEA
static bool cmd_aea(RzCore *core, RzOutputMode output_mode, int behavior_flags, ut64 addr, int length_or_ops) {
	RzAnalysisEsil *esil;
	int ptr, ops, ops_end = 0, len, buf_sz, maxopsize;
	ut64 addr_end_bytes; 
	AeaStats stats;
	const char *esilstr;
	RzAnalysisOp aop = RZ_EMPTY;
	ut8 *buf;
	RzList *regnow; // Registers read but not written (inputs)
	PJ *pj_local = NULL; // Local PJ for JSON output

	if (!core) {
		return false;
	}
	maxopsize = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE);
	if (maxopsize < 1) {
		maxopsize = 16;
	}

	if (behavior_flags & AEA_FLAG_NUM_IS_BYTES) {
		buf_sz = length_or_ops;
		addr_end_bytes = addr + buf_sz;
	} else {
		ops_end = length_or_ops;
		if (ops_end < 1) {
			ops_end = 1;
		}
		buf_sz = ops_end * maxopsize;
		addr_end_bytes = UT64_MAX; 
	}
	if (buf_sz < 1) { 
		buf_sz = maxopsize;
	}

	buf = malloc(buf_sz);
	if (!buf) {
		return false;
	}
	(void)rz_io_read_at(core->io, addr, (ut8 *)buf, buf_sz); 
	aea_stats_init(&stats);

	rz_reg_arena_push(core->analysis->reg);
	int stacksize = rz_config_get_i(core->config, "esil.stack.depth");
	bool iotrap = rz_config_get_i(core->config, "esil.iotrap");
	int romem = rz_config_get_i(core->config, "esil.romem");
	int stats1 = rz_config_get_i(core->config, "esil.stats");
	int noNULL = rz_config_get_i(core->config, "esil.noNULL");
	unsigned int esil_addrsize = rz_config_get_i(core->config, "esil.addr.size"); 
	esil = rz_analysis_esil_new(stacksize, iotrap, esil_addrsize);
	rz_analysis_esil_setup(esil, core->analysis, romem, stats1, noNULL);

#define hasNextAEA() (behavior_flags & AEA_FLAG_NUM_IS_BYTES) ? (current_addr_for_loop < addr_end_bytes) : (ops < ops_end)
	ut64 current_addr_for_loop = addr; 

	esil->user = &stats;
	esil->cb.hook_reg_write = myregwrite;
	esil->cb.hook_reg_read = myregread;
	esil->cb.hook_mem_write = mymemwrite;
	esil->cb.hook_mem_read = mymemread;
	esil->nowrite = true;

	for (ops = ptr = 0; ptr < buf_sz && hasNextAEA(); ops++, ptr += len) {
		current_addr_for_loop = addr + ptr; 
		rz_analysis_op_init(&aop);
		len = rz_analysis_op(core->analysis, &aop, addr + ptr, buf + ptr, buf_sz - ptr, RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_HINT);
		if (len < 1) {
			RZ_LOG_ERROR("core: Invalid 0x%08" PFMT64x " instruction %02x %02x\n",
				addr + ptr, buf[ptr], buf[ptr + 1]);
			rz_analysis_op_fini(&aop); 
			break;
		}
		esilstr = RZ_STRBUF_SAFEGET(&aop.esil);
		if (RZ_STR_ISNOTEMPTY(esilstr)) {
			rz_analysis_esil_parse(esil, esilstr);
			rz_analysis_esil_stack_free(esil);
		}
		rz_analysis_op_fini(&aop);
	}
	esil->nowrite = false;
	esil->cb.hook_reg_write = NULL;
	esil->cb.hook_reg_read = NULL;
	rz_analysis_esil_free(esil);
	rz_reg_arena_pop(core->analysis->reg);

	regnow = rz_list_newf(free);
	if (regnow) {
		RzListIter *iter_reg;
		char *reg_name;
		rz_list_foreach (stats.regs, iter_reg, reg_name) {
			if (!contains(stats.regwrite, reg_name)) {
				rz_list_push(regnow, rz_str_dup(reg_name));
			}
		}
	}

	// Refactored output logic
	switch (output_mode) {
	case RZ_OUTPUT_MODE_JSON:
		pj_local = pj_new();
		if (!pj_local) {
			free(buf); aea_stats_fini(&stats); RZ_FREE(regnow);
			rz_list_free(ESILISTATE->memreads); rz_list_free(ESILISTATE->memwrites);
			ESILISTATE->memreads = NULL; ESILISTATE->memwrites = NULL;
			return false;
		}
		pj_o(pj_local);
		if (behavior_flags & AEA_SHOW_REGS_ALL || // If all regs are requested OR
			(behavior_flags & (AEA_SHOW_REG_READ | AEA_SHOW_REG_WRITE | AEA_SHOW_REG_INPUT))) { // any specific reg group
			// pj_k(pj_local, "registers"); pj_o(pj_local); // Optional grouping key
			if (behavior_flags & AEA_SHOW_REG_READ) { pj_k(pj_local, "R"); showregs_ng(stats.regread, output_mode, pj_local); }
			if (behavior_flags & AEA_SHOW_REG_WRITE) { pj_k(pj_local, "W"); showregs_ng(stats.regwrite, output_mode, pj_local); }
			if (behavior_flags & AEA_SHOW_REG_INPUT && regnow) { pj_k(pj_local, "N"); showregs_ng(regnow, output_mode, pj_local); }
			if (behavior_flags & AEA_SHOW_REGS_ALL) { // Show these only if ALL is explicitly set
				pj_k(pj_local, "A"); showregs_ng(stats.regs, output_mode, pj_local);
				pj_k(pj_local, "I"); showregs_ng(stats.inputregs, output_mode, pj_local);
				if (!rz_list_empty(stats.regvalues)) { pj_k(pj_local, "V"); showregs_ng(stats.regvalues, output_mode, pj_local); }
			}
			// pj_end(pj_local); // Close "registers" group
		}
		if (!rz_list_empty(ESILISTATE->memreads))  { pj_k(pj_local, "@R"); showmem_ng(ESILISTATE->memreads, output_mode, pj_local, true); }
		if (!rz_list_empty(ESILISTATE->memwrites)) { pj_k(pj_local, "@W"); showmem_ng(ESILISTATE->memwrites, output_mode, pj_local, false); }
		pj_end(pj_local);
		rz_cons_println(pj_string(pj_local));
		pj_free(pj_local);
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		showmem_ng(ESILISTATE->memreads, output_mode, NULL, true);
		showmem_ng(ESILISTATE->memwrites, output_mode, NULL, false);
		// Register output in Rizin format could be added here if needed
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		if ((behavior_flags & AEA_SHOW_REG_INPUT) && regnow && !rz_list_empty(regnow)) {
			rz_cons_printf(" I: "); showregs_ng(regnow, output_mode, NULL);
		}
		if ((behavior_flags & AEA_SHOW_REG_READ) && !rz_list_empty(stats.regread)) {
			rz_cons_printf(" R: "); showregs_ng(stats.regread, output_mode, NULL);
		}
		if ((behavior_flags & AEA_SHOW_REG_WRITE) && !rz_list_empty(stats.regwrite)) {
			rz_cons_printf(" W: "); showregs_ng(stats.regwrite, output_mode, NULL);
		}
		if (!(behavior_flags & (AEA_SHOW_REG_READ | AEA_SHOW_REG_WRITE | AEA_SHOW_REG_INPUT)) && (behavior_flags & AEA_SHOW_REGS_ALL)) { // Show A and V if all requested and no specific
			if (!rz_list_empty(stats.regs))      { rz_cons_printf(" A: "); showregs_ng(stats.regs, output_mode, NULL); }
			if (!rz_list_empty(stats.regvalues)) { rz_cons_printf(" V: "); showregs_ng(stats.regvalues, output_mode, NULL); }
		}
		if (!rz_list_empty(ESILISTATE->memreads))  { rz_cons_printf("@R:"); showmem_ng(ESILISTATE->memreads, output_mode, NULL, true); }
		if (!rz_list_empty(ESILISTATE->memwrites)) { rz_cons_printf("@W:"); showmem_ng(ESILISTATE->memwrites, output_mode, NULL, false); }
		break;
	case RZ_OUTPUT_MODE_QUIET:
	case RZ_OUTPUT_MODE_QUIETEST:
		// No output
		break;
	default:
		// Should not happen if RzOutputMode is used correctly
		break;
	}

	rz_list_free(ESILISTATE->memreads);
	rz_list_free(ESILISTATE->memwrites);
	ESILISTATE->memreads = NULL;
	ESILISTATE->memwrites = NULL;
	aea_stats_fini(&stats);
	free(buf);
	RZ_FREE(regnow);
	return true;
}
#undef hasNextAEA
