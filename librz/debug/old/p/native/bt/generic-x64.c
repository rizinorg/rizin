// SPDX-FileCopyrightText: 2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

static RzList /*<RzDebugFrame *>*/ *backtrace_x86_64(RzDebug *dbg, ut64 at) {
	int i;
	ut8 buf[8];
	RzDebugFrame *frame;
	ut64 ptr, ebp2;
	ut64 _rip, _rsp, _rbp = 0;
	RzList *list;
	RzReg *reg = dbg->reg;
	RzIOBind *bio = &dbg->iob;

	_rip = rz_reg_get_value(reg, rz_reg_get(reg, "rip", RZ_REG_TYPE_GPR));
	if (at == UT64_MAX) {
		_rsp = rz_reg_get_value(reg, rz_reg_get(reg, "rsp", RZ_REG_TYPE_GPR));
		_rbp = rz_reg_get_value(reg, rz_reg_get(reg, "rbp", RZ_REG_TYPE_GPR));
	} else {
		_rsp = _rbp = at;
	}

	list = rz_list_new();
	list->free = free;
	bio->read_at(bio->io, _rip, (ut8 *)&buf, 8);
	/* %rbp=old rbp, %rbp+4 points to ret */
	/* Plugin before function prelude: push %rbp ; mov %rsp, %rbp */
	if (!memcmp(buf, "\x55\x89\xe5", 3) || !memcmp(buf, "\x89\xe5\x57", 3)) {
		if (!bio->read_at(bio->io, _rsp, (ut8 *)&ptr, 8)) {
			eprintf("read error at 0x%08" PFMT64x "\n", _rsp);
			rz_list_purge(list);
			free(list);
			return false;
		}
		frame = RZ_NEW0(RzDebugFrame);
		frame->addr = ptr;
		frame->size = 0; // TODO ?
		rz_list_append(list, frame);
		_rbp = ptr;
	}

	for (i = 1; i < dbg->btdepth; i++) {
		// TODO: make those two reads in a shot
		bio->read_at(bio->io, _rbp, (ut8 *)&ebp2, 8);
		if (ebp2 == UT64_MAX)
			break;
		bio->read_at(bio->io, _rbp + 8, (ut8 *)&ptr, 8);
		if (!ptr || !_rbp)
			break;
		frame = RZ_NEW0(RzDebugFrame);
		frame->addr = ptr;
		frame->size = 0; // TODO ?
		rz_list_append(list, frame);
		_rbp = ebp2;
	}
	return list;
}
// XXX: Do this work correctly?
static RzList /*<RzDebugFrame *>*/ *backtrace_x86_64_analysis(RzDebug *dbg, ut64 at) {
	int i;
	ut8 buf[8];
	RzDebugFrame *frame;
	ut64 ptr, ebp2 = UT64_MAX;
	ut64 _rip, _rbp;
	RzList *list;
	RzReg *reg = dbg->reg;
	RzIOBind *bio = &dbg->iob;
	RzAnalysisFunction *fcn;

	_rip = rz_reg_get_value(reg, rz_reg_get(reg, "rip", RZ_REG_TYPE_GPR));
	if (at == UT64_MAX) {
		//_rsp = rz_reg_get_value (reg, rz_reg_get (reg, "rsp", RZ_REG_TYPE_GPR));
		_rbp = rz_reg_get_value(reg, rz_reg_get(reg, "rbp", RZ_REG_TYPE_GPR));
	} else {
		_rbp = at;
	}

	list = rz_list_new();
	list->free = free;
	bio->read_at(bio->io, _rip, (ut8 *)&buf, 8);

	// TODO : frame->size by using esil to emulate first instructions
	fcn = rz_analysis_get_fcn_in(dbg->analysis, _rip, RZ_ANALYSIS_FCN_TYPE_NULL);
	if (fcn) {
		frame = RZ_NEW0(RzDebugFrame);
		frame->addr = _rip;
		frame->size = 0;
		frame->sp = _rbp;
		frame->bp = _rbp + 8; // XXX
		rz_list_append(list, frame);
	}

	for (i = 1; i < dbg->btdepth; i++) {
		// TODO: make those two reads in a shot
		bio->read_at(bio->io, _rbp, (ut8 *)&ebp2, 8);
		if (ebp2 == UT64_MAX)
			break;
		bio->read_at(bio->io, _rbp + 8, (ut8 *)&ptr, 8);
		if (!ptr || !_rbp)
			break;
		// fcn = rz_analysis_get_fcn_in (dbg->analysis, ptr, RZ_ANALYSIS_FCN_TYPE_NULL);
		frame = RZ_NEW0(RzDebugFrame);
		frame->addr = ptr;
		frame->size = 0;
		frame->sp = _rbp;
		frame->bp = _rbp + 8;
		// frame->name = (fcn && fcn->name) ? rz_str_dup (fcn->name) : NULL;
		rz_list_append(list, frame);
		_rbp = ebp2;
	}

	return list;
}
