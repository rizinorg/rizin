// SPDX-FileCopyrightText: 2018 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_util.h>
#include <rz_lib.h>

static void interrupt_free(RzAnalysisEsilInterrupt *i) {
	rz_analysis_esil_interrupt_free(i->esil, i);
}

RZ_API void rz_analysis_esil_interrupts_init(RzAnalysisEsil *esil) {
	rz_return_if_fail(esil);
	esil->interrupts = ht_up_new(NULL, (HtUPFreeValue)interrupt_free);
}

RZ_API RzAnalysisEsilInterrupt *rz_analysis_esil_interrupt_new(RzAnalysisEsil *esil, ut32 src_id, RzAnalysisEsilInterruptHandler *ih) {
	rz_return_val_if_fail(esil && ih && ih->cb, NULL);
	RzAnalysisEsilInterrupt *intr = RZ_NEW0(RzAnalysisEsilInterrupt);
	if (!intr) {
		return NULL;
	}
	intr->esil = esil;
	intr->handler = ih;
	if (ih->init && ih->fini) {
		intr->user = ih->init(esil);
	}
	intr->src_id = src_id;
	rz_analysis_esil_claim_source(esil, src_id);
	return intr;
}

RZ_API void rz_analysis_esil_interrupt_free(RzAnalysisEsil *esil, RzAnalysisEsilInterrupt *intr) {
	rz_return_if_fail(esil);
	if (intr) {
		if (intr->user) {
			intr->handler->fini(intr->user); // fini must exist when user is !NULL
		}
		rz_analysis_esil_release_source(esil, intr->src_id);
		free(intr);
	}
}

RZ_API bool rz_analysis_esil_set_interrupt(RzAnalysisEsil *esil, RzAnalysisEsilInterrupt *intr) {
	rz_return_val_if_fail(esil && esil->interrupts && intr && intr->handler && intr->handler->cb, false);
	return ht_up_update(esil->interrupts, intr->handler->num, intr);
}

RZ_API int rz_analysis_esil_fire_interrupt(RzAnalysisEsil *esil, ut32 intr_num) {
	rz_return_val_if_fail(esil, false);

	if (esil->cmd && esil->cmd(esil, esil->cmd_intr, intr_num, 0)) { // compatibility
		return true;
	}

	if (!esil->interrupts) {
		RZ_LOG_ERROR("no interrupts initialized\n");
		return false;
	}
	RzAnalysisEsilInterrupt *intr = ht_up_find(esil->interrupts, intr_num, NULL);
#if 0
	// we don't want this warning
	if (!intr) {
		RZ_LOG_WARN("no interrupt handler registered for 0x%x\n", intr_num);
	}
#endif
	return (intr && intr->handler && intr->handler->cb) ? intr->handler->cb(esil, intr_num, intr->user) : false;
}

RZ_API bool rz_analysis_esil_load_interrupts(RzAnalysisEsil *esil, RzAnalysisEsilInterruptHandler *handlers[], ut32 src_id) {
	RzAnalysisEsilInterrupt *intr;
	ut32 i = 0;

	rz_return_val_if_fail(esil && esil->interrupts && handlers, false);

	while (handlers[i]) {
		intr = rz_analysis_esil_interrupt_new(esil, src_id, handlers[i]);
		if (!intr) {
			return false;
		}
		if (!rz_analysis_esil_set_interrupt(esil, intr)) {
			free(intr);
		}
		i++;
	}

	return true;
}

RZ_API bool rz_analysis_esil_load_interrupts_from_lib(RzAnalysisEsil *esil, const char *path) {
	rz_return_val_if_fail(esil, false);
	ut32 src_id = rz_analysis_esil_load_source(esil, path);
	if (!src_id) { // why id=0 is invalid?
		return false;
	}
	RzAnalysisEsilInterruptHandler **handlers = (RzAnalysisEsilInterruptHandler **)
		rz_sys_dlsym(rz_analysis_esil_get_source(esil, src_id), "interrupts");
	if (!handlers) {
		rz_analysis_esil_release_source(esil, src_id); // unload
		return false;
	}
	return rz_analysis_esil_load_interrupts(esil, handlers, src_id);
}

RZ_API void rz_analysis_esil_interrupts_fini(RzAnalysisEsil *esil) {
	rz_return_if_fail(esil && esil->interrupts);
	ht_up_free(esil->interrupts);
	esil->interrupts = NULL;
}
