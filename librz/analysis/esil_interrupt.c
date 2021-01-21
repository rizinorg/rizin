#include <rz_analysis.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <sdb.h>

static void _interrupt_free_cb(void *user) {
	RzAnalysisEsilInterrupt *intr = (RzAnalysisEsilInterrupt *)user;
	if (intr && intr->handler && intr->handler->fini) {
		intr->handler->fini(intr->user);
	}
	free(intr);
}

static bool _set_interrupt(RzAnalysisEsil *esil, RzAnalysisEsilInterrupt *intr) {
	return intr->handler->num ? dict_set(esil->interrupts, intr->handler->num, intr->handler->num, intr) : (esil->intr0 = intr, true);
}

static RzAnalysisEsilInterrupt *_get_interrupt(RzAnalysisEsil *esil, ut32 intr_num) {
	return intr_num ? (RzAnalysisEsilInterrupt *)dict_getu(esil->interrupts, intr_num) : esil->intr0;
}

static void _del_interrupt(RzAnalysisEsil *esil, ut32 intr_num) {
	if (intr_num) {
		dict_del(esil->interrupts, intr_num);
	} else {
		esil->intr0 = NULL;
	}
}

RZ_API void rz_analysis_esil_interrupts_init(RzAnalysisEsil *esil) {
	rz_return_if_fail(esil);
	esil->interrupts = dict_new(sizeof(ut32), NULL);
	esil->intr0 = NULL; // is this needed?
}

RZ_API RzAnalysisEsilInterrupt *rz_analysis_esil_interrupt_new(RzAnalysisEsil *esil, ut32 src_id, RzAnalysisEsilInterruptHandler *ih) {
	rz_return_val_if_fail(esil && ih && ih->cb, NULL);
	RzAnalysisEsilInterrupt *intr = RZ_NEW0(RzAnalysisEsilInterrupt);
	if (!intr) {
		return NULL;
	}
	intr->handler = ih;
	if (ih->init && ih->fini) {
		intr->user = ih->init(esil);
	}
	intr->src_id = src_id;
	rz_analysis_esil_claim_source(esil, src_id);
	return intr;
}

RZ_API void rz_analysis_esil_interrupt_free(RzAnalysisEsil *esil, RzAnalysisEsilInterrupt *intr) {
	if (intr && esil) {
		_del_interrupt(esil, intr->handler->num);
	}
	if (intr) {
		if (intr->user) {
			intr->handler->fini(intr->user); //fini must exist when user is !NULL
		}
		rz_analysis_esil_release_source(esil, intr->src_id);
	}
	free(intr);
}

RZ_API bool rz_analysis_esil_set_interrupt(RzAnalysisEsil *esil, RzAnalysisEsilInterrupt *intr) {
	rz_return_val_if_fail(esil && esil->interrupts && intr && intr->handler && intr->handler->cb, false);
	// check if interrupt is already set
	RzAnalysisEsilInterrupt *o_intr = _get_interrupt(esil, intr->handler->num);
	if (o_intr) {
		rz_analysis_esil_interrupt_free(esil, o_intr);
	}
	//set the new interrupt
	return _set_interrupt(esil, intr);
}

RZ_API int rz_analysis_esil_fire_interrupt(RzAnalysisEsil *esil, ut32 intr_num) {
	rz_return_val_if_fail(esil, false);

	if (esil->cmd && esil->cmd(esil, esil->cmd_intr, intr_num, 0)) { //compatibility
		return true;
	}

	if (!esil->interrupts) {
		eprintf("no interrupts initialized\n");
		return false;
	}
	RzAnalysisEsilInterrupt *intr = _get_interrupt(esil, intr_num);
#if 0
	// we don't want this warning
	if (!intr) {
		eprintf ("Warning no interrupt handler registered for 0x%x\n", intr_num);
	}
#endif
	return (intr && intr->handler && intr->handler->cb) ? intr->handler->cb(esil, intr_num, intr->user) : false;
}

RZ_API bool rz_analysis_esil_load_interrupts(RzAnalysisEsil *esil, RzAnalysisEsilInterruptHandler *handlers[], ut32 src_id) {
	RzAnalysisEsilInterrupt *intr;
	ut32 i = 0;

	rz_return_val_if_fail(esil && esil->interrupts && handlers, false);

	while (handlers[i]) {
		intr = _get_interrupt(esil, handlers[i]->num);
		if (intr) {
			//first free, then load the new handler or stuff might break in the handlers
			rz_analysis_esil_interrupt_free(esil, intr);
		}
		intr = rz_analysis_esil_interrupt_new(esil, src_id, handlers[i]);
		if (!intr) {
			return false;
		}
		rz_analysis_esil_set_interrupt(esil, intr);
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
		rz_lib_dl_sym(rz_analysis_esil_get_source(esil, src_id), "interrupts");
	if (!handlers) {
		rz_analysis_esil_release_source(esil, src_id); //unload
		return false;
	}
	return rz_analysis_esil_load_interrupts(esil, handlers, src_id);
}

RZ_API void rz_analysis_esil_interrupts_fini(RzAnalysisEsil *esil) {
	if (esil && esil->interrupts) {
		_interrupt_free_cb(esil->intr0);
		esil->intr0 = NULL;
		esil->interrupts->f = _interrupt_free_cb;
		dict_free(esil->interrupts);
		esil->interrupts = NULL;
	}
}
