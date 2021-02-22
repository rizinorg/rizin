// SPDX-FileCopyrightText: 2019-2020 pancake
// SPDX-License-Identifier: LGPL-3.0-only

/* This code has been based on Alvaro's
 * rzpipe-python script which was based on FireEye script for IDA Pro.
 *
 * https://www.fireeye.com/blog/threat-research/2017/03/introduction_to_reve.html
 */

#include <rz_core.h>

#include "core_private.h"

typedef struct {
	RzCore *core;
	HtUP *up;
	size_t word_size;
	RzBinSection *_selrefs;
	RzBinSection *_msgrefs;
	RzBinSection *_const;
	RzBinSection *_data;
} RzCoreObjc;

const size_t objc2ClassSize = 0x28;
const size_t objc2ClassInfoOffs = 0x20;
const size_t objc2ClassMethSize = 0x18;
const size_t objc2ClassBaseMethsOffs = 0x20;
const size_t objc2ClassMethImpOffs = 0x10;

static void array_add(RzCoreObjc *o, ut64 va, ut64 xrefs_to) {
	bool found = false;
	RzVector *vec = ht_up_find(o->up, va, &found);
	if (!found || !vec) {
		vec = rz_vector_new(sizeof(ut64), NULL, NULL);
		ht_up_insert(o->up, va, vec);
	}
	ut64 *addr;
	rz_vector_foreach(vec, addr) {
		if (xrefs_to == *addr) {
			return;
		}
	}
	// extend vector and insert new element
	rz_vector_push(vec, &xrefs_to);
}

static void kv_array_free(HtUPKv *kv) {
	rz_vector_free(kv->value);
}

static inline bool isValid(ut64 addr) {
	return (addr != 0LL && addr != UT64_MAX);
}

static inline bool isInvalid(ut64 addr) {
	return !isValid(addr);
}

static inline bool inBetween(RzBinSection *s, ut64 addr) {
	if (!s || isInvalid(addr)) {
		return false;
	}
	const ut64 from = s->vaddr;
	const ut64 to = from + s->vsize;
	return RZ_BETWEEN(from, addr, to);
}

static ut32 readDword(RzCoreObjc *objc, ut64 addr, bool *success) {
	ut8 buf[4];
	*success = rz_io_read_at(objc->core->io, addr, buf, sizeof(buf));
	return rz_read_le32(buf);
}

static ut64 readQword(RzCoreObjc *objc, ut64 addr, bool *success) {
	ut8 buf[8] = { 0 };
	*success = rz_io_read_at(objc->core->io, addr, buf, sizeof(buf));
	return rz_read_le64(buf);
}

static void objc_analyze(RzCore *core) {
	const char *oldstr = rz_print_rowlog(core->print, "Analyzing code to find selref references");
	(void)rz_core_analysis_refs(core, "");
	if (!strcmp("arm", rz_config_get(core->config, "asm.arch"))) {
		const bool emu_lazy = rz_config_get_i(core->config, "emu.lazy");
		rz_config_set_i(core->config, "emu.lazy", true);
		rz_core_analysis_esil_default(core);
		rz_config_set_i(core->config, "emu.lazy", emu_lazy);
	}
	rz_print_rowlog_done(core->print, oldstr);
}

static ut64 getRefPtr(RzCoreObjc *o, ut64 classMethodsVA, bool *rfound) {
	*rfound = false;

	bool readSuccess;
	ut64 namePtr = readQword(o, classMethodsVA, &readSuccess);
	if (!readSuccess) {
		return UT64_MAX;
	}

	size_t cnt = 0;
	ut64 ref = UT64_MAX;
	bool isMsgRef = false;

	RzVector *vec = ht_up_find(o->up, namePtr, rfound);
	if (!*rfound || !vec) {
		*rfound = false;
		return false;
	}
	ut64 *addr;
	rz_vector_foreach(vec, addr) {
		const ut64 at = *addr;
		if (inBetween(o->_selrefs, at)) {
			isMsgRef = false;
			ref = at;
		} else if (inBetween(o->_msgrefs, at)) {
			isMsgRef = true;
			ref = at;
		} else if (inBetween(o->_const, at)) {
			cnt++;
		}
	}
	if (cnt > 1 || ref == 0 || ref == UT64_MAX) {
		*rfound = false;
		return UT64_MAX;
	}
	return isMsgRef ? ref - 8 : ref;
}

static bool objc_build_refs(RzCoreObjc *objc) {
	ut64 off;
	rz_return_val_if_fail(objc->_const && objc->_selrefs, false);

	const ut64 va_const = objc->_const->vaddr;
	size_t ss_const = objc->_const->vsize;
	const ut64 va_selrefs = objc->_selrefs->vaddr;
	size_t ss_selrefs = objc->_selrefs->vsize;

	// TODO: check if ss_const or ss_selrefs are too big before going further
	size_t maxsize = RZ_MAX(ss_const, ss_selrefs);
	ut8 *buf = calloc(1, maxsize);
	if (!buf) {
		return false;
	}
	const size_t word_size = objc->word_size; // assuming 8 because of the read_le64
	if (!rz_io_read_at(objc->core->io, objc->_const->vaddr, buf, ss_const)) {
		eprintf("aao: Cannot read the whole const section %zu\n", ss_const);
		return false;
	}
	for (off = 0; off + word_size < ss_const; off += word_size) {
		ut64 va = va_const + off;
		ut64 xrefs_to = rz_read_le64(buf + off);
		if (isValid(xrefs_to)) {
			array_add(objc, va, xrefs_to);
		}
	}
	if (!rz_io_read_at(objc->core->io, va_selrefs, buf, ss_selrefs)) {
		eprintf("aao: Cannot read the whole selrefs section\n");
		return false;
	}
	for (off = 0; off + word_size < ss_selrefs; off += word_size) {
		ut64 va = va_selrefs + off;
		ut64 xrefs_to = rz_read_le64(buf + off);
		if (isValid(xrefs_to)) {
			array_add(objc, xrefs_to, va);
		}
	}
	free(buf);
	return true;
}

static RzCoreObjc *core_objc_new(RzCore *core) {
	RzList *sections = rz_bin_get_sections(core->bin);
	if (!sections) {
		return false;
	}
	RzCoreObjc *o = RZ_NEW0(RzCoreObjc);
	o->core = core;
	o->word_size = (core->rasm->bits == 64) ? 8 : 4;
	if (o->word_size != 8) {
		eprintf("Warning: aao experimental on 32bit binaries\n");
	}

	RzBinSection *s;
	RzListIter *iter;
	rz_list_foreach (sections, iter, s) {
		const char *name = s->name;
		if (strstr(name, "__objc_data")) {
			o->_data = s;
		} else if (strstr(name, "__objc_selrefs")) {
			o->_selrefs = s;
		} else if (strstr(name, "__objc_msgrefs")) {
			o->_msgrefs = s;
		} else if (strstr(name, "__objc_const")) {
			o->_const = s;
		}
	}
	if (!o->_const || ((o->_selrefs || o->_msgrefs) && !(o->_data && o->_const))) {
		free(o);
		return NULL;
	}
	o->up = ht_up_new(NULL, kv_array_free, NULL);

	return o;
}

static void core_objc_free(RzCoreObjc *o) {
	if (o) {
		ht_up_free(o->up);
		free(o);
	}
}

static bool objc_find_refs(RzCore *core) {
	RzCoreObjc *objc = core_objc_new(core);
	if (!objc) {
		if (core->analysis->verbose) {
			eprintf("Could not find necessary Objective-C sections...\n");
		}
		return false;
	}

	if (!objc_build_refs(objc)) {
		core_objc_free(objc);
		return false;
	}
	const char *oldstr = rz_print_rowlog(core->print, "Parsing metadata in ObjC to find hidden xrefs");
	rz_print_rowlog_done(core->print, oldstr);

	ut64 off;
	size_t total_xrefs = 0;
	bool readSuccess = true;
	for (off = 0; off < objc->_data->vsize && readSuccess; off += objc2ClassSize) {
		if (!readSuccess || rz_cons_is_breaked()) {
			break;
		}

		ut64 va = objc->_data->vaddr + off;
		// XXX do a single rz_io_read_at() and just rz_read_le64() here
		ut64 classRoVA = readQword(objc, va + objc2ClassInfoOffs, &readSuccess);
		if (!readSuccess || isInvalid(classRoVA)) {
			continue;
		}
		ut64 classMethodsVA = readQword(objc, classRoVA + objc2ClassBaseMethsOffs, &readSuccess);
		if (!readSuccess || isInvalid(classMethodsVA)) {
			continue;
		}

		ut32 count = readDword(objc, classMethodsVA + 4, &readSuccess);
		if (!readSuccess || ((ut32)count == UT32_MAX)) {
			continue;
		}

		classMethodsVA += 8; // advance to start of class methods array
		ut64 to = classMethodsVA + (objc2ClassMethSize * count);
		if (classMethodsVA > to || classMethodsVA + 0xfffff < to) {
			eprintf("Warning: Fuzzed binary or bug in here, checking next\n");
			continue;
		}
		for (va = classMethodsVA; va < to; va += objc2ClassMethSize) {
			if (rz_cons_is_breaked()) {
				break;
			}
			bool found = false;
			ut64 selRefVA = getRefPtr(objc, va, &found);
			if (!found) {
				continue;
			}
			bool succ = false;
			ut64 funcVA = readQword(objc, va + objc2ClassMethImpOffs, &succ);
			if (!succ) {
				break;
			}

			RzList *list = rz_analysis_xrefs_get(core->analysis, selRefVA);
			if (list) {
				RzListIter *iter;
				RzAnalysisRef *ref;
				rz_list_foreach (list, iter, ref) {
					rz_analysis_xrefs_set(core->analysis, ref->addr, funcVA, RZ_ANALYSIS_REF_TYPE_CODE);
					total_xrefs++;
				}
			}
		}
	}

	const ut64 va_selrefs = objc->_selrefs->vaddr;
	const ut64 ss_selrefs = va_selrefs + objc->_selrefs->vsize;

	char rs[128];
	snprintf(rs, sizeof(rs), "Found %zu objc xrefs...", total_xrefs);
	rz_print_rowlog(core->print, rs);
	size_t total_words = 0;
	ut64 a;
	const size_t word_size = objc->word_size;
	for (a = va_selrefs; a < ss_selrefs; a += word_size) {
		rz_meta_set(core->analysis, RZ_META_TYPE_DATA, a, word_size, NULL);
		total_words++;
	}
	snprintf(rs, sizeof(rs), "Found %zu objc xrefs in %zu dwords.", total_xrefs, total_words);
	rz_print_rowlog_done(core->print, rs);
	core_objc_free(objc);
	return true;
}

RZ_API bool cmd_analysis_objc(RzCore *core, bool auto_analysis) {
	rz_return_val_if_fail(core, 0);
	if (!auto_analysis) {
		objc_analyze(core);
	}
	return objc_find_refs(core);
}
