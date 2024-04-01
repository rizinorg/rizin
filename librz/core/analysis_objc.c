// SPDX-FileCopyrightText: 2023 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2019-2020 pancake
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

#include "core_private.h"

/* The reference analysis code has been based on Alvaro's
 * rzpipe-python script which was based on FireEye script for IDA Pro.
 *
 * https://www.fireeye.com/blog/threat-research/2017/03/introduction_to_reve.html
 */

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
	const char *notify = "Analyzing code to find selfref references";
	rz_core_notify_begin(core, "%s", notify);
	(void)rz_core_analysis_refs(core, 0);
	if (!strcmp("arm", rz_config_get(core->config, "asm.arch"))) {
		const bool emu_lazy = rz_config_get_i(core->config, "emu.lazy");
		rz_config_set_i(core->config, "emu.lazy", true);
		rz_core_analysis_esil_default(core);
		rz_config_set_i(core->config, "emu.lazy", emu_lazy);
	}
	rz_core_notify_done(core, "%s", notify);
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
		RZ_LOG_ERROR("aao: Cannot read the whole const section %zu\n", ss_const);
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
		RZ_LOG_ERROR("aao: Cannot read the whole selrefs section\n");
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
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	const RzPVector *sections = obj ? rz_bin_object_get_sections_all(obj) : NULL;
	if (!sections) {
		return false;
	}
	RzCoreObjc *o = RZ_NEW0(RzCoreObjc);
	o->core = core;
	o->word_size = (core->rasm->bits == 64) ? 8 : 4;
	if (o->word_size != 8) {
		RZ_LOG_WARN("aao is experimental on 32bit binaries\n");
	}

	RzBinSection *s;
	void **iter;
	rz_pvector_foreach (sections, iter) {
		s = *iter;
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
		RZ_LOG_DEBUG("Could not find necessary Objective-C sections...\n");
		return false;
	}

	if (!objc_build_refs(objc)) {
		core_objc_free(objc);
		return false;
	}
	const char *notify = "Parsing metadata in ObjC to find hidden xrefs";
	rz_core_notify_begin(core, "%s", notify);

	size_t total_xrefs = 0;
	bool readSuccess = true;
	for (ut64 off = 0; off < objc->_data->vsize && readSuccess; off += objc2ClassSize) {
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
			RZ_LOG_WARN("objc: the input binary might be malformed or this could be a bug.\n");
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

			RzList *list = rz_analysis_xrefs_get_to(core->analysis, selRefVA);
			if (list) {
				RzListIter *iter;
				RzAnalysisXRef *xref;
				rz_list_foreach (list, iter, xref) {
					rz_analysis_xrefs_set(core->analysis, xref->from, funcVA, RZ_ANALYSIS_XREF_TYPE_CODE);
					total_xrefs++;
				}
			}
		}
	}
	rz_core_notify_done(core, "%s", notify);

	const ut64 va_selrefs = objc->_selrefs->vaddr;
	const ut64 ss_selrefs = va_selrefs + objc->_selrefs->vsize;

	rz_core_notify_begin(core, "Found %zu objc xrefs...", total_xrefs);
	size_t total_words = 0;
	const size_t word_size = objc->word_size;
	for (ut64 a = va_selrefs; a < ss_selrefs; a += word_size) {
		rz_meta_set(core->analysis, RZ_META_TYPE_DATA, a, word_size, NULL);
		total_words++;
	}
	rz_core_notify_done(core, "Found %zu objc xrefs in %zu dwords.", total_xrefs, total_words);
	core_objc_free(objc);
	return true;
}

RZ_API bool rz_core_analysis_objc_refs(RzCore *core, bool auto_analysis) {
	rz_return_val_if_fail(core, 0);
	if (!auto_analysis) {
		objc_analyze(core);
	}
	return objc_find_refs(core);
}

static const ut8 objc_stubs_pattern_x86_64[] = {
	0x48, 0x8b, 0x35, 0x00, 0x00, 0x00, 0x00, // mov   rsi, qword [<str pointer addr>]
	0xff, 0x25, 0x00, 0x00, 0x00, 0x00 // jmp   qword reloc.objc_msgSend
};
static const ut8 objc_stubs_mask_x86_64[] = {
	0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, // mov   rsi, qword [<str pointer addr>]
	0xff, 0xff, 0x00, 0x00, 0x00, 0x00 // jmp   qword reloc.objc_msgSend
};

// clang -arch arm64e ...
static const ut8 objc_stubs_pattern_arm64e[] = {
	0x01, 0x00, 0x00, 0x90, // adrp  x1, <section.__DATA.__objc_const>
	0x21, 0x00, 0x40, 0xf9, // ldr   x1, [x1, <selector string ptr offset>]
	0x11, 0x00, 0x00, 0x90, // adrp  x17, <reloc base>
	0x31, 0x02, 0x00, 0x91, // add   x17, x17, <reloc offset>
	0x30, 0x02, 0x40, 0xf9, // ldr   x16, [x17]
	0x11, 0x0a, 0x1f, 0xd7, // braa  x16, x17
	0x20, 0x00, 0x20, 0xd4, // brk   1
	0x20, 0x00, 0x20, 0xd4 // brk   1
};
static const ut8 objc_stubs_mask_arm64e[] = {
	0x1f, 0x00, 0x00, 0x9f, // adrp  x1, <section.__DATA.__objc_const>
	0xff, 0x03, 0xc0, 0xff, // ldr   x1, [x1, <selector string ptr offset>]
	0x1f, 0x00, 0x00, 0x9f, // adrp  x17, <reloc base>
	0xff, 0x03, 0xc0, 0xff, // add   x17, x17, <reloc offset>
	0xff, 0xff, 0xff, 0xff, // ldr   x16, [x17]
	0xff, 0xff, 0xff, 0xff, // braa  x16, x17
	0xff, 0xff, 0xff, 0xff, // brk   1
	0xff, 0xff, 0xff, 0xff // brk   1
};

// clang -arch arm64 ...
static const ut8 objc_stubs_pattern_arm64[] = {
	0x01, 0x00, 0x00, 0x90, // adrp  x1, <section.__DATA.__objc_const>
	0x21, 0x00, 0x40, 0xf9, // ldr   x1, [x1, <selector string ptr offset>]
	0x10, 0x00, 0x00, 0x90, // adrp  x16, <reloc base>
	0x10, 0x02, 0x40, 0xf9, // ldr   x16, [x17, <reloc offset>]
	0x00, 0x02, 0x1f, 0xd6, // br    x16
	0x20, 0x00, 0x20, 0xd4, // brk   1
	0x20, 0x00, 0x20, 0xd4, // brk   1
	0x20, 0x00, 0x20, 0xd4 // brk   1
};
static const ut8 objc_stubs_mask_arm64[] = {
	0x1f, 0x00, 0x00, 0x9f, // adrp  x1, <section.__DATA.__objc_const>
	0xff, 0x03, 0xc0, 0xff, // ldr   x1, [x1, <selector string ptr offset>]
	0x1f, 0x00, 0x00, 0x9f, // adrp  x16, <reloc base>
	0xff, 0x03, 0xc0, 0xff, // ldr   x16, [x16, <reloc offset>]
	0xff, 0xff, 0xff, 0xff, // br    x16
	0xff, 0xff, 0xff, 0xff, // brk   1
	0xff, 0xff, 0xff, 0xff, // brk   1
	0xff, 0xff, 0xff, 0xff // brk   1
};

// clang -arch arm64 -Wl,-objc_stubs_small ... (-arch arm64e -Wl,-objc_stubs_small exists too but generates nonsense)
static const ut8 objc_stubs_pattern_arm64_small[] = {
	0x01, 0x00, 0x00, 0x90, // adrp  x1, <section.__DATA.__objc_const>
	0x21, 0x00, 0x40, 0xf9, // ldr   x1, [x1, <selector string ptr offset>]
	0x00, 0x00, 0x00, 0x14 // b    <sym.imp.objc_msgSend>
};
static const ut8 objc_stubs_mask_arm64_small[] = {
	0x1f, 0x00, 0x00, 0x9f, // adrp  x1, <section.__DATA.__objc_const>
	0xff, 0x03, 0xc0, 0xff, // ldr   x1, [x1, <selector string ptr offset>]
	0x00, 0x00, 0x00, 0xfc, // b    <sym.imp.objc_msgSend>
};

static const ut8 objc_stubs_pattern_arm64_32[] = {
	0x01, 0x00, 0x00, 0x90, // adrp  x1, <section.__DATA.__objc_const>
	0x21, 0x00, 0x40, 0xb9, // ldr   w1, [x1, <selector string ptr offset>]
	0x10, 0x00, 0x00, 0x90, // adrp  x16, <reloc base>
	0x10, 0x02, 0x40, 0xb9, // ldr   w16, [x17, <reloc offset>]
	0x00, 0x02, 0x1f, 0xd6, // br    x16
	0x20, 0x00, 0x20, 0xd4, // brk   1
	0x20, 0x00, 0x20, 0xd4, // brk   1
	0x20, 0x00, 0x20, 0xd4 // brk   1
};
static const ut8 objc_stubs_mask_arm64_32[] = {
	0x1f, 0x00, 0x00, 0x9f, // adrp  x1, <section.__DATA.__objc_const>
	0xff, 0x03, 0xc0, 0xff, // ldr   w1, [x1, <selector string ptr offset>]
	0x1f, 0x00, 0x00, 0x9f, // adrp  x16, <reloc base>
	0xff, 0x03, 0xc0, 0xff, // ldr   w16, [x16, <reloc offset>]
	0xff, 0xff, 0xff, 0xff, // br    x16
	0xff, 0xff, 0xff, 0xff, // brk   1
	0xff, 0xff, 0xff, 0xff, // brk   1
	0xff, 0xff, 0xff, 0xff // brk   1
};

static const ut8 objc_stubs_pattern_arm64_32_small[] = {
	0x01, 0x00, 0x00, 0x90, // adrp  x1, <section.__DATA.__objc_const>
	0x21, 0x00, 0x40, 0xb9, // ldr   w1, [x1, <selector string ptr offset>]
	0x00, 0x00, 0x00, 0x14 // b    <sym.imp.objc_msgSend>
};
static const ut8 objc_stubs_mask_arm64_32_small[] = {
	0x1f, 0x00, 0x00, 0x9f, // adrp  x1, <section.__DATA.__objc_const>
	0xff, 0x03, 0xc0, 0xff, // ldr   w1, [x1, <selector string ptr offset>]
	0x00, 0x00, 0x00, 0xfc, // b    <sym.imp.objc_msgSend>
};

static ut64 arm64_adrp_get_addr(ut64 pc, ut32 op) {
	ut64 imm = (((op >> 5) & 0x7ffff) << 2) | ((op >> 29) & 3);
	imm <<= 12;
	if (imm & (1ULL << 32)) {
		// sign extend
		imm = (((ut64)-1LL) << 33) | imm;
	}
	return (pc & ~0xfffULL) + imm;
}

static ut64 arm64_get_imm12(ut32 op) {
	return (op >> 10) & 0xfff;
}

/**
 * Try to read the actual selector string through a pointer
 *
 * \param str_ptr_addr the address where a pointer to the selector string is
 * \param ptr_size size of the pointer in bytes
 * \param selector_out buffer to write the selector string to
 * \param selector_out_sz buffer size of \p selector_out
 */
static bool read_selector_indirect(RzIO *io, ut64 str_ptr_addr, size_t ptr_size, char *selector_out, size_t selector_out_sz) {
	ut8 ptr[8];
	if (!rz_io_read_at_mapped(io, str_ptr_addr, ptr, ptr_size)) {
		return false;
	}
	ut64 str_addr = ptr_size == 4 ? rz_read_le32(ptr) : rz_read_le64(ptr);
	if (rz_io_nread_at(io, str_addr, (ut8 *)selector_out, selector_out_sz - 1) <= 0) {
		return false;
	}
	selector_out[selector_out_sz - 1] = '\0';
	return true;
}

static bool objc_stubs_extract_arm64(RzCore *core, ut8 *stub_contents, ut64 addr, char *selector_out, size_t selector_out_sz, size_t ptr_size) {
	ut64 str_base = arm64_adrp_get_addr(addr, rz_read_le32(stub_contents));
	ut64 str_off = arm64_get_imm12(rz_read_le32(stub_contents + 4)) * ptr_size;
	ut64 str_ptr = str_base + str_off;
	return read_selector_indirect(core->io, str_ptr, ptr_size, selector_out, selector_out_sz);
}

static bool objc_stubs_extract_arm64_64(RzCore *core, ut8 *stub_contents, ut64 addr, char *selector_out, size_t selector_out_sz) {
	return objc_stubs_extract_arm64(core, stub_contents, addr, selector_out, selector_out_sz, 8);
}

static bool objc_stubs_extract_arm64_32(RzCore *core, ut8 *stub_contents, ut64 addr, char *selector_out, size_t selector_out_sz) {
	return objc_stubs_extract_arm64(core, stub_contents, addr, selector_out, selector_out_sz, 4);
}

static bool objc_stubs_extract_x86_64(RzCore *core, ut8 *stub_contents, ut64 addr, char *selector_out, size_t selector_out_sz) {
	// mov   rsi, qword [<str pointer addr>]
	// Encoded as:
	//   48 - REX opcode for 64bit operand
	//   8b - opcode: MOV Gv, Ev
	//   35 - ModRM:
	//          reg = 6 = rsi
	//          mod / r/m = 0 / 5 = disp32
	//   followed by 4 bytes forming the disp32
	st32 disp32 = rz_read_le32(stub_contents + 3);
	ut64 str_ptr = addr + 7 + (st64)disp32;
	return read_selector_indirect(core->io, str_ptr, 8, selector_out, selector_out_sz);
}

typedef struct {
	const ut8 *pattern;
	const ut8 *mask;
	size_t size;
	bool (*extract_selector_str)(RzCore *core, ut8 *stub_contents, ut64 addr, char *selector_out, size_t selector_out_sz);
} ObjcStubsPattern;

#define PATTERN(name, extract_fn) \
	{ objc_stubs_pattern_##name, objc_stubs_mask_##name, sizeof(objc_stubs_pattern_##name), extract_fn }

static const ObjcStubsPattern objc_stubs_patterns[] = {
	PATTERN(arm64e, objc_stubs_extract_arm64_64),
	PATTERN(arm64, objc_stubs_extract_arm64_64),
	PATTERN(arm64_small, objc_stubs_extract_arm64_64),
	PATTERN(arm64_32, objc_stubs_extract_arm64_32),
	PATTERN(arm64_32_small, objc_stubs_extract_arm64_32),
	PATTERN(x86_64, objc_stubs_extract_x86_64),
	{ 0 }
};

#undef PATTERN

static bool flag_with_space_exists_at(RzCore *core, ut64 addr, RzSpace *space) {
	const RzList *existing = rz_flag_get_list(core->flags, addr);
	if (!existing) {
		return false;
	}
	RzListIter *it;
	RzFlagItem *fi;
	rz_list_foreach (existing, it, fi) {
		if (rz_flag_item_get_space(fi) && rz_flag_item_get_space(fi) == space) {
			// Do not create a flag if there is already a symbol (unstripped bin)
			return true;
		}
	}
	return false;
}

static void apply_selector_stub_at(RzCore *core, ut64 addr, ut32 size, char *selector) {
	char name[512];
	RzFlagItem *fi = rz_flag_set_next(core->flags, rz_strf(name, "stub.objc_msgSend$%s", selector), addr, size);
	if (!fi) {
		return;
	}
	rz_flag_item_set_realname(fi, rz_strf(name, "objc_msgSend$%s", selector));
	// If there is already a function (e.g. from aa), rename it too
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, addr);
	if (fcn) {
		rz_core_analysis_function_rename(core, addr, rz_flag_item_get_name(fi));
	}
}

static void analyze_objc_stubs(RzCore *core, ut64 start, ut64 size) {
	// Selecting only a subset of the known patterns would be possible by checking the architecture.
	// But as long as there are only a few, checking them all for all binaries is ok.
	const ObjcStubsPattern *patterns = objc_stubs_patterns;

	size_t max_pattern_sz = 0;
	size_t min_pattern_sz = SIZE_MAX;
	for (const ObjcStubsPattern *pattern = patterns; pattern->pattern; pattern++) {
		if (pattern->size > max_pattern_sz) {
			max_pattern_sz = pattern->size;
		}
		if (pattern->size < min_pattern_sz) {
			min_pattern_sz = pattern->size;
		}
	}
	ut64 offset = 0;
	ut8 *stub_contents = malloc(max_pattern_sz);
	if (!stub_contents) {
		return;
	}
	RzSpace *symbols_space = rz_spaces_get(&core->flags->spaces, RZ_FLAGS_FS_SYMBOLS);
	rz_flag_space_push(core->flags, "objc-stubs");
	rz_cons_break_push(NULL, NULL);
	while (offset + min_pattern_sz <= size && !rz_cons_is_breaked()) {
		ut64 addr = start + offset;
		size_t read_sz = RZ_MIN(max_pattern_sz, size - offset);
		if (!rz_io_read_at_mapped(core->io, addr, stub_contents, read_sz)) {
			RZ_LOG_ERROR("Failed to read in __objc_stubs at 0x%" PFMT64x "\n", addr);
			break;
		}
		ut64 stride = 0;
		for (const ObjcStubsPattern *pattern = patterns; pattern->pattern; pattern++) {
			if (pattern->size > read_sz) {
				// not enough bytes remaining in section for this pattern to match
				continue;
			}
			if (!rz_mem_eq_masked(stub_contents, pattern->pattern, pattern->mask, pattern->size)) {
				// no match
				continue;
			}
			stride = pattern->size;
			if (flag_with_space_exists_at(core, addr, symbols_space)) {
				// there is already a symbol, no need to annotate
				break;
			}
			char selector[256];
			if (!pattern->extract_selector_str(core, stub_contents, addr, selector, sizeof(selector))) {
				break;
			}
			// An optional sanity check here would be to also assert that really objc_msgSend is
			// called and no other function.
			apply_selector_stub_at(core, addr, pattern->size, selector);
			break;
		}
		if (!stride) {
			RZ_LOG_ERROR("Failed to match any known pattern against __objc_stubs contents. "
				     "If this is not a manually modified binary, please consider opening an "
				     "issue to let the rizin team know about this new format.\n");
			// no pattern matched, cancel the entire search because the section is not in a known format.
			break;
		}
		offset += stride;
	}
	rz_cons_break_pop();
	rz_flag_space_pop(core->flags);
	free(stub_contents);
}

/**
 * Analyze the __objc_stubs section and assign names to all detected
 * selector stubs found
 */
RZ_API void rz_core_analysis_objc_stubs(RzCore *core) {
	rz_return_if_fail(core);
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	const RzPVector *sections = obj ? rz_bin_object_get_sections_all(obj) : NULL;
	if (!sections) {
		return;
	}
	RzBinSection *stubs_section;
	void **iter;
	rz_pvector_foreach (sections, iter) {
		stubs_section = *iter;
		if (strstr(stubs_section->name, "__objc_stubs")) {
			goto found;
		}
	}
	RZ_LOG_ERROR("__objc_stubs section not found for analysis");
	return;
found:
	analyze_objc_stubs(core, stubs_section->vaddr, stubs_section->vsize);
}
