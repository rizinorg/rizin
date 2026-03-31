// SPDX-FileCopyrightText: 2023 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <rz_core.h>
#include "../i/private.h"
#include "mach0/mach0.h"
#include "objc/mach0_classes.h"
#include <rz_util/ht_uu.h>

// wip settings

static RzBinInfo *mach0_info(RzBinFile *bf);

static Sdb *mach0_get_sdb(RzBinFile *bf) {
	RzBinObject *o = bf->o;
	if (!o) {
		return NULL;
	}
	struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *)o->bin_obj;
	return bin ? bin->kv : NULL;
}

static char *mach0_entitlements(RzBinFile *bf, bool json) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	struct MACH0_(obj_t) *bin = bf->o->bin_obj;
	if (!bin->signature) {
		return NULL;
	}
	if (json) {
		PJ *pj = pj_new();
		pj_s(pj, (const char *)bin->signature);
		return pj_drain(pj);
	} else {
		return rz_str_dup((const char *)bin->signature);
	}
}

static bool mach0_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	rz_return_val_if_fail(bf && obj && buf, false);
	struct MACH0_(opts_t) opts;
	MACH0_(opts_set_default)
	(&opts, bf);
	struct MACH0_(obj_t) *res = MACH0_(new_buf)(buf, &opts);
	if (res) {
		sdb_ns_set(sdb, "info", res->kv);
		obj->bin_obj = res;
		return true;
	}
	return false;
}

static void mach0_destroy(RzBinFile *bf) {
	MACH0_(mach0_free)
	(bf->o->bin_obj);
}

static ut64 mach0_baddr(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, UT64_MAX);
	struct MACH0_(obj_t) *bin = bf->o->bin_obj;
	return MACH0_(get_baddr)(bin);
}

static RzPVector /*<RzBinVirtualFile *>*/ *mach0_virtual_files(RzBinFile *bf) {
	return MACH0_(get_virtual_files)(bf);
}

static RzPVector /*<RzBinMap *>*/ *mach0_maps(RzBinFile *bf) {
	return MACH0_(get_maps)(bf);
}

static RzPVector /*<RzBinSection *>*/ *mach0_sections(RzBinFile *bf) {
	return MACH0_(get_segments)(bf);
}

static RzBinAddr *newEntry(ut64 hpaddr, ut64 paddr, int type, int bits) {
	RzBinAddr *ptr = RZ_NEW0(RzBinAddr);
	if (ptr) {
		ptr->paddr = paddr;
		ptr->vaddr = paddr;
		ptr->hpaddr = hpaddr;
		ptr->bits = bits;
		ptr->type = type;
		// realign due to thumb
		if (bits == 16 && ptr->vaddr & 1) {
			ptr->paddr--;
			ptr->vaddr--;
		}
	}
	return ptr;
}

static void process_constructors(RzBinFile *bf, RzPVector /*<RzBinAddr *>*/ *ret, int bits) {
	RzPVector *secs = mach0_sections(bf);
	void **iter;
	RzBinSection *sec;
	int i, type;
	rz_pvector_foreach (secs, iter) {
		sec = *iter;
		type = -1;
		if (strstr(sec->name, "_mod_fini_func")) {
			type = RZ_BIN_ENTRY_TYPE_FINI;
		} else if (strstr(sec->name, "_mod_init_func")) {
			type = RZ_BIN_ENTRY_TYPE_INIT;
		}
		if (type != -1) {
			ut8 *buf = calloc(sec->size, 1);
			if (!buf) {
				continue;
			}
			int read = rz_buf_read_at(bf->buf, sec->paddr, buf, sec->size);
			if (read < sec->size) {
				RZ_LOG_ERROR("process_constructors: cannot process section %s\n", sec->name);
				continue;
			}
			if (bits == 32) {
				for (i = 0; i + 3 < sec->size; i += 4) {
					ut32 addr32 = rz_read_le32(buf + i);
					RzBinAddr *ba = newEntry(sec->paddr + i, (ut64)addr32, type, bits);
					if (ba) {
						rz_pvector_push(ret, ba);
					}
				}
			} else {
				for (i = 0; i + 7 < sec->size; i += 8) {
					ut64 addr64 = rz_read_le64(buf + i);
					RzBinAddr *ba = newEntry(sec->paddr + i, addr64, type, bits);
					if (ba) {
						rz_pvector_push(ret, ba);
					}
				}
			}
			free(buf);
		}
	}
}

static RzPVector /*<RzBinAddr *>*/ *mach0_entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);

	RzBinAddr *ptr = NULL;
	struct addr_t *entry = NULL;

	RzPVector *ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}

	int bits = MACH0_(get_bits)(bf->o->bin_obj);
	if (!(entry = MACH0_(get_entrypoint)(bf->o->bin_obj))) {
		return ret;
	}
	if ((ptr = RZ_NEW0(RzBinAddr))) {
		ptr->paddr = entry->offset + bf->o->boffset;
		ptr->vaddr = entry->addr;
		ptr->hpaddr = entry->haddr;
		ptr->bits = bits;
		// realign due to thumb
		if (bits == 16) {
			if (ptr->vaddr & 1) {
				ptr->paddr--;
				ptr->vaddr--;
			}
		}
		rz_pvector_push(ret, ptr);
	}

	process_constructors(bf, ret, bits);
	// constructors
	free(entry);
	return ret;
}

static void _handle_arm_thumb(struct MACH0_(obj_t) * bin, RzBinSymbol **p) {
	RzBinSymbol *ptr = *p;
	if (bin) {
		if (ptr->paddr & 1) {
			ptr->paddr--;
			ptr->vaddr--;
			ptr->bits = 16;
		}
	}
}

static RzPVector /*<RzBinSymbol *>*/ *mach0_symbols(RzBinFile *bf) {
	struct MACH0_(obj_t) * bin;
	int i;
	const struct symbol_t *syms = NULL;
	RzBinSymbol *ptr = NULL;
	RzBinObject *obj = bf ? bf->o : NULL;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	int wordsize = 0;
	if (!ret) {
		return NULL;
	}
	if (!obj || !obj->bin_obj) {
		free(ret);
		return NULL;
	}
	bool isStripped = false;
	wordsize = MACH0_(get_bits)(obj->bin_obj);

	// OLD CODE
	if (!(syms = MACH0_(get_symbols)(obj->bin_obj))) {
		return ret;
	}
	RzSetU *symcache = rz_set_u_new();
	bin = (struct MACH0_(obj_t) *)obj->bin_obj;
	for (i = 0; !syms[i].last; i++) {
		if (syms[i].name == NULL || syms[i].name[0] == '\0' || syms[i].addr < 100) {
			continue;
		}
		if (!(ptr = RZ_NEW0(RzBinSymbol))) {
			break;
		}
		ptr->name = rz_str_dup((char *)syms[i].name);
		ptr->is_imported = syms[i].is_imported;
		ptr->forwarder = "NONE";
		ptr->bind = (syms[i].type == RZ_BIN_MACH0_SYMBOL_TYPE_LOCAL) ? RZ_BIN_BIND_LOCAL_STR : RZ_BIN_BIND_GLOBAL_STR;
		ptr->type = RZ_BIN_TYPE_FUNC_STR;
		ptr->vaddr = syms[i].addr;
		ptr->paddr = syms[i].offset + obj->boffset;
		ptr->size = syms[i].size;
		ptr->bits = syms[i].bits;
		if (bin->hdr.cputype == CPU_TYPE_ARM && wordsize < 64) {
			_handle_arm_thumb(bin, &ptr);
		}
		ptr->ordinal = i;
		bin->dbg_info = strncmp(ptr->name, "radr://", 7) ? 0 : 1;
		rz_set_u_add(symcache, ptr->vaddr);
		rz_pvector_push(ret, ptr);
	}
	// functions from LC_FUNCTION_STARTS
	if (bin->func_start) {
		ut64 value = 0, address = 0;
		const ut8 *temp = bin->func_start;
		const ut8 *temp_end = bin->func_start + bin->func_size;
		while (temp + 3 < temp_end && *temp) {
			temp = rz_uleb128_decode(temp, NULL, &value);
			address += value;
			ptr = RZ_NEW0(RzBinSymbol);
			if (!ptr) {
				break;
			}
			ptr->vaddr = bin->baddr + address;
			ptr->paddr = address;
			ptr->size = 0;
			ptr->name = rz_str_newf("func.%08" PFMT64x, ptr->vaddr);
			ptr->type = RZ_BIN_TYPE_FUNC_STR;
			ptr->forwarder = "NONE";
			ptr->bind = RZ_BIN_BIND_LOCAL_STR;
			ptr->ordinal = i++;
			if (bin->hdr.cputype == CPU_TYPE_ARM && wordsize < 64) {
				_handle_arm_thumb(bin, &ptr);
			}
			rz_pvector_push(ret, ptr);
			// if any func is not found in syms then we can consider it is stripped
			if (!isStripped) {
				if (!rz_set_u_contains(symcache, ptr->vaddr)) {
					isStripped = true;
				}
			}
		}
	}
	if (isStripped) {
		bin->dbg_info |= RZ_BIN_DBG_STRIPPED;
	}
	rz_set_u_free(symcache);
	return ret;
}

static RzBinImport *import_from_name(RzBin *rbin, const char *orig_name, HtPP *imports_by_name) {
	if (imports_by_name) {
		bool found = false;
		RzBinImport *ptr = ht_pp_find(imports_by_name, orig_name, &found);
		if (found) {
			return ptr;
		}
	}

	RzBinImport *ptr = NULL;
	if (!(ptr = RZ_NEW0(RzBinImport))) {
		return NULL;
	}

	char *name = (char *)orig_name;
	const char *_objc_class = "_OBJC_CLASS_$";
	const int _objc_class_len = strlen(_objc_class);
	const char *_objc_metaclass = "_OBJC_METACLASS_$";
	const int _objc_metaclass_len = strlen(_objc_metaclass);
	char *type = "FUNC";

	if (!strncmp(name, _objc_class, _objc_class_len)) {
		name += _objc_class_len;
		type = "OBJC_CLASS";
	} else if (!strncmp(name, _objc_metaclass, _objc_metaclass_len)) {
		name += _objc_metaclass_len;
		type = "OBJC_METACLASS";
	}

	// Remove the extra underscore that every import seems to have in Mach-O.
	if (*name == '_') {
		name++;
	}
	ptr->name = rz_str_dup(name);
	ptr->bind = "NONE";
	ptr->type = rz_str_constpool_get(&rbin->constpool, type);

	if (imports_by_name) {
		ht_pp_insert(imports_by_name, orig_name, ptr);
	}

	return ptr;
}

typedef struct {
	RzBin *bin;
	struct MACH0_(obj_t) * obj;
	RzPVector /*<RzBinImport *>*/ *imports_dst;
} ImportsForeachCtx;

static void imports_foreach_cb(char *name, int ord, void *user) {
	ImportsForeachCtx *ctx = user;
	RzBinImport *ptr = import_from_name(ctx->bin, name, NULL);
	if (!ptr) {
		free(name);
		return;
	}
	ptr->ordinal = ord;
	if (ptr->ordinal < rz_pvector_len(&ctx->obj->imports_by_ord)) {
		rz_pvector_set(&ctx->obj->imports_by_ord, ptr->ordinal, ptr);
	}
	if (!strcmp(name, "__stack_chk_fail")) {
		ctx->obj->has_canary = true;
	}
	if (!strcmp(name, "__asan_init") ||
		!strcmp(name, "__tsan_init")) {
		ctx->obj->has_sanitizers = true;
	}
	if (!strcmp(name, "_NSConcreteGlobalBlock")) {
		ctx->obj->has_blocks_ext = true;
	}
	rz_pvector_push(ctx->imports_dst, ptr);
	free(name);
}

static RzPVector /*<RzBinImport *>*/ *mach0_imports(RzBinFile *bf) {
	RzBinObject *obj = bf ? bf->o : NULL;
	struct MACH0_(obj_t) *bin = bf ? bf->o->bin_obj : NULL;
	if (!obj || !bin || !obj->bin_obj) {
		return NULL;
	}
	bin->has_canary = false;
	bin->has_retguard = -1;
	bin->has_sanitizers = false;
	bin->has_blocks_ext = false;
	RzPVector *ret = rz_pvector_new((RzListFree)rz_bin_import_free);
	if (!ret) {
		return NULL;
	}
	if (!rz_pvector_len(&bin->imports_by_ord)) {
		size_t count = MACH0_(imports_count)(bin);
		if (count) {
			void **imp = rz_pvector_insert_range(&bin->imports_by_ord, 0, NULL, count);
			if (imp) {
				memset(imp, 0, sizeof(void *) * rz_pvector_len(&bin->imports_by_ord));
			}
		}
	}
	ImportsForeachCtx ctx = { bf->rbin, bin, ret };
	// clang-format off
	MACH0_(imports_foreach)(bin, imports_foreach_cb, &ctx);
	// clang-format on
	return ret;
}

static RzPVector /*<RzBinReloc *>*/ *mach0_relocs(RzBinFile *bf) {
	RzPVector *ret = NULL;
	struct MACH0_(obj_t) *bin = NULL;
	RzBinObject *obj = bf ? bf->o : NULL;
	if (bf && bf->o) {
		bin = bf->o->bin_obj;
	}
	if (!obj || !obj->bin_obj || !(ret = rz_pvector_new(free))) {
		return NULL;
	}

	RzSkipList *relocs = MACH0_(get_relocs)(bf->o->bin_obj);
	if (!relocs) {
		return ret;
	}
	RzSkipListNode *it;
	struct reloc_t *reloc;
	rz_skiplist_foreach (relocs, it, reloc) {
		RzBinReloc *ptr = RZ_NEW0(RzBinReloc);
		if (!ptr) {
			break;
		}
		ptr->type = reloc->type;
		ptr->additive = 0;
		if (reloc->name[0]) {
			RzBinImport *imp;
			if (!(imp = import_from_name(bf->rbin, (char *)reloc->name, bin->imports_by_name))) {
				free(ptr);
				break;
			}
			ptr->import = imp;
		} else if (reloc->ord >= 0 && reloc->ord < rz_pvector_len(&bin->imports_by_ord)) {
			ptr->import = rz_pvector_at(&bin->imports_by_ord, reloc->ord);
		}
		ptr->addend = reloc->addend;
		ptr->vaddr = reloc->addr;
		ptr->paddr = reloc->offset;
		ptr->target_vaddr = reloc->target;
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

static RzPVector /*<char *>*/ *mach0_libs(RzBinFile *bf) {
	int i;
	char *ptr = NULL;
	struct lib_t *libs;
	RzPVector *ret = NULL;
	RzBinObject *obj = bf ? bf->o : NULL;

	if (!obj || !obj->bin_obj || !(ret = rz_pvector_new(free))) {
		return NULL;
	}
	if ((libs = MACH0_(get_libs)(obj->bin_obj))) {
		for (i = 0; !libs[i].last; i++) {
			ptr = rz_str_dup(libs[i].name);
			rz_pvector_push(ret, ptr);
		}
		free(libs);
	}
	return ret;
}

static RzBinInfo *mach0_info(RzBinFile *bf) {
	struct MACH0_(obj_t) *bin = NULL;
	char *str;

	rz_return_val_if_fail(bf && bf->o, NULL);
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}

	bin = bf->o->bin_obj;
	if (bf->file) {
		ret->file = rz_str_dup(bf->file);
	}
	if ((str = MACH0_(get_class)(bf->o->bin_obj))) {
		ret->bclass = str;
	}
	if (bin) {
		ret->has_canary = bin->has_canary;
		ret->has_retguard = -1;
		ret->has_sanitizers = bin->has_sanitizers;
		ret->dbg_info = bin->dbg_info;
		ret->lang = bin->lang;
	}
	ret->intrp = rz_str_dup(MACH0_(get_intrp)(bf->o->bin_obj));
	ret->compiler = rz_str_dup("");
	ret->rclass = rz_str_dup("mach0");
	ret->os = rz_str_dup("darwin");
	ret->subsystem = rz_str_dup(MACH0_(get_platform)(bf->o->bin_obj));
	ret->arch = strdup(MACH0_(get_cputype)(bf->o->bin_obj));
	ret->cpu = MACH0_(get_cpusubtype)(bf->o->bin_obj);
	ret->machine = MACH0_(get_cpusubtype)(bf->o->bin_obj);
	ret->type = MACH0_(get_filetype)(bf->o->bin_obj);
	ret->big_endian = MACH0_(is_big_endian)(bf->buf);
	ret->bits = MACH0_(get_bits)(bf->o->bin_obj);
	if (bf && bf->o && bf->o->bin_obj) {
		ret->has_crypto = ((struct MACH0_(obj_t) *)
					   bf->o->bin_obj)
					  ->has_crypto;
		ret->bits = MACH0_(get_bits)(bf->o->bin_obj);
	}
	ret->has_va = true;
	ret->has_pi = MACH0_(is_pie)(bf->o->bin_obj);
	ret->has_nx = MACH0_(has_nx)(bf->o->bin_obj);

	return ret;
}

static RzPVector /*<RzBinClass *>*/ *mach0_classes(RzBinFile *bf) {
	return MACH0_(parse_classes)(bf, NULL);
}
