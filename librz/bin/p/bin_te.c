// SPDX-FileCopyrightText: 2013-2019 xvilka <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "te/te_specs.h"
#include "te/te.h"

static Sdb *get_sdb(RzBinFile *bf) {
	RzBinObject *o = bf->o;
	if (!o) {
		return NULL;
	}
	struct rz_bin_te_obj_t *bin = (struct rz_bin_te_obj_t *)o->bin_obj;
	return bin ? bin->kv : NULL;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	rz_return_val_if_fail(bf && obj && b, false);
	ut64 sz = rz_buf_size(b);
	if (sz == 0 || sz == UT64_MAX) {
		return false;
	}
	struct rz_bin_te_obj_t *res = rz_bin_te_new_buf(b);
	if (res) {
		sdb_ns_set(sdb, "info", res->kv);
	}
	obj->bin_obj = res;
	return true;
}

static void destroy(RzBinFile *bf) {
	rz_bin_te_free((struct rz_bin_te_obj_t *)bf->o->bin_obj);
}

static ut64 baddr(RzBinFile *bf) {
	return rz_bin_te_get_image_base(bf->o->bin_obj);
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol type) {
	RzBinAddr *ret = NULL;
	switch (type) {
	case RZ_BIN_SPECIAL_SYMBOL_MAIN:
		if (!(ret = RZ_NEW(RzBinAddr))) {
			return NULL;
		}
		ret->paddr = ret->vaddr = rz_bin_te_get_main_paddr(bf->o->bin_obj);
		break;
	default:
		break;
	}
	return ret;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new(free);
	if (ret) {
		RzBinAddr *entry = rz_bin_te_get_entrypoint(bf->o->bin_obj);
		if (entry) {
			RzBinAddr *ptr = RZ_NEW0(RzBinAddr);
			if (ptr) {
				ptr->paddr = entry->paddr;
				ptr->vaddr = entry->vaddr;
				rz_pvector_push(ret, ptr);
			}
			free(entry);
		}
	}
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzPVector *ret = NULL;
	RzBinSection *ptr = NULL;
	struct rz_bin_te_section_t *sections = NULL;
	int i;

	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}
	if (!(sections = rz_bin_te_get_sections(bf->o->bin_obj))) {
		free(ret);
		return NULL;
	}
	for (i = 0; !sections[i].last; i++) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			break;
		}
		ptr->name = rz_str_dup((char *)sections[i].name);
		ptr->size = sections[i].size;
		ptr->vsize = sections[i].vsize;
		ptr->paddr = sections[i].paddr;
		ptr->vaddr = sections[i].vaddr;
		ptr->perm = 0;
		if (RZ_BIN_TE_SCN_IS_EXECUTABLE(sections[i].flags)) {
			ptr->perm |= RZ_PERM_X;
		}
		if (RZ_BIN_TE_SCN_IS_WRITABLE(sections[i].flags)) {
			ptr->perm |= RZ_PERM_W;
		}
		if (RZ_BIN_TE_SCN_IS_READABLE(sections[i].flags)) {
			ptr->perm |= RZ_PERM_R;
		}
		if (RZ_BIN_TE_SCN_IS_SHAREABLE(sections[i].flags)) {
			ptr->perm |= RZ_PERM_SHAR;
		}
		/* All TE files have _TEXT_RE section, which is 16-bit, because of
		 * CPU start in this mode */
		if (!strncmp(ptr->name, "_TEXT_RE", 8)) {
			ptr->bits = RZ_SYS_BITS_16;
		}
		rz_pvector_push(ret, ptr);
	}
	free(sections);
	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->bclass = rz_str_dup("TE");
	ret->rclass = rz_str_dup("te");
	ret->os = rz_bin_te_get_os(bf->o->bin_obj);
	ret->arch = rz_bin_te_get_arch(bf->o->bin_obj);
	ret->machine = rz_bin_te_get_machine(bf->o->bin_obj);
	ret->subsystem = rz_bin_te_get_subsystem(bf->o->bin_obj);
	ret->type = rz_str_dup("EXEC (Executable file)");
	ret->bits = rz_bin_te_get_bits(bf->o->bin_obj);
	ret->big_endian = 1;
	ret->dbg_info = 0;
	ret->has_va = true;

	sdb_num_set(bf->sdb, "te.bits", ret->bits);

	return ret;
}

static bool check_buffer(RzBuffer *b) {
	ut8 buf[2];
	if (rz_buf_read_at(b, 0, buf, 2) == 2) {
		return !memcmp(buf, "\x56\x5a", 2);
	}
	return false;
}

RzBinPlugin rz_bin_plugin_te = {
	.name = "te",
	.desc = "TE bin plugin", // Terse Executable format
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &sections,
	.info = &info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_te,
	.version = RZ_VERSION
};
#endif
