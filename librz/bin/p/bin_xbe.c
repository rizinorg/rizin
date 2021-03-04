// SPDX-FileCopyrightText: 2014-2019 thatlemon@gmail.com <thatlemon@gmail.com>
// SPDX-FileCopyrightText: 2014-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <string.h>
#include "../format/xbe/xbe.h"

static const char *kt_name[] = {
#include "../format/xbe/kernel.h"
};

static bool check_buffer(RzBuffer *b) {
	ut8 magic[4];
	if (rz_buf_read_at(b, 0, magic, sizeof(magic)) == 4) {
		return !memcmp(magic, "XBEH", 4);
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	rz_bin_xbe_obj_t *obj = RZ_NEW(rz_bin_xbe_obj_t);
	if (!obj) {
		return false;
	}
	st64 r = rz_buf_read_at(buf, 0, (ut8 *)&obj->header, sizeof(obj->header));
	if (r != sizeof(obj->header)) {
		RZ_FREE(obj);
		return false;
	}

	if ((obj->header.ep & 0xf0000000) == 0x40000000) {
		// Sega Chihiro xbe
		obj->ep_key = XBE_EP_CHIHIRO;
		obj->kt_key = XBE_KP_CHIHIRO;
	} else if ((obj->header.ep ^ XBE_EP_RETAIL) > 0x1000000) {
		// Debug xbe
		obj->ep_key = XBE_EP_DEBUG;
		obj->kt_key = XBE_KP_DEBUG;
	} else {
		// Retail xbe
		obj->ep_key = XBE_EP_RETAIL;
		obj->kt_key = XBE_KP_RETAIL;
	}
	*bin_obj = obj;
	return true;
}

static void destroy(RzBinFile *bf) {
	RZ_FREE(bf->o->bin_obj);
}

static RzBinAddr *binsym(RzBinFile *bf, int type) {
	if (!bf || !bf->buf || type != RZ_BIN_SYM_MAIN) {
		return NULL;
	}
	rz_bin_xbe_obj_t *obj = bf->o->bin_obj;
	RzBinAddr *ret = RZ_NEW0(RzBinAddr);
	if (!ret) {
		return NULL;
	}
	ret->vaddr = obj->header.ep ^ obj->ep_key;
	ret->paddr = ret->vaddr - obj->header.base;
	return ret;
}

static RzList *entries(RzBinFile *bf) {
	const rz_bin_xbe_obj_t *obj;
	RzList *ret;
	RzBinAddr *ptr = RZ_NEW0(RzBinAddr);
	if (!bf || !bf->buf || !bf->o->bin_obj || !ptr) {
		free(ptr);
		return NULL;
	}
	ret = rz_list_new();
	if (!ret) {
		free(ptr);
		return NULL;
	}
	ret->free = free;
	obj = bf->o->bin_obj;
	ptr->vaddr = obj->header.ep ^ obj->ep_key;
	ptr->paddr = ptr->vaddr - obj->header.base;
	rz_list_append(ret, ptr);
	return ret;
}

static RzList *sections(RzBinFile *bf) {
	xbe_section *sect = NULL;
	rz_bin_xbe_obj_t *obj = NULL;
	xbe_header *h = NULL;
	RzList *ret = NULL;
	char tmp[0x100];
	int i, r;
	ut32 addr;

	if (!bf || !bf->o || !bf->o->bin_obj || !bf->buf) {
		return NULL;
	}
	obj = bf->o->bin_obj;
	h = &obj->header;
	if (h->sections < 1) {
		return NULL;
	}
	ret = rz_list_new();
	if (!ret) {
		return NULL;
	}
	ret->free = free;
	if (h->sections < 1 || h->sections > 255) {
		goto out_error;
	}
	sect = calloc(h->sections, sizeof(xbe_section));
	if (!sect) {
		goto out_error;
	}
	addr = h->sechdr_addr - h->base;
	if (addr > bf->size || addr + (sizeof(xbe_section) * h->sections) > bf->size) {
		goto out_error;
	}
	r = rz_buf_read_at(bf->buf, addr, (ut8 *)sect, sizeof(xbe_section) * h->sections);
	if (r < 1) {
		goto out_error;
	}
	for (i = 0; i < h->sections; i++) {
		RzBinSection *item = RZ_NEW0(RzBinSection);
		addr = sect[i].name_addr - h->base;
		tmp[0] = 0;
		if (addr > bf->size || addr + sizeof(tmp) > bf->size) {
			free(item);
			goto out_error;
		}
		r = rz_buf_read_at(bf->buf, addr, (ut8 *)tmp, sizeof(tmp));
		if (r < 1) {
			free(item);
			goto out_error;
		}
		tmp[sizeof(tmp) - 1] = 0;
		item->name = rz_str_newf("%s.%i", tmp, i);
		item->paddr = sect[i].offset;
		item->vaddr = sect[i].vaddr;
		item->size = sect[i].size;
		item->vsize = sect[i].vsize;
		item->add = true;

		item->perm = RZ_PERM_R;
		if (sect[i].flags & SECT_FLAG_X) {
			item->perm |= RZ_PERM_X;
		}
		if (sect[i].flags & SECT_FLAG_W) {
			item->perm |= RZ_PERM_W;
		}
		rz_list_append(ret, item);
	}
	free(sect);
	return ret;
out_error:
	rz_list_free(ret);
	free(sect);
	return NULL;
}

static RzList *libs(RzBinFile *bf) {
	rz_bin_xbe_obj_t *obj;
	xbe_header *h = NULL;
	int i, off, libs, r;
	xbe_lib lib;
	RzList *ret;
	char *s;
	ut32 addr;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	obj = bf->o->bin_obj;
	h = &obj->header;
	ret = rz_list_new();
	if (!ret) {
		return NULL;
	}
	ret->free = free;
	if (h->kernel_lib_addr < h->base) {
		off = 0;
	} else {
		off = h->kernel_lib_addr - h->base;
	}
	if (off > bf->size || off + sizeof(xbe_lib) > bf->size) {
		goto out_error;
	}
	r = rz_buf_read_at(bf->buf, off, (ut8 *)&lib, sizeof(xbe_lib));
	if (r < 1) {
		goto out_error;
	}
	lib.name[7] = 0;
	s = rz_str_newf("%s %i.%i.%i", lib.name, lib.major, lib.minor, lib.build);
	if (s) {
		rz_list_append(ret, s);
	}
	if (h->xapi_lib_addr < h->base) {
		off = 0;
	} else {
		off = h->xapi_lib_addr - h->base;
	}
	if (off > bf->size || off + sizeof(xbe_lib) > bf->size) {
		goto out_error;
	}
	r = rz_buf_read_at(bf->buf, off, (ut8 *)&lib, sizeof(xbe_lib));
	if (r < 1) {
		goto out_error;
	}

	lib.name[7] = 0;
	s = rz_str_newf("%s %i.%i.%i", lib.name, lib.major, lib.minor, lib.build);
	if (s) {
		rz_list_append(ret, s);
	}
	libs = h->lib_versions;
	if (libs < 1) {
		goto out_error;
	}
	for (i = 0; i < libs; i++) {
		addr = h->lib_versions_addr - h->base + (i * sizeof(xbe_lib));
		if (addr > bf->size || addr + sizeof(xbe_lib) > bf->size) {
			goto out_error;
		}
		r = rz_buf_read_at(bf->buf, addr, (ut8 *)&lib, sizeof(xbe_lib));
		if (r < 1) {
			goto out_error;
		}
		// make sure it ends with 0
		lib.name[7] = '\0';
		s = rz_str_newf("%s %i.%i.%i", lib.name, lib.major, lib.minor, lib.build);
		if (s) {
			rz_list_append(ret, s);
		}
	}

	return ret;
out_error:
	rz_list_free(ret);
	return NULL;
}

static RzList *symbols(RzBinFile *bf) {
	rz_bin_xbe_obj_t *obj;
	xbe_header *h;
	RzList *ret;
	int i, found = false;
	ut32 thunk_addr[XBE_MAX_THUNK];
	ut32 kt_addr;
	xbe_section sect;
	ut32 addr;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}

	obj = bf->o->bin_obj;
	h = &obj->header;
	kt_addr = h->kernel_thunk_addr ^ obj->kt_key;
	ret = rz_list_new();
	if (!ret) {
		return NULL;
	}
	ret->free = free;
	eprintf("sections %d\n", h->sections);
	int limit = h->sections;
	if (limit * (sizeof(xbe_section)) >= bf->size - h->sechdr_addr) {
		goto out_error;
	}
	for (i = 0; found == false && i < limit; i++) {
		addr = h->sechdr_addr - h->base + (sizeof(xbe_section) * i);
		if (addr > bf->size || addr + sizeof(sect) > bf->size) {
			goto out_error;
		}
		rz_buf_read_at(bf->buf, addr, (ut8 *)&sect, sizeof(sect));
		if (kt_addr >= sect.vaddr && kt_addr < sect.vaddr + sect.vsize) {
			found = true;
		}
	}
	if (!found) {
		goto out_error;
	}
	addr = sect.offset + (kt_addr - sect.vaddr);
	if (addr > bf->size || addr + sizeof(thunk_addr) > bf->size) {
		goto out_error;
	}
	i = rz_buf_read_at(bf->buf, addr, (ut8 *)&thunk_addr, sizeof(thunk_addr));
	if (i != sizeof(thunk_addr)) {
		goto out_error;
	}
	for (i = 0; i < XBE_MAX_THUNK && thunk_addr[i]; i++) {
		RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
		if (!sym) {
			goto out_error;
		}
		const ut32 thunk_index = thunk_addr[i] ^ 0x80000000;
		// Basic sanity checks
		if (thunk_addr[i] & 0x80000000 && thunk_index > 0 && thunk_index <= XBE_MAX_THUNK) {
			eprintf("thunk_index %d\n", thunk_index);
			sym->name = rz_str_newf("kt.%s", kt_name[thunk_index - 1]);
			sym->vaddr = (h->kernel_thunk_addr ^ obj->kt_key) + (4 * i);
			sym->paddr = sym->vaddr - h->base;
			sym->size = 4;
			sym->ordinal = i;
			rz_list_append(ret, sym);
		} else {
			free(sym);
		}
	}
	return ret;
out_error:
	rz_list_free(ret);
	return NULL;
}

static RzBinInfo *info(RzBinFile *bf) {
	rz_bin_xbe_obj_t *obj;
	RzBinInfo *ret;
	ut8 dbg_name[256];

	if (!bf || !bf->buf) {
		return NULL;
	}

	ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}

	obj = bf->o->bin_obj;

	memset(dbg_name, 0, sizeof(dbg_name));
	rz_buf_read_at(bf->buf, obj->header.debug_name_addr - obj->header.base, dbg_name, sizeof(dbg_name));
	dbg_name[sizeof(dbg_name) - 1] = 0;
	ret->file = strdup((char *)dbg_name);
	ret->bclass = strdup("program");
	ret->machine = strdup("Microsoft Xbox");
	ret->os = strdup("xbox");
	ret->type = strdup("Microsoft Xbox executable");
	ret->arch = strdup("x86");
	ret->has_va = 1;
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	ret->lang = NULL;
	return ret;
}

static ut64 baddr(RzBinFile *bf) {
	rz_bin_xbe_obj_t *obj = bf->o->bin_obj;
	return obj->header.base;
}

RzBinPlugin rz_bin_plugin_xbe = {
	.name = "xbe",
	.desc = "Microsoft Xbox xbe format rz_bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.libs = &libs,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_xbe,
	.version = RZ_VERSION
};
#endif
