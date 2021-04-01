// SPDX-FileCopyrightText: 2016-2019 Oscar Salvador <osalvador.vilardaga@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <rz_io.h>
#include "bflt/bflt.h"

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	*bin_obj = rz_bin_bflt_new_buf(buf);
	return *bin_obj;
}

static RzList *entries(RzBinFile *bf) {
	struct rz_bin_bflt_obj *obj = (struct rz_bin_bflt_obj *)bf->o->bin_obj;
	RzList *ret;
	RzBinAddr *ptr;

	if (!(ret = rz_list_newf(free))) {
		return NULL;
	}
	ptr = rz_bflt_get_entry(obj);
	if (!ptr) {
		rz_list_free(ret);
		return NULL;
	}
	rz_list_append(ret, ptr);
	return ret;
}

static void __patch_reloc(RzBuffer *buf, ut32 addr_to_patch, ut32 data_offset) {
	ut8 val[4] = {
		0
	};
	rz_write_le32(val, data_offset);
	rz_buf_write_at(buf, addr_to_patch, (void *)val, sizeof(val));
}

static int search_old_relocation(struct reloc_struct_t *reloc_table,
	ut32 addr_to_patch, int n_reloc) {
	int i;
	for (i = 0; i < n_reloc; i++) {
		if (addr_to_patch == reloc_table[i].data_offset) {
			return i;
		}
	}
	return -1;
}

static RzList *patch_relocs(RzBinFile *bf) {
	RzBin *b = bf->rbin;
	struct rz_bin_bflt_obj *bin = (struct rz_bin_bflt_obj *)bf->o->bin_obj;
	if (!(b->iob.io->cached & RZ_PERM_W)) {
		eprintf(
			"Warning: please run rizin with -e io.cache=true to patch "
			"relocations\n");
		return NULL;
	}
	RzList *list = rz_list_newf((RzListFree)free);
	if (!list) {
		return NULL;
	}
	if (bin->got_table) {
		struct reloc_struct_t *got_table = bin->got_table;
		for (int i = 0; i < bin->n_got; i++) {
			__patch_reloc(bin->b, got_table[i].addr_to_patch,
				got_table[i].data_offset);
			RzBinReloc *reloc = RZ_NEW0(RzBinReloc);
			if (reloc) {
				reloc->type = RZ_BIN_RELOC_32;
				reloc->paddr = got_table[i].addr_to_patch;
				reloc->vaddr = reloc->paddr;
				rz_list_append(list, reloc);
			}
		}
		RZ_FREE(bin->got_table);
	}

	if (bin->reloc_table) {
		struct reloc_struct_t *reloc_table = bin->reloc_table;
		for (int i = 0; i < bin->hdr->reloc_count; i++) {
			int found = search_old_relocation(reloc_table,
				reloc_table[i].addr_to_patch,
				bin->hdr->reloc_count);
			if (found != -1) {
				__patch_reloc(bin->b, reloc_table[found].addr_to_patch,
					reloc_table[i].data_offset);
			} else {
				__patch_reloc(bin->b, reloc_table[i].addr_to_patch,
					reloc_table[i].data_offset);
			}
			RzBinReloc *reloc = RZ_NEW0(RzBinReloc);
			if (reloc) {
				reloc->type = RZ_BIN_RELOC_32;
				reloc->paddr = reloc_table[i].addr_to_patch;
				reloc->vaddr = reloc->paddr;
				rz_list_append(list, reloc);
			}
		}
		RZ_FREE(bin->reloc_table);
	}
	ut64 tmpsz;
	const ut8 *tmp = rz_buf_data(bin->b, &tmpsz);
	b->iob.write_at(b->iob.io, 0, tmp, tmpsz);
	return list;
}

static ut32 get_ngot_entries(struct rz_bin_bflt_obj *obj) {
	ut32 data_size = obj->hdr->data_end - obj->hdr->data_start;
	ut32 i = 0, n_got = 0;
	if (data_size > obj->size) {
		return 0;
	}
	for (; i < data_size; i += 4, n_got++) {
		ut32 entry, offset = obj->hdr->data_start;
		if (offset + i + sizeof(ut32) > obj->size ||
			offset + i + sizeof(ut32) < offset) {
			return 0;
		}
		int len = rz_buf_read_at(obj->b, offset + i, (ut8 *)&entry,
			sizeof(ut32));
		if (len != sizeof(ut32)) {
			return 0;
		}
		if (!VALID_GOT_ENTRY(entry)) {
			break;
		}
	}
	return n_got;
}

static RzList *relocs(RzBinFile *bf) {
	struct rz_bin_bflt_obj *obj = (struct rz_bin_bflt_obj *)bf->o->bin_obj;
	RzList *list = rz_list_newf((RzListFree)free);
	ut32 i, len, n_got, amount;
	if (!list || !obj) {
		rz_list_free(list);
		return NULL;
	}
	if (obj->hdr->flags & FLAT_FLAG_GOTPIC) {
		n_got = get_ngot_entries(obj);
		if (n_got) {
			if (n_got > UT32_MAX / sizeof(struct reloc_struct_t)) {
				goto out_error;
			}
			amount = n_got * sizeof(struct reloc_struct_t);
			struct reloc_struct_t *got_table = calloc(1, amount);
			if (got_table) {
				ut32 offset = 0;
				for (i = 0; i < n_got; offset += 4, i++) {
					ut32 got_entry;
					if (obj->hdr->data_start + offset + 4 > obj->size ||
						obj->hdr->data_start + offset + 4 < offset) {
						break;
					}
					len = rz_buf_read_at(obj->b, obj->hdr->data_start + offset,
						(ut8 *)&got_entry, sizeof(ut32));
					if (!VALID_GOT_ENTRY(got_entry) || len != sizeof(ut32)) {
						break;
					}
					got_table[i].addr_to_patch = got_entry;
					got_table[i].data_offset = got_entry + BFLT_HDR_SIZE;
				}
				obj->n_got = n_got;
				obj->got_table = got_table;
			}
		}
	}

	if (obj->hdr->reloc_count > 0) {
		ut32 n_reloc = obj->hdr->reloc_count;
		if (n_reloc > UT32_MAX / sizeof(struct reloc_struct_t)) {
			goto out_error;
		}
		amount = n_reloc * sizeof(struct reloc_struct_t);
		struct reloc_struct_t *reloc_table = calloc(1, amount);
		if (!reloc_table) {
			goto out_error;
		}
		amount = n_reloc * sizeof(ut32);
		ut32 *reloc_pointer_table = calloc(1, amount);
		if (!reloc_pointer_table) {
			free(reloc_table);
			goto out_error;
		}
		if (obj->hdr->reloc_start + amount > obj->size ||
			obj->hdr->reloc_start + amount < amount) {
			free(reloc_table);
			free(reloc_pointer_table);
			goto out_error;
		}
		len = rz_buf_read_at(obj->b, obj->hdr->reloc_start,
			(ut8 *)reloc_pointer_table, amount);
		if (len != amount) {
			free(reloc_table);
			free(reloc_pointer_table);
			goto out_error;
		}
		for (i = 0; i < n_reloc; i++) {
			// XXX it doesn't take endian as consideration when swapping
			ut32 reloc_offset =
				rz_swap_ut32(reloc_pointer_table[i]) +
				BFLT_HDR_SIZE;

			if (reloc_offset < obj->hdr->bss_end && reloc_offset < obj->size) {
				ut32 reloc_fixed, reloc_data_offset;
				if (reloc_offset + sizeof(ut32) > obj->size ||
					reloc_offset + sizeof(ut32) < reloc_offset) {
					free(reloc_table);
					free(reloc_pointer_table);
					goto out_error;
				}
				len = rz_buf_read_at(obj->b, reloc_offset,
					(ut8 *)&reloc_fixed,
					sizeof(ut32));
				if (len != sizeof(ut32)) {
					eprintf("problem while reading relocation entries\n");
					free(reloc_table);
					free(reloc_pointer_table);
					goto out_error;
				}
				reloc_data_offset = rz_swap_ut32(reloc_fixed) + BFLT_HDR_SIZE;
				reloc_table[i].addr_to_patch = reloc_offset;
				reloc_table[i].data_offset = reloc_data_offset;

				RzBinReloc *reloc = RZ_NEW0(RzBinReloc);
				if (reloc) {
					reloc->type = RZ_BIN_RELOC_32;
					reloc->paddr = reloc_table[i].addr_to_patch;
					reloc->vaddr = reloc->paddr;
					rz_list_append(list, reloc);
				}
			}
		}
		free(reloc_pointer_table);
		obj->reloc_table = reloc_table;
	}
	return list;
out_error:
	rz_list_free(list);
	return NULL;
}

static RzBinInfo *info(RzBinFile *bf) {
	struct rz_bin_bflt_obj *obj = NULL;
	RzBinInfo *info = NULL;
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	obj = (struct rz_bin_bflt_obj *)bf->o->bin_obj;
	if (!(info = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	info->file = bf->file ? strdup(bf->file) : NULL;
	info->rclass = strdup("bflt");
	info->bclass = strdup("bflt");
	info->type = strdup("bFLT (Executable file)");
	info->os = strdup("Linux");
	info->subsystem = strdup("Linux");
	info->arch = strdup("arm");
	info->big_endian = obj->endian;
	info->bits = 32;
	info->has_va = false;
	info->dbg_info = 0;
	info->machine = strdup("unknown");
	return info;
}

static bool check_buffer(RzBuffer *buf) {
	ut8 tmp[4];
	int r = rz_buf_read_at(buf, 0, tmp, sizeof(tmp));
	return r == sizeof(tmp) && !memcmp(tmp, "bFLT", 4);
}

static void destroy(RzBinFile *bf) {
	rz_bin_bflt_free(bf->o->bin_obj);
}

RzBinPlugin rz_bin_plugin_bflt = {
	.name = "bflt",
	.desc = "bFLT format rz_bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.info = &info,
	.relocs = &relocs,
	.patch_relocs = &patch_relocs,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_bflt,
	.version = RZ_VERSION
};
#endif
