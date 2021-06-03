
#include "coff.h"
#include <rz_util.h>
#include <ht_uu.h>

/// base vaddr where to map the artificial reloc target vfile
RZ_API ut64 rz_coff_get_reloc_targets_map_base(struct rz_bin_coff_obj *obj) {
	rz_return_val_if_fail(obj, 0);
	if (obj->reloc_targets_map_base_calculated) {
		return obj->reloc_targets_map_base;
	}
	if (!obj->scn_va) {
		return 0;
	}
	ut64 max = 0;
	for (size_t i = 0; i < obj->hdr.f_nscns; i++) {
		struct coff_scn_hdr *hdr = &obj->scn_hdrs[i];
		ut64 val = obj->scn_va[i] + hdr->s_size;
		if (val > max) {
			max = val;
		}
	}
	max += 8;
	max += rz_num_align_delta(max, RZ_COFF_RELOC_TARGET_SIZE);
	obj->reloc_targets_map_base = max;
	obj->reloc_targets_map_base_calculated = true;
	return obj->reloc_targets_map_base;
}

RZ_API ut64 rz_coff_import_index_addr(struct rz_bin_coff_obj *obj, ut64 imp_index) {
	return rz_coff_get_reloc_targets_map_base(obj) + imp_index * RZ_COFF_RELOC_TARGET_SIZE;
}

typedef void (*RelocsForeachCb)(RZ_BORROW RzBinReloc *reloc, ut8 *patch_buf, size_t patch_buf_sz, void *user);

static void relocs_foreach(struct rz_bin_coff_obj *bin, RelocsForeachCb cb, void *user) {
	struct coff_reloc *rel;
	for (size_t i = 0; i < bin->hdr.f_nscns; i++) {
		if (!bin->scn_hdrs[i].s_nreloc) {
			continue;
		}
		int len = 0, size = bin->scn_hdrs[i].s_nreloc * sizeof(struct coff_reloc);
		if (size < 0) {
			break;
		}
		rel = calloc(1, size + sizeof(struct coff_reloc));
		if (!rel) {
			break;
		}
		if (bin->scn_hdrs[i].s_relptr > bin->size ||
			bin->scn_hdrs[i].s_relptr + size > bin->size) {
			free(rel);
			break;
		}
		len = rz_buf_read_at(bin->b, bin->scn_hdrs[i].s_relptr, (ut8 *)rel, size);
		if (len != size) {
			free(rel);
			break;
		}
		for (size_t j = 0; j < bin->scn_hdrs[i].s_nreloc; j++) {
			RzBinSymbol *symbol = (RzBinSymbol *)ht_up_find(bin->sym_ht, (ut64)rel[j].rz_symndx, NULL);
			if (!symbol) {
				continue;
			}
			RzBinReloc reloc = { 0 };

			reloc.symbol = symbol;
			reloc.paddr = bin->scn_hdrs[i].s_scnptr + rel[j].rz_vaddr;
			if (bin->scn_va) {
				reloc.vaddr = bin->scn_va[i] + rel[j].rz_vaddr;
			}
			reloc.type = rel[j].rz_type;

			ut64 sym_vaddr = symbol->vaddr;
			if (symbol->is_imported) {
				reloc.import = (RzBinImport *)ht_up_find(bin->imp_ht, (ut64)rel[j].rz_symndx, NULL);
				ut64 imp_idx = ht_uu_find(bin->imp_index, (ut64)rel[j].rz_symndx, NULL);
				sym_vaddr = rz_coff_import_index_addr(bin, imp_idx);
			}
			reloc.target_vaddr = sym_vaddr;

			size_t plen = 0;
			ut8 patch_buf[8];
			if (sym_vaddr) {
				switch (bin->hdr.f_magic) {
				case COFF_FILE_MACHINE_I386:
					switch (rel[j].rz_type) {
					case COFF_REL_I386_DIR32:
						reloc.type = RZ_BIN_RELOC_32;
						rz_write_le32(patch_buf, (ut32)sym_vaddr);
						plen = 4;
						break;
					case COFF_REL_I386_REL32:
						reloc.type = RZ_BIN_RELOC_32;
						reloc.additive = 1;
						ut64 data = rz_buf_read_le32_at(bin->b, reloc.paddr);
						if (data == UT32_MAX) {
							break;
						}
						reloc.addend = data;
						data += sym_vaddr - reloc.vaddr - 4;
						rz_write_le32(patch_buf, (st32)data);
						plen = 4;
						break;
					}
					break;
				case COFF_FILE_MACHINE_AMD64:
					switch (rel[j].rz_type) {
					case COFF_REL_AMD64_REL32:
						reloc.type = RZ_BIN_RELOC_32;
						reloc.additive = 1;
						ut64 data = rz_buf_read_le32_at(bin->b, reloc.paddr);
						if (data == UT32_MAX) {
							break;
						}
						reloc.addend = data;
						data += sym_vaddr - reloc.vaddr - 4;
						rz_write_le32(patch_buf, (st32)data);
						plen = 4;
						break;
					}
					break;
				case COFF_FILE_MACHINE_ARMNT:
					switch (rel[j].rz_type) {
					case COFF_REL_ARM_BRANCH24T:
					case COFF_REL_ARM_BLX23T:
						reloc.type = RZ_BIN_RELOC_32;
						ut16 hiword = rz_buf_read_le16_at(bin->b, reloc.paddr);
						if (hiword == UT16_MAX) {
							break;
						}
						ut16 loword = rz_buf_read_le16_at(bin->b, reloc.paddr + 2);
						if (loword == UT16_MAX) {
							break;
						}
						ut64 dst = sym_vaddr - reloc.vaddr - 4;
						if (dst & 1) {
							break;
						}
						loword |= (ut16)(dst >> 1) & 0x7ff;
						hiword |= (ut16)(dst >> 12) & 0x7ff;
						rz_write_le16(patch_buf, hiword);
						rz_write_le16(patch_buf + 2, loword);
						plen = 4;
						break;
					}
					break;
				case COFF_FILE_MACHINE_ARM64:
					switch (rel[j].rz_type) {
					case COFF_REL_ARM64_BRANCH26:
						reloc.type = RZ_BIN_RELOC_32;
						ut32 data = rz_buf_read_le32_at(bin->b, reloc.paddr);
						if (data == UT32_MAX) {
							break;
						}
						ut64 dst = sym_vaddr - reloc.vaddr;
						data |= (ut32)((dst >> 2) & 0x3ffffffULL);
						rz_write_le32(patch_buf, data);
						plen = 4;
						break;
					}
					break;
				}
			}
			cb(&reloc, plen ? patch_buf : NULL, plen, user);
		}
		free(rel);
	}
}

void get_relocs_list_cb(RZ_BORROW RzBinReloc *reloc, ut8 *patch_buf, size_t patch_buf_sz, void *user) {
	RzList *r = user;
	RzBinReloc *reloc_copy = RZ_NEW(RzBinReloc);
	if (!reloc_copy) {
		return;
	}
	memcpy(reloc_copy, reloc, sizeof(*reloc_copy));
	rz_list_push(r, reloc_copy);
}

RZ_API RzList *rz_coff_get_relocs(struct rz_bin_coff_obj *bin) {
	rz_return_val_if_fail(bin && bin->scn_hdrs, NULL);
	RzList *r = rz_list_newf(free);
	if (!r) {
		return NULL;
	}
	relocs_foreach(bin, get_relocs_list_cb, r);
	return r;
}

/// size of the artificial reloc target vfile
RZ_API ut64 rz_coff_get_reloc_targets_vfile_size(struct rz_bin_coff_obj *obj) {
	rz_return_val_if_fail(obj, 0);
	ut64 count = obj->imp_index ? obj->imp_index->count : 0;
	return count * RZ_COFF_RELOC_TARGET_SIZE;
}

static void patch_reloc_cb(RZ_BORROW RzBinReloc *reloc, ut8 *patch_buf, size_t patch_buf_sz, void *user) {
	RzBuffer *buf = user;
	if (patch_buf) {
		rz_buf_write_at(buf, reloc->paddr, patch_buf, patch_buf_sz);
	}
}

RZ_API RZ_BORROW RzBuffer *rz_coff_get_patched_buf(struct rz_bin_coff_obj *bin) {
	rz_return_val_if_fail(bin, NULL);
	if (bin->buf_patched) {
		return bin->buf_patched;
	}
	bin->buf_patched = rz_buf_new_sparse_overlay(bin->b, RZ_BUF_SPARSE_WRITE_MODE_SPARSE);
	if (!bin->buf_patched) {
		return NULL;
	}
	relocs_foreach(bin, patch_reloc_cb, bin->buf_patched);
	rz_buf_sparse_set_write_mode(bin->buf_patched, RZ_BUF_SPARSE_WRITE_MODE_THROUGH);
	return bin->buf_patched;
}
