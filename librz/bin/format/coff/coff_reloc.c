// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "coff.h"
#include <rz_util.h>
#include <rz_util/ht_uu.h>

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

	size_t i = 0;
	CoffScnHdr *hdr;
	rz_vector_enumerate (obj->scn_hdrs, hdr, i) {
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

static size_t reloc_general_arch_rel32_common(struct rz_bin_coff_obj *bin, RzBinReloc *reloc, ut64 sym_vaddr, ut8 *patch_buf, const char *print_name) {
	reloc->print_name = print_name;
	reloc->type = RZ_BIN_RELOC_32;
	reloc->additive = 1;
	ut32 data;
	if (!rz_buf_read_le32_at(bin->b, reloc->paddr, &data)) {
		return 0;
	}
	reloc->addend = data;
	data += sym_vaddr - reloc->vaddr - 4;
	rz_write_le32(patch_buf, (st32)data);

	return 4;
}

static size_t reloc_arm_branches_common(struct rz_bin_coff_obj *bin, RzBinReloc *reloc, ut64 sym_vaddr, ut8 *patch_buf, const char *print_name) {
	reloc->print_name = print_name;
	reloc->type = RZ_BIN_RELOC_32;
	ut16 hiword;
	if (!rz_buf_read_le16_at(bin->b, reloc->paddr, &hiword)) {
		return 0;
	}
	ut16 loword;
	if (!rz_buf_read_le16_at(bin->b, reloc->paddr + 2, &loword)) {
		return 0;
	}
	ut64 dst = sym_vaddr - reloc->vaddr - 4;
	if (dst & 1) {
		return 0;
	}
	loword |= (ut16)(dst >> 1) & 0x7ff;
	hiword |= (ut16)(dst >> 12) & 0x7ff;
	rz_write_le16(patch_buf, hiword);
	rz_write_le16(patch_buf + 2, loword);

	return 4;
}

static ut8 handle_i386_relocs(struct rz_bin_coff_obj *bin, RzBinReloc *reloc, ut64 sym_vaddr, ut8 *patch_buf, ut16 reloc_type) {
	switch (reloc_type) {
	case COFF_REL_I386_DIR32:
		reloc->type = RZ_BIN_RELOC_32;
		rz_write_le32(patch_buf, (ut32)sym_vaddr);
		reloc->print_name = "IMAGE_REL_I386_32";
		return 4;
	case COFF_REL_I386_REL32:
		return reloc_general_arch_rel32_common(bin, reloc, sym_vaddr, patch_buf, "IMAGE_REL_I386_REL32");
		// TODO: Missing handling of other relocation types
	default:
		RZ_LOG_DEBUG("Unimplemented/unknown COFF i386 relocation type: %d\n", reloc_type);
		break;
	}

	return 0;
}

static ut8 handle_amd64_relocs(struct rz_bin_coff_obj *bin, RzBinReloc *reloc, ut64 sym_vaddr, ut8 *patch_buf, ut16 reloc_type) {
	switch (reloc_type) {
	case COFF_REL_AMD64_REL32:
		return reloc_general_arch_rel32_common(bin, reloc, sym_vaddr, patch_buf, "IMAGE_REL_AMD64_REL32");
		// TODO: Missing handling of other relocation types
	default:
		RZ_LOG_DEBUG("Unimplemented/unknown COFF AMD64 relocation type: %d\n", reloc_type);
		break;
	}

	return 0;
}

static ut8 handle_arm_relocs(struct rz_bin_coff_obj *bin, RzBinReloc *reloc, ut64 sym_vaddr, ut8 *patch_buf, ut16 reloc_type) {
	switch (reloc_type) {
	case COFF_REL_ARM_BRANCH24T:
		return reloc_arm_branches_common(bin, reloc, sym_vaddr, patch_buf, "IMAGE_REL_ARM_BRANCH24T");
	case COFF_REL_ARM_BLX23T:
		return reloc_arm_branches_common(bin, reloc, sym_vaddr, patch_buf, "IMAGE_REL_ARM_BLX23T");
		// TODO: Missing handling of other relocation types
	default:
		RZ_LOG_DEBUG("Unimplemented/unknown COFF ARM relocation type: %d\n", reloc_type);
		break;
	}

	return 0;
}

static ut8 handle_arm64_relocs(struct rz_bin_coff_obj *bin, RzBinReloc *reloc, ut64 sym_vaddr, ut8 *patch_buf, ut16 reloc_type) {
	switch (reloc_type) {
	case COFF_REL_ARM64_BRANCH26:
		reloc->type = RZ_BIN_RELOC_32;
		ut32 data;
		if (!rz_buf_read_le32_at(bin->b, reloc->paddr, &data)) {
			break;
		}
		ut64 dst = sym_vaddr - reloc->vaddr;
		data |= (ut32)((dst >> 2) & 0x3ffffffULL);
		rz_write_le32(patch_buf, data);
		reloc->print_name = "IMAGE_REL_ARM64_BRANCH26";
		return 4;
		// TODO: Missing handling of other relocation types
	default:
		RZ_LOG_DEBUG("Unimplemented/unknown COFF ARM64 relocation type: %d\n", reloc_type);
		break;
	}

	return 0;
}

// Store `value` into the field of the little-endian word at `paddr` that a TI
// C6000 field spec describes: bits [start, start + size) of a `container`-bit
// word, other bits preserved. The patched word is written to patch_buf; returns
// the byte count (container / 8), or 0 if the spec or read is invalid.
static size_t ti_c6000_store_field(struct rz_bin_coff_obj *bin, ut64 paddr, ut32 fldspec, ut64 value, ut8 *patch_buf) {
	ut8 start = fldspec & 0xff;
	ut8 size = (fldspec >> 8) & 0xff;
	ut8 container = (fldspec >> 16) & 0xff;
	if (!size || size > container || start + size > container) {
		return 0;
	}
	ut64 mask = size >= 64 ? UT64_MAX : (((ut64)1 << size) - 1);
	ut64 field = (value & mask) << start;
	ut64 clear = mask << start;
	switch (container) {
	case 32: {
		ut32 word;
		if (!rz_buf_read_le32_at(bin->b, paddr, &word)) {
			return 0;
		}
		word = (word & ~(ut32)clear) | (ut32)field;
		rz_write_le32(patch_buf, word);
		return 4;
	}
	case 16: {
		ut16 hw;
		if (!rz_buf_read_le16_at(bin->b, paddr, &hw)) {
			return 0;
		}
		hw = (hw & ~(ut16)clear) | (ut16)field;
		rz_write_le16(patch_buf, hw);
		return 2;
	}
	case 8: {
		ut8 b;
		if (rz_buf_read_at(bin->b, paddr, &b, 1) != 1) {
			return 0;
		}
		patch_buf[0] = (b & ~(ut8)clear) | (ut8)field;
		return 1;
	}
	default:
		return 0;
	}
}

// Evaluate the TI TMS320C6000 relocation expressions of every section. Each
// field is patched by a contiguous RPN sequence (operators in coff_specs.h)
// that ends in a store; the running stack is reset at each store so the next
// field starts clean. One RzBinReloc is emitted per store, carrying the field
// width and the symbol the expression referenced.
static void ti_c6000_relocs_foreach(struct rz_bin_coff_obj *bin, RelocsForeachCb cb, void *user) {
	size_t i = 0;
	CoffScnHdr *scn_hdr = NULL;
	rz_vector_enumerate (bin->scn_hdrs, scn_hdr, i) {
		if (!scn_hdr->s_nreloc || !bin->scn_va) {
			continue;
		}
		if (scn_hdr->s_relptr > bin->size ||
			scn_hdr->s_relptr + (ut64)scn_hdr->s_nreloc * RZ_COFF_TI_RELOC_SIZE > bin->size) {
			continue;
		}
		ut64 off = scn_hdr->s_relptr;
		ut64 stack[16];
		int sp = 0;
		RzBinSymbol *cur_sym = NULL;
		for (ut32 j = 0; j < scn_hdr->s_nreloc; j++) {
			ut32 r_vaddr, r_symndx;
			ut16 r_disp, r_type;
			if (!rz_buf_read_le32_offset(bin->b, &off, &r_vaddr) ||
				!rz_buf_read_le32_offset(bin->b, &off, &r_symndx) ||
				!rz_buf_read_le16_offset(bin->b, &off, &r_disp) ||
				!rz_buf_read_le16_offset(bin->b, &off, &r_type)) {
				break;
			}
#define C6000_BINOP(expr) \
	do { \
		if (sp >= 2) { \
			ut64 b = stack[--sp], a = stack[sp - 1]; \
			stack[sp - 1] = (expr); \
		} \
	} while (0)
			switch (r_type) {
			case COFF_REL_C6000_PUSH: {
				RzBinSymbol *sym = ht_up_find(bin->sym_ht, (ut64)r_symndx, NULL);
				if (sp < 16) {
					stack[sp++] = sym ? sym->vaddr : 0;
				}
				if (sym) {
					cur_sym = sym;
				}
				break;
			}
			case COFF_REL_C6000_PUSHUK:
				if (sp < 16) {
					stack[sp++] = r_symndx;
				}
				break;
			case COFF_REL_C6000_PUSHSK:
				if (sp < 16) {
					stack[sp++] = (ut64)(st64)(st32)r_symndx;
				}
				break;
			case COFF_REL_C6000_ADD: C6000_BINOP(a + b); break;
			case COFF_REL_C6000_SUB: C6000_BINOP(a - b); break;
			case COFF_REL_C6000_MPY: C6000_BINOP(a * b); break;
			case COFF_REL_C6000_DIV: C6000_BINOP(b ? a / b : 0); break;
			case COFF_REL_C6000_MOD: C6000_BINOP(b ? a % b : 0); break;
			case COFF_REL_C6000_SR: C6000_BINOP(b < 64 ? a >> b : 0); break;
			case COFF_REL_C6000_ASR: C6000_BINOP(b < 64 ? (ut64)((st64)a >> b) : 0); break;
			case COFF_REL_C6000_SL: C6000_BINOP(b < 64 ? a << b : 0); break;
			case COFF_REL_C6000_AND: C6000_BINOP(a & b); break;
			case COFF_REL_C6000_OR: C6000_BINOP(a | b); break;
			case COFF_REL_C6000_XOR: C6000_BINOP(a ^ b); break;
			case COFF_REL_C6000_NEG:
				if (sp >= 1) {
					stack[sp - 1] = (ut64)(-(st64)stack[sp - 1]);
				}
				break;
			case COFF_REL_C6000_NOTB:
				if (sp >= 1) {
					stack[sp - 1] = ~stack[sp - 1];
				}
				break;
			case COFF_REL_C6000_USTFLD:
			case COFF_REL_C6000_SSTFLD:
			case COFF_REL_C6000_XSTFLD: {
				if (sp < 1) {
					break;
				}
				ut64 value = stack[--sp];
				ut8 patch_buf[8];
				ut8 container = (r_symndx >> 16) & 0xff;
				RzBinReloc reloc = { 0 };
				reloc.paddr = scn_hdr->s_scnptr + r_vaddr;
				reloc.vaddr = bin->scn_va[i] + r_vaddr;
				reloc.symbol = cur_sym;
				reloc.target_vaddr = cur_sym ? cur_sym->vaddr : value;
				reloc.type = container == 16 ? RZ_BIN_RELOC_16 : (container == 8 ? RZ_BIN_RELOC_8 : RZ_BIN_RELOC_32);
				reloc.print_name = "R_C6000_STFLD";
				size_t plen = ti_c6000_store_field(bin, reloc.paddr, r_symndx, value, patch_buf);
				cb(&reloc, plen ? patch_buf : NULL, plen, user);
				sp = 0;
				cur_sym = NULL;
				break;
			}
			case COFF_REL_C6000_RELBYTE:
			case COFF_REL_C6000_RELWORD:
			case COFF_REL_C6000_RELLONG: {
				// classic direct relocations: add the symbol value to the
				// in-place field, no stack involved
				RzBinSymbol *sym = ht_up_find(bin->sym_ht, (ut64)r_symndx, NULL);
				sp = 0;
				cur_sym = NULL;
				if (!sym) {
					break;
				}
				ut8 width = r_type == COFF_REL_C6000_RELLONG ? 32 : (r_type == COFF_REL_C6000_RELWORD ? 16 : 8);
				ut8 patch_buf[8];
				RzBinReloc reloc = { 0 };
				reloc.paddr = scn_hdr->s_scnptr + r_vaddr;
				reloc.vaddr = bin->scn_va[i] + r_vaddr;
				reloc.symbol = sym;
				reloc.additive = 1;
				reloc.type = width == 32 ? RZ_BIN_RELOC_32 : (width == 16 ? RZ_BIN_RELOC_16 : RZ_BIN_RELOC_8);
				reloc.print_name = r_type == COFF_REL_C6000_RELLONG ? "R_C6000_RELLONG" : (r_type == COFF_REL_C6000_RELWORD ? "R_C6000_RELWORD" : "R_C6000_RELBYTE");
				ut32 fldspec = ((ut32)width << 16) | ((ut32)width << 8);
				ut64 addend = 0;
				if (width == 32) {
					ut32 v;
					addend = rz_buf_read_le32_at(bin->b, reloc.paddr, &v) ? v : 0;
				} else if (width == 16) {
					ut16 v;
					addend = rz_buf_read_le16_at(bin->b, reloc.paddr, &v) ? v : 0;
				} else {
					ut8 v;
					addend = rz_buf_read_at(bin->b, reloc.paddr, &v, 1) == 1 ? v : 0;
				}
				reloc.addend = addend;
				reloc.target_vaddr = sym->vaddr;
				size_t plen = ti_c6000_store_field(bin, reloc.paddr, fldspec, sym->vaddr + addend, patch_buf);
				cb(&reloc, plen ? patch_buf : NULL, plen, user);
				break;
			}
			default:
				// framing/attribute relocations (alignment, fetch-packet
				// header, no-compact): no operand, and they terminate any
				// field expression, so drop the stack
				sp = 0;
				cur_sym = NULL;
				break;
			}
#undef C6000_BINOP
		}
	}
}

static void relocs_foreach(struct rz_bin_coff_obj *bin, RelocsForeachCb cb, void *user) {
	if (!bin->scn_hdrs) {
		return;
	}
	if (bin->target_id == COFF_FILE_TARGET_TI_TMS320C6000) {
		ti_c6000_relocs_foreach(bin, cb, user);
		return;
	}

	size_t i = 0;
	CoffScnHdr *scn_hdr = NULL;
	rz_vector_enumerate (bin->scn_hdrs, scn_hdr, i) {
		if (!scn_hdr->s_nreloc) {
			continue;
		}
		int size = scn_hdr->s_nreloc * sizeof(struct coff_reloc);
		if (size < 0) {
			break;
		}
		struct coff_reloc *rel = calloc(1, size + sizeof(struct coff_reloc));
		if (!rel) {
			break;
		}
		if (scn_hdr->s_relptr > bin->size ||
			scn_hdr->s_relptr + size > bin->size) {
			free(rel);
			break;
		}
		ut64 offset = scn_hdr->s_relptr;
		bool read_success = false;
		for (size_t j = 0; j < scn_hdr->s_nreloc; j++) {
			struct coff_reloc *coff_rel = rel + j;
			read_success = rz_buf_read_le32_offset(bin->b, &offset, &coff_rel->rz_vaddr) &&
				rz_buf_read_le32_offset(bin->b, &offset, &coff_rel->rz_symndx) &&
				rz_buf_read_le16_offset(bin->b, &offset, &coff_rel->rz_type);
			if (!read_success) {
				break;
			}
		}
		if (!read_success) {
			free(rel);
			break;
		}
		for (size_t j = 0; j < scn_hdr->s_nreloc; j++) {
			RzBinSymbol *symbol = (RzBinSymbol *)ht_up_find(bin->sym_ht, (ut64)rel[j].rz_symndx, NULL);
			if (!symbol) {
				continue;
			}
			RzBinReloc reloc = { 0 };

			reloc.symbol = symbol;
			reloc.paddr = scn_hdr->s_scnptr + rel[j].rz_vaddr;
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
				// TODO: Missing handling of MIPS architecture
				case COFF_FILE_MACHINE_I386:
					plen = handle_i386_relocs(bin, &reloc, sym_vaddr, patch_buf, rel[j].rz_type);
					break;
				case COFF_FILE_MACHINE_AMD64:
					plen = handle_amd64_relocs(bin, &reloc, sym_vaddr, patch_buf, rel[j].rz_type);
					break;
				case COFF_FILE_MACHINE_ARMNT:
					plen = handle_arm_relocs(bin, &reloc, sym_vaddr, patch_buf, rel[j].rz_type);
					break;
				case COFF_FILE_MACHINE_ARM64:
					plen = handle_arm64_relocs(bin, &reloc, sym_vaddr, patch_buf, rel[j].rz_type);
					break;
				default:
					RZ_LOG_DEBUG("Unimplemented/unknown COFF architecture type: %d\n", bin->hdr.f_magic);
					break;
				}
			}
			cb(&reloc, plen ? patch_buf : NULL, plen, user);
		}
		free(rel);
	}
}

void get_relocs_pvector_cb(RZ_BORROW RzBinReloc *reloc, ut8 *patch_buf, size_t patch_buf_sz, void *user) {
	RzPVector *r = user;
	RzBinReloc *reloc_copy = RZ_NEW(RzBinReloc);
	if (!reloc_copy) {
		return;
	}
	memcpy(reloc_copy, reloc, sizeof(*reloc_copy));
	rz_pvector_push(r, reloc_copy);
}

RZ_API RzPVector /*<RzBinReloc *>*/ *rz_coff_get_relocs(struct rz_bin_coff_obj *bin) {
	rz_return_val_if_fail(bin, NULL);
	RzPVector *r = rz_pvector_new(free);
	if (!r) {
		return NULL;
	}
	relocs_foreach(bin, get_relocs_pvector_cb, r);
	return r;
}

/// size of the artificial reloc target vfile
RZ_API ut64 rz_coff_get_reloc_targets_vfile_size(struct rz_bin_coff_obj *obj) {
	rz_return_val_if_fail(obj, 0);
	ut64 count = obj->imp_index ? ht_uu_size(obj->imp_index) : 0;
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
