// SPDX-FileCopyrightText: 2015-2018 nodepad <nod3pad@gmail.com>
// SPDX-FileCopyrightText: 2015-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "mz.h"
#include <rz_list.h>

static ut64 rz_bin_mz_va_to_la(const ut16 segment, const ut16 offset) {
	return (segment << 4) + offset;
}

static ut64 rz_bin_mz_la_to_pa(const struct rz_bin_mz_obj_t *bin, ut64 la) {
	return la + (bin->dos_header->header_paragraphs << 4);
}

RzBinAddr *rz_bin_mz_get_entrypoint(const struct rz_bin_mz_obj_t *bin) {
	const MZ_image_dos_header *mz;
	ut64 la;
	RzBinAddr *entrypoint;

	if (!bin || !bin->dos_header) {
		return NULL;
	}

	mz = bin->dos_header;
	la = rz_bin_mz_va_to_la(mz->cs, mz->ip);
	la &= 0xfffff;
	if (la >= bin->load_module_size) {
		eprintf("Error: entry point outside load module\n");
		return NULL;
	}
	entrypoint = RZ_NEW0(RzBinAddr);
	if (entrypoint) {
		entrypoint->vaddr = la;
		entrypoint->paddr = rz_bin_mz_la_to_pa(bin, la);
	}

	return entrypoint;
}

static int cmp_sections(const void *a, const void *b) {
	const RzBinSection *s_a, *s_b;

	s_a = a;
	s_b = b;

	return s_a->vaddr - s_b->vaddr;
}

static RzBinSection *rz_bin_mz_init_section(const struct rz_bin_mz_obj_t *bin,
	ut64 laddr) {
	RzBinSection *section;

	section = RZ_NEW0(RzBinSection);
	if (section) {
		section->vaddr = laddr;
	}

	return section;
}

RzList *rz_bin_mz_get_segments(const struct rz_bin_mz_obj_t *bin) {
	RzList *seg_list;
	RzListIter *iter;
	RzBinSection *section;
	MZ_image_relocation_entry *relocs;
	int i, num_relocs, section_number;
	ut16 ss;

	if (!bin || !bin->dos_header) {
		return NULL;
	}

	seg_list = rz_list_newf((RzListFree)rz_bin_section_free);
	if (!seg_list) {
		return NULL;
	}

	/* Add address of first segment to make sure that it is present
	 * even if there are no relocations or there isn't first segment in
	 * the relocations. */
	section = rz_bin_mz_init_section(bin, 0);
	if (!section) {
		goto err_out;
	}
	rz_list_add_sorted(seg_list, section, cmp_sections);

	relocs = bin->relocation_entries;
	num_relocs = bin->dos_header->num_relocs;
	for (i = 0; i < num_relocs; i++) {
		RzBinSection c;
		ut64 laddr, paddr, section_laddr;
		ut16 curr_seg;

		laddr = rz_bin_mz_va_to_la(relocs[i].segment, relocs[i].offset);
		if ((laddr + 2) >= bin->load_module_size) {
			continue;
		}

		paddr = rz_bin_mz_la_to_pa(bin, laddr);
		if (rz_buf_size(bin->b) < paddr + 2) {
			continue;
		}
		curr_seg = rz_buf_read_le16_at(bin->b, paddr);

		section_laddr = rz_bin_mz_va_to_la(curr_seg, 0);
		if (section_laddr > bin->load_module_size) {
			continue;
		}

		c.vaddr = section_laddr;
		if (rz_list_find(seg_list, &c, cmp_sections)) {
			continue;
		}

		section = rz_bin_mz_init_section(bin, section_laddr);
		if (!section) {
			goto err_out;
		}
		rz_list_add_sorted(seg_list, section, cmp_sections);
	}

	/* Add address of stack segment if it's inside the load module. */
	ss = bin->dos_header->ss;
	if (rz_bin_mz_va_to_la(ss, 0) < bin->load_module_size) {
		section = rz_bin_mz_init_section(bin, rz_bin_mz_va_to_la(ss, 0));
		if (!section) {
			goto err_out;
		}
		rz_list_add_sorted(seg_list, section, cmp_sections);
	}

	/* Fixup sizes and addresses, set name, permissions and set add flag */
	section_number = 0;
	rz_list_foreach (seg_list, iter, section) {
		section->name = rz_str_newf("seg_%03d", section_number);
		if (section_number) {
			RzBinSection *p_section = iter->p->data;
			p_section->size = section->vaddr - p_section->vaddr;
			p_section->vsize = p_section->size;
		}
		section->vsize = section->size;
		section->paddr = rz_bin_mz_la_to_pa(bin, section->vaddr);
		section->perm = rz_str_rwx("rwx");
		section_number++;
	}
	section = rz_list_get_top(seg_list);
	section->size = bin->load_module_size - section->vaddr;
	section->vsize = section->size;

	return seg_list;

err_out:
	eprintf("Error: alloc (RzBinSection)\n");
	rz_list_free(seg_list);

	return NULL;
}

struct rz_bin_mz_reloc_t *rz_bin_mz_get_relocs(const struct rz_bin_mz_obj_t *bin) {
	int i, j;
	const int num_relocs = bin->dos_header->num_relocs;
	const MZ_image_relocation_entry *const rel_entry = bin->relocation_entries;

	struct rz_bin_mz_reloc_t *relocs = calloc(num_relocs + 1, sizeof(*relocs));
	if (!relocs) {
		eprintf("Error: calloc (struct rz_bin_mz_reloc_t)\n");
		return NULL;
	}
	for (i = 0, j = 0; i < num_relocs; i++) {
		relocs[j].vaddr = rz_bin_mz_va_to_la(rel_entry[i].segment,
			rel_entry[i].offset);
		relocs[j].paddr = rz_bin_mz_la_to_pa(bin, relocs[j].vaddr);

		/* Add only relocations which resides inside dos executable */
		if (relocs[j].vaddr < bin->load_module_size) {
			j++;
		}
	}
	relocs[j].last = 1;

	return relocs;
}

void *rz_bin_mz_free(struct rz_bin_mz_obj_t *bin) {
	if (!bin) {
		return NULL;
	}
	free((void *)bin->dos_header);
	free((void *)bin->dos_extended_header);
	free((void *)bin->relocation_entries);
	rz_buf_free(bin->b);
	bin->b = NULL;
	free(bin);
	return NULL;
}

static int rz_bin_mz_init_hdr(struct rz_bin_mz_obj_t *bin) {
	int relocations_size, dos_file_size;
	MZ_image_dos_header *mz;
	if (!(mz = RZ_NEW0(MZ_image_dos_header))) {
		rz_sys_perror("malloc (MZ_image_dos_header)");
		return false;
	}
	bin->dos_header = mz;
	// TODO: read field by field to avoid endian and alignment issues
	if (rz_buf_read_at(bin->b, 0, (ut8 *)mz, sizeof(*mz)) == -1) {
		eprintf("Error: read (MZ_image_dos_header)\n");
		return false;
	}
	// dos_header is not endian safe here in this point
	if (mz->blocks_in_file < 1) {
		return false;
	}
	dos_file_size = ((mz->blocks_in_file - 1) << 9) +
		mz->bytes_in_last_block;

	bin->dos_file_size = dos_file_size;
	if (dos_file_size > bin->size) {
		return false;
	}
	bin->load_module_size = dos_file_size - (mz->header_paragraphs << 4);
	relocations_size = mz->num_relocs * sizeof(MZ_image_relocation_entry);
	if ((mz->reloc_table_offset + relocations_size) > bin->size) {
		return false;
	}

	sdb_num_set(bin->kv, "mz.initial.cs", mz->cs, 0);
	sdb_num_set(bin->kv, "mz.initial.ip", mz->ip, 0);
	sdb_num_set(bin->kv, "mz.initial.ss", mz->ss, 0);
	sdb_num_set(bin->kv, "mz.initial.sp", mz->sp, 0);
	sdb_num_set(bin->kv, "mz.overlay_number", mz->overlay_number, 0);
	sdb_num_set(bin->kv, "mz.dos_header.offset", 0, 0);
	sdb_set(bin->kv, "mz.dos_header.format", "[2]zwwwwwwwwwwwww"
						 " signature bytes_in_last_block blocks_in_file num_relocs "
						 " header_paragraphs min_extra_paragraphs max_extra_paragraphs "
						 " ss sp checksum ip cs reloc_table_offset overlay_number ",
		0);

	bin->dos_extended_header_size = mz->reloc_table_offset -
		sizeof(MZ_image_dos_header);

	if (bin->dos_extended_header_size > 0) {
		if (!(bin->dos_extended_header =
				    malloc(bin->dos_extended_header_size))) {
			rz_sys_perror("malloc (dos extended header)");
			return false;
		}
		if (rz_buf_read_at(bin->b, sizeof(MZ_image_dos_header),
			    (ut8 *)bin->dos_extended_header,
			    bin->dos_extended_header_size) == -1) {
			eprintf("Error: read (dos extended header)\n");
			return false;
		}
	}

	if (relocations_size > 0) {
		if (!(bin->relocation_entries = malloc(relocations_size))) {
			rz_sys_perror("malloc (dos relocation entries)");
			return false;
		}
		if (rz_buf_read_at(bin->b, bin->dos_header->reloc_table_offset,
			    (ut8 *)bin->relocation_entries, relocations_size) == -1) {
			eprintf("Error: read (dos relocation entries)\n");
			RZ_FREE(bin->relocation_entries);
			return false;
		}
	}
	return true;
}

static bool rz_bin_mz_init(struct rz_bin_mz_obj_t *bin) {
	bin->dos_header = NULL;
	bin->dos_extended_header = NULL;
	bin->relocation_entries = NULL;
	bin->kv = sdb_new0();
	if (!rz_bin_mz_init_hdr(bin)) {
		eprintf("Warning: File is not MZ\n");
		return false;
	}
	return true;
}

struct rz_bin_mz_obj_t *rz_bin_mz_new(const char *file) {
	struct rz_bin_mz_obj_t *bin = RZ_NEW0(struct rz_bin_mz_obj_t);
	if (!bin) {
		return NULL;
	}
	bin->file = file;
	size_t binsz;
	ut8 *buf = (ut8 *)rz_file_slurp(file, &binsz);
	bin->size = binsz;
	if (!buf) {
		return rz_bin_mz_free(bin);
	}
	bin->b = rz_buf_new();
	if (!rz_buf_set_bytes(bin->b, buf, bin->size)) {
		free((void *)buf);
		return rz_bin_mz_free(bin);
	}
	free((void *)buf);
	if (!rz_bin_mz_init(bin)) {
		return rz_bin_mz_free(bin);
	}
	return bin;
}

struct rz_bin_mz_obj_t *rz_bin_mz_new_buf(RzBuffer *buf) {
	struct rz_bin_mz_obj_t *bin = RZ_NEW0(struct rz_bin_mz_obj_t);
	if (!bin) {
		return NULL;
	}
	bin->b = rz_buf_new_with_buf(buf);
	if (!bin->b) {
		return rz_bin_mz_free(bin);
	}
	bin->size = rz_buf_size(buf);
	return rz_bin_mz_init(bin) ? bin : rz_bin_mz_free(bin);
}

RzBinAddr *rz_bin_mz_get_main_vaddr(struct rz_bin_mz_obj_t *bin) {
	int n;
	ut8 b[512];
	if (!bin || !bin->b) {
		return NULL;
	}
	RzBinAddr *entry = rz_bin_mz_get_entrypoint(bin);
	if (!entry) {
		return NULL;
	}
	ZERO_FILL(b);
	if (rz_buf_read_at(bin->b, entry->paddr, b, sizeof(b)) < 0) {
		eprintf("Warning: Cannot read entry at 0x%16" PFMT64x "\n", (ut64)entry->paddr);
		free(entry);
		return NULL;
	}
	// MSVC
	if (b[0] == 0xb4 && b[1] == 0x30) {
		// ff 36 XX XX			push	XXXX
		// ff 36 XX XX			push	argv
		// ff 36 XX XX			push	argc
		// 9a XX XX XX XX		lcall	_main
		// 50				push	ax
		for (n = 0; n < sizeof(b) - 18; n++) {
			if (b[n] == 0xff && b[n + 4] == 0xff && b[n + 8] == 0xff && b[n + 12] == 0x9a && b[n + 17] == 0x50) {
				const ut16 call_addr = rz_read_ble16(b + n + 13, 0);
				const ut16 call_seg = rz_read_ble16(b + n + 15, 0);
				entry->vaddr = rz_bin_mz_va_to_la(call_seg, call_addr);
				entry->paddr = rz_bin_mz_la_to_pa(bin, entry->vaddr);
				return entry;
			}
		}
	}

	RZ_FREE(entry);
	return NULL;
}
