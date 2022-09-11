// SPDX-FileCopyrightText: 2008-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2019 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pe.h"

// This function try to detect anomalies within section
// we check if there is a section mapped at entrypoint, otherwise add it up
void PE_(rz_bin_pe_check_sections)(RzBinPEObj *bin, struct rz_bin_pe_section_t **sects) {
	int i = 0;
	struct rz_bin_pe_section_t *sections = *sects;
	ut64 addr_beg, addr_end, new_section_size, new_perm, base_addr;
	struct rz_bin_pe_addr_t *entry = PE_(rz_bin_pe_get_entrypoint)(bin);

	if (!entry) {
		return;
	}
	new_section_size = bin->size;
	new_section_size -= entry->paddr > bin->size ? 0 : entry->paddr;
	new_perm = (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_MEM_WRITE | PE_IMAGE_SCN_MEM_EXECUTE);
	base_addr = PE_(rz_bin_pe_get_image_base)(bin);

	for (i = 0; !sections[i].last; i++) {
		// strcmp against .text doesn't work in somes cases
		if (strstr((const char *)sections[i].name, "text")) {
			bool fix = false;
			int j;
			// check paddr boundaries
			addr_beg = sections[i].paddr;
			addr_end = addr_beg + sections[i].size;
			if (entry->paddr < addr_beg || entry->paddr > addr_end) {
				fix = true;
			}
			// check vaddr boundaries
			addr_beg = sections[i].vaddr + base_addr;
			addr_end = addr_beg + sections[i].vsize;
			if (entry->vaddr < addr_beg || entry->vaddr > addr_end) {
				fix = true;
			}
			// look for other segment with x that is already mapped and hold entrypoint
			for (j = 0; !sections[j].last; j++) {
				addr_beg = sections[j].paddr;
				addr_end = addr_beg + sections[j].size;
				if (addr_beg <= entry->paddr && entry->paddr < addr_end) {
					if (!sections[j].vsize) {
						sections[j].vsize = sections[j].size;
					}
					addr_beg = sections[j].vaddr + base_addr;
					addr_end = addr_beg + sections[j].vsize;
					if (addr_beg <= entry->vaddr || entry->vaddr < addr_end) {
						if (!(sections[j].perm & PE_IMAGE_SCN_MEM_EXECUTE)) {
							if (bin->verbose) {
								RZ_LOG_ERROR("Found entrypoint in non-executable section.\n");
							}
							sections[j].perm |= PE_IMAGE_SCN_MEM_EXECUTE;
						}
						fix = false;
						break;
					}
				}
			}
			// if either vaddr or paddr fail we should update this section
			if (fix) {
				strcpy((char *)sections[i].name, "blob");
				sections[i].paddr = entry->paddr;
				sections[i].vaddr = entry->vaddr - base_addr;
				sections[i].size = sections[i].vsize = new_section_size;
				sections[i].perm = new_perm;
			}
			goto out_function;
		}
	}
	// if we arrive til here means there is no text section find one that is holding the code
	for (i = 0; !sections[i].last; i++) {
		if (sections[i].size > bin->size) {
			continue;
		}
		addr_beg = sections[i].paddr;
		addr_end = addr_beg + sections[i].size;
		if (addr_beg <= entry->paddr && entry->paddr < addr_end) {
			if (!sections[i].vsize) {
				sections[i].vsize = sections[i].size;
			}
			addr_beg = sections[i].vaddr + base_addr;
			addr_end = addr_beg + sections[i].vsize;
			if (entry->vaddr < addr_beg || entry->vaddr > addr_end) {
				sections[i].vaddr = entry->vaddr - base_addr;
			}
			goto out_function;
		}
	}
	// we need to create another section in order to load the entrypoint
	void *ss = realloc(sections, (bin->num_sections + 2) * sizeof(struct rz_bin_pe_section_t));
	if (!ss) {
		goto out_function;
	}
	bin->sections = sections = ss;
	i = bin->num_sections;
	sections[i].last = 0;
	strcpy((char *)sections[i].name, "blob");
	sections[i].paddr = entry->paddr;
	sections[i].vaddr = entry->vaddr - base_addr;
	sections[i].size = sections[i].vsize = new_section_size;
	sections[i].perm = new_perm;
	sections[i + 1].last = 1;
	*sects = sections;
out_function:
	free(entry);
	return;
}

RzList /*<char *>*/ *PE_(section_flag_to_rzlist)(ut64 flag) {
	RzList *flag_list = rz_list_new();
	if (flag & IMAGE_SCN_TYPE_NO_PAD) {
		rz_list_append(flag_list, "TYPE_NO_PAD");
	}
	if (flag & IMAGE_SCN_CNT_CODE) {
		rz_list_append(flag_list, "CNT_CODE");
	}
	if (flag & IMAGE_SCN_CNT_INITIALIZED_DATA) {
		rz_list_append(flag_list, "CNT_INITIALIZED_DATA");
	}
	if (flag & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
		rz_list_append(flag_list, "CNT_UNINITIALIZED");
	}
	if (flag & IMAGE_SCN_LNK_OTHER) {
		rz_list_append(flag_list, "LNK_OTHER");
	}
	if (flag & IMAGE_SCN_LNK_INFO) {
		rz_list_append(flag_list, "LNK_INFO");
	}
	if (flag & IMAGE_SCN_LNK_REMOVE) {
		rz_list_append(flag_list, "LNK_REMOVE");
	}
	if (flag & IMAGE_SCN_LNK_COMDAT) {
		rz_list_append(flag_list, "LNK_COMDAT");
	}
	if (flag & IMAGE_SCN_GPREL) {
		rz_list_append(flag_list, "GPREL");
	}
	if (flag & IMAGE_SCN_MEM_PURGEABLE) {
		rz_list_append(flag_list, "MEM_PURGEABLE");
	}
	if (flag & IMAGE_SCN_MEM_16BIT) {
		rz_list_append(flag_list, "MEM_16BIT");
	}
	if (flag & IMAGE_SCN_MEM_LOCKED) {
		rz_list_append(flag_list, "MEM_LOCKED");
	}
	if (flag & IMAGE_SCN_MEM_PRELOAD) {
		rz_list_append(flag_list, "MEM_PRELOAD");
	}
	// Alignment flags overlap
	if ((flag & PE_SCN_ALIGN_MASK) == IMAGE_SCN_ALIGN_1BYTES) {
		rz_list_append(flag_list, "ALIGN_1BYTES");
	}
	if ((flag & PE_SCN_ALIGN_MASK) == IMAGE_SCN_ALIGN_2BYTES) {
		rz_list_append(flag_list, "ALIGN_2BYTES");
	}
	if ((flag & PE_SCN_ALIGN_MASK) == IMAGE_SCN_ALIGN_4BYTES) {
		rz_list_append(flag_list, "ALIGN_4BYTES");
	}
	if ((flag & PE_SCN_ALIGN_MASK) == IMAGE_SCN_ALIGN_8BYTES) {
		rz_list_append(flag_list, "ALIGN_8BYTES");
	}
	if ((flag & PE_SCN_ALIGN_MASK) == IMAGE_SCN_ALIGN_16BYTES) {
		rz_list_append(flag_list, "ALIGN_16BYTES");
	}
	if ((flag & PE_SCN_ALIGN_MASK) == IMAGE_SCN_ALIGN_32BYTES) {
		rz_list_append(flag_list, "ALIGN_32BYTES");
	}
	if ((flag & PE_SCN_ALIGN_MASK) == IMAGE_SCN_ALIGN_64BYTES) {
		rz_list_append(flag_list, "ALIGN_64BYTES");
	}
	if ((flag & PE_SCN_ALIGN_MASK) == IMAGE_SCN_ALIGN_128BYTES) {
		rz_list_append(flag_list, "ALIGN_128BYTES");
	}
	if ((flag & PE_SCN_ALIGN_MASK) == IMAGE_SCN_ALIGN_256BYTES) {
		rz_list_append(flag_list, "ALIGN_256BYTES");
	}
	if ((flag & PE_SCN_ALIGN_MASK) == IMAGE_SCN_ALIGN_512BYTES) {
		rz_list_append(flag_list, "ALIGN_512BYTES");
	}
	if ((flag & PE_SCN_ALIGN_MASK) == IMAGE_SCN_ALIGN_1024BYTES) {
		rz_list_append(flag_list, "ALIGN_1024BYTES");
	}
	if ((flag & PE_SCN_ALIGN_MASK) == IMAGE_SCN_ALIGN_2048BYTES) {
		rz_list_append(flag_list, "ALIGN_2048BYTES");
	}
	if ((flag & PE_SCN_ALIGN_MASK) == IMAGE_SCN_ALIGN_4096BYTES) {
		rz_list_append(flag_list, "ALIGN_4096BYTES");
	}
	if ((flag & PE_SCN_ALIGN_MASK) == IMAGE_SCN_ALIGN_8192BYTES) {
		rz_list_append(flag_list, "ALIGN_8192BYTES");
	}
	if (flag & IMAGE_SCN_LNK_NRELOC_OVFL) {
		rz_list_append(flag_list, "LNK_NRELOC_OVFL");
	}
	if (flag & IMAGE_SCN_MEM_DISCARDABLE) {
		rz_list_append(flag_list, "IMAGE_SCN_MEM_DISCARDABLE");
	}
	if (flag & IMAGE_SCN_MEM_NOT_CACHED) {
		rz_list_append(flag_list, "MEM_NOT_CACHED");
	}
	if (flag & IMAGE_SCN_MEM_NOT_PAGED) {
		rz_list_append(flag_list, "MEM_NOT_PAGED");
	}
	return flag_list;
}

bool PE_(read_image_section_header)(RzBuffer *b, ut64 addr, PE_(image_section_header) * section_header) {
	ut8 buf[sizeof(PE_(image_section_header))];
	rz_buf_read_at(b, addr, buf, sizeof(buf));
	memcpy(section_header->Name, buf, PE_IMAGE_SIZEOF_SHORT_NAME);
	PE_READ_STRUCT_FIELD(section_header, PE_(image_section_header), Misc.PhysicalAddress, 32);
	PE_READ_STRUCT_FIELD(section_header, PE_(image_section_header), VirtualAddress, 32);
	PE_READ_STRUCT_FIELD(section_header, PE_(image_section_header), SizeOfRawData, 32);
	PE_READ_STRUCT_FIELD(section_header, PE_(image_section_header), PointerToRawData, 32);
	PE_READ_STRUCT_FIELD(section_header, PE_(image_section_header), PointerToRelocations, 32);
	PE_READ_STRUCT_FIELD(section_header, PE_(image_section_header), PointerToLinenumbers, 32);
	PE_READ_STRUCT_FIELD(section_header, PE_(image_section_header), NumberOfRelocations, 16);
	PE_READ_STRUCT_FIELD(section_header, PE_(image_section_header), NumberOfLinenumbers, 16);
	PE_READ_STRUCT_FIELD(section_header, PE_(image_section_header), Characteristics, 32);
	return true;
}

void PE_(write_image_section_header)(RzBuffer *b, ut64 addr, PE_(image_section_header) * section_header) {
	ut8 buf[sizeof(PE_(image_section_header))];
	memcpy(buf, section_header->Name, PE_IMAGE_SIZEOF_SHORT_NAME);
	rz_write_at_le32(buf, section_header->Misc.PhysicalAddress, PE_IMAGE_SIZEOF_SHORT_NAME);
	rz_write_at_le32(buf, section_header->VirtualAddress, PE_IMAGE_SIZEOF_SHORT_NAME + 4);
	rz_write_at_le32(buf, section_header->SizeOfRawData, PE_IMAGE_SIZEOF_SHORT_NAME + 8);
	rz_write_at_le32(buf, section_header->PointerToRawData, PE_IMAGE_SIZEOF_SHORT_NAME + 12);
	rz_write_at_le32(buf, section_header->PointerToRelocations, PE_IMAGE_SIZEOF_SHORT_NAME + 16);
	rz_write_at_le32(buf, section_header->PointerToLinenumbers, PE_IMAGE_SIZEOF_SHORT_NAME + 20);
	rz_write_at_le16(buf, section_header->NumberOfRelocations, PE_IMAGE_SIZEOF_SHORT_NAME + 24);
	rz_write_at_le16(buf, section_header->NumberOfLinenumbers, PE_IMAGE_SIZEOF_SHORT_NAME + 26);
	rz_write_at_le32(buf, section_header->Characteristics, PE_IMAGE_SIZEOF_SHORT_NAME + 28);
	rz_buf_write_at(b, addr, buf, sizeof(PE_(image_section_header)));
}

struct rz_bin_pe_section_t *PE_(rz_bin_pe_get_sections)(RzBinPEObj *bin) {
	struct rz_bin_pe_section_t *sections = NULL;
	PE_(image_section_header) * shdr;
	int i, j, section_count = 0;
	char sec_name[PE_IMAGE_SIZEOF_SHORT_NAME + 1];

	if (!bin || !bin->nt_headers) {
		return NULL;
	}
	shdr = bin->section_header;
	for (i = 0; i < bin->num_sections; i++) {
		// just allocate the needed
		if (shdr[i].SizeOfRawData || shdr[i].Misc.VirtualSize) {
			section_count++;
		}
	}
	sections = calloc(section_count + 1, sizeof(struct rz_bin_pe_section_t));
	if (!sections) {
		rz_sys_perror("malloc (sections)");
		return NULL;
	}
	for (i = 0, j = 0; i < bin->num_sections; i++) {
		if (!shdr[i].SizeOfRawData && !shdr[i].Misc.VirtualSize) {
			continue;
		}
		if (shdr[i].Name[0] == '\0') {
			char *new_name = rz_str_newf("sect_%d", j);
			strncpy((char *)sections[j].name, new_name, RZ_ARRAY_SIZE(sections[j].name) - 1);
			free(new_name);
		} else if (shdr[i].Name[0] == '/') {
			// long name is something deprecated but still used
			memcpy(sec_name, shdr[i].Name, PE_IMAGE_SIZEOF_SHORT_NAME);
			sec_name[PE_IMAGE_SIZEOF_SHORT_NAME] = '\0';
			int idx = atoi(sec_name + 1);
			ut64 sym_tbl_off = bin->nt_headers->file_header.PointerToSymbolTable;
			int num_symbols = bin->nt_headers->file_header.NumberOfSymbols;
			st64 off = num_symbols * COFF_SYMBOL_SIZE;
			if (off > 0 && sym_tbl_off &&
				sym_tbl_off + off + idx < bin->size &&
				sym_tbl_off + off + idx > off) {
				int sz = PE_IMAGE_SIZEOF_SHORT_NAME * 3;
				char *buf[64] = { 0 };
				if (rz_buf_read_at(bin->b,
					    sym_tbl_off + off + idx,
					    (ut8 *)buf, 64)) {
					memcpy(sections[j].name, buf, sz);
					sections[j].name[sz - 1] = '\0';
				}
			}
		} else {
			memcpy(sections[j].name, shdr[i].Name, PE_IMAGE_SIZEOF_SHORT_NAME);
			sections[j].name[PE_IMAGE_SIZEOF_SHORT_NAME] = '\0';
		}
		sections[j].vaddr = shdr[i].VirtualAddress;
		sections[j].size = shdr[i].SizeOfRawData;
		if (shdr[i].Misc.VirtualSize) {
			sections[j].vsize = shdr[i].Misc.VirtualSize;
		} else {
			sections[j].vsize = shdr[i].SizeOfRawData;
		}
		sections[j].paddr = shdr[i].PointerToRawData;
		sections[j].flags = shdr[i].Characteristics;
		if (bin->optional_header) {
			ut32 sa = bin->optional_header->SectionAlignment;
			if (sa) {
				ut64 diff = sections[j].vsize % sa;
				if (diff) {
					sections[j].vsize += sa - diff;
				}
				if (sections[j].vaddr % sa) {
					RZ_LOG_INFO("section %s not aligned to SectionAlignment.\n",
						sections[j].name);
				}
			}
			const ut32 fa = bin->optional_header->FileAlignment;
			if (fa) {
				const ut64 diff = sections[j].paddr % fa;
				if (diff) {
					RZ_LOG_INFO("section %s not aligned to FileAlignment.\n", sections[j].name);
					sections[j].paddr -= diff;
					sections[j].size += diff;
				}
			}
		}
		sections[j].perm = shdr[i].Characteristics;
		sections[j].last = 0;
		j++;
	}
	sections[j].last = 1;
	bin->num_sections = section_count;
	return sections;
}

int PE_(bin_pe_init_sections)(RzBinPEObj *bin) {
	bin->num_sections = bin->nt_headers->file_header.NumberOfSections;
	if (bin->num_sections < 1) {
		return true;
	}
	ut64 sections_size = sizeof(PE_(image_section_header)) * bin->num_sections;
	if (sections_size > bin->size) {
		sections_size = bin->size;
		bin->num_sections = bin->size / sizeof(PE_(image_section_header));
		// massage this to make corkami happy
		// RZ_LOG_INFO("Invalid NumberOfSections value\n");
		// goto out_error;
	}
	if (!(bin->section_header = malloc(sections_size))) {
		rz_sys_perror("malloc (section header)");
		goto out_error;
	}
	bin->section_header_offset = bin->dos_header->e_lfanew + 4 + sizeof(PE_(image_file_header)) +
		bin->nt_headers->file_header.SizeOfOptionalHeader;
	int i;
	for (i = 0; i < bin->num_sections; i++) {
		if (!PE_(read_image_section_header)(bin->b, bin->section_header_offset + i * sizeof(PE_(image_section_header)),
			    bin->section_header + i)) {
			RZ_LOG_INFO("read (sections)\n");
			RZ_FREE(bin->section_header);
			goto out_error;
		}
	}
#if 0
	Each symbol table entry includes a name, storage class, type, value and section number.Short names (8 characters or fewer) are stored directly in the symbol table;
	longer names are stored as an paddr into the string table at the end of the COFF object.

	================================================================
	COFF SYMBOL TABLE RECORDS (18 BYTES)
	================================================================
	record
	paddr

	struct symrec {
		union {
			char string[8]; // short name
			struct {
				ut32 seros;
				ut32 stridx;
			} stridx;
		} name;
		ut32 value;
		ut16 secnum;
		ut16 symtype;
		ut8 symclass;
		ut8 numaux;
	}
	------------------------------------------------------ -
	0 | 8 - char symbol name |
	| or 32 - bit zeroes followed by 32 - bit |
	| index into string table |
	------------------------------------------------------ -
	8 | symbol value |
	------------------------------------------------------ -
	0Ch | section number | symbol type |
	------------------------------------------------------ -
	10h | sym class | num aux |
	-------------------------- -
	12h

#endif
	return true;
out_error:
	bin->num_sections = 0;
	return false;
}
