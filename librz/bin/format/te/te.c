// SPDX-FileCopyrightText: 2008-2013 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2013 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2013 xvilka <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rz_types.h>
#include <rz_util.h>
#include "te_specs.h"
#include "te.h"

ut64 rz_bin_te_get_stripped_delta(struct rz_bin_te_obj_t *bin) {
	if (bin && bin->header) {
		return bin->header->StrippedSize - sizeof(TE_image_file_header);
	}
	return 0LL;
}

#define macro_str(s) #s
#define rz_buf_read_le8_at(a, b, c) \
	(rz_buf_read_at(a, b, (ut8 *)c, sizeof(ut8)) == 1)
#define parse_header_value(off, bits, key) \
	do { \
		if (!rz_buf_read_le##bits##_at(bin->b, off, &bin->header->key)) { \
			RZ_LOG_ERROR("Cannot read TE_image_file_header." macro_str(key) "\n"); \
			return false; \
		} \
		off += (bits / 8); \
	} while (0)

static int rz_bin_te_init_hdr(struct rz_bin_te_obj_t *bin) {
	if (!bin) {
		return false;
	} else if (!bin->kv) {
		RZ_LOG_ERROR("Sdb instance is empty\n");
		return false;
	} else if (!(bin->header = malloc(sizeof(TE_image_file_header)))) {
		RZ_LOG_ERROR("cannot allocate TE_image_file_header\n");
		return false;
	}

	ut64 offset = 0;
	parse_header_value(offset, 16, Signature);
	parse_header_value(offset, 16, Machine);
	parse_header_value(offset, 8, NumberOfSections);
	parse_header_value(offset, 8, Subsystem);
	parse_header_value(offset, 16, StrippedSize);
	parse_header_value(offset, 32, AddressOfEntryPoint);
	parse_header_value(offset, 32, BaseOfCode);
	parse_header_value(offset, 64, ImageBase);
	parse_header_value(offset, 32, DataDirectory[0].VirtualAddress);
	parse_header_value(offset, 32, DataDirectory[0].Size);
	parse_header_value(offset, 32, DataDirectory[1].VirtualAddress);
	parse_header_value(offset, 32, DataDirectory[1].Size);

	sdb_set(bin->kv, "te_machine.cparse", "enum te_machine { TE_IMAGE_FILE_MACHINE_UNKNOWN=0x0, TE_IMAGE_FILE_MACHINE_ALPHA=0x184, "
					      "TE_IMAGE_FILE_MACHINE_ALPHA64=0x284, TE_IMAGE_FILE_MACHINE_AM33=0x1d3, TE_IMAGE_FILE_MACHINE_AMD64=0x8664, "
					      "TE_IMAGE_FILE_MACHINE_ARM=0x1c0, TE_IMAGE_FILE_MACHINE_AXP64=0x184, TE_IMAGE_FILE_MACHINE_CEE=0xc0ee, "
					      "TE_IMAGE_FILE_MACHINE_CEF=0x0cef, TE_IMAGE_FILE_MACHINE_EBC=0x0ebc, TE_IMAGE_FILE_MACHINE_I386=0x014c, "
					      "TE_IMAGE_FILE_MACHINE_IA64=0x0200, TE_IMAGE_FILE_MACHINE_M32R=0x9041, TE_IMAGE_FILE_MACHINE_M68K=0x0268, "
					      "TE_IMAGE_FILE_MACHINE_MIPS16=0x0266, TE_IMAGE_FILE_MACHINE_MIPSFPU=0x0366, TE_IMAGE_FILE_MACHINE_MIPSFPU16=0x0466, "
					      "TE_IMAGE_FILE_MACHINE_POWERPC=0x01f0, TE_IMAGE_FILE_MACHINE_POWERPCFP=0x01f1, TE_IMAGE_FILE_MACHINE_R10000=0x0168, "
					      "TE_IMAGE_FILE_MACHINE_R3000=0x0162, TE_IMAGE_FILE_MACHINE_R4000=0x0166, TE_IMAGE_FILE_MACHINE_SH3=0x01a2, "
					      "TE_IMAGE_FILE_MACHINE_SH3DSP=0x01a3, TE_IMAGE_FILE_MACHINE_SH3E=0x01a4, TE_IMAGE_FILE_MACHINE_SH4=0x01a6, "
					      "TE_IMAGE_FILE_MACHINE_SH5=0x01a8, TE_IMAGE_FILE_MACHINE_THUMB=0x01c2, TE_IMAGE_FILE_MACHINE_TRICORE=0x0520, "
					      "TE_IMAGE_FILE_MACHINE_WCEMIPSV2=0x0169};");
	sdb_set(bin->kv, "te_subsystem.cparse", "enum te_subsystem { TE_IMAGE_SUBSYSTEM_UNKNOWN=0, TE_IMAGE_SUBSYSTEM_NATIVE=1, "
						"TE_IMAGE_SUBSYSTEM_WINDOWS_GUI=2, TE_IMAGE_SUBSYSTEM_WINDOWS_CUI=3, "
						"TE_IMAGE_SUBSYSTEM_POSIX_CUI=7, TE_IMAGE_SUBSYSTEM_WINDOWS_CE_GU=9, "
						"TE_IMAGE_SUBSYSTEM_EFI_APPLICATION=10, TE_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER=11, TE_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER=12, "
						"TE_IMAGE_SUBSYSTEM_EFI_ROM=13, TE_IMAGE_SUBSYSTEM_XBOX=14};");
	sdb_num_set(bin->kv, "te_header.offset", 0);
	sdb_set(bin->kv, "te_header.format", "[2]z[2]Eb[1]Ewxxq"
					     " Signature (te_machine)Machine NumberOfSections (te_subsystem)Subsystem StrippedSize AddressOfEntryPoint BaseOfCode ImageBase");
	sdb_num_set(bin->kv, "te_directory1_header.offset", 24);
	sdb_set(bin->kv, "te_directory1_header.format", "xx"
							" VirtualAddress Size");
	sdb_num_set(bin->kv, "te_directory2_header.offset", 32);
	sdb_set(bin->kv, "te_directory2_header.format", "xx"
							" VirtualAddress Size");

	if (strncmp((char *)&bin->header->Signature, "VZ", 2)) {
		return false;
	}
	return true;
}

ut64 rz_bin_te_get_main_paddr(struct rz_bin_te_obj_t *bin) {
	RzBinAddr *entry = rz_bin_te_get_entrypoint(bin);
	ut64 addr = 0LL;
	ut8 buf[512];
	if (!bin) {
		return 0LL;
	}
	if (rz_buf_read_at(bin->b, entry->paddr, buf, sizeof(buf)) == -1) {
		eprintf("Error: read (entry)\n");
	} else {
		if (buf[367] == 0xe8) {
			int delta = (buf[368] | buf[369] << 8 | buf[370] << 16 | buf[371] << 24);
			delta += 367 + 5;
			addr = entry->vaddr;
			if (delta >= (UT64_MAX - addr)) {
				free(entry);
				return UT64_MAX;
			}
			addr += delta;
		}
	}
	free(entry);
	return addr;
}

static TE_DWord rz_bin_te_vaddr_to_paddr(struct rz_bin_te_obj_t *bin, TE_DWord vaddr) {
	TE_DWord section_base;
	int i, section_size;

	for (i = 0; i < bin->header->NumberOfSections; i++) {
		section_base = bin->section_header[i].VirtualAddress;
		section_size = bin->section_header[i].VirtualSize;
		if (vaddr >= section_base && vaddr < section_base + section_size) {
			return bin->section_header[i].PointerToRawData + (vaddr - section_base);
		}
	}
	return 0;
}

static int rz_bin_te_init_sections(struct rz_bin_te_obj_t *bin) {
	int sections_size = sizeof(TE_image_section_header) * bin->header->NumberOfSections;
	if (sections_size > bin->size) {
		eprintf("Invalid NumberOfSections value\n");
		return false;
	}
	if (!(bin->section_header = malloc(sections_size))) {
		perror("malloc (sections headers)");
		return false;
	}
	if (rz_buf_read_at(bin->b, sizeof(TE_image_file_header),
		    (ut8 *)bin->section_header, sections_size) == -1) {
		eprintf("Error: read (sections headers)\n");
		return false;
	}
	return true;
}

static int rz_bin_te_init(struct rz_bin_te_obj_t *bin) {
	bin->header = NULL;
	bin->section_header = NULL;
	bin->endian = 0;
	if (!rz_bin_te_init_hdr(bin)) {
		eprintf("Warning: File is not TE\n");
		return false;
	}
	if (!rz_bin_te_init_sections(bin)) {
		eprintf("Warning: Cannot initialize sections\n");
		return false;
	}
	return true;
}

char *rz_bin_te_get_arch(struct rz_bin_te_obj_t *bin) {
	char *arch;
	if (!bin) {
		return NULL;
	}
	switch (bin->header->Machine) {
	case TE_IMAGE_FILE_MACHINE_ALPHA:
	case TE_IMAGE_FILE_MACHINE_ALPHA64:
		arch = strdup("alpha");
		break;
	case TE_IMAGE_FILE_MACHINE_ARM:
	case TE_IMAGE_FILE_MACHINE_THUMB:
		arch = strdup("arm");
		break;
	case TE_IMAGE_FILE_MACHINE_M68K:
		arch = strdup("m68k");
		break;
	case TE_IMAGE_FILE_MACHINE_MIPS16:
	case TE_IMAGE_FILE_MACHINE_MIPSFPU:
	case TE_IMAGE_FILE_MACHINE_MIPSFPU16:
	case TE_IMAGE_FILE_MACHINE_WCEMIPSV2:
		arch = strdup("mips");
		break;
	case TE_IMAGE_FILE_MACHINE_POWERPC:
	case TE_IMAGE_FILE_MACHINE_POWERPCFP:
		arch = strdup("ppc");
		break;
	default:
		arch = strdup("x86");
	}
	return arch;
}

int rz_bin_te_get_bits(struct rz_bin_te_obj_t *bin) {
	return 32; // It is always 32 bit by now
}

RzBinAddr *rz_bin_te_get_entrypoint(struct rz_bin_te_obj_t *bin) {
	RzBinAddr *entry = NULL;

	if (!bin || !bin->header) {
		return NULL;
	}
	if (!(entry = malloc(sizeof(RzBinAddr)))) {
		perror("malloc (entrypoint)");
		return NULL;
	}
	entry->vaddr = bin->header->AddressOfEntryPoint - rz_bin_te_get_stripped_delta(bin);
	if (entry->vaddr == 0) { // in TE if EP = 0 then EP = baddr
		entry->vaddr = bin->header->ImageBase;
	}
	entry->paddr = rz_bin_te_vaddr_to_paddr(bin, entry->vaddr);
	return entry;
}

ut64 rz_bin_te_get_image_base(struct rz_bin_te_obj_t *bin) {
	if (bin && bin->header) {
		return (ut64)bin->header->ImageBase;
	}
	return 0LL;
}

char *rz_bin_te_get_machine(struct rz_bin_te_obj_t *bin) {
	char *machine;
	if (!bin) {
		return NULL;
	}
	switch (bin->header->Machine) {
	case TE_IMAGE_FILE_MACHINE_ALPHA:
		machine = strdup("Alpha");
		break;
	case TE_IMAGE_FILE_MACHINE_ALPHA64:
		machine = strdup("Alpha 64");
		break;
	case TE_IMAGE_FILE_MACHINE_AM33:
		machine = strdup("AM33");
		break;
	case TE_IMAGE_FILE_MACHINE_AMD64:
		machine = strdup("AMD 64");
		break;
	case TE_IMAGE_FILE_MACHINE_ARM:
		machine = strdup("ARM");
		break;
	case TE_IMAGE_FILE_MACHINE_CEE:
		machine = strdup("CEE");
		break;
	case TE_IMAGE_FILE_MACHINE_CEF:
		machine = strdup("CEF");
		break;
	case TE_IMAGE_FILE_MACHINE_EBC:
		machine = strdup("EBC");
		break;
	case TE_IMAGE_FILE_MACHINE_I386:
		machine = strdup("i386");
		break;
	case TE_IMAGE_FILE_MACHINE_IA64:
		machine = strdup("ia64");
		break;
	case TE_IMAGE_FILE_MACHINE_M32R:
		machine = strdup("M32R");
		break;
	case TE_IMAGE_FILE_MACHINE_M68K:
		machine = strdup("M68K");
		break;
	case TE_IMAGE_FILE_MACHINE_MIPS16:
		machine = strdup("Mips 16");
		break;
	case TE_IMAGE_FILE_MACHINE_MIPSFPU:
		machine = strdup("Mips FPU");
		break;
	case TE_IMAGE_FILE_MACHINE_MIPSFPU16:
		machine = strdup("Mips FPU 16");
		break;
	case TE_IMAGE_FILE_MACHINE_POWERPC:
		machine = strdup("PowerPC");
		break;
	case TE_IMAGE_FILE_MACHINE_POWERPCFP:
		machine = strdup("PowerPC FP");
		break;
	case TE_IMAGE_FILE_MACHINE_R10000:
		machine = strdup("R10000");
		break;
	case TE_IMAGE_FILE_MACHINE_R3000:
		machine = strdup("R3000");
		break;
	case TE_IMAGE_FILE_MACHINE_R4000:
		machine = strdup("R4000");
		break;
	case TE_IMAGE_FILE_MACHINE_SH3:
		machine = strdup("SH3");
		break;
	case TE_IMAGE_FILE_MACHINE_SH3DSP:
		machine = strdup("SH3DSP");
		break;
	case TE_IMAGE_FILE_MACHINE_SH3E:
		machine = strdup("SH3E");
		break;
	case TE_IMAGE_FILE_MACHINE_SH4:
		machine = strdup("SH4");
		break;
	case TE_IMAGE_FILE_MACHINE_SH5:
		machine = strdup("SH5");
		break;
	case TE_IMAGE_FILE_MACHINE_THUMB:
		machine = strdup("Thumb");
		break;
	case TE_IMAGE_FILE_MACHINE_TRICORE:
		machine = strdup("Tricore");
		break;
	case TE_IMAGE_FILE_MACHINE_WCEMIPSV2:
		machine = strdup("WCE Mips V2");
		break;
	default:
		machine = strdup("unknown");
	}
	return machine;
}

char *rz_bin_te_get_os(struct rz_bin_te_obj_t *bin) {
	char *os;
	if (!bin) {
		return NULL;
	}

	switch (bin->header->Subsystem) {
	case TE_IMAGE_SUBSYSTEM_NATIVE:
		os = strdup("native");
		break;
	case TE_IMAGE_SUBSYSTEM_WINDOWS_GUI:
	case TE_IMAGE_SUBSYSTEM_WINDOWS_CUI:
	case TE_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		os = strdup("windows");
		break;
	case TE_IMAGE_SUBSYSTEM_POSIX_CUI:
		os = strdup("posix");
		break;
	case TE_IMAGE_SUBSYSTEM_EFI_APPLICATION:
	case TE_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
	case TE_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
	case TE_IMAGE_SUBSYSTEM_EFI_ROM:
		os = strdup("efi");
		break;
	case TE_IMAGE_SUBSYSTEM_XBOX:
		os = strdup("xbox");
		break;
	default:
		// XXX: this is unknown
		os = strdup("windows");
	}
	return os;
}

struct rz_bin_te_section_t *rz_bin_te_get_sections(struct rz_bin_te_obj_t *bin) {
	struct rz_bin_te_section_t *sections = NULL;
	TE_image_section_header *shdr;
	int i, sections_count;
	if (!bin) {
		return NULL;
	}
	shdr = bin->section_header;
	sections_count = bin->header->NumberOfSections;

	if (!(sections = calloc((sections_count + 1), sizeof(struct rz_bin_te_section_t)))) {
		perror("malloc (sections)");
		return NULL;
	}
	for (i = 0; i < sections_count; i++) {
		memcpy(sections[i].name, shdr[i].Name, TE_IMAGE_SIZEOF_NAME);
		// not a null terminated string if len==buflen
		// sections[i].name[TE_IMAGE_SIZEOF_NAME] = '\0';
		sections[i].vaddr = shdr[i].VirtualAddress - rz_bin_te_get_stripped_delta(bin);
		sections[i].size = shdr[i].SizeOfRawData;
		sections[i].vsize = shdr[i].VirtualSize;
		sections[i].paddr = shdr[i].PointerToRawData - rz_bin_te_get_stripped_delta(bin);
		sections[i].flags = shdr[i].Characteristics;
		sections[i].last = 0;
	}
	sections[i].last = 1;
	return sections;
}

char *rz_bin_te_get_subsystem(struct rz_bin_te_obj_t *bin) {
	char *subsystem;

	if (!bin) {
		return NULL;
	}
	switch (bin->header->Subsystem) {
	case TE_IMAGE_SUBSYSTEM_NATIVE:
		subsystem = strdup("Native");
		break;
	case TE_IMAGE_SUBSYSTEM_WINDOWS_GUI:
		subsystem = strdup("Windows GUI");
		break;
	case TE_IMAGE_SUBSYSTEM_WINDOWS_CUI:
		subsystem = strdup("Windows CUI");
		break;
	case TE_IMAGE_SUBSYSTEM_POSIX_CUI:
		subsystem = strdup("POSIX CUI");
		break;
	case TE_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		subsystem = strdup("Windows CE GUI");
		break;
	case TE_IMAGE_SUBSYSTEM_EFI_APPLICATION:
		subsystem = strdup("EFI Application");
		break;
	case TE_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		subsystem = strdup("EFI Boot Service Driver");
		break;
	case TE_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		subsystem = strdup("EFI Runtime Driver");
		break;
	case TE_IMAGE_SUBSYSTEM_EFI_ROM:
		subsystem = strdup("EFI ROM");
		break;
	case TE_IMAGE_SUBSYSTEM_XBOX:
		subsystem = strdup("XBOX");
		break;
	default:
		subsystem = strdup("Unknown");
	}
	return subsystem;
}

void *rz_bin_te_free(struct rz_bin_te_obj_t *bin) {
	if (!bin) {
		return NULL;
	}
	free(bin->header);
	free(bin->section_header);
	rz_buf_free(bin->b);
	free(bin);
	return NULL;
}

struct rz_bin_te_obj_t *rz_bin_te_new(const char *file) {
	struct rz_bin_te_obj_t *bin = RZ_NEW0(struct rz_bin_te_obj_t);
	if (!bin) {
		return NULL;
	}
	bin->file = file;
	size_t binsz;
	ut8 *buf = (ut8 *)rz_file_slurp(file, &binsz);
	bin->size = binsz;
	if (!buf) {
		return rz_bin_te_free(bin);
	}
	bin->b = rz_buf_new_with_bytes(NULL, 0);
	if (!rz_buf_set_bytes(bin->b, buf, bin->size)) {
		free(buf);
		return rz_bin_te_free(bin);
	}
	free(buf);
	if (!rz_bin_te_init(bin)) {
		return rz_bin_te_free(bin);
	}
	return bin;
}

struct rz_bin_te_obj_t *rz_bin_te_new_buf(RzBuffer *buf) {
	struct rz_bin_te_obj_t *bin = RZ_NEW0(struct rz_bin_te_obj_t);
	if (!bin) {
		return NULL;
	}
	bin->kv = sdb_new0();
	bin->size = rz_buf_size(buf);
	bin->b = rz_buf_new_with_buf(buf);
	if (!bin->b) {
		return rz_bin_te_free(bin);
	}
	if (!rz_bin_te_init(bin)) {
		return rz_bin_te_free(bin);
	}
	return bin;
}
