// SPDX-FileCopyrightText: 2008-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2019 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pe.h"

static inline int is_thumb(RzBinPEObj *bin) {
	return bin->nt_headers->optional_header.AddressOfEntryPoint & 1;
}

static inline int is_arm(RzBinPEObj *bin) {
	switch (bin->nt_headers->file_header.Machine) {
	case PE_IMAGE_FILE_MACHINE_ARM:
	case PE_IMAGE_FILE_MACHINE_ARM64:
	case PE_IMAGE_FILE_MACHINE_ARMNT:
	case PE_IMAGE_FILE_MACHINE_THUMB:
		return 1;
	}
	return 0;
}

// TODO: make it const! like in elf
char *PE_(rz_bin_pe_get_machine)(RzBinPEObj *bin) {
	char *machine = NULL;

	if (bin && bin->nt_headers) {
		switch (bin->nt_headers->file_header.Machine) {
		case PE_IMAGE_FILE_MACHINE_ALPHA: machine = "Alpha"; break;
		case PE_IMAGE_FILE_MACHINE_ALPHA64: machine = "Alpha 64"; break;
		case PE_IMAGE_FILE_MACHINE_AM33: machine = "AM33"; break;
		case PE_IMAGE_FILE_MACHINE_AMD64: machine = "AMD 64"; break;
		case PE_IMAGE_FILE_MACHINE_ARM: machine = "ARM"; break;
		case PE_IMAGE_FILE_MACHINE_ARMNT: machine = "ARM Thumb-2"; break;
		case PE_IMAGE_FILE_MACHINE_ARM64: machine = "ARM64"; break;
		case PE_IMAGE_FILE_MACHINE_CEE: machine = "CEE"; break;
		case PE_IMAGE_FILE_MACHINE_CEF: machine = "CEF"; break;
		case PE_IMAGE_FILE_MACHINE_EBC: machine = "EBC"; break;
		case PE_IMAGE_FILE_MACHINE_I386: machine = "i386"; break;
		case PE_IMAGE_FILE_MACHINE_IA64: machine = "ia64"; break;
		case PE_IMAGE_FILE_MACHINE_M32R: machine = "M32R"; break;
		case PE_IMAGE_FILE_MACHINE_M68K: machine = "M68K"; break;
		case PE_IMAGE_FILE_MACHINE_MIPS16: machine = "Mips 16"; break;
		case PE_IMAGE_FILE_MACHINE_MIPSFPU: machine = "Mips FPU"; break;
		case PE_IMAGE_FILE_MACHINE_MIPSFPU16: machine = "Mips FPU 16"; break;
		case PE_IMAGE_FILE_MACHINE_POWERPC: machine = "PowerPC"; break;
		case PE_IMAGE_FILE_MACHINE_POWERPCFP: machine = "PowerPC FP"; break;
		case PE_IMAGE_FILE_MACHINE_POWERPCBE: machine = "PowerPC BE"; break;
		case PE_IMAGE_FILE_MACHINE_R10000: machine = "R10000"; break;
		case PE_IMAGE_FILE_MACHINE_R3000: machine = "R3000"; break;
		case PE_IMAGE_FILE_MACHINE_R4000: machine = "R4000"; break;
		case PE_IMAGE_FILE_MACHINE_SH3: machine = "SH3"; break;
		case PE_IMAGE_FILE_MACHINE_SH3DSP: machine = "SH3DSP"; break;
		case PE_IMAGE_FILE_MACHINE_SH3E: machine = "SH3E"; break;
		case PE_IMAGE_FILE_MACHINE_SH4: machine = "SH4"; break;
		case PE_IMAGE_FILE_MACHINE_SH5: machine = "SH5"; break;
		case PE_IMAGE_FILE_MACHINE_THUMB: machine = "Thumb"; break;
		case PE_IMAGE_FILE_MACHINE_TRICORE: machine = "Tricore"; break;
		case PE_IMAGE_FILE_MACHINE_WCEMIPSV2: machine = "WCE Mips V2"; break;
		case PE_IMAGE_FILE_MACHINE_RISCV32: machine = "RISC-V 32-bit"; break;
		case PE_IMAGE_FILE_MACHINE_RISCV64: machine = "RISC-V 64-bit"; break;
		case PE_IMAGE_FILE_MACHINE_RISCV128: machine = "RISC-V 128-bit"; break;
		default: machine = "unknown";
		}
	}
	return machine ? strdup(machine) : NULL;
}

// TODO: make it const! like in elf
char *PE_(rz_bin_pe_get_os)(RzBinPEObj *bin) {
	char *os;
	if (!bin || !bin->nt_headers) {
		return NULL;
	}
	switch (bin->nt_headers->optional_header.Subsystem) {
	case PE_IMAGE_SUBSYSTEM_NATIVE:
		os = strdup("native");
		break;
	case PE_IMAGE_SUBSYSTEM_WINDOWS_GUI:
	case PE_IMAGE_SUBSYSTEM_WINDOWS_CUI:
	case PE_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		os = strdup("windows");
		break;
	case PE_IMAGE_SUBSYSTEM_POSIX_CUI:
		os = strdup("posix");
		break;
	case PE_IMAGE_SUBSYSTEM_EFI_APPLICATION:
	case PE_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
	case PE_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
	case PE_IMAGE_SUBSYSTEM_EFI_ROM:
		os = strdup("efi");
		break;
	case PE_IMAGE_SUBSYSTEM_XBOX:
		os = strdup("xbox");
		break;
	default:
		// XXX: this is unknown
		os = strdup("windows");
	}
	return os;
}

// TODO: make it const
char *PE_(rz_bin_pe_get_class)(RzBinPEObj *bin) {
	if (bin && bin->nt_headers) {
		switch (bin->nt_headers->optional_header.Magic) {
		case PE_IMAGE_FILE_TYPE_PE32: return strdup("PE32");
		case PE_IMAGE_FILE_TYPE_PE32PLUS: return strdup("PE32+");
		default: return strdup("Unknown");
		}
	}
	return NULL;
}

char *PE_(rz_bin_pe_get_arch)(RzBinPEObj *bin) {
	char *arch;
	if (!bin || !bin->nt_headers) {
		return strdup("x86");
	}
	switch (bin->nt_headers->file_header.Machine) {
	case PE_IMAGE_FILE_MACHINE_ALPHA:
	case PE_IMAGE_FILE_MACHINE_ALPHA64:
		arch = strdup("alpha");
		break;
	case PE_IMAGE_FILE_MACHINE_ARM:
	case PE_IMAGE_FILE_MACHINE_ARMNT:
	case PE_IMAGE_FILE_MACHINE_THUMB:
		arch = strdup("arm");
		break;
	case PE_IMAGE_FILE_MACHINE_M68K:
		arch = strdup("m68k");
		break;
	case PE_IMAGE_FILE_MACHINE_MIPS16:
	case PE_IMAGE_FILE_MACHINE_MIPSFPU:
	case PE_IMAGE_FILE_MACHINE_MIPSFPU16:
	case PE_IMAGE_FILE_MACHINE_WCEMIPSV2:
		arch = strdup("mips");
		break;
	case PE_IMAGE_FILE_MACHINE_POWERPC:
	case PE_IMAGE_FILE_MACHINE_POWERPCFP:
	case PE_IMAGE_FILE_MACHINE_POWERPCBE:
		arch = strdup("ppc");
		break;
	case PE_IMAGE_FILE_MACHINE_EBC:
		arch = strdup("ebc");
		break;
	case PE_IMAGE_FILE_MACHINE_ARM64:
		arch = strdup("arm");
		break;
	case PE_IMAGE_FILE_MACHINE_RISCV32:
	case PE_IMAGE_FILE_MACHINE_RISCV64:
	case PE_IMAGE_FILE_MACHINE_RISCV128:
		arch = strdup("riscv");
		break;
	default:
		arch = strdup("x86");
	}
	return arch;
}

char *PE_(rz_bin_pe_get_subsystem)(RzBinPEObj *bin) {
	char *subsystem = NULL;
	if (bin && bin->nt_headers) {
		switch (bin->nt_headers->optional_header.Subsystem) {
		case PE_IMAGE_SUBSYSTEM_NATIVE:
			subsystem = "Native";
			break;
		case PE_IMAGE_SUBSYSTEM_WINDOWS_GUI:
			subsystem = "Windows GUI";
			break;
		case PE_IMAGE_SUBSYSTEM_WINDOWS_CUI:
			subsystem = "Windows CUI";
			break;
		case PE_IMAGE_SUBSYSTEM_POSIX_CUI:
			subsystem = "POSIX CUI";
			break;
		case PE_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
			subsystem = "Windows CE GUI";
			break;
		case PE_IMAGE_SUBSYSTEM_EFI_APPLICATION:
			subsystem = "EFI Application";
			break;
		case PE_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
			subsystem = "EFI Boot Service Driver";
			break;
		case PE_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
			subsystem = "EFI Runtime Driver";
			break;
		case PE_IMAGE_SUBSYSTEM_EFI_ROM:
			subsystem = "EFI ROM";
			break;
		case PE_IMAGE_SUBSYSTEM_XBOX:
			subsystem = "XBOX";
			break;
		default:
			subsystem = "Unknown";
			break;
		}
	}
	return subsystem ? strdup(subsystem) : NULL;
}

char *PE_(rz_bin_pe_get_cc)(RzBinPEObj *bin) {
	if (bin && bin->nt_headers) {
		if (is_arm(bin)) {
			if (is_thumb(bin)) {
				return strdup("arm16");
			}
			switch (bin->nt_headers->optional_header.Magic) {
			case PE_IMAGE_FILE_TYPE_PE32: return strdup("arm32");
			case PE_IMAGE_FILE_TYPE_PE32PLUS: return strdup("arm64");
			}
		} else {
			switch (bin->nt_headers->optional_header.Magic) {
			case PE_IMAGE_FILE_TYPE_PE32: return strdup("cdecl");
			case PE_IMAGE_FILE_TYPE_PE32PLUS: return strdup("ms");
			}
		}
	}
	return NULL;
}

int PE_(bin_pe_get_claimed_checksum)(RzBinPEObj *bin) {
	if (!bin || !bin->optional_header) {
		return 0;
	}
	return bin->optional_header->CheckSum;
}

typedef struct {
	ut64 *computed_cs;
	bool big_endian;
} checksum_ctx;

static ut64 buf_fwd_checksum(const ut8 *buf, ut64 size, void *user) {
	checksum_ctx *ctx = user;
	ut64 computed_cs = *ctx->computed_cs;
	ut64 i;
	for (i = 0; i < size; i += 4) {
		ut32 cur = rz_read_at_ble32(buf, i, ctx->big_endian);

		computed_cs = (computed_cs & 0xFFFFFFFF) + cur + (computed_cs >> 32);
		if (computed_cs >> 32) {
			computed_cs = (computed_cs & 0xFFFFFFFF) + (computed_cs >> 32);
		}
	}
	*ctx->computed_cs = computed_cs;
	return i;
}

int PE_(bin_pe_get_actual_checksum)(RzBinPEObj *bin) {
	size_t i, j, checksum_offset = 0;
	ut64 computed_cs = 0;
	int remaining_bytes;
	int shift;
	ut32 cur;
	if (!bin || !bin->nt_header_offset) {
		return 0;
	}
	const size_t buf_sz = 0x1000;
	ut32 *buf = malloc(buf_sz);
	if (!buf) {
		return 0;
	}
	if (rz_buf_read_at(bin->b, 0, (ut8 *)buf, buf_sz) < 0) {
		free(buf);
		return 0;
	}
	checksum_offset = bin->nt_header_offset + 4 + sizeof(PE_(image_file_header)) + 0x40;
	checksum_ctx ctx = { &computed_cs, bin->big_endian };
	rz_buf_fwd_scan(bin->b, 0, checksum_offset, buf_fwd_checksum, &ctx);
	rz_buf_fwd_scan(bin->b, checksum_offset + 4, bin->size - checksum_offset - 4 - bin->size % 4, buf_fwd_checksum, &ctx);

	// add resultant bytes to checksum
	remaining_bytes = bin->size % 4;
	i = bin->size - remaining_bytes;
	if (remaining_bytes != 0) {
		ut8 tmp;
		if (!rz_buf_read8_at(bin->b, i, &tmp)) {
			return 0;
		}
		cur = tmp;

		shift = 8;
		for (j = 1; j < remaining_bytes; j++, shift += 8) {
			if (!rz_buf_read8_at(bin->b, i + j, &tmp)) {
				return 0;
			}
			cur |= tmp << shift;
		}
		computed_cs = (computed_cs & 0xFFFFFFFF) + cur + (computed_cs >> 32);
		if (computed_cs >> 32) {
			computed_cs = (computed_cs & 0xFFFFFFFF) + (computed_cs >> 32);
		}
	}

	// 32bits -> 16bits
	computed_cs = (computed_cs & 0xFFFF) + (computed_cs >> 16);
	computed_cs = (computed_cs) + (computed_cs >> 16);
	computed_cs = (computed_cs & 0xFFFF);

	// add filesize
	computed_cs += bin->size;
	free(buf);
	return computed_cs;
}

int PE_(rz_bin_pe_get_bits)(RzBinPEObj *bin) {
	int bits = 32;
	if (bin && bin->nt_headers) {
		if (is_arm(bin) && is_thumb(bin)) {
			bits = 16;
		} else {
			switch (bin->nt_headers->optional_header.Magic) {
			case PE_IMAGE_FILE_TYPE_PE32: bits = 32; break;
			case PE_IMAGE_FILE_TYPE_PE32PLUS: bits = 64; break;
			default: bits = -1;
			}
		}
	}
	return bits;
}

#define HASCHR(x) (bin->nt_headers->file_header.Characteristics & (x))

int PE_(rz_bin_pe_is_dll)(RzBinPEObj *bin) {
	if (!bin || !bin->nt_headers) {
		return false;
	}
	return HASCHR(PE_IMAGE_FILE_DLL);
}

int PE_(rz_bin_pe_is_pie)(RzBinPEObj *bin) {
	if (!bin || !bin->nt_headers) {
		return false;
	}
	return HASCHR(IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE);
#if 0
	BOOL aslr = inh->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
//TODO: implement dep?
	BOOL dep = inh->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
#endif
}

int PE_(rz_bin_pe_is_big_endian)(RzBinPEObj *bin) {
	ut16 arch;
	if (!bin || !bin->nt_headers) {
		return false;
	}
	arch = bin->nt_headers->file_header.Machine;
	if (arch == PE_IMAGE_FILE_MACHINE_I386 ||
		arch == PE_IMAGE_FILE_MACHINE_AMD64) {
		return false;
	} else if (arch == PE_IMAGE_FILE_MACHINE_POWERPCBE) {
		return true;
	}
	return HASCHR(PE_IMAGE_FILE_BYTES_REVERSED_HI);
}

int PE_(rz_bin_pe_is_stripped_relocs)(RzBinPEObj *bin) {
	if (!bin || !bin->nt_headers) {
		return false;
	}
	return HASCHR(PE_IMAGE_FILE_RELOCS_STRIPPED);
}

int PE_(rz_bin_pe_is_stripped_line_nums)(RzBinPEObj *bin) {
	if (!bin || !bin->nt_headers) {
		return false;
	}
	return HASCHR(PE_IMAGE_FILE_LINE_NUMS_STRIPPED);
}

int PE_(rz_bin_pe_is_stripped_local_syms)(RzBinPEObj *bin) {
	if (!bin || !bin->nt_headers) {
		return false;
	}
	return HASCHR(PE_IMAGE_FILE_LOCAL_SYMS_STRIPPED);
}

int PE_(rz_bin_pe_is_stripped_debug)(RzBinPEObj *bin) {
	if (!bin || !bin->nt_headers) {
		return false;
	}
	return HASCHR(PE_IMAGE_FILE_DEBUG_STRIPPED);
}

struct rz_bin_pe_lib_t *PE_(rz_bin_pe_get_libs)(RzBinPEObj *bin) {
	if (!bin) {
		return NULL;
	}
	struct rz_bin_pe_lib_t *libs = NULL;
	struct rz_bin_pe_lib_t *new_libs = NULL;
	PE_(image_import_directory)
	curr_import_dir;
	PE_(image_delay_import_directory)
	curr_delay_import_dir;
	PE_DWord name_off = 0;
	HtSS *lib_map = NULL;
	ut64 off; // cache value
	int index = 0;
	int len = 0;
	int max_libs = 20;
	libs = calloc(max_libs + 1, sizeof(struct rz_bin_pe_lib_t));
	if (!libs) {
		rz_sys_perror("malloc (libs)");
		return NULL;
	}

	if (bin->import_directory_offset + bin->import_directory_size > bin->size) {
		RZ_LOG_INFO("import directory offset bigger than file\n");
		goto out_error;
	}
	lib_map = sdb_ht_new();
	off = bin->import_directory_offset;
	if (off < bin->size && off > 0) {
		ut64 last;
		int iidi = 0;
		// normal imports
		if (off + sizeof(PE_(image_import_directory)) > bin->size) {
			goto out_error;
		}
		int r = PE_(read_image_import_directory)(bin->b, off + iidi * sizeof(curr_import_dir),
			&curr_import_dir);
		last = off + bin->import_directory_size;
		while (r == sizeof(curr_import_dir) && off + (iidi + 1) * sizeof(curr_import_dir) <= last && (curr_import_dir.FirstThunk || curr_import_dir.Name || curr_import_dir.TimeDateStamp || curr_import_dir.Characteristics || curr_import_dir.ForwarderChain)) {
			name_off = PE_(bin_pe_rva_to_paddr)(bin, curr_import_dir.Name);
			len = rz_buf_read_at(bin->b, name_off, (ut8 *)libs[index].name, PE_STRING_LENGTH);
			if (!libs[index].name[0]) { // minimum string length
				goto next;
			}
			if (len < 2 || libs[index].name[0] == 0) { // minimum string length
				RZ_LOG_INFO("read (libs - import dirs) %d\n", len);
				break;
			}
			libs[index].name[len - 1] = '\0';
			rz_str_case(libs[index].name, 0);
			if (!sdb_ht_find(lib_map, libs[index].name, NULL)) {
				sdb_ht_insert(lib_map, libs[index].name, "a");
				libs[index++].last = 0;
				if (index >= max_libs) {
					new_libs = realloc(libs, (max_libs * 2) * sizeof(struct rz_bin_pe_lib_t));
					if (!new_libs) {
						rz_sys_perror("realloc (libs)");
						goto out_error;
					}
					libs = new_libs;
					new_libs = NULL;
					max_libs *= 2;
				}
			}
		next:
			iidi++;
			r = PE_(read_image_import_directory)(bin->b, off + iidi * sizeof(curr_import_dir),
				&curr_import_dir);
		}
	}
	off = bin->delay_import_directory_offset;
	if (off < bin->size && off > 0) {
		ut64 did = 0;
		if (off + sizeof(PE_(image_delay_import_directory)) > bin->size) {
			goto out_error;
		}
		int r = PE_(read_image_delay_import_directory)(bin->b, off, &curr_delay_import_dir);
		if (r != sizeof(curr_delay_import_dir)) {
			goto out_error;
		}
		while (r == sizeof(curr_delay_import_dir) &&
			curr_delay_import_dir.Name != 0 && curr_delay_import_dir.DelayImportNameTable != 0) {
			name_off = PE_(bin_pe_rva_to_paddr)(bin, curr_delay_import_dir.Name);
			if (name_off > bin->size || name_off + PE_STRING_LENGTH > bin->size) {
				goto out_error;
			}
			len = rz_buf_read_at(bin->b, name_off, (ut8 *)libs[index].name, PE_STRING_LENGTH);
			if (len != PE_STRING_LENGTH) {
				RZ_LOG_INFO("read (libs - delay import dirs)\n");
				break;
			}
			libs[index].name[len - 1] = '\0';
			rz_str_case(libs[index].name, 0);
			if (!sdb_ht_find(lib_map, libs[index].name, NULL)) {
				sdb_ht_insert(lib_map, libs[index].name, "a");
				libs[index++].last = 0;
				if (index >= max_libs) {
					new_libs = realloc(libs, (max_libs * 2) * sizeof(struct rz_bin_pe_lib_t));
					if (!new_libs) {
						rz_sys_perror("realloc (libs)");
						goto out_error;
					}
					libs = new_libs;
					new_libs = NULL;
					max_libs *= 2;
				}
			}
			did++;
			r = PE_(read_image_delay_import_directory)(bin->b, off + did * sizeof(curr_delay_import_dir),
				&curr_delay_import_dir);
		}
	}
	sdb_ht_free(lib_map);
	libs[index].last = 1;
	return libs;
out_error:
	sdb_ht_free(lib_map);
	free(libs);
	return NULL;
}

int PE_(rz_bin_pe_get_image_size)(RzBinPEObj *bin) {
	return bin->nt_headers->optional_header.SizeOfImage;
}

struct rz_bin_pe_addr_t *PE_(rz_bin_pe_get_entrypoint)(RzBinPEObj *bin) {
	struct rz_bin_pe_addr_t *entry = NULL;
	int i;
	ut64 base_addr = PE_(rz_bin_pe_get_image_base)(bin);
	if (!bin || !bin->optional_header) {
		return NULL;
	}
	if (!(entry = malloc(sizeof(struct rz_bin_pe_addr_t)))) {
		rz_sys_perror("malloc (entrypoint)");
		return NULL;
	}
	PE_DWord pe_entry = bin->optional_header->AddressOfEntryPoint;
	entry->vaddr = PE_(bin_pe_rva_to_va)(bin, pe_entry);
	entry->paddr = PE_(bin_pe_rva_to_paddr)(bin, pe_entry);
	// haddr is the address of AddressOfEntryPoint in header.
	entry->haddr = bin->dos_header->e_lfanew + 4 + sizeof(PE_(image_file_header)) + 16;

	if (entry->paddr >= bin->size) {
		struct rz_bin_pe_section_t *sections = bin->sections;
		ut64 paddr = 0;
		for (i = 0; i < bin->num_sections; i++) {
			if (sections[i].perm & PE_IMAGE_SCN_MEM_EXECUTE) {
				entry->paddr = sections[i].paddr;
				entry->vaddr = sections[i].vaddr + base_addr;
				paddr = 1;
				break;
			}
		}
		if (!paddr) {
			ut64 min_off = -1;
			for (i = 0; i < bin->num_sections; i++) {
				// get the lowest section's paddr
				if (sections[i].paddr < min_off) {
					entry->paddr = sections[i].paddr;
					entry->vaddr = sections[i].vaddr + base_addr;
					min_off = sections[i].paddr;
				}
			}
			if (min_off == -1) {
				// no section just a hack to try to fix entrypoint
				// maybe doesn't work always
				int sa = RZ_MAX(bin->optional_header->SectionAlignment, 0x1000);
				entry->paddr = pe_entry & ((sa << 1) - 1);
				entry->vaddr = entry->paddr + base_addr;
			}
		}
	}
	if (!entry->paddr) {
		struct rz_bin_pe_section_t *sections = bin->sections;
		for (i = 0; i < bin->num_sections; i++) {
			// If there is a section with x without w perm is a good candidate to be the entrypoint
			if (sections[i].perm & PE_IMAGE_SCN_MEM_EXECUTE && !(sections[i].perm & PE_IMAGE_SCN_MEM_WRITE)) {
				entry->paddr = sections[i].paddr;
				entry->vaddr = sections[i].vaddr + base_addr;
				break;
			}
		}
	}

	if (is_arm(bin) && entry->vaddr & 1) {
		entry->vaddr--;
		if (entry->paddr & 1) {
			entry->paddr--;
		}
	}
	return entry;
}

ut64 PE_(rz_bin_pe_get_image_base)(RzBinPEObj *bin) {
	ut64 imageBase = 0;
	if (!bin || !bin->nt_headers) {
		return 0LL;
	}
	imageBase = bin->nt_headers->optional_header.ImageBase;
	if (!imageBase) {
		// this should only happens with messed up binaries
		// XXX this value should be user defined by bin.baddr
		// but from here we can not access config API
		imageBase = 0x10000;
	}
	return imageBase;
}

static inline bool read_and_follow_jump(struct rz_bin_pe_addr_t *entry, RzBuffer *buf, ut8 *b, int len, bool big_endian) {
	if (!rz_buf_read_at(buf, entry->paddr, b, len)) {
		return false;
	}
	if (b[0] != 0xe9) {
		return true;
	}
	const st32 jmp_dst = rz_read_ble32(b + 1, big_endian) + 5;
	entry->paddr += jmp_dst;
	entry->vaddr += jmp_dst;
	return rz_buf_read_at(buf, entry->paddr, b, len) > 0;
}

static inline bool follow_offset(struct rz_bin_pe_addr_t *entry, RzBuffer *buf, ut8 *b, size_t len, bool big_endian, size_t instr_off) {
	if (instr_off + 5 >= len) {
		return false;
	}
	const st32 dst_offset = rz_read_ble32(b + instr_off + 1, big_endian) + instr_off + 5;
	entry->paddr += dst_offset;
	entry->vaddr += dst_offset;
	return read_and_follow_jump(entry, buf, b, len, big_endian);
}

struct rz_bin_pe_addr_t *PE_(check_msvcseh)(RzBinPEObj *bin) {
	rz_return_val_if_fail(bin && bin->b, NULL);
	ut8 b[512];
	size_t n = 0;
	struct rz_bin_pe_addr_t *entry = PE_(rz_bin_pe_get_entrypoint)(bin);
	ZERO_FILL(b);
	if (rz_buf_read_at(bin->b, entry->paddr, b, sizeof(b)) < 0) {
		RZ_LOG_INFO("Cannot read entry at 0x%08" PFMT64x "\n", entry->paddr);
		free(entry);
		return NULL;
	}

	read_and_follow_jump(entry, bin->b, b, sizeof(b), bin->big_endian);

	// MSVC SEH
	// E8 13 09 00 00  call    0x44C388
	// E9 05 00 00 00  jmp     0x44BA7F
	if (b[0] == 0xe8 && b[5] == 0xe9) {
		if (follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, 5)) {
			// case1:
			// from des address of jmp search for 68 xx xx xx xx e8 and test xx xx xx xx = imagebase
			// 68 00 00 40 00  push    0x400000
			// E8 3E F9 FF FF  call    0x44B4FF
			ut32 imageBase = bin->nt_headers->optional_header.ImageBase;
			for (n = 0; n < sizeof(b) - 6; n++) {
				const ut32 tmp_imgbase = rz_read_ble32(b + n + 1, bin->big_endian);
				if (b[n] == 0x68 && tmp_imgbase == imageBase && b[n + 5] == 0xe8) {
					follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, n + 5);
					return entry;
				}
			}
			// case2:
			//  from des address of jmp search for 50 FF xx FF xx E8
			// 50			 push    eax
			// FF 37			 push    dword ptr[edi]
			// FF 36          push    dword ptr[esi]
			// E8 6F FC FF FF call    _main
			for (n = 0; n < sizeof(b) - 6; n++) {
				if (b[n] == 0x50 && b[n + 1] == 0xff && b[n + 3] == 0xff && b[n + 5] == 0xe8) {
					follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, n + 5);
					return entry;
				}
			}
			// case3:
			// 50                                         push    eax
			// FF 35 0C E2 40 00                          push    xxxxxxxx
			// FF 35 08 E2 40 00                          push    xxxxxxxx
			// E8 2B FD FF FF                             call    _main
			for (n = 0; n < sizeof(b) - 20; n++) {
				if (b[n] == 0x50 && b[n + 1] == 0xff && b[n + 7] == 0xff && b[n + 13] == 0xe8) {
					follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, n + 13);
					return entry;
				}
			}
			// case4:
			// 50                                        push    eax
			// 57                                        push    edi
			// FF 36                                     push    dword ptr[esi]
			// E8 D9 FD FF FF                            call    _main
			for (n = 0; n < sizeof(b) - 5; n++) {
				if (b[n] == 0x50 && b[n + 1] == 0x57 && b[n + 2] == 0xff && b[n + 4] == 0xe8) {
					follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, n + 4);
					return entry;
				}
			}
			// case5:
			// 57                                        push    edi
			// 56                                        push    esi
			// FF 36                                     push    dword ptr[eax]
			// E8 D9 FD FF FF                            call    _main
			for (n = 0; n < sizeof(b) - 5; n++) {
				if (b[n] == 0x57 && b[n + 1] == 0x56 && b[n + 2] == 0xff && b[n + 4] == 0xe8) {
					follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, n + 4);
					return entry;
				}
			}
		}
	}

	// MSVC 32bit debug
	if (b[3] == 0xe8) {
		// 55                    push ebp
		// 8B EC                 mov ebp, esp
		// E8 xx xx xx xx        call xxxxxxxx
		// 5D                    pop ebp
		// C3                    ret
		follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, 3);
		if (b[8] == 0xe8) {
			// 55                    push ebp
			// 8B EC                 mov ebp, esp
			// E8 xx xx xx xx        call xxxxxxxx
			// E8 xx xx xx xx        call xxxxxxxx <- Follow this
			// 5D                    pop ebp
			// C3                    ret
			follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, 8);
			for (n = 0; n < sizeof(b) - 17; n++) {
				// E8 xx xx xx xx    call sub.ucrtbased.dll__register_thread_local_exe_atexit_callback
				// 83 C4 04          add esp, 4
				// E8 xx xx xx xx    call xxxxxxxx <- Follow this
				// 89 xx xx          mov dword [xxxx], eax
				// E8 xx xx xx xx    call xxxxxxxx
				if (b[n] == 0xe8 && !memcmp(b + n + 5, "\x83\xc4\x04", 3) && b[n + 8] == 0xe8 && b[n + 13] == 0x89 && b[n + 16] == 0xe8) {
					follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, n + 8);
					int j, calls = 0;
					for (j = 0; j < sizeof(b) - 4; j++) {
						if (b[j] == 0xe8) {
							// E8 xx xx xx xx        call xxxxxxxx
							calls++;
							if (calls == 4) {
								follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, j);
								return entry;
							}
						}
					}
				}
			}
		}
	}

	// MSVC AMD64
	int i;
	for (i = 0; i < sizeof(b) - 14; i++) {
		if (b[i] == 0x48 && b[i + 1] == 0x83 && b[i + 2] == 0xEC) {
			break;
		}
	}
	bool found_caller = false;
	if (b[i + 13] == 0xe9) {
		// 48 83 EC 28       sub     rsp, 0x28
		// E8 xx xx xx xx    call    xxxxxxxx
		// 48 83 C4 28       add     rsp, 0x28
		// E9 xx xx xx xx    jmp     xxxxxxxx <- Follow this
		found_caller = follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, i + 13);
	} else {
		// Debug
		// 48 83 EC 28       sub     rsp, 0x28
		// E8 xx xx xx xx    call    xxxxxxxx
		// 48 83 C4 28       add     rsp, 0x28
		// C3                ret
		follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, i + 4);
		if (b[9] == 0xe8) {
			// 48 83 EC 28       sub     rsp, 0x28
			// E8 xx xx xx xx    call    xxxxxxxx
			// E8 xx xx xx xx    call    xxxxxxxx <- Follow this
			// 48 83 C4 28       add     rsp, 0x28
			// C3                ret
			follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, 9);
			if (b[0x129] == 0xe8) {
				// E8 xx xx xx xx        call xxxxxxxx
				found_caller = follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, 0x129);
			}
		}
	}
	if (found_caller) {
		// from des address of jmp, search for 4C ... 48 ... 8B ... E8
		// 4C 8B C0                    mov     r8, rax
		// 48 8B 17                    mov     rdx, qword [rdi]
		// 8B 0B                       mov     ecx, dword [rbx]
		// E8 xx xx xx xx              call    main
		// or
		// 4C 8B 44 24 28              mov r8, qword [rsp + 0x28]
		// 48 8B 54 24 30              mov rdx, qword [rsp + 0x30]
		// 8B 4C 24 20                 mov ecx, dword [rsp + 0x20]
		// E8 xx xx xx xx              call    main
		for (n = 0; n < sizeof(b) - 14; n++) {
			if (b[n] == 0x4c && b[n + 3] == 0x48 && b[n + 6] == 0x8b && b[n + 8] == 0xe8) {
				follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, n + 8);
				return entry;
			} else if (b[n] == 0x4c && b[n + 5] == 0x48 && b[n + 10] == 0x8b && b[n + 14] == 0xe8) {
				follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, n + 14);
				return entry;
			}
		}
	}
	// Microsoft Visual-C
	//  50                  push eax
	//  FF 75 9C            push dword [ebp - local_64h]
	//  56                  push    esi
	//  56                  push    esi
	//  FF 15 CC C0  44 00  call dword [sym.imp.KERNEL32.dll_GetModuleHandleA]
	//  50                  push    eax
	//  E8 DB DA 00 00      call    main
	//  89 45 A0            mov dword [ebp - local_60h], eax
	//  50                  push    eax
	//  E8 2D 00 00  00     call 0x4015a6
	if (b[188] == 0x50 && b[201] == 0xe8) {
		follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, 201);
		return entry;
	}

	if (b[292] == 0x50 && b[303] == 0xe8) {
		follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, 303);
		return entry;
	}

	free(entry);
	return NULL;
}

struct rz_bin_pe_addr_t *PE_(check_mingw)(RzBinPEObj *bin) {
	struct rz_bin_pe_addr_t *entry;
	bool sw = false;
	ut8 b[1024];
	size_t n = 0;
	if (!bin || !bin->b) {
		return 0LL;
	}
	entry = PE_(rz_bin_pe_get_entrypoint)(bin);
	ZERO_FILL(b);
	if (rz_buf_read_at(bin->b, entry->paddr, b, sizeof(b)) < 0) {
		RZ_LOG_INFO("Cannot read entry at 0x%08" PFMT64x "\n", entry->paddr);
		free(entry);
		return NULL;
	}
	// mingw
	// 55                                         push    ebp
	// 89 E5                                      mov     ebp, esp
	// 83 EC 08                                   sub     esp, 8
	// C7 04 24 01 00 00 00                       mov     dword ptr[esp], 1
	// FF 15 C8 63 41 00                          call    ds : __imp____set_app_type
	// E8 B8 FE FF FF                             call    ___mingw_CRTStartup
	if (b[0] == 0x55 && b[1] == 0x89 && b[3] == 0x83 && b[6] == 0xc7 && b[13] == 0xff && b[19] == 0xe8) {
		sw = follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, 19);
	}
	// 83 EC 1C                                   sub     esp, 1Ch
	// C7 04 24 01 00 00 00                       mov[esp + 1Ch + var_1C], 1
	// FF 15 F8 60 40 00                          call    ds : __imp____set_app_type
	// E8 6B FD FF FF                             call    ___mingw_CRTStartup
	if (b[0] == 0x83 && b[3] == 0xc7 && b[10] == 0xff && b[16] == 0xe8) {
		sw = follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, 16);
	}
	// 83 EC 0C                                            sub     esp, 0Ch
	// C7 05 F4 0A 81 00 00 00 00 00                       mov     ds : _mingw_app_type, 0
	// ED E8 3E AD 24 00                                      call    ___security_init_cookie
	// F2 83 C4 0C                                            add     esp, 0Ch
	// F5 E9 86 FC FF FF                                      jmp     ___tmainCRTStartup
	if (b[0] == 0x83 && b[3] == 0xc7 && b[13] == 0xe8 && b[18] == 0x83 && b[21] == 0xe9) {
		sw = follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, 21);
	}
	if (sw) {
		// case1:
		// from des address of call search for a1 xx xx xx xx 89 xx xx e8 xx xx xx xx
		// A1 04 50 44 00                             mov     eax, ds:dword_445004
		// 89 04 24                                   mov[esp + 28h + lpTopLevelExceptionFilter], eax
		// E8 A3 01 00 00                             call    sub_4013EE
		for (n = 0; n < sizeof(b) - 12; n++) {
			if (b[n] == 0xa1 && b[n + 5] == 0x89 && b[n + 8] == 0xe8) {
				follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, n + 8);
				return entry;
			}
		}
	}
	free(entry);
	return NULL;
}

struct rz_bin_pe_addr_t *PE_(check_unknow)(RzBinPEObj *bin) {
	struct rz_bin_pe_addr_t *entry;
	if (!bin || !bin->b) {
		return 0LL;
	}
	ut8 b[512];
	ZERO_FILL(b);
	entry = PE_(rz_bin_pe_get_entrypoint)(bin);
	// option2: /x 8bff558bec83ec20
	if (rz_buf_read_at(bin->b, entry->paddr, b, 512) < 1) {
		RZ_LOG_INFO("Cannot read entry at 0x%08" PFMT64x "\n", entry->paddr);
		free(entry);
		return NULL;
	}
	/* Decode the jmp instruction, this gets the address of the 'main'
	   function for PE produced by a compiler whose name someone forgot to
	   write down. */
	// this is dirty only a single byte check, can return false positives
	if (b[367] == 0xe8) {
		follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, 367);
		return entry;
	}
	size_t i;
	for (i = 0; i < 512 - 16; i++) {
		// 5. ff 15 .. .. .. .. 50 e8 [main]
		if (!memcmp(b + i, "\xff\x15", 2)) {
			if (b[i + 6] == 0x50) {
				if (b[i + 7] == 0xe8) {
					follow_offset(entry, bin->b, b, sizeof(b), bin->big_endian, i + 7);
					return entry;
				}
			}
		}
	}
	free(entry);
	return NULL;
}

struct rz_bin_pe_addr_t *PE_(rz_bin_pe_get_main_vaddr)(RzBinPEObj *bin) {
	struct rz_bin_pe_addr_t *winmain = PE_(check_msvcseh)(bin);
	if (!winmain) {
		winmain = PE_(check_mingw)(bin);
		if (!winmain) {
			winmain = PE_(check_unknow)(bin);
		}
	}
	return winmain;
}
