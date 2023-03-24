// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only
#define RZ_BIN_PE64 1
#include "bin_pe.inc"

// equivalent of PE64_UNWIND_INFO but endian-free
typedef struct windows_x64_unwind_info_t {
	ut8 Version; // : 3;
	ut8 Flags; // : 5;
	ut8 SizeOfProlog;
	ut8 CountOfCodes;
	ut8 FrameRegister; // : 4;
	ut8 FrameOffset; // : 4;
} WinUnwindInfo;

static bool windows_unwind_info_read(WinUnwindInfo *info, RzBuffer *b, ut64 at) {
	ut8 tmp[sizeof(PE64_UNWIND_INFO)] = { 0 };

	if (!rz_buf_read_at(b, at, tmp, sizeof(tmp))) {
		return false;
	}

	// The ordering of bits in C bitfields is implementation defined.
	// this ensures the endianness (here is little endian) is kept
	info->Version = tmp[0] & 0x07;
	info->Flags = tmp[0] >> 3;
	info->SizeOfProlog = tmp[1];
	info->CountOfCodes = tmp[2];
	info->FrameRegister = tmp[3] & 0x0F;
	info->FrameOffset = tmp[3] >> 4;
	return true;
}

static bool check_buffer(RzBuffer *b) {
	ut64 length = rz_buf_size(b);
	if (length <= 0x3d) {
		return false;
	}

	ut16 idx;
	if (!rz_buf_read_le16_at(b, 0x3c, &idx)) {
		return false;
	}

	if (idx + 26 < length) {
		/* Here PE signature for usual PE files
		 * and PL signature for Phar Lap TNT DOS extender 32bit executables
		 */
		ut8 buf[2];
		rz_buf_read_at(b, 0, buf, sizeof(buf));
		if (!memcmp(buf, "MZ", 2)) {
			rz_buf_read_at(b, idx, buf, sizeof(buf));
			// TODO: Add one more indicator, to prevent false positives
			// if (!memcmp (buf, "PL", 2)) { return true; }
			if (!memcmp(buf, "PE", 2)) {
				rz_buf_read_at(b, idx + 0x18, buf, sizeof(buf));
				return !memcmp(buf, "\x0b\x02", 2);
			}
		}
	}
	return false;
}

static RzList /*<RzBinField *>*/ *fields(RzBinFile *bf) {
	RzList *ret = rz_list_newf((RzListFree)rz_bin_field_free);
	if (!ret) {
		return NULL;
	}

#define ROWL(nam, siz, val, fmt) \
	rz_list_append(ret, rz_bin_field_new(addr, addr, siz, nam, sdb_fmt("0x%08" PFMT64x, (ut64)val), fmt, false));

	struct PE_(rz_bin_pe_obj_t) *bin = bf->o->bin_obj;
	ut64 addr = bin->rich_header_offset ? bin->rich_header_offset : 128;

	RzListIter *it;
	Pe_image_rich_entry *rich;
	rz_list_foreach (bin->rich_entries, it, rich) {
		rz_list_append(ret, rz_bin_field_new(addr, addr, 0, "RICH_ENTRY_NAME", strdup(rich->productName), "s", false));
		ROWL("RICH_ENTRY_ID", 2, rich->productId, "x");
		addr += 2;
		ROWL("RICH_ENTRY_VERSION", 2, rich->minVersion, "x");
		addr += 2;
		ROWL("RICH_ENTRY_TIMES", 4, rich->timesUsed, "x");
		addr += 4;
	}

	ROWL("Signature", 4, bin->nt_headers->Signature, "x");
	addr += 4;
	ROWL("Machine", 2, bin->nt_headers->file_header.Machine, "x");
	addr += 2;
	ROWL("NumberOfSections", 2, bin->nt_headers->file_header.NumberOfSections, "x");
	addr += 2;
	ROWL("TimeDateStamp", 4, bin->nt_headers->file_header.TimeDateStamp, "x");
	addr += 4;
	ROWL("PointerToSymbolTable", 4, bin->nt_headers->file_header.PointerToSymbolTable, "x");
	addr += 4;
	ROWL("NumberOfSymbols ", 4, bin->nt_headers->file_header.NumberOfSymbols, "x");
	addr += 4;
	ROWL("SizeOfOptionalHeader", 2, bin->nt_headers->file_header.SizeOfOptionalHeader, "x");
	addr += 2;
	ROWL("Characteristics", 2, bin->nt_headers->file_header.Characteristics, "x");
	addr += 2;
	ROWL("Magic", 2, bin->nt_headers->optional_header.Magic, "x");
	addr += 2;
	ROWL("MajorLinkerVersion", 1, bin->nt_headers->optional_header.MajorLinkerVersion, "x");
	addr += 1;
	ROWL("MinorLinkerVersion", 1, bin->nt_headers->optional_header.MinorLinkerVersion, "x");
	addr += 1;
	ROWL("SizeOfCode", 4, bin->nt_headers->optional_header.SizeOfCode, "x");
	addr += 4;
	ROWL("SizeOfInitializedData", 4, bin->nt_headers->optional_header.SizeOfInitializedData, "x");
	addr += 4;
	ROWL("SizeOfUninitializedData", 4, bin->nt_headers->optional_header.SizeOfUninitializedData, "x");
	addr += 4;
	ROWL("AddressOfEntryPoint", 4, bin->nt_headers->optional_header.AddressOfEntryPoint, "x");
	addr += 4;
	ROWL("BaseOfCode", 4, bin->nt_headers->optional_header.BaseOfCode, "x");
	addr += 4;
	ROWL("ImageBase", 4, bin->nt_headers->optional_header.ImageBase, "x");
	addr += 4;
	ROWL("SectionAlignment", 4, bin->nt_headers->optional_header.SectionAlignment, "x");
	addr += 4;
	ROWL("FileAlignment", 4, bin->nt_headers->optional_header.FileAlignment, "x");
	addr += 4;
	ROWL("MajorOperatingSystemVersion", 2, bin->nt_headers->optional_header.MajorOperatingSystemVersion, "x");
	addr += 2;
	ROWL("MinorOperatingSystemVersion", 2, bin->nt_headers->optional_header.MinorOperatingSystemVersion, "x");
	addr += 2;
	ROWL("MajorImageVersion", 2, bin->nt_headers->optional_header.MajorImageVersion, "x");
	addr += 2;
	ROWL("MinorImageVersion", 2, bin->nt_headers->optional_header.MinorImageVersion, "x");
	addr += 2;
	ROWL("MajorSubsystemVersion", 2, bin->nt_headers->optional_header.MajorSubsystemVersion, "x");
	addr += 2;
	ROWL("MinorSubsystemVersion", 2, bin->nt_headers->optional_header.MinorSubsystemVersion, "x");
	addr += 2;
	ROWL("Win32VersionValue", 4, bin->nt_headers->optional_header.Win32VersionValue, "x");
	addr += 4;
	ROWL("SizeOfImage", 4, bin->nt_headers->optional_header.SizeOfImage, "x");
	addr += 4;
	ROWL("SizeOfHeaders", 4, bin->nt_headers->optional_header.SizeOfHeaders, "x");
	addr += 4;
	ROWL("CheckSum", 4, bin->nt_headers->optional_header.CheckSum, "x");
	addr += 4;
	ROWL("Subsystem", 24, bin->nt_headers->optional_header.Subsystem, "x");
	addr += 2;
	ROWL("DllCharacteristics", 2, bin->nt_headers->optional_header.DllCharacteristics, "x");
	addr += 2;
	ROWL("SizeOfStackReserve", 4, bin->nt_headers->optional_header.SizeOfStackReserve, "x");
	addr += 4;
	ROWL("SizeOfStackCommit", 4, bin->nt_headers->optional_header.SizeOfStackCommit, "x");
	addr += 4;
	ROWL("SizeOfHeapReserve", 4, bin->nt_headers->optional_header.SizeOfHeapReserve, "x");
	addr += 4;
	ROWL("SizeOfHeapCommit", 4, bin->nt_headers->optional_header.SizeOfHeapCommit, "x");
	addr += 4;
	ROWL("LoaderFlags", 4, bin->nt_headers->optional_header.LoaderFlags, "x");
	addr += 4;
	ROWL("NumberOfRvaAndSizes", 4, bin->nt_headers->optional_header.NumberOfRvaAndSizes, "x");
	addr += 4;

	int i;
	ut64 tmp = addr;
	for (i = 0; i < PE_IMAGE_DIRECTORY_ENTRIES - 1; i++) {
		if (bin->nt_headers->optional_header.DataDirectory[i].Size > 0) {
			addr = tmp + i * 8;
			switch (i) {
			case PE_IMAGE_DIRECTORY_ENTRY_EXPORT:
				ROWL("IMAGE_DIRECTORY_ENTRY_EXPORT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL("SIZE_IMAGE_DIRECTORY_ENTRY_EXPORT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IMPORT:
				ROWL("IMAGE_DIRECTORY_ENTRY_IMPORT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL("SIZE_IMAGE_DIRECTORY_ENTRY_IMPORT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_RESOURCE:
				ROWL("IMAGE_DIRECTORY_ENTRY_RESOURCE", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL("SIZE_IMAGE_DIRECTORY_ENTRY_RESOURCE", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION:
				ROWL("IMAGE_DIRECTORY_ENTRY_EXCEPTION", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL("SIZE_IMAGE_DIRECTORY_ENTRY_EXCEPTION", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_SECURITY:
				ROWL("IMAGE_DIRECTORY_ENTRY_SECURITY", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL("SIZE_IMAGE_DIRECTORY_ENTRY_SECURITY", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BASERELOC:
				ROWL("IMAGE_DIRECTORY_ENTRY_BASERELOC", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL("SIZE_IMAGE_DIRECTORY_ENTRY_BASERELOC", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DEBUG:
				ROWL("IMAGE_DIRECTORY_ENTRY_DEBUG", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL("SIZE_IMAGE_DIRECTORY_ENTRY_DEBUG", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COPYRIGHT:
				ROWL("IMAGE_DIRECTORY_ENTRY_COPYRIGHT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL("SIZE_IMAGE_DIRECTORY_ENTRY_COPYRIGHT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
				ROWL("IMAGE_DIRECTORY_ENTRY_GLOBALPTR", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL("SIZE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_TLS:
				ROWL("IMAGE_DIRECTORY_ENTRY_TLS", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL("SIZE_IMAGE_DIRECTORY_ENTRY_TLS", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
				ROWL("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL("SIZE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
				ROWL("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL("SIZE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IAT:
				ROWL("IMAGE_DIRECTORY_ENTRY_IAT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL("SIZE_IMAGE_DIRECTORY_ENTRY_IAT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
				ROWL("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL("SIZE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
				ROWL("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL("SIZE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			}
		}
	}

	return ret;
}

static void header(RzBinFile *bf) {
	struct PE_(rz_bin_pe_obj_t) *bin = bf->o->bin_obj;
	struct rz_bin_t *rbin = bf->rbin;
	rbin->cb_printf("PE file header:\n");
	rbin->cb_printf("IMAGE_NT_HEADERS\n");
	rbin->cb_printf("  Signature : 0x%x\n", bin->nt_headers->Signature);
	rbin->cb_printf("IMAGE_FILE_HEADERS\n");
	rbin->cb_printf("  Machine : 0x%x\n", bin->nt_headers->file_header.Machine);
	rbin->cb_printf("  NumberOfSections : 0x%x\n", bin->nt_headers->file_header.NumberOfSections);
	rbin->cb_printf("  TimeDateStamp : 0x%x\n", bin->nt_headers->file_header.TimeDateStamp);
	rbin->cb_printf("  PointerToSymbolTable : 0x%x\n", bin->nt_headers->file_header.PointerToSymbolTable);
	rbin->cb_printf("  NumberOfSymbols : 0x%x\n", bin->nt_headers->file_header.NumberOfSymbols);
	rbin->cb_printf("  SizeOfOptionalHeader : 0x%x\n", bin->nt_headers->file_header.SizeOfOptionalHeader);
	rbin->cb_printf("  Characteristics : 0x%x\n", bin->nt_headers->file_header.Characteristics);
	rbin->cb_printf("IMAGE_OPTIONAL_HEADERS\n");
	rbin->cb_printf("  Magic : 0x%x\n", bin->nt_headers->optional_header.Magic);
	rbin->cb_printf("  MajorLinkerVersion : 0x%x\n", bin->nt_headers->optional_header.MajorLinkerVersion);
	rbin->cb_printf("  MinorLinkerVersion : 0x%x\n", bin->nt_headers->optional_header.MinorLinkerVersion);
	rbin->cb_printf("  SizeOfCode : 0x%x\n", bin->nt_headers->optional_header.SizeOfCode);
	rbin->cb_printf("  SizeOfInitializedData : 0x%x\n", bin->nt_headers->optional_header.SizeOfInitializedData);
	rbin->cb_printf("  SizeOfUninitializedData : 0x%x\n", bin->nt_headers->optional_header.SizeOfUninitializedData);
	rbin->cb_printf("  AddressOfEntryPoint : 0x%x\n", bin->nt_headers->optional_header.AddressOfEntryPoint);
	rbin->cb_printf("  BaseOfCode : 0x%x\n", bin->nt_headers->optional_header.BaseOfCode);
	rbin->cb_printf("  ImageBase : 0x%" PFMT64x "\n", bin->nt_headers->optional_header.ImageBase);
	rbin->cb_printf("  SectionAlignment : 0x%x\n", bin->nt_headers->optional_header.SectionAlignment);
	rbin->cb_printf("  FileAlignment : 0x%x\n", bin->nt_headers->optional_header.FileAlignment);
	rbin->cb_printf("  MajorOperatingSystemVersion : 0x%x\n", bin->nt_headers->optional_header.MajorOperatingSystemVersion);
	rbin->cb_printf("  MinorOperatingSystemVersion : 0x%x\n", bin->nt_headers->optional_header.MinorOperatingSystemVersion);
	rbin->cb_printf("  MajorImageVersion : 0x%x\n", bin->nt_headers->optional_header.MajorImageVersion);
	rbin->cb_printf("  MinorImageVersion : 0x%x\n", bin->nt_headers->optional_header.MinorImageVersion);
	rbin->cb_printf("  MajorSubsystemVersion : 0x%x\n", bin->nt_headers->optional_header.MajorSubsystemVersion);
	rbin->cb_printf("  MinorSubsystemVersion : 0x%x\n", bin->nt_headers->optional_header.MinorSubsystemVersion);
	rbin->cb_printf("  Win32VersionValue : 0x%x\n", bin->nt_headers->optional_header.Win32VersionValue);
	rbin->cb_printf("  SizeOfImage : 0x%x\n", bin->nt_headers->optional_header.SizeOfImage);
	rbin->cb_printf("  SizeOfHeaders : 0x%x\n", bin->nt_headers->optional_header.SizeOfHeaders);
	rbin->cb_printf("  CheckSum : 0x%x\n", bin->nt_headers->optional_header.CheckSum);
	rbin->cb_printf("  Subsystem : 0x%x\n", bin->nt_headers->optional_header.Subsystem);
	rbin->cb_printf("  DllCharacteristics : 0x%x\n", bin->nt_headers->optional_header.DllCharacteristics);
	rbin->cb_printf("  SizeOfStackReserve : 0x%" PFMT64x "\n", bin->nt_headers->optional_header.SizeOfStackReserve);
	rbin->cb_printf("  SizeOfStackCommit : 0x%" PFMT64x "\n", bin->nt_headers->optional_header.SizeOfStackCommit);
	rbin->cb_printf("  SizeOfHeapReserve : 0x%" PFMT64x "\n", bin->nt_headers->optional_header.SizeOfHeapReserve);
	rbin->cb_printf("  SizeOfHeapCommit : 0x%" PFMT64x "\n", bin->nt_headers->optional_header.SizeOfHeapCommit);
	rbin->cb_printf("  LoaderFlags : 0x%x\n", bin->nt_headers->optional_header.LoaderFlags);
	rbin->cb_printf("  NumberOfRvaAndSizes : 0x%x\n", bin->nt_headers->optional_header.NumberOfRvaAndSizes);
	RzListIter *it;
	Pe_image_rich_entry *entry;
	rbin->cb_printf("RICH_FIELDS\n");
	rz_list_foreach (bin->rich_entries, it, entry) {
		rbin->cb_printf("  Product: %d Name: %s Version: %d Times: %d\n", entry->productId, entry->productName, entry->minVersion, entry->timesUsed);
	}
	int i;
	for (i = 0; i < PE_IMAGE_DIRECTORY_ENTRIES - 1; i++) {
		if (bin->nt_headers->optional_header.DataDirectory[i].Size > 0) {
			switch (i) {
			case PE_IMAGE_DIRECTORY_ENTRY_EXPORT:
				rbin->cb_printf("IMAGE_DIRECTORY_ENTRY_EXPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IMPORT:
				rbin->cb_printf("IMAGE_DIRECTORY_ENTRY_IMPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_RESOURCE:
				rbin->cb_printf("IMAGE_DIRECTORY_ENTRY_RESOURCE\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION:
				rbin->cb_printf("IMAGE_DIRECTORY_ENTRY_EXCEPTION\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_SECURITY:
				rbin->cb_printf("IMAGE_DIRECTORY_ENTRY_SECURITY\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BASERELOC:
				rbin->cb_printf("IMAGE_DIRECTORY_ENTRY_BASERELOC\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DEBUG:
				rbin->cb_printf("IMAGE_DIRECTORY_ENTRY_DEBUG\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COPYRIGHT:
				rbin->cb_printf("IMAGE_DIRECTORY_ENTRY_COPYRIGHT\n");
				rbin->cb_printf("IMAGE_DIRECTORY_ENTRY_ARCHITECTURE\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
				rbin->cb_printf("IMAGE_DIRECTORY_ENTRY_GLOBALPTR\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_TLS:
				rbin->cb_printf("IMAGE_DIRECTORY_ENTRY_TLS\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
				rbin->cb_printf("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
				rbin->cb_printf("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IAT:
				rbin->cb_printf("IMAGE_DIRECTORY_ENTRY_IAT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
				rbin->cb_printf("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
				rbin->cb_printf("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR\n");
				break;
			}
			rbin->cb_printf("  VirtualAddress : 0x%x\n", bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress);
			rbin->cb_printf("  Size : 0x%x\n", bin->nt_headers->optional_header.DataDirectory[i].Size);
		}
	}
}

#define RzBinPEObj struct PE_(rz_bin_pe_obj_t)
static inline int find_section(RzBinPEObj *bin, PE_DWord rva) {
	PE_DWord section_base;
	int i, section_size;
	for (i = 0; i < bin->num_sections; i++) {
		section_base = bin->sections[i].vaddr;
		section_size = bin->sections[i].vsize;
		if (rva >= section_base && rva < section_base + section_size) {
			return i;
		}
	}
	return -1;
}

static inline ut64 rva_to_paddr(const struct rz_bin_pe_section_t *section, ut64 rva) {
	return section->paddr + (rva - section->vaddr);
}

static inline const struct rz_bin_pe_section_t *get_section(RzBinPEObj *bin, const struct rz_bin_pe_section_t *unwind_data_section, PE_DWord rva) {
	if (!unwind_data_section || (rva < unwind_data_section->vaddr || rva > unwind_data_section->vaddr + unwind_data_section->vsize)) {
		const int section_idx = find_section(bin, rva);
		if (section_idx == -1) {
			return NULL;
		}
		if (bin->sections[section_idx].paddr > rz_buf_size(bin->b)) {
			return NULL;
		}
		return &bin->sections[section_idx];
	}
	return unwind_data_section;
}

static bool read_pe64_runtime_function(RzBuffer *buf, ut64 base, PE64_RUNTIME_FUNCTION *rfcn, bool big_endian) {
	ut64 offset = base;
	return rz_buf_read_ble32_offset(buf, &offset, &rfcn->BeginAddress, big_endian) &&
		rz_buf_read_ble32_offset(buf, &offset, &rfcn->EndAddress, big_endian) &&
		rz_buf_read_ble32_offset(buf, &offset, &rfcn->UnwindInfoAddress, big_endian);
}

static bool read_pe64_scope_record(RzBuffer *buf, ut64 base, PE64_SCOPE_RECORD *record, bool big_endian) {
	ut64 offset = base;
	return rz_buf_read_ble32_offset(buf, &offset, &record->BeginAddress, big_endian) &&
		rz_buf_read_ble32_offset(buf, &offset, &record->EndAddress, big_endian) &&
		rz_buf_read_ble32_offset(buf, &offset, &record->HandlerAddress, big_endian) &&
		rz_buf_read_ble32_offset(buf, &offset, &record->JumpTarget, big_endian);
}

static RzList /*<RzBinTrycatch *>*/ *trycatch(RzBinFile *bf) {
	ut64 baseAddr = bf->o->opts.baseaddr;
	ut64 offset;

	struct PE_(rz_bin_pe_obj_t) *bin = bf->o->bin_obj;
	if (bin->optional_header->NumberOfRvaAndSizes < PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
		return NULL;
	}
	if (bin->optional_header->DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress == 0) {
		return NULL;
	}
	PE_(image_data_directory) *expdir = &bin->optional_header->DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (!expdir->Size) {
		return NULL;
	}
	const struct rz_bin_pe_section_t *pdata = get_section(bin, NULL, expdir->VirtualAddress);
	if (!pdata) {
		return NULL;
	}
	const ut64 paddr = rva_to_paddr(pdata, expdir->VirtualAddress);
	if (paddr > rz_buf_size(bin->b)) {
		return NULL;
	}

	RzList *tclist = rz_list_newf((RzListFree)rz_bin_trycatch_free);
	if (!tclist) {
		return NULL;
	}
	const struct rz_bin_pe_section_t *unwind_data_section = NULL;

	const ut64 end = RZ_MIN(rz_buf_size(bin->b), pdata->paddr + pdata->size);

	for (offset = paddr; offset < end; offset += sizeof(PE64_RUNTIME_FUNCTION)) {
		PE64_RUNTIME_FUNCTION rfcn = { 0 };
		bool suc = read_pe64_runtime_function(bin->b, offset, &rfcn, bin->big_endian);
		if (!rfcn.BeginAddress) {
			break;
		}
		ut32 savedBeginOff = rfcn.BeginAddress;
		ut32 savedEndOff = rfcn.EndAddress;
		while (suc && rfcn.UnwindData & 1) {
			ut64 paddr = rva_to_paddr(pdata, rfcn.UnwindData & ~1);
			suc = read_pe64_runtime_function(bin->b, paddr, &rfcn, bin->big_endian);
		}
		rfcn.BeginAddress = savedBeginOff;
		rfcn.EndAddress = savedEndOff;
		if (!suc) {
			continue;
		}
		unwind_data_section = get_section(bin, unwind_data_section, rfcn.UnwindData);
		if (!unwind_data_section) {
			continue;
		}
		ut64 unwind_data_paddr = rva_to_paddr(unwind_data_section, rfcn.UnwindData);
		if (unwind_data_paddr > unwind_data_section->paddr + unwind_data_section->size) {
			continue;
		}
		WinUnwindInfo info;
		suc = windows_unwind_info_read(&info, bin->b, unwind_data_paddr);
		if (!suc || info.Version != 1 || (!(info.Flags & PE64_UNW_FLAG_EHANDLER) && !(info.Flags & PE64_UNW_FLAG_CHAININFO))) {
			continue;
		}

		ut32 sizeOfCodeEntries = info.CountOfCodes % 2 ? info.CountOfCodes + 1 : info.CountOfCodes;
		sizeOfCodeEntries *= sizeof(PE64_UNWIND_CODE);
		ut64 exceptionDataOff = unwind_data_paddr + offsetof(PE64_UNWIND_INFO, UnwindCode) + sizeOfCodeEntries;

		if (info.Flags & PE64_UNW_FLAG_CHAININFO) {
			savedBeginOff = rfcn.BeginAddress;
			savedEndOff = rfcn.EndAddress;
			do {
				if (!read_pe64_runtime_function(bin->b, exceptionDataOff, &rfcn, bin->big_endian)) {
					break;
				}
				unwind_data_section = get_section(bin, unwind_data_section, rfcn.UnwindData);
				if (!unwind_data_section) {
					break;
				}
				unwind_data_paddr = rva_to_paddr(unwind_data_section, rfcn.UnwindData);
				suc = windows_unwind_info_read(&info, bin->b, unwind_data_paddr);
				if (!suc || info.Version != 1) {
					break;
				}
				while (suc && (unwind_data_paddr & 1)) {
					suc = read_pe64_runtime_function(bin->b, unwind_data_paddr & ~1, &rfcn, bin->big_endian);
					unwind_data_paddr = rva_to_paddr(unwind_data_section, rfcn.UnwindData);
				}
				if (!suc || info.Version != 1) {
					break;
				}
				sizeOfCodeEntries = info.CountOfCodes % 2 ? info.CountOfCodes + 1 : info.CountOfCodes;
				sizeOfCodeEntries *= sizeof(PE64_UNWIND_CODE);
				exceptionDataOff = unwind_data_paddr + offsetof(PE64_UNWIND_INFO, UnwindCode) + sizeOfCodeEntries;
			} while (info.Flags & PE64_UNW_FLAG_CHAININFO);
			if (!(info.Flags & PE64_UNW_FLAG_EHANDLER)) {
				continue;
			}
			rfcn.BeginAddress = savedBeginOff;
			rfcn.EndAddress = savedEndOff;
		}

		ut32 handler = 0;
		if (!rz_buf_read_ble32_at(bin->b, exceptionDataOff, &handler, bin->big_endian)) {
			continue;
		}
		exceptionDataOff += sizeof(ut32);

		PE64_SCOPE_TABLE tbl;
		if (!rz_buf_read_ble32_at(bin->b, exceptionDataOff, &tbl.Count, bin->big_endian)) {
			continue;
		}
		const ut64 last_scope_addr = RZ_MIN(rz_buf_size(bin->b), unwind_data_section->paddr + unwind_data_section->size) - sizeof(PE64_SCOPE_RECORD);
		PE64_SCOPE_RECORD scope;
		ut64 scopeRecOff = exceptionDataOff + sizeof(tbl);
		int i;
		for (i = 0; i < tbl.Count && scopeRecOff <= last_scope_addr; i++, scopeRecOff += sizeof(PE64_SCOPE_RECORD)) {
			if (!read_pe64_scope_record(bin->b, scopeRecOff, &scope, bin->big_endian)) {
				break;
			}
			if (scope.BeginAddress > scope.EndAddress || scope.BeginAddress == UT32_MAX || scope.EndAddress == UT32_MAX || !scope.BeginAddress || !scope.EndAddress) {
				break;
			}
			if (!(scope.BeginAddress >= rfcn.BeginAddress - 1 && scope.BeginAddress < rfcn.EndAddress && scope.EndAddress <= rfcn.EndAddress + 1 && scope.EndAddress > rfcn.BeginAddress)) {
				continue;
			}
			if (!scope.JumpTarget) {
				// scope.HandlerAddress == __finally block
				scope.JumpTarget = scope.HandlerAddress;
				scope.HandlerAddress = 1;
			}
			ut64 handlerAddr = scope.HandlerAddress == 1 ? 0 : scope.HandlerAddress + baseAddr;
			RzBinTrycatch *tc = rz_bin_trycatch_new(
				rfcn.BeginAddress + baseAddr,
				scope.BeginAddress + baseAddr,
				scope.EndAddress + baseAddr,
				scope.JumpTarget + baseAddr,
				handlerAddr);
			rz_list_append(tclist, tc);
		}
	}
	return tclist;
}

RzBinPlugin rz_bin_plugin_pe64 = {
	.name = "pe64",
	.desc = "PE64 (PE32+) bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.maps = &maps,
	.sections = &sections,
	.populate_symbols = &symbols,
	.imports = &imports,
	.strings = &strings,
	.info = &info,
	.header = &header,
	.fields = &fields,
	.libs = &libs,
	.relocs = &relocs,
	.get_offset = &get_offset,
	.get_vaddr = &get_vaddr,
	.trycatch = &trycatch,
	.hashes = &compute_hashes,
	.resources = &resources,
	.section_flag_to_rzlist = &PE_(section_flag_to_rzlist),
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_pe64,
	.version = RZ_VERSION
};
#endif
