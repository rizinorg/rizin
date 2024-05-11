// SPDX-FileCopyrightText: 2008-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2019 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pe.h"

static bool read_dos_header_aux(RzBuffer *buf, ut64 *offset, PE_(image_dos_header) * header) {
	return rz_buf_read_le16_offset(buf, offset, &header->e_magic) &&
		rz_buf_read_le16_offset(buf, offset, &header->e_cblp) &&
		rz_buf_read_le16_offset(buf, offset, &header->e_cp) &&
		rz_buf_read_le16_offset(buf, offset, &header->e_crlc) &&
		rz_buf_read_le16_offset(buf, offset, &header->e_cparhdr) &&
		rz_buf_read_le16_offset(buf, offset, &header->e_minalloc) &&
		rz_buf_read_le16_offset(buf, offset, &header->e_maxalloc) &&
		rz_buf_read_le16_offset(buf, offset, &header->e_ss) &&
		rz_buf_read_le16_offset(buf, offset, &header->e_sp) &&
		rz_buf_read_le16_offset(buf, offset, &header->e_csum) &&
		rz_buf_read_le16_offset(buf, offset, &header->e_ip) &&
		rz_buf_read_le16_offset(buf, offset, &header->e_cs) &&
		rz_buf_read_le16_offset(buf, offset, &header->e_lfarlc) &&
		rz_buf_read_le16_offset(buf, offset, &header->e_ovno);
}

bool PE_(read_dos_header)(RzBuffer *buf, PE_(image_dos_header) * header) {
	ut64 offset = 0;
	if (!read_dos_header_aux(buf, &offset, header)) {
		return false;
	}

	for (size_t i = 0; i < 4; i++) {
		if (!rz_buf_read_le16_offset(buf, &offset, &header->e_res[i])) {
			return false;
		}
	}

	if (!rz_buf_read_le16_offset(buf, &offset, &header->e_oemid)) {
		return false;
	}

	if (!rz_buf_read_le16_offset(buf, &offset, &header->e_oeminfo)) {
		return false;
	}

	for (size_t i = 0; i < 10; i++) {
		if (!rz_buf_read_le16_offset(buf, &offset, &header->e_res2[i])) {
			return false;
		}
	}

	if (!rz_buf_read_le32_offset(buf, &offset, &header->e_lfanew)) {
		return false;
	}
	return true;
}

static bool read_nt_headers_aux(RzBuffer *buf, ut64 *offset, PE_(image_nt_headers) * headers) {
	return rz_buf_read_le32_offset(buf, offset, &headers->Signature) &&
		rz_buf_read_le16_offset(buf, offset, &headers->file_header.Machine) &&
		rz_buf_read_le16_offset(buf, offset, &headers->file_header.NumberOfSections) &&
		rz_buf_read_le32_offset(buf, offset, &headers->file_header.TimeDateStamp) &&
		rz_buf_read_le32_offset(buf, offset, &headers->file_header.PointerToSymbolTable) &&
		rz_buf_read_le32_offset(buf, offset, &headers->file_header.NumberOfSymbols) &&
		rz_buf_read_le16_offset(buf, offset, &headers->file_header.SizeOfOptionalHeader) &&
		rz_buf_read_le16_offset(buf, offset, &headers->file_header.Characteristics) &&
		rz_buf_read_le16_offset(buf, offset, &headers->optional_header.Magic) &&
		rz_buf_read8_offset(buf, offset, &headers->optional_header.MajorLinkerVersion) &&
		rz_buf_read8_offset(buf, offset, &headers->optional_header.MinorLinkerVersion) &&
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.SizeOfCode) &&
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.SizeOfInitializedData) &&
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.SizeOfUninitializedData) &&
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.AddressOfEntryPoint) &&
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.BaseOfCode) &&
#ifdef RZ_BIN_PE64
		rz_buf_read_le64_offset(buf, offset, &headers->optional_header.ImageBase) &&
#else
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.BaseOfData) &&
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.ImageBase) &&
#endif
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.SectionAlignment) &&
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.FileAlignment) &&
		rz_buf_read_le16_offset(buf, offset, &headers->optional_header.MajorOperatingSystemVersion) &&
		rz_buf_read_le16_offset(buf, offset, &headers->optional_header.MinorOperatingSystemVersion) &&
		rz_buf_read_le16_offset(buf, offset, &headers->optional_header.MajorImageVersion) &&
		rz_buf_read_le16_offset(buf, offset, &headers->optional_header.MinorImageVersion) &&
		rz_buf_read_le16_offset(buf, offset, &headers->optional_header.MajorSubsystemVersion) &&
		rz_buf_read_le16_offset(buf, offset, &headers->optional_header.MinorSubsystemVersion) &&
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.Win32VersionValue) &&
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.SizeOfImage) &&
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.SizeOfHeaders) &&
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.CheckSum) &&
		rz_buf_read_le16_offset(buf, offset, &headers->optional_header.Subsystem) &&
		rz_buf_read_le16_offset(buf, offset, &headers->optional_header.DllCharacteristics) &&
#ifdef RZ_BIN_PE64
		rz_buf_read_le64_offset(buf, offset, &headers->optional_header.SizeOfStackReserve) &&
		rz_buf_read_le64_offset(buf, offset, &headers->optional_header.SizeOfStackCommit) &&
		rz_buf_read_le64_offset(buf, offset, &headers->optional_header.SizeOfHeapReserve) &&
		rz_buf_read_le64_offset(buf, offset, &headers->optional_header.SizeOfHeapCommit) &&
#else
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.SizeOfStackReserve) &&
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.SizeOfStackCommit) &&
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.SizeOfHeapReserve) &&
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.SizeOfHeapCommit) &&
#endif
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.LoaderFlags) &&
		rz_buf_read_le32_offset(buf, offset, &headers->optional_header.NumberOfRvaAndSizes);
}

bool PE_(read_nt_headers)(RzBuffer *buf, ut64 addr, PE_(image_nt_headers) * headers) {
	ut64 offset = addr;
	if (!read_nt_headers_aux(buf, &offset, headers)) {
		return false;
	}

	for (size_t i = 0; i < PE_IMAGE_DIRECTORY_ENTRIES; i++) {
		if (!rz_buf_read_le32_offset(buf, &offset, &headers->optional_header.DataDirectory[i].VirtualAddress) ||
			!rz_buf_read_le32_offset(buf, &offset, &headers->optional_header.DataDirectory[i].Size)) {
			return false;
		}
	}

	return true;
}

int PE_(bin_pe_init_hdr)(RzBinPEObj *bin) {
	if (!(bin->dos_header = malloc(sizeof(PE_(image_dos_header))))) {
		rz_sys_perror("malloc (dos header)");
		return false;
	}
	if (!PE_(read_dos_header)(bin->b, bin->dos_header)) {
		RZ_LOG_INFO("read (dos header)\n");
		return false;
	}
	sdb_num_set(bin->kv, "pe_dos_header.offset", 0);
	sdb_set(bin->kv, "pe_dos_header.format", "[2]zwwwwwwwwwwwww[4]www[10]wx"
						 " e_magic e_cblp e_cp e_crlc e_cparhdr e_minalloc e_maxalloc"
						 " e_ss e_sp e_csum e_ip e_cs e_lfarlc e_ovno e_res e_oemid"
						 " e_oeminfo e_res2 e_lfanew");
	if (bin->dos_header->e_lfanew > (unsigned int)bin->size) {
		RZ_LOG_INFO("Invalid e_lfanew field\n");
		return false;
	}
	if (!(bin->nt_headers = malloc(sizeof(PE_(image_nt_headers))))) {
		rz_sys_perror("malloc (nt header)");
		return false;
	}
	bin->nt_header_offset = bin->dos_header->e_lfanew;
	if (!PE_(read_nt_headers)(bin->b, bin->dos_header->e_lfanew, bin->nt_headers)) {
		RZ_LOG_INFO("read (nt header)\n");
		return false;
	}
	sdb_set(bin->kv, "pe_magic.cparse", "enum pe_magic { IMAGE_NT_OPTIONAL_HDR32_MAGIC=0x10b, IMAGE_NT_OPTIONAL_HDR64_MAGIC=0x20b, IMAGE_ROM_OPTIONAL_HDR_MAGIC=0x107 };");
	sdb_set(bin->kv, "pe_subsystem.cparse", "enum pe_subsystem { IMAGE_SUBSYSTEM_UNKNOWN=0, IMAGE_SUBSYSTEM_NATIVE=1, IMAGE_SUBSYSTEM_WINDOWS_GUI=2, "
						" IMAGE_SUBSYSTEM_WINDOWS_CUI=3, IMAGE_SUBSYSTEM_OS2_CUI=5, IMAGE_SUBSYSTEM_POSIX_CUI=7, IMAGE_SUBSYSTEM_WINDOWS_CE_GUI=9, "
						" IMAGE_SUBSYSTEM_EFI_APPLICATION=10, IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER=11, IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER=12, "
						" IMAGE_SUBSYSTEM_EFI_ROM=13, IMAGE_SUBSYSTEM_XBOX=14, IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION=16 };");
	sdb_set(bin->kv, "pe_dllcharacteristics.cparse", "enum pe_dllcharacteristics { IMAGE_LIBRARY_PROCESS_INIT=0x0001, IMAGE_LIBRARY_PROCESS_TERM=0x0002, "
							 " IMAGE_LIBRARY_THREAD_INIT=0x0004, IMAGE_LIBRARY_THREAD_TERM=0x0008, IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA=0x0020, "
							 " IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE=0x0040, IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY=0x0080, "
							 " IMAGE_DLLCHARACTERISTICS_NX_COMPAT=0x0100, IMAGE_DLLCHARACTERISTICS_NO_ISOLATION=0x0200,IMAGE_DLLCHARACTERISTICS_NO_SEH=0x0400, "
							 " IMAGE_DLLCHARACTERISTICS_NO_BIND=0x0800, IMAGE_DLLCHARACTERISTICS_APPCONTAINER=0x1000, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER=0x2000, "
							 " IMAGE_DLLCHARACTERISTICS_GUARD_CF=0x4000, IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE=0x8000};");
#if RZ_BIN_PE64
	sdb_num_set(bin->kv, "pe_nt_image_headers64.offset", bin->dos_header->e_lfanew);
	sdb_set(bin->kv, "pe_nt_image_headers64.format", "[4]z?? signature (pe_image_file_header)fileHeader (pe_image_optional_header64)optionalHeader");
	sdb_set(bin->kv, "pe_image_optional_header64.format", "[2]Ebbxxxxxqxxwwwwwwxxxx[2]E[2]Bqqqqxx[16]?"
							      " (pe_magic)magic majorLinkerVersion minorLinkerVersion sizeOfCode sizeOfInitializedData"
							      " sizeOfUninitializedData addressOfEntryPoint baseOfCode imageBase"
							      " sectionAlignment fileAlignment majorOperatingSystemVersion minorOperatingSystemVersion"
							      " majorImageVersion minorImageVersion majorSubsystemVersion minorSubsystemVersion"
							      " win32VersionValue sizeOfImage sizeOfHeaders checkSum (pe_subsystem)subsystem (pe_dllcharacteristics)dllCharacteristics"
							      " sizeOfStackReserve sizeOfStackCommit sizeOfHeapReserve sizeOfHeapCommit loaderFlags"
							      " numberOfRvaAndSizes (pe_image_data_directory)dataDirectory");
#else
	sdb_num_set(bin->kv, "pe_nt_image_headers32.offset", bin->dos_header->e_lfanew);
	sdb_set(bin->kv, "pe_nt_image_headers32.format", "[4]z?? signature (pe_image_file_header)fileHeader (pe_image_optional_header32)optionalHeader");
	sdb_set(bin->kv, "pe_image_optional_header32.format", "[2]Ebbxxxxxxxxxwwwwwwxxxx[2]E[2]Bxxxxxx[16]?"
							      " (pe_magic)magic majorLinkerVersion minorLinkerVersion sizeOfCode sizeOfInitializedData"
							      " sizeOfUninitializedData addressOfEntryPoint baseOfCode baseOfData imageBase"
							      " sectionAlignment fileAlignment majorOperatingSystemVersion minorOperatingSystemVersion"
							      " majorImageVersion minorImageVersion majorSubsystemVersion minorSubsystemVersion"
							      " win32VersionValue sizeOfImage sizeOfHeaders checkSum (pe_subsystem)subsystem (pe_dllcharacteristics)dllCharacteristics"
							      " sizeOfStackReserve sizeOfStackCommit sizeOfHeapReserve sizeOfHeapCommit loaderFlags numberOfRvaAndSizes"
							      " (pe_image_data_directory)dataDirectory");
#endif
	sdb_set(bin->kv, "pe_machine.cparse", "enum pe_machine { IMAGE_FILE_MACHINE_I386=0x014c, IMAGE_FILE_MACHINE_IA64=0x0200, IMAGE_FILE_MACHINE_AMD64=0x8664 };");
	sdb_set(bin->kv, "pe_characteristics.cparse", "enum pe_characteristics { "
						      " IMAGE_FILE_RELOCS_STRIPPED=0x0001, IMAGE_FILE_EXECUTABLE_IMAGE=0x0002, IMAGE_FILE_LINE_NUMS_STRIPPED=0x0004, "
						      " IMAGE_FILE_LOCAL_SYMS_STRIPPED=0x0008, IMAGE_FILE_AGGRESIVE_WS_TRIM=0x0010, IMAGE_FILE_LARGE_ADDRESS_AWARE=0x0020, "
						      " IMAGE_FILE_BYTES_REVERSED_LO=0x0080, IMAGE_FILE_32BIT_MACHINE=0x0100, IMAGE_FILE_DEBUG_STRIPPED=0x0200, "
						      " IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP=0x0400, IMAGE_FILE_NET_RUN_FROM_SWAP=0x0800, IMAGE_FILE_SYSTEM=0x1000, "
						      " IMAGE_FILE_DLL=0x2000, IMAGE_FILE_UP_SYSTEM_ONLY=0x4000, IMAGE_FILE_BYTES_REVERSED_HI=0x8000 };");
	sdb_set(bin->kv, "pe_image_file_header.format", "[2]Ewtxxw[2]B"
							" (pe_machine)machine numberOfSections timeDateStamp pointerToSymbolTable"
							" numberOfSymbols sizeOfOptionalHeader (pe_characteristics)characteristics");
	sdb_set(bin->kv, "pe_image_data_directory.format", "xx virtualAddress size");

	// adding compile time to the SDB
	{
		sdb_num_set(bin->kv, "image_file_header.TimeDateStamp", bin->nt_headers->file_header.TimeDateStamp);
		char *timestr = rz_time_stamp_to_str(bin->nt_headers->file_header.TimeDateStamp);
		sdb_set_owned(bin->kv, "image_file_header.TimeDateStamp_string", timestr);
	}
	bin->optional_header = &bin->nt_headers->optional_header;
	bin->data_directory = (PE_(image_data_directory *)) & bin->optional_header->DataDirectory;

	if (bin->dos_header->e_magic != 0x5a4d || // "MZ"
		(bin->nt_headers->Signature != 0x4550 && // "PE"
			/* Check also for Phar Lap TNT DOS extender PL executable */
			bin->nt_headers->Signature != 0x4c50)) { // "PL"
		return false;
	}
	return true;
}
