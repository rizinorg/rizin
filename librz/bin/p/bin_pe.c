// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2019 alvarofe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bin_pe.inc"

static bool pe_check_buffer(RzBuffer *b) {
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
			if (!memcmp(buf, "PL", 2)) {
				return true;
			}
			if (!memcmp(buf, "PE", 2)) {
				rz_buf_read_at(b, idx + 0x18, buf, sizeof(buf));
				return !memcmp(buf, "\x0b\x01", 2);
			}
		}
	}
	return false;
}

/* inspired in http://www.phreedom.org/solar/code/tinype/tiny.97/tiny.asm */
static RzBuffer *pe_create(RzBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RzBinArchOptions *opt) {
	ut32 hdrsize, p_start, p_opthdr, p_sections, p_lsrlc, n;
	ut32 baddr = 0x400000;
	RzBuffer *buf = rz_buf_new_with_bytes(NULL, 0);

#define B(x, y)    rz_buf_append_bytes(buf, (const ut8 *)(x), y)
#define H(x)       rz_buf_append_ut16(buf, x)
#define D(x)       rz_buf_append_ut32(buf, x)
#define Z(x)       rz_buf_append_nbytes(buf, x)
#define W(x, y, z) rz_buf_write_at(buf, x, (const ut8 *)(y), z)
#define WZ(x, y) \
	p_tmp = rz_buf_size(buf); \
	Z(x); \
	W(p_tmp, y, strlen(y))

	B("MZ\x00\x00", 4); // MZ Header
	B("PE\x00\x00", 4); // PE Signature
	H(0x14c); // Machine
	H(1); // Number of sections
	D(0); // Timestamp (Unused)
	D(0); // PointerToSymbolTable (Unused)
	D(0); // NumberOfSymbols (Unused)
	p_lsrlc = rz_buf_size(buf);
	H(-1); // SizeOfOptionalHeader
	H(0x103); // Characteristics

	/* Optional Header */
	p_opthdr = rz_buf_size(buf);
	H(0x10b); // Magic
	B("\x08\x00", 2); // (Major/Minor)LinkerVersion (Unused)

	p_sections = rz_buf_size(buf);
	n = p_sections - p_opthdr;
	W(p_lsrlc, &n, 2); // Fix SizeOfOptionalHeader

	/* Sections */
	p_start = 0x7c; // HACK: Headersize
	hdrsize = 0x7c;

	D(RZ_ROUND(codelen, 4)); // SizeOfCode (Unused)
	D(0); // SizeOfInitializedData (Unused)
	D(codelen); // codesize
	D(p_start);
	D(codelen);
	D(p_start);
	D(baddr); // ImageBase
	D(4); // SectionAlignment
	D(4); // FileAlignment
	H(4); // MajorOperatingSystemVersion (Unused)
	H(0); // MinorOperatingSystemVersion (Unused)
	H(0); // MajorImageVersion (Unused)
	H(0); // MinorImageVersion (Unused)
	H(4); // MajorSubsystemVersion
	H(0); // MinorSubsystemVersion (Unused)
	D(0); // Win32VersionValue (Unused)
	D((RZ_ROUND(hdrsize, 4)) + (RZ_ROUND(codelen, 4))); // SizeOfImage
	D(RZ_ROUND(hdrsize, 4)); // SizeOfHeaders
	D(0); // CheckSum (Unused)
	H(2); // Subsystem (Win32 GUI)
	H(0x400); // DllCharacteristics (Unused)
	D(0x100000); // SizeOfStackReserve (Unused)
	D(0x1000); // SizeOfStackCommit
	D(0x100000); // SizeOfHeapReserve
	D(0x1000); // SizeOfHeapCommit (Unused)
	D(0); // LoaderFlags (Unused)
	D(0); // NumberOfRvaAndSizes (Unused)
	B(code, codelen);

	if (data && datalen > 0) {
		// ut32 data_section = buf->length;
		RZ_LOG_WARN("DATA section not support for PE yet\n");
		B(data, datalen);
	}
	return buf;
}

static char *pe_signature(RzBinFile *bf, bool json) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	struct PE_(rz_bin_pe_obj_t) *bin = bf->o->bin_obj;

	RzStructuredData *pe_cms = rz_pkcs7_cms_to_structure(bin->cms);
	if (!pe_cms) {
		return rz_str_dup(json ? "{}" : "");
	}

	char *value = NULL;
	if (json) {
		value = rz_structured_data_to_json(pe_cms);
	} else {
		value = rz_structured_data_to_yaml(pe_cms);
	}
	rz_structured_data_free(pe_cms);

	return value;
}

static RzPVector /*<RzBinField *>*/ *pe_fields(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_field_free);
	if (!ret) {
		return NULL;
	}

#define ROWL(buf, nam, siz, val, fmt) \
	rz_pvector_push(ret, rz_bin_field_new(addr, addr, siz, nam, rz_strf(buf, "0x%08x", val), fmt, false));

	struct PE_(rz_bin_pe_obj_t) *bin = bf->o->bin_obj;
	ut64 addr = bin->rich_header_offset ? bin->rich_header_offset : 128;

	char tmpbuf[32];
	RzListIter *it;
	Pe_image_rich_entry *rich;
	rz_list_foreach (bin->rich_entries, it, rich) {
		rz_pvector_push(ret, rz_bin_field_new(addr, addr, 0, "RICH_ENTRY_NAME", rz_str_dup(rich->productName), "s", false));
		ROWL(tmpbuf, "RICH_ENTRY_ID", 2, rich->productId, "x");
		addr += 2;
		ROWL(tmpbuf, "RICH_ENTRY_VERSION", 2, rich->minVersion, "x");
		addr += 2;
		ROWL(tmpbuf, "RICH_ENTRY_TIMES", 4, rich->timesUsed, "x");
		addr += 4;
	}

	ROWL(tmpbuf, "Signature", 4, bin->nt_headers->Signature, "x");
	addr += 4;
	ROWL(tmpbuf, "Machine", 2, bin->nt_headers->file_header.Machine, "x");
	addr += 2;
	ROWL(tmpbuf, "NumberOfSections", 2, bin->nt_headers->file_header.NumberOfSections, "x");
	addr += 2;
	ROWL(tmpbuf, "TimeDateStamp", 4, bin->nt_headers->file_header.TimeDateStamp, "x");
	addr += 4;
	ROWL(tmpbuf, "PointerToSymbolTable", 4, bin->nt_headers->file_header.PointerToSymbolTable, "x");
	addr += 4;
	ROWL(tmpbuf, "NumberOfSymbols ", 4, bin->nt_headers->file_header.NumberOfSymbols, "x");
	addr += 4;
	ROWL(tmpbuf, "SizeOfOptionalHeader", 2, bin->nt_headers->file_header.SizeOfOptionalHeader, "x");
	addr += 2;
	ROWL(tmpbuf, "Characteristics", 2, bin->nt_headers->file_header.Characteristics, "x");
	addr += 2;
	ROWL(tmpbuf, "Magic", 2, bin->nt_headers->optional_header.Magic, "x");
	addr += 2;
	ROWL(tmpbuf, "MajorLinkerVersion", 1, bin->nt_headers->optional_header.MajorLinkerVersion, "x");
	addr += 1;
	ROWL(tmpbuf, "MinorLinkerVersion", 1, bin->nt_headers->optional_header.MinorLinkerVersion, "x");
	addr += 1;
	ROWL(tmpbuf, "SizeOfCode", 4, bin->nt_headers->optional_header.SizeOfCode, "x");
	addr += 4;
	ROWL(tmpbuf, "SizeOfInitializedData", 4, bin->nt_headers->optional_header.SizeOfInitializedData, "x");
	addr += 4;
	ROWL(tmpbuf, "SizeOfUninitializedData", 4, bin->nt_headers->optional_header.SizeOfUninitializedData, "x");
	addr += 4;
	ROWL(tmpbuf, "AddressOfEntryPoint", 4, bin->nt_headers->optional_header.AddressOfEntryPoint, "x");
	addr += 4;
	ROWL(tmpbuf, "BaseOfCode", 4, bin->nt_headers->optional_header.BaseOfCode, "x");
	addr += 4;
	ROWL(tmpbuf, "BaseOfData", 4, bin->nt_headers->optional_header.BaseOfData, "x");
	addr += 4;
	ROWL(tmpbuf, "ImageBase", 4, bin->nt_headers->optional_header.ImageBase, "x");
	addr += 4;
	ROWL(tmpbuf, "SectionAlignment", 4, bin->nt_headers->optional_header.SectionAlignment, "x");
	addr += 4;
	ROWL(tmpbuf, "FileAlignment", 4, bin->nt_headers->optional_header.FileAlignment, "x");
	addr += 4;
	ROWL(tmpbuf, "MajorOperatingSystemVersion", 2, bin->nt_headers->optional_header.MajorOperatingSystemVersion, "x");
	addr += 2;
	ROWL(tmpbuf, "MinorOperatingSystemVersion", 2, bin->nt_headers->optional_header.MinorOperatingSystemVersion, "x");
	addr += 2;
	ROWL(tmpbuf, "MajorImageVersion", 2, bin->nt_headers->optional_header.MajorImageVersion, "x");
	addr += 2;
	ROWL(tmpbuf, "MinorImageVersion", 2, bin->nt_headers->optional_header.MinorImageVersion, "x");
	addr += 2;
	ROWL(tmpbuf, "MajorSubsystemVersion", 2, bin->nt_headers->optional_header.MajorSubsystemVersion, "x");
	addr += 2;
	ROWL(tmpbuf, "MinorSubsystemVersion", 2, bin->nt_headers->optional_header.MinorSubsystemVersion, "x");
	addr += 2;
	ROWL(tmpbuf, "Win32VersionValue", 4, bin->nt_headers->optional_header.Win32VersionValue, "x");
	addr += 4;
	ROWL(tmpbuf, "SizeOfImage", 4, bin->nt_headers->optional_header.SizeOfImage, "x");
	addr += 4;
	ROWL(tmpbuf, "SizeOfHeaders", 4, bin->nt_headers->optional_header.SizeOfHeaders, "x");
	addr += 4;
	ROWL(tmpbuf, "CheckSum", 4, bin->nt_headers->optional_header.CheckSum, "x");
	addr += 4;
	ROWL(tmpbuf, "Subsystem", 24, bin->nt_headers->optional_header.Subsystem, "x");
	addr += 2;
	ROWL(tmpbuf, "DllCharacteristics", 2, bin->nt_headers->optional_header.DllCharacteristics, "x");
	addr += 2;
	ROWL(tmpbuf, "SizeOfStackReserve", 4, bin->nt_headers->optional_header.SizeOfStackReserve, "x");
	addr += 4;
	ROWL(tmpbuf, "SizeOfStackCommit", 4, bin->nt_headers->optional_header.SizeOfStackCommit, "x");
	addr += 4;
	ROWL(tmpbuf, "SizeOfHeapReserve", 4, bin->nt_headers->optional_header.SizeOfHeapReserve, "x");
	addr += 4;
	ROWL(tmpbuf, "SizeOfHeapCommit", 4, bin->nt_headers->optional_header.SizeOfHeapCommit, "x");
	addr += 4;
	ROWL(tmpbuf, "LoaderFlags", 4, bin->nt_headers->optional_header.LoaderFlags, "x");
	addr += 4;
	ROWL(tmpbuf, "NumberOfRvaAndSizes", 4, bin->nt_headers->optional_header.NumberOfRvaAndSizes, "x");
	addr += 4;

	int i;
	ut64 tmp = addr;
	for (i = 0; i < PE_IMAGE_DIRECTORY_ENTRIES - 1; i++) {
		if (bin->nt_headers->optional_header.DataDirectory[i].Size > 0) {
			addr = tmp + i * 8;
			switch (i) {
			case PE_IMAGE_DIRECTORY_ENTRY_EXPORT:
				ROWL(tmpbuf, "IMAGE_DIRECTORY_ENTRY_EXPORT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL(tmpbuf, "SIZE_IMAGE_DIRECTORY_ENTRY_EXPORT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IMPORT:
				ROWL(tmpbuf, "IMAGE_DIRECTORY_ENTRY_IMPORT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL(tmpbuf, "SIZE_IMAGE_DIRECTORY_ENTRY_IMPORT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_RESOURCE:
				ROWL(tmpbuf, "IMAGE_DIRECTORY_ENTRY_RESOURCE", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL(tmpbuf, "SIZE_IMAGE_DIRECTORY_ENTRY_RESOURCE", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION:
				ROWL(tmpbuf, "IMAGE_DIRECTORY_ENTRY_EXCEPTION", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL(tmpbuf, "SIZE_IMAGE_DIRECTORY_ENTRY_EXCEPTION", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_SECURITY:
				ROWL(tmpbuf, "IMAGE_DIRECTORY_ENTRY_SECURITY", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL(tmpbuf, "SIZE_IMAGE_DIRECTORY_ENTRY_SECURITY", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BASERELOC:
				ROWL(tmpbuf, "IMAGE_DIRECTORY_ENTRY_BASERELOC", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL(tmpbuf, "SIZE_IMAGE_DIRECTORY_ENTRY_BASERELOC", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DEBUG:
				ROWL(tmpbuf, "IMAGE_DIRECTORY_ENTRY_DEBUG", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL(tmpbuf, "SIZE_IMAGE_DIRECTORY_ENTRY_DEBUG", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COPYRIGHT:
				ROWL(tmpbuf, "IMAGE_DIRECTORY_ENTRY_COPYRIGHT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL(tmpbuf, "SIZE_IMAGE_DIRECTORY_ENTRY_COPYRIGHT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
				ROWL(tmpbuf, "IMAGE_DIRECTORY_ENTRY_GLOBALPTR", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL(tmpbuf, "SIZE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_TLS:
				ROWL(tmpbuf, "IMAGE_DIRECTORY_ENTRY_TLS", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL(tmpbuf, "SIZE_IMAGE_DIRECTORY_ENTRY_TLS", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
				ROWL(tmpbuf, "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL(tmpbuf, "SIZE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
				ROWL(tmpbuf, "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL(tmpbuf, "SIZE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IAT:
				ROWL(tmpbuf, "IMAGE_DIRECTORY_ENTRY_IAT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL(tmpbuf, "SIZE_IMAGE_DIRECTORY_ENTRY_IAT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
				ROWL(tmpbuf, "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL(tmpbuf, "SIZE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
				ROWL(tmpbuf, "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", 4,
					bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL(tmpbuf, "SIZE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", 4,
					bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			}
		}
	}

	return ret;
}

static RzStructuredData *pe_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	struct PE_(rz_bin_pe_obj_t) *bin = bf->o->bin_obj;
	if (!bin) {
		return NULL;
	}

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *pe32 = rz_structured_data_map_add_map(info, "pe32");
	if (!pe32) {
		rz_structured_data_free(info);
		return NULL;
	}

	RzStructuredData *image = rz_structured_data_map_add_map(pe32, "IMAGE_NT_HEADERS");
	if (!image) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(image, "Signature", bin->nt_headers->Signature, true);

	if (!(image = rz_structured_data_map_add_map(pe32, "IMAGE_FILE_HEADERS"))) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(image, "Machine", bin->nt_headers->file_header.Machine, true);
	rz_structured_data_map_add_unsigned(image, "NumberOfSections", bin->nt_headers->file_header.NumberOfSections, false);
	rz_structured_data_map_add_unsigned(image, "TimeDateStamp", bin->nt_headers->file_header.TimeDateStamp, false);
	rz_structured_data_map_add_unsigned(image, "PointerToSymbolTable", bin->nt_headers->file_header.PointerToSymbolTable, true);
	rz_structured_data_map_add_unsigned(image, "NumberOfSymbols", bin->nt_headers->file_header.NumberOfSymbols, false);
	rz_structured_data_map_add_unsigned(image, "SizeOfOptionalHeader", bin->nt_headers->file_header.SizeOfOptionalHeader, false);
	rz_structured_data_map_add_unsigned(image, "Characteristics", bin->nt_headers->file_header.Characteristics, true);

	if (!(image = rz_structured_data_map_add_map(pe32, "IMAGE_OPTIONAL_HEADERS"))) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(image, "Magic", bin->nt_headers->optional_header.Magic, true);
	rz_structured_data_map_add_unsigned(image, "MajorLinkerVersion", bin->nt_headers->optional_header.MajorLinkerVersion, false);
	rz_structured_data_map_add_unsigned(image, "MinorLinkerVersion", bin->nt_headers->optional_header.MinorLinkerVersion, false);
	rz_structured_data_map_add_unsigned(image, "SizeOfCode", bin->nt_headers->optional_header.SizeOfCode, false);
	rz_structured_data_map_add_unsigned(image, "SizeOfInitializedData", bin->nt_headers->optional_header.SizeOfInitializedData, false);
	rz_structured_data_map_add_unsigned(image, "SizeOfUninitializedData", bin->nt_headers->optional_header.SizeOfUninitializedData, false);
	rz_structured_data_map_add_unsigned(image, "AddressOfEntryPoint", bin->nt_headers->optional_header.AddressOfEntryPoint, true);
	rz_structured_data_map_add_unsigned(image, "BaseOfCode", bin->nt_headers->optional_header.BaseOfCode, true);
	rz_structured_data_map_add_unsigned(image, "BaseOfData", bin->nt_headers->optional_header.BaseOfData, true);
	rz_structured_data_map_add_unsigned(image, "ImageBase", bin->nt_headers->optional_header.ImageBase, true);
	rz_structured_data_map_add_unsigned(image, "SectionAlignment", bin->nt_headers->optional_header.SectionAlignment, true);
	rz_structured_data_map_add_unsigned(image, "FileAlignment", bin->nt_headers->optional_header.FileAlignment, true);
	rz_structured_data_map_add_unsigned(image, "MajorOperatingSystemVersion", bin->nt_headers->optional_header.MajorOperatingSystemVersion, true);
	rz_structured_data_map_add_unsigned(image, "MinorOperatingSystemVersion", bin->nt_headers->optional_header.MinorOperatingSystemVersion, true);
	rz_structured_data_map_add_unsigned(image, "MajorImageVersion", bin->nt_headers->optional_header.MajorImageVersion, true);
	rz_structured_data_map_add_unsigned(image, "MinorImageVersion", bin->nt_headers->optional_header.MinorImageVersion, true);
	rz_structured_data_map_add_unsigned(image, "MajorSubsystemVersion", bin->nt_headers->optional_header.MajorSubsystemVersion, true);
	rz_structured_data_map_add_unsigned(image, "MinorSubsystemVersion", bin->nt_headers->optional_header.MinorSubsystemVersion, true);
	rz_structured_data_map_add_unsigned(image, "Win32VersionValue", bin->nt_headers->optional_header.Win32VersionValue, true);
	rz_structured_data_map_add_unsigned(image, "SizeOfImage", bin->nt_headers->optional_header.SizeOfImage, false);
	rz_structured_data_map_add_unsigned(image, "SizeOfHeaders", bin->nt_headers->optional_header.SizeOfHeaders, false);
	rz_structured_data_map_add_unsigned(image, "CheckSum", bin->nt_headers->optional_header.CheckSum, true);
	rz_structured_data_map_add_unsigned(image, "Subsystem", bin->nt_headers->optional_header.Subsystem, true);
	rz_structured_data_map_add_unsigned(image, "DllCharacteristics", bin->nt_headers->optional_header.DllCharacteristics, true);
	rz_structured_data_map_add_unsigned(image, "SizeOfStackReserve", bin->nt_headers->optional_header.SizeOfStackReserve, false);
	rz_structured_data_map_add_unsigned(image, "SizeOfStackCommit", bin->nt_headers->optional_header.SizeOfStackCommit, false);
	rz_structured_data_map_add_unsigned(image, "SizeOfHeapReserve", bin->nt_headers->optional_header.SizeOfHeapReserve, false);
	rz_structured_data_map_add_unsigned(image, "SizeOfHeapCommit", bin->nt_headers->optional_header.SizeOfHeapCommit, false);
	rz_structured_data_map_add_unsigned(image, "LoaderFlags", bin->nt_headers->optional_header.LoaderFlags, true);
	rz_structured_data_map_add_unsigned(image, "NumberOfRvaAndSizes", bin->nt_headers->optional_header.NumberOfRvaAndSizes, false);

	if (rz_list_length(bin->rich_entries) > 0) {
		if (!(image = rz_structured_data_map_add_array(pe32, "RICH_FIELDS"))) {
			rz_structured_data_free(info);
			return NULL;
		}

		RzListIter *it;
		Pe_image_rich_entry *entry;
		rz_list_foreach (bin->rich_entries, it, entry) {
			RzStructuredData *field = rz_structured_data_array_add_map(image);
			if (!field) {
				rz_structured_data_free(info);
				return NULL;
			}

			rz_structured_data_map_add_unsigned(field, "Product", entry->productId, false);
			rz_structured_data_map_add_string(field, "Name", entry->productName);
			rz_structured_data_map_add_unsigned(field, "Version", entry->minVersion, false);
			rz_structured_data_map_add_unsigned(field, "Times", entry->timesUsed, false);
		}
	}

	for (size_t i = 0; i < PE_IMAGE_DIRECTORY_ENTRIES - 1; i++) {
		if (bin->nt_headers->optional_header.DataDirectory[i].Size < 1) {
			continue;
		}

		const char *name = "unknown";
		switch (i) {
		case PE_IMAGE_DIRECTORY_ENTRY_EXPORT:
			name = "IMAGE_DIRECTORY_ENTRY_EXPORT";
			break;
		case PE_IMAGE_DIRECTORY_ENTRY_IMPORT:
			name = "IMAGE_DIRECTORY_ENTRY_IMPORT";
			break;
		case PE_IMAGE_DIRECTORY_ENTRY_RESOURCE:
			name = "IMAGE_DIRECTORY_ENTRY_RESOURCE";
			break;
		case PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION:
			name = "IMAGE_DIRECTORY_ENTRY_EXCEPTION";
			break;
		case PE_IMAGE_DIRECTORY_ENTRY_SECURITY:
			name = "IMAGE_DIRECTORY_ENTRY_SECURITY";
			break;
		case PE_IMAGE_DIRECTORY_ENTRY_BASERELOC:
			name = "IMAGE_DIRECTORY_ENTRY_BASERELOC";
			break;
		case PE_IMAGE_DIRECTORY_ENTRY_DEBUG:
			name = "IMAGE_DIRECTORY_ENTRY_DEBUG";
			break;
		case PE_IMAGE_DIRECTORY_ENTRY_COPYRIGHT:
			name = "IMAGE_DIRECTORY_ENTRY_COPYRIGHT";
			name = "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE";
			break;
		case PE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
			name = "IMAGE_DIRECTORY_ENTRY_GLOBALPTR";
			break;
		case PE_IMAGE_DIRECTORY_ENTRY_TLS:
			name = "IMAGE_DIRECTORY_ENTRY_TLS";
			break;
		case PE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
			name = "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG";
			break;
		case PE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
			name = "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT";
			break;
		case PE_IMAGE_DIRECTORY_ENTRY_IAT:
			name = "IMAGE_DIRECTORY_ENTRY_IAT";
			break;
		case PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
			name = "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT";
			break;
		case PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
			name = "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR";
			break;
		}
		if (!(image = rz_structured_data_map_add_map(pe32, name))) {
			rz_structured_data_free(info);
			return NULL;
		}
		rz_structured_data_map_add_unsigned(image, "VirtualAddress", bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, true);
		rz_structured_data_map_add_unsigned(image, "Size", bin->nt_headers->optional_header.DataDirectory[i].Size, false);
	}

	if (bin->cms) {
		RzStructuredData *pe_cms = rz_pkcs7_cms_to_structure(bin->cms);
		rz_structured_data_map_add(pe32, "CryptographicMessageSyntax", pe_cms);
	}

	if (bin->spcinfo) {
		RzStructuredData *pe_auth = rz_pkcs7_spcinfo_to_structure(bin->spcinfo);
		rz_structured_data_map_add(pe32, "Authenticode", pe_auth);
	}

	return info;
}

RzBinPlugin rz_bin_plugin_pe = {
	.name = "pe",
	.desc = "PE (Portable Executable)",
	.license = "LGPL3",
	.author = "nibble",
	.get_sdb = &pe_get_sdb,
	.load_buffer = &pe_load_buffer,
	.destroy = &pe_destroy,
	.check_buffer = &pe_check_buffer,
	.baddr = &pe_baddr,
	.binsym = &pe_binsym,
	.entries = &pe_entries,
	.maps = &pe_maps,
	.sections = &pe_sections,
	.signature = &pe_signature,
	.symbols = &pe_symbols,
	.imports = &pe_imports,
	.info = &pe_info,
	.bin_structure = &pe_structure,
	.fields = &pe_fields,
	.libs = &pe_libs,
	.relocs = &pe_relocs,
	.create = &pe_create,
	.get_offset = &pe_get_offset,
	.get_vaddr = &pe_get_vaddr,
	.hashes = &pe_compute_hashes,
	.resources = &pe_resources,
	.section_flag_to_rzlist = &PE_(section_flag_to_rzlist),
	.strings = &pe_strings,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_pe,
	.version = RZ_VERSION
};
#endif
