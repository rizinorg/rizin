// SPDX-FileCopyrightText: 2008-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2019 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pe.h"
#include <rz_util/ht_uu.h>

static void _free_resource(rz_pe_resource *rs) {
	if (rs) {
		free(rs->name);
		free(rs->timestr);
		free(rs->data);
		free(rs->type);
		free(rs->language);
		free(rs);
	}
}

static bool read_image_resource_directory_aux(RzBuffer *b, Pe_image_resource_directory *dir) {
	return rz_buf_read_le32(b, &dir->Characteristics) &&
		rz_buf_read_le32(b, &dir->TimeDateStamp) &&
		rz_buf_read_le16(b, &dir->MajorVersion) &&
		rz_buf_read_le16(b, &dir->MinorVersion) &&
		rz_buf_read_le16(b, &dir->NumberOfNamedEntries) &&
		rz_buf_read_le16(b, &dir->NumberOfIdEntries);
}

static int read_image_resource_directory(RzBuffer *b, ut64 addr, Pe_image_resource_directory *dir) {
	st64 tmp = rz_buf_tell(b);
	if (tmp < 0) {
		return -1;
	}

	if (rz_buf_seek(b, addr, RZ_BUF_SET) < 0) {
		return -1;
	}

	if (!read_image_resource_directory_aux(b, dir)) {
		return -1;
	}

	if (rz_buf_seek(b, tmp, RZ_BUF_SET) < 0) {
		return -1;
	}

	return sizeof(Pe_image_resource_directory);
}

int PE_(bin_pe_init_resource)(RzBinPEObj *bin) {
	PE_(image_data_directory) *resource_dir = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_RESOURCE];
	PE_DWord resource_dir_paddr = PE_(bin_pe_rva_to_paddr)(bin, resource_dir->VirtualAddress);
	if (!resource_dir_paddr) {
		return false;
	}

	bin->resources = rz_list_newf((RzListFree)_free_resource);
	if (!bin->resources) {
		return false;
	}
	if (!(bin->resource_directory = malloc(sizeof(*bin->resource_directory)))) {
		rz_sys_perror("malloc (resource directory)");
		return false;
	}
	if (read_image_resource_directory(bin->b, resource_dir_paddr, bin->resource_directory) < 0) {
		RZ_LOG_INFO("read (resource directory)\n");
		RZ_FREE(bin->resource_directory);
		return false;
	}
	bin->resource_directory_offset = resource_dir_paddr;
	return true;
}

static void free_Var(Var *var) {
	if (var) {
		free(var->szKey);
		free(var->Value);
		free(var);
	}
}

static void free_VarFileInfo(VarFileInfo *varFileInfo) {
	if (varFileInfo) {
		free(varFileInfo->szKey);
		if (varFileInfo->Children) {
			ut32 children = 0;
			for (; children < varFileInfo->numOfChildren; children++) {
				free_Var(varFileInfo->Children[children]);
			}
			free(varFileInfo->Children);
		}
		free(varFileInfo);
	}
}

static void free_String(String *string) {
	if (string) {
		free(string->szKey);
		free(string->Value);
		free(string);
	}
}

static void free_StringTable(StringTable *stringTable) {
	if (stringTable) {
		free(stringTable->szKey);
		if (stringTable->Children) {
			ut32 childrenST = 0;
			for (; childrenST < stringTable->numOfChildren; childrenST++) {
				free_String(stringTable->Children[childrenST]);
			}
			free(stringTable->Children);
		}
		free(stringTable);
	}
}

static void free_StringFileInfo(StringFileInfo *stringFileInfo) {
	if (stringFileInfo) {
		free(stringFileInfo->szKey);
		if (stringFileInfo->Children) {
			ut32 childrenSFI = 0;
			for (; childrenSFI < stringFileInfo->numOfChildren; childrenSFI++) {
				free_StringTable(stringFileInfo->Children[childrenSFI]);
			}
			free(stringFileInfo->Children);
		}
		free(stringFileInfo);
	}
}

#define align32(x) x = (((x)&0x3) == 0) ? (x) : ((x) & ~0x3) + 0x4;

static void free_VS_VERSIONINFO(PE_VS_VERSIONINFO *vs_VersionInfo) {
	if (vs_VersionInfo) {
		free(vs_VersionInfo->szKey);
		free(vs_VersionInfo->Value);
		free_VarFileInfo(vs_VersionInfo->varFileInfo);
		free_StringFileInfo(vs_VersionInfo->stringFileInfo);
		free(vs_VersionInfo);
	}
}

void PE_(free_VS_VERSIONINFO)(PE_VS_VERSIONINFO *vs_VersionInfo) {
	free_VS_VERSIONINFO(vs_VersionInfo);
}

static Var *Pe_r_bin_pe_parse_var(RzBinPEObj *bin, PE_DWord *curAddr) {
	Var *var = RZ_NEW0(Var);
	if (!var) {
		RZ_LOG_INFO("calloc (Var)\n");
		return NULL;
	}
	if (!rz_buf_read_le16_at(bin->b, *curAddr, &var->wLength)) {
		RZ_LOG_INFO("read (Var wLength)\n");
		free_Var(var);
		return NULL;
	}
	*curAddr += sizeof(var->wLength);
	if (!rz_buf_read_le16_at(bin->b, *curAddr, &var->wValueLength)) {
		RZ_LOG_INFO("read (Var wValueLength)\n");
		free_Var(var);
		return NULL;
	}
	*curAddr += sizeof(var->wValueLength);
	if (!rz_buf_read_le16_at(bin->b, *curAddr, &var->wType)) {
		RZ_LOG_INFO("read (Var wType)\n");
		free_Var(var);
		return NULL;
	}
	*curAddr += sizeof(var->wType);
	if (var->wType != 0 && var->wType != 1) {
		RZ_LOG_INFO("check (Var wType)\n");
		free_Var(var);
		return NULL;
	}

	var->szKey = (ut16 *)malloc(UT16_ALIGN(TRANSLATION_UTF_16_LEN)); // L"Translation"
	if (!var->szKey) {
		RZ_LOG_INFO("malloc (Var szKey)\n");
		free_Var(var);
		return NULL;
	}
	if (rz_buf_read_at(bin->b, *curAddr, (ut8 *)var->szKey, TRANSLATION_UTF_16_LEN) < 1) {
		RZ_LOG_INFO("read (Var szKey)\n");
		free_Var(var);
		return NULL;
	}
	*curAddr += TRANSLATION_UTF_16_LEN;
	if (memcmp(var->szKey, TRANSLATION_UTF_16, TRANSLATION_UTF_16_LEN)) {
		RZ_LOG_INFO("check (Var szKey)\n");
		free_Var(var);
		return NULL;
	}
	align32(*curAddr);
	var->numOfValues = var->wValueLength / 4;
	if (!var->numOfValues) {
		RZ_LOG_INFO("check (Var numOfValues)\n");
		free_Var(var);
		return NULL;
	}
	var->Value = (ut32 *)malloc(var->wValueLength);
	if (!var->Value) {
		RZ_LOG_INFO("malloc (Var Value)\n");
		free_Var(var);
		return NULL;
	}
	if (rz_buf_read_at(bin->b, *curAddr, (ut8 *)var->Value, var->wValueLength) != var->wValueLength) {
		RZ_LOG_INFO("read (Var Value)\n");
		free_Var(var);
		return NULL;
	}
	*curAddr += var->wValueLength;
	return var;
}

static VarFileInfo *Pe_r_bin_pe_parse_var_file_info(RzBinPEObj *bin, PE_DWord *curAddr) {
	VarFileInfo *varFileInfo = RZ_NEW0(VarFileInfo);
	if (!varFileInfo) {
		RZ_LOG_INFO("calloc (VarFileInfo)\n");
		return NULL;
	}
	PE_DWord startAddr = *curAddr;
	if (!rz_buf_read_le16_at(bin->b, *curAddr, &varFileInfo->wLength)) {
		RZ_LOG_INFO("read (VarFileInfo wLength)\n");
		free_VarFileInfo(varFileInfo);
		return NULL;
	}
	*curAddr += sizeof(varFileInfo->wLength);

	if (!rz_buf_read_le16_at(bin->b, *curAddr, &varFileInfo->wValueLength)) {
		RZ_LOG_INFO("read (VarFileInfo wValueLength)\n");
		free_VarFileInfo(varFileInfo);
		return NULL;
	}
	*curAddr += sizeof(varFileInfo->wValueLength);

	if (varFileInfo->wValueLength != 0) {
		RZ_LOG_INFO("check (VarFileInfo wValueLength)\n");
		free_VarFileInfo(varFileInfo);
		return NULL;
	}

	if (!rz_buf_read_le16_at(bin->b, *curAddr, &varFileInfo->wType)) {
		RZ_LOG_INFO("read (VarFileInfo wType)\n");
		free_VarFileInfo(varFileInfo);
		return NULL;
	}
	*curAddr += sizeof(varFileInfo->wType);
	if (varFileInfo->wType && varFileInfo->wType != 1) {
		RZ_LOG_INFO("check (VarFileInfo wType)\n");
		free_VarFileInfo(varFileInfo);
		return NULL;
	}

	varFileInfo->szKey = (ut16 *)malloc(UT16_ALIGN(VARFILEINFO_UTF_16_LEN)); // L"VarFileInfo"
	if (!varFileInfo->szKey) {
		RZ_LOG_INFO("malloc (VarFileInfo szKey)\n");
		free_VarFileInfo(varFileInfo);
		return NULL;
	}

	if (rz_buf_read_at(bin->b, *curAddr, (ut8 *)varFileInfo->szKey, VARFILEINFO_UTF_16_LEN) != VARFILEINFO_UTF_16_LEN) {
		RZ_LOG_INFO("read (VarFileInfo szKey)\n");
		free_VarFileInfo(varFileInfo);
		return NULL;
	}
	*curAddr += VARFILEINFO_UTF_16_LEN;

	if (memcmp(varFileInfo->szKey, VARFILEINFO_UTF_16, VARFILEINFO_UTF_16_LEN)) {
		RZ_LOG_INFO("check (VarFileInfo szKey)\n");
		free_VarFileInfo(varFileInfo);
		return NULL;
	}
	align32(*curAddr);
	while (startAddr + varFileInfo->wLength > *curAddr) {
		Var **tmp = (Var **)realloc(varFileInfo->Children, (varFileInfo->numOfChildren + 1) * sizeof(*varFileInfo->Children));
		if (!tmp) {
			RZ_LOG_INFO("realloc (VarFileInfo Children)\n");
			free_VarFileInfo(varFileInfo);
			return NULL;
		}
		varFileInfo->Children = tmp;
		if (!(varFileInfo->Children[varFileInfo->numOfChildren] = Pe_r_bin_pe_parse_var(bin, curAddr))) {
			RZ_LOG_INFO("bad parsing Var\n");
			free_VarFileInfo(varFileInfo);
			return NULL;
		}
		varFileInfo->numOfChildren++;
		align32(*curAddr);
	}
	return varFileInfo;
}

static String *Pe_r_bin_pe_parse_string(RzBinPEObj *bin, PE_DWord *curAddr) {
	String *string = RZ_NEW0(String);
	PE_DWord begAddr = *curAddr;
	int len_value = 0;
	int i = 0;
	if (!string) {
		RZ_LOG_INFO("calloc (String)\n");
		return NULL;
	}
	if (begAddr > bin->size || begAddr + sizeof(string->wLength) > bin->size) {
		free_String(string);
		return NULL;
	}
	if (!rz_buf_read_le16_at(bin->b, *curAddr, &string->wLength)) {
		RZ_LOG_INFO("read (String wLength)\n");
		goto out_error;
	}
	*curAddr += sizeof(string->wLength);
	if (*curAddr > bin->size || *curAddr + sizeof(string->wValueLength) > bin->size) {
		goto out_error;
	}
	if (!rz_buf_read_le16_at(bin->b, *curAddr, &string->wValueLength)) {
		RZ_LOG_INFO("read (String wValueLength)\n");
		goto out_error;
	}
	*curAddr += sizeof(string->wValueLength);

	if (*curAddr > bin->size || *curAddr + sizeof(string->wType) > bin->size) {
		goto out_error;
	}
	if (!rz_buf_read_le16_at(bin->b, *curAddr, &string->wType)) {
		RZ_LOG_INFO("read (String wType)\n");
		goto out_error;
	}
	*curAddr += sizeof(string->wType);
	if (string->wType != 0 && string->wType != 1) {
		RZ_LOG_INFO("check (String wType)\n");
		goto out_error;
	}

	for (i = 0; *curAddr < begAddr + string->wLength; i++, *curAddr += sizeof(ut16)) {
		ut16 utf16_char;
		ut16 *tmpKey;
		if (*curAddr > bin->size || *curAddr + sizeof(ut16) > bin->size) {
			goto out_error;
		}
		if (rz_buf_read_at(bin->b, *curAddr, (ut8 *)&utf16_char, sizeof(ut16)) != sizeof(ut16)) {
			RZ_LOG_INFO("check (String szKey)\n");
			goto out_error;
		}
		tmpKey = (ut16 *)realloc(string->szKey, (i + 1) * sizeof(ut16));
		if (!tmpKey) {
			RZ_LOG_INFO("realloc (String szKey)\n");
			goto out_error;
		}
		string->szKey = tmpKey;
		string->szKey[i] = utf16_char;
		string->wKeyLen += sizeof(ut16);
		if (!utf16_char) {
			*curAddr += sizeof(ut16);
			break;
		}
	}
	align32(*curAddr);
	len_value = RZ_MIN(string->wValueLength * 2, string->wLength - (*curAddr - begAddr));
	string->wValueLength = len_value;
	if (len_value < 0) {
		len_value = 0;
	}
	string->Value = (ut16 *)calloc(len_value + 1, 1);
	if (!string->Value) {
		RZ_LOG_INFO("malloc (String Value)\n");
		goto out_error;
	}
	if (*curAddr > bin->size || *curAddr + len_value > bin->size) {
		goto out_error;
	}
	if (rz_buf_read_at(bin->b, *curAddr, (ut8 *)string->Value, len_value) != len_value) {
		RZ_LOG_INFO("read (String Value)\n");
		goto out_error;
	}
	*curAddr += len_value;
	return string;
out_error:
	free_String(string);
	return NULL;
}

static StringTable *Pe_r_bin_pe_parse_string_table(RzBinPEObj *bin, PE_DWord *curAddr) {
	StringTable *stringTable = RZ_NEW0(StringTable);
	if (!stringTable) {
		RZ_LOG_INFO("calloc (stringTable)\n");
		return NULL;
	}

	PE_DWord startAddr = *curAddr;
	if (!rz_buf_read_le16_at(bin->b, *curAddr, &stringTable->wLength)) {
		RZ_LOG_INFO("read (StringTable wLength)\n");
		free_StringTable(stringTable);
		return NULL;
	}
	*curAddr += sizeof(stringTable->wLength);

	if (!rz_buf_read_le16_at(bin->b, *curAddr, &stringTable->wValueLength)) {
		RZ_LOG_INFO("read (StringTable wValueLength)\n");
		free_StringTable(stringTable);
		return NULL;
	}
	*curAddr += sizeof(stringTable->wValueLength);

	if (stringTable->wValueLength) {
		RZ_LOG_INFO("check (StringTable wValueLength)\n");
		free_StringTable(stringTable);
		return NULL;
	}

	if (!rz_buf_read_le16_at(bin->b, *curAddr, &stringTable->wType)) {
		RZ_LOG_INFO("read (StringTable wType)\n");
		free_StringTable(stringTable);
		return NULL;
	}
	*curAddr += sizeof(stringTable->wType);
	if (stringTable->wType && stringTable->wType != 1) {
		RZ_LOG_INFO("check (StringTable wType)\n");
		free_StringTable(stringTable);
		return NULL;
	}
	stringTable->szKey = (ut16 *)malloc(UT16_ALIGN(EIGHT_HEX_DIG_UTF_16_LEN)); // EIGHT_HEX_DIG_UTF_16_LEN
	if (!stringTable->szKey) {
		RZ_LOG_INFO("malloc (stringTable szKey)\n");
		free_StringTable(stringTable);
		return NULL;
	}

	if (rz_buf_read_at(bin->b, *curAddr, (ut8 *)stringTable->szKey, EIGHT_HEX_DIG_UTF_16_LEN) != EIGHT_HEX_DIG_UTF_16_LEN) {
		RZ_LOG_INFO("read (StringTable szKey)\n");
		free_StringTable(stringTable);
		return NULL;
	}
	*curAddr += EIGHT_HEX_DIG_UTF_16_LEN;
	align32(*curAddr);
	while (startAddr + stringTable->wLength > *curAddr) {
		String **tmp = (String **)realloc(stringTable->Children, (stringTable->numOfChildren + 1) * sizeof(*stringTable->Children));
		if (!tmp) {
			RZ_LOG_INFO("realloc (StringTable Children)\n");
			free_StringTable(stringTable);
			return NULL;
		}
		stringTable->Children = tmp;
		if (!(stringTable->Children[stringTable->numOfChildren] = Pe_r_bin_pe_parse_string(bin, curAddr))) {
			RZ_LOG_INFO("bad parsing String\n");
			free_StringTable(stringTable);
			return NULL;
		}
		stringTable->numOfChildren++;
		align32(*curAddr);
	}

	if (!stringTable->numOfChildren) {
		RZ_LOG_INFO("check (StringTable numOfChildren)\n");
		free_StringTable(stringTable);
		return NULL;
	}

	return stringTable;
}

static StringFileInfo *Pe_r_bin_pe_parse_string_file_info(RzBinPEObj *bin, PE_DWord *curAddr) {
	StringFileInfo *stringFileInfo = RZ_NEW0(StringFileInfo);
	if (!stringFileInfo) {
		RZ_LOG_INFO("calloc (StringFileInfo)\n");
		return NULL;
	}

	PE_DWord startAddr = *curAddr;

	if (!rz_buf_read_le16_at(bin->b, *curAddr, &stringFileInfo->wLength)) {
		RZ_LOG_INFO("read (StringFileInfo wLength)\n");
		free_StringFileInfo(stringFileInfo);
		return NULL;
	}
	*curAddr += sizeof(stringFileInfo->wLength);

	if (!rz_buf_read_le16_at(bin->b, *curAddr, &stringFileInfo->wValueLength)) {
		RZ_LOG_INFO("read (StringFileInfo wValueLength)\n");
		free_StringFileInfo(stringFileInfo);
		return NULL;
	}
	*curAddr += sizeof(stringFileInfo->wValueLength);

	if (stringFileInfo->wValueLength) {
		RZ_LOG_INFO("check (StringFileInfo wValueLength)\n");
		free_StringFileInfo(stringFileInfo);
		return NULL;
	}

	if (!rz_buf_read_le16_at(bin->b, *curAddr, &stringFileInfo->wType)) {
		RZ_LOG_INFO("read (StringFileInfo wType)\n");
		free_StringFileInfo(stringFileInfo);
		return NULL;
	}
	*curAddr += sizeof(stringFileInfo->wType);

	if (stringFileInfo->wType && stringFileInfo->wType != 1) {
		RZ_LOG_INFO("check (StringFileInfo wType)\n");
		free_StringFileInfo(stringFileInfo);
		return NULL;
	}

	stringFileInfo->szKey = (ut16 *)malloc(UT16_ALIGN(STRINGFILEINFO_UTF_16_LEN)); // L"StringFileInfo"
	if (!stringFileInfo->szKey) {
		RZ_LOG_INFO("malloc (StringFileInfo szKey)\n");
		free_StringFileInfo(stringFileInfo);
		return NULL;
	}

	if (rz_buf_read_at(bin->b, *curAddr, (ut8 *)stringFileInfo->szKey, STRINGFILEINFO_UTF_16_LEN) != STRINGFILEINFO_UTF_16_LEN) {
		RZ_LOG_INFO("read (StringFileInfo szKey)\n");
		free_StringFileInfo(stringFileInfo);
		return NULL;
	}
	*curAddr += STRINGFILEINFO_UTF_16_LEN;

	if (memcmp(stringFileInfo->szKey, STRINGFILEINFO_UTF_16, STRINGFILEINFO_UTF_16_LEN) != 0) {
		RZ_LOG_INFO("check (StringFileInfo szKey)\n");
		free_StringFileInfo(stringFileInfo);
		return NULL;
	}

	align32(*curAddr);

	while (startAddr + stringFileInfo->wLength > *curAddr) {
		StringTable **tmp = (StringTable **)realloc(stringFileInfo->Children, (stringFileInfo->numOfChildren + 1) * sizeof(*stringFileInfo->Children));
		if (!tmp) {
			RZ_LOG_INFO("realloc (StringFileInfo Children)\n");
			free_StringFileInfo(stringFileInfo);
			return NULL;
		}
		stringFileInfo->Children = tmp;
		if (!(stringFileInfo->Children[stringFileInfo->numOfChildren] = Pe_r_bin_pe_parse_string_table(bin, curAddr))) {
			RZ_LOG_INFO("bad parsing StringTable\n");
			free_StringFileInfo(stringFileInfo);
			return NULL;
		}
		stringFileInfo->numOfChildren++;
		align32(*curAddr);
	}

	if (!stringFileInfo->numOfChildren) {
		RZ_LOG_INFO("check (StringFileInfo numOfChildren)\n");
		free_StringFileInfo(stringFileInfo);
		return NULL;
	}

	return stringFileInfo;
}

#define EXIT_ON_OVERFLOW(S) \
	if (curAddr > bin->size || curAddr + (S) > bin->size) { \
		goto out_error; \
	}
static PE_VS_VERSIONINFO *Pe_r_bin_pe_parse_version_info(RzBinPEObj *bin, PE_DWord version_info_paddr) {
	ut32 sz;
	PE_VS_VERSIONINFO *vs_VersionInfo = RZ_NEW0(PE_VS_VERSIONINFO);
	if (!vs_VersionInfo) {
		return NULL;
	}
	PE_DWord startAddr = version_info_paddr;
	PE_DWord curAddr = version_info_paddr;
	// align32(curAddr); // XXX: do we really need this? Because in msdn
	// wLength is The length, in bytes, of the VS_VERSIONINFO structure.
	// This length does not include any padding that aligns any subsequent
	// version resource data on a 32-bit boundary.
	// Mb we are in subsequent version resource data and not aligned.
	sz = sizeof(ut16);
	EXIT_ON_OVERFLOW(sz);
	if (!rz_buf_read_le16_at(bin->b, curAddr, &vs_VersionInfo->wLength)) {
		RZ_LOG_INFO("read (VS_VERSIONINFO wLength)\n");
		goto out_error;
	}
	curAddr += sz;
	EXIT_ON_OVERFLOW(sz);
	if (!rz_buf_read_le16_at(bin->b, curAddr, &vs_VersionInfo->wValueLength)) {
		RZ_LOG_INFO("read (VS_VERSIONINFO wValueLength)\n");
		goto out_error;
	}
	curAddr += sz;
	EXIT_ON_OVERFLOW(sz);
	if (!rz_buf_read_le16_at(bin->b, curAddr, &vs_VersionInfo->wType)) {
		RZ_LOG_INFO("read (VS_VERSIONINFO wType)\n");
		goto out_error;
	}
	curAddr += sz;
	if (vs_VersionInfo->wType && vs_VersionInfo->wType != 1) {
		RZ_LOG_INFO("check (VS_VERSIONINFO wType)\n");
		goto out_error;
	}

	vs_VersionInfo->szKey = (ut16 *)malloc(UT16_ALIGN(VS_VERSION_INFO_UTF_16_LEN)); // L"VS_VERSION_INFO"
	if (!vs_VersionInfo->szKey) {
		RZ_LOG_INFO("malloc (VS_VERSIONINFO szKey)\n");
		goto out_error;
	}
	sz = VS_VERSION_INFO_UTF_16_LEN;
	EXIT_ON_OVERFLOW(sz);
	if (rz_buf_read_at(bin->b, curAddr, (ut8 *)vs_VersionInfo->szKey, sz) != sz) {
		RZ_LOG_INFO("read (VS_VERSIONINFO szKey)\n");
		goto out_error;
	}
	curAddr += sz;
	if (memcmp(vs_VersionInfo->szKey, VS_VERSION_INFO_UTF_16, sz)) {
		goto out_error;
	}
	align32(curAddr);
	if (vs_VersionInfo->wValueLength) {
		if (vs_VersionInfo->wValueLength != sizeof(*vs_VersionInfo->Value)) {
			RZ_LOG_INFO("check (VS_VERSIONINFO wValueLength != sizeof PE_VS_FIXEDFILEINFO)\n");
			goto out_error;
		}

		PE_VS_FIXEDFILEINFO *ffi = vs_VersionInfo->Value = (PE_VS_FIXEDFILEINFO *)malloc(sizeof(*vs_VersionInfo->Value));
		if (!ffi) {
			RZ_LOG_INFO("malloc (VS_VERSIONINFO Value)\n");
			goto out_error;
		}
		sz = sizeof(PE_VS_FIXEDFILEINFO);
		EXIT_ON_OVERFLOW(sz);
		if (!rz_buf_read_le32_at(bin->b, curAddr, &ffi->dwSignature) ||
			!rz_buf_read_le32_at(bin->b, curAddr + sizeof(ut32), &ffi->dwStrucVersion) ||
			!rz_buf_read_le32_at(bin->b, curAddr + sizeof(ut32) * 2, &ffi->dwFileVersionMS) ||
			!rz_buf_read_le32_at(bin->b, curAddr + sizeof(ut32) * 3, &ffi->dwFileVersionLS) ||
			!rz_buf_read_le32_at(bin->b, curAddr + sizeof(ut32) * 4, &ffi->dwProductVersionMS) ||
			!rz_buf_read_le32_at(bin->b, curAddr + sizeof(ut32) * 5, &ffi->dwProductVersionLS) ||
			!rz_buf_read_le32_at(bin->b, curAddr + sizeof(ut32) * 6, &ffi->dwFileFlagsMask) ||
			!rz_buf_read_le32_at(bin->b, curAddr + sizeof(ut32) * 7, &ffi->dwFileFlags) ||
			!rz_buf_read_le32_at(bin->b, curAddr + sizeof(ut32) * 8, &ffi->dwFileOS) ||
			!rz_buf_read_le32_at(bin->b, curAddr + sizeof(ut32) * 9, &ffi->dwFileType) ||
			!rz_buf_read_le32_at(bin->b, curAddr + sizeof(ut32) * 10, &ffi->dwFileSubtype) ||
			!rz_buf_read_le32_at(bin->b, curAddr + sizeof(ut32) * 11, &ffi->dwFileDateMS) ||
			!rz_buf_read_le32_at(bin->b, curAddr + sizeof(ut32) * 12, &ffi->dwFileDateLS)) {
			RZ_LOG_INFO("read (VS_VERSIONINFO Value)\n");
			goto out_error;
		}
		if (ffi->dwSignature != 0xFEEF04BD) {
			RZ_LOG_INFO("check (PE_VS_FIXEDFILEINFO signature) 0x%08x\n", ffi->dwSignature);
			goto out_error;
		}
		curAddr += sz;
		align32(curAddr);
	}

	if (startAddr + vs_VersionInfo->wLength > curAddr) {
		char t = '\0';
		if (curAddr + 3 * sizeof(ut16) > bin->size || curAddr + 3 + sizeof(ut64) + 1 > bin->size) {
			goto out_error;
		}
		if (rz_buf_read_at(bin->b, curAddr + 3 * sizeof(ut16), (ut8 *)&t, 1) != 1) {
			RZ_LOG_INFO("read (VS_VERSIONINFO Children V or S)\n");
			goto out_error;
		}
		if (!(t == 'S' || t == 'V')) {
			RZ_LOG_INFO("bad type (VS_VERSIONINFO Children)\n");
			goto out_error;
		}
		if (t == 'S') {
			if (!(vs_VersionInfo->stringFileInfo = Pe_r_bin_pe_parse_string_file_info(bin, &curAddr))) {
				RZ_LOG_INFO("bad parsing (VS_VERSIONINFO StringFileInfo)\n");
				goto out_error;
			}
		}
		if (t == 'V') {
			if (!(vs_VersionInfo->varFileInfo = Pe_r_bin_pe_parse_var_file_info(bin, &curAddr))) {
				RZ_LOG_INFO("bad parsing (VS_VERSIONINFO VarFileInfo)\n");
				goto out_error;
			}
		}

		align32(curAddr);

		if (startAddr + vs_VersionInfo->wLength > curAddr) {
			if (t == 'V') {
				if (!(vs_VersionInfo->stringFileInfo = Pe_r_bin_pe_parse_string_file_info(bin, &curAddr))) {
					RZ_LOG_INFO("bad parsing (VS_VERSIONINFO StringFileInfo)\n");
					goto out_error;
				}
			} else if (t == 'S') {
				if (!(vs_VersionInfo->varFileInfo = Pe_r_bin_pe_parse_var_file_info(bin, &curAddr))) {
					RZ_LOG_INFO("bad parsing (VS_VERSIONINFO VarFileInfo)\n");
					goto out_error;
				}
			}
			if (startAddr + vs_VersionInfo->wLength > curAddr) {
				RZ_LOG_INFO("bad parsing (VS_VERSIONINFO wLength left)\n");
				goto out_error;
			}
		}
	}
	return vs_VersionInfo;
out_error:
	free_VS_VERSIONINFO(vs_VersionInfo);
	return NULL;
}

static Sdb *Pe_r_bin_store_var(Var *var) {
	unsigned int i = 0;
	char key[20];
	Sdb *sdb = NULL;
	if (var) {
		sdb = sdb_new0();
		if (sdb) {
			for (; i < var->numOfValues; i++) {
				snprintf(key, 20, "%d", i);
				sdb_num_set(sdb, key, var->Value[i]);
			}
		}
	}
	return sdb;
}

static Sdb *Pe_r_bin_store_var_file_info(VarFileInfo *varFileInfo) {
	char key[20];
	unsigned int i = 0;
	if (!varFileInfo) {
		return NULL;
	}
	Sdb *sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}
	for (; i < varFileInfo->numOfChildren; i++) {
		snprintf(key, 20, "var%d", i);
		sdb_ns_set(sdb, key, Pe_r_bin_store_var(varFileInfo->Children[i]));
	}
	return sdb;
}

static Sdb *Pe_r_bin_store_string(String *string) {
	Sdb *sdb = NULL;
	char *encodedVal = NULL, *encodedKey = NULL;
	if (!string) {
		return NULL;
	}
	sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}
	encodedKey = sdb_encode((unsigned char *)string->szKey, string->wKeyLen);
	if (!encodedKey) {
		sdb_free(sdb);
		return NULL;
	}
	encodedVal = sdb_encode((unsigned char *)string->Value, string->wValueLength);
	if (!encodedVal) {
		free(encodedKey);
		sdb_free(sdb);
		return NULL;
	}
	sdb_set(sdb, "key", encodedKey);
	sdb_set(sdb, "value", encodedVal);
	free(encodedKey);
	free(encodedVal);
	return sdb;
}

static Sdb *Pe_r_bin_store_string_table(StringTable *stringTable) {
	char key[20];
	char *encodedKey = NULL;
	int i = 0;
	Sdb *sdb = NULL;
	if (!stringTable) {
		return NULL;
	}
	sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}
	encodedKey = sdb_encode((unsigned char *)stringTable->szKey, EIGHT_HEX_DIG_UTF_16_LEN);
	if (!encodedKey) {
		sdb_free(sdb);
		return NULL;
	}
	sdb_set(sdb, "key", encodedKey);
	free(encodedKey);
	for (; i < stringTable->numOfChildren; i++) {
		snprintf(key, 20, "string%d", i);
		sdb_ns_set(sdb, key, Pe_r_bin_store_string(stringTable->Children[i]));
	}
	return sdb;
}

static Sdb *Pe_r_bin_store_string_file_info(StringFileInfo *stringFileInfo) {
	char key[30];
	int i = 0;
	Sdb *sdb = NULL;
	if (!stringFileInfo) {
		return NULL;
	}
	sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}
	for (; i < stringFileInfo->numOfChildren; i++) {
		snprintf(key, 30, "stringtable%d", i);
		sdb_ns_set(sdb, key, Pe_r_bin_store_string_table(stringFileInfo->Children[i]));
	}
	return sdb;
}

static Sdb *Pe_r_bin_store_fixed_file_info(PE_VS_FIXEDFILEINFO *vs_fixedFileInfo) {
	Sdb *sdb = NULL;
	if (!vs_fixedFileInfo) {
		return NULL;
	}
	sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}
	sdb_num_set(sdb, "Signature", vs_fixedFileInfo->dwSignature);
	sdb_num_set(sdb, "StrucVersion", vs_fixedFileInfo->dwStrucVersion);
	sdb_num_set(sdb, "FileVersionMS", vs_fixedFileInfo->dwFileVersionMS);
	sdb_num_set(sdb, "FileVersionLS", vs_fixedFileInfo->dwFileVersionLS);
	sdb_num_set(sdb, "ProductVersionMS", vs_fixedFileInfo->dwProductVersionMS);
	sdb_num_set(sdb, "ProductVersionLS", vs_fixedFileInfo->dwProductVersionLS);
	sdb_num_set(sdb, "FileFlagsMask", vs_fixedFileInfo->dwFileFlagsMask);
	sdb_num_set(sdb, "FileFlags", vs_fixedFileInfo->dwFileFlags);
	sdb_num_set(sdb, "FileOS", vs_fixedFileInfo->dwFileOS);
	sdb_num_set(sdb, "FileType", vs_fixedFileInfo->dwFileType);
	sdb_num_set(sdb, "FileSubtype", vs_fixedFileInfo->dwFileSubtype);
	sdb_num_set(sdb, "FileDateMS", vs_fixedFileInfo->dwFileDateMS);
	sdb_num_set(sdb, "FileDateLS", vs_fixedFileInfo->dwFileDateLS);
	return sdb;
}

static Sdb *Pe_r_bin_store_resource_version_info(PE_VS_VERSIONINFO *vs_VersionInfo) {
	Sdb *sdb = NULL;
	if (!vs_VersionInfo) {
		return NULL;
	}
	sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}
	if (vs_VersionInfo->Value) {
		sdb_ns_set(sdb, "fixed_file_info", Pe_r_bin_store_fixed_file_info(vs_VersionInfo->Value));
	}
	if (vs_VersionInfo->varFileInfo) {
		sdb_ns_set(sdb, "var_file_info", Pe_r_bin_store_var_file_info(vs_VersionInfo->varFileInfo));
	}
	if (vs_VersionInfo->stringFileInfo) {
		sdb_ns_set(sdb, "string_file_info", Pe_r_bin_store_string_file_info(vs_VersionInfo->stringFileInfo));
	}
	return sdb;
}

static char *_known_product_ids(int id) {
	switch (id) {
	case 0: return "Unknown";
	case 1: return "Import0";
	case 2: return "Linker510";
	case 3: return "Cvtomf510";
	case 4: return "Linker600";
	case 5: return "Cvtomf600";
	case 6: return "Cvtres500";
	case 7: return "Utc11_Basic";
	case 8: return "Utc11_C";
	case 9: return "Utc12_Basic";
	case 10: return "Utc12_C";
	case 11: return "Utc12_CPP";
	case 12: return "AliasObj60";
	case 13: return "VisualBasic60";
	case 14: return "Masm613";
	case 15: return "Masm710";
	case 16: return "Linker511";
	case 17: return "Cvtomf511";
	case 18: return "Masm614";
	case 19: return "Linker512";
	case 20: return "Cvtomf512";
	case 21: return "Utc12_C_Std";
	case 22: return "Utc12_CPP_Std";
	case 23: return "Utc12_C_Book";
	case 24: return "Utc12_CPP_Book";
	case 25: return "Implib700";
	case 26: return "Cvtomf700";
	case 27: return "Utc13_Basic";
	case 28: return "Utc13_C";
	case 29: return "Utc13_CPP";
	case 30: return "Linker610";
	case 31: return "Cvtomf610";
	case 32: return "Linker601";
	case 33: return "Cvtomf601";
	case 34: return "Utc12_1_Basic";
	case 35: return "Utc12_1_C";
	case 36: return "Utc12_1_CPP";
	case 37: return "Linker620";
	case 38: return "Cvtomf620";
	case 39: return "AliasObj70";
	case 40: return "Linker621";
	case 41: return "Cvtomf621";
	case 42: return "Masm615";
	case 43: return "Utc13_LTCG_C";
	case 44: return "Utc13_LTCG_CPP";
	case 45: return "Masm620";
	case 46: return "ILAsm100";
	case 47: return "Utc12_2_Basic";
	case 48: return "Utc12_2_C";
	case 49: return "Utc12_2_CPP";
	case 50: return "Utc12_2_C_Std";
	case 51: return "Utc12_2_CPP_Std";
	case 52: return "Utc12_2_C_Book";
	case 53: return "Utc12_2_CPP_Book";
	case 54: return "Implib622";
	case 55: return "Cvtomf622";
	case 56: return "Cvtres501";
	case 57: return "Utc13_C_Std";
	case 58: return "Utc13_CPP_Std";
	case 59: return "Cvtpgd1300";
	case 60: return "Linker622";
	case 61: return "Linker700";
	case 62: return "Export622";
	case 63: return "Export700";
	case 64: return "Masm700";
	case 65: return "Utc13_POGO_I_C";
	case 66: return "Utc13_POGO_I_CPP";
	case 67: return "Utc13_POGO_O_C";
	case 68: return "Utc13_POGO_O_CPP";
	case 69: return "Cvtres700";
	case 70: return "Cvtres710p";
	case 71: return "Linker710p";
	case 72: return "Cvtomf710p";
	case 73: return "Export710p";
	case 74: return "Implib710p";
	case 75: return "Masm710p";
	case 76: return "Utc1310p_C";
	case 77: return "Utc1310p_CPP";
	case 78: return "Utc1310p_C_Std";
	case 79: return "Utc1310p_CPP_Std";
	case 80: return "Utc1310p_LTCG_C";
	case 81: return "Utc1310p_LTCG_CPP";
	case 82: return "Utc1310p_POGO_I_C";
	case 83: return "Utc1310p_POGO_I_CPP";
	case 84: return "Utc1310p_POGO_O_C";
	case 85: return "Utc1310p_POGO_O_CPP";
	case 86: return "Linker624";
	case 87: return "Cvtomf624";
	case 88: return "Export624";
	case 89: return "Implib624";
	case 90: return "Linker710";
	case 91: return "Cvtomf710";
	case 92: return "Export710";
	case 93: return "Implib710";
	case 94: return "Cvtres710";
	case 95: return "Utc1310_C";
	case 96: return "Utc1310_CPP";
	case 97: return "Utc1310_C_Std";
	case 98: return "Utc1310_CPP_Std";
	case 99: return "Utc1310_LTCG_C";
	case 100: return "Utc1310_LTCG_CPP";
	case 101: return "Utc1310_POGO_I_C";
	case 102: return "Utc1310_POGO_I_CPP";
	case 103: return "Utc1310_POGO_O_C";
	case 104: return "Utc1310_POGO_O_CPP";
	case 105: return "AliasObj710";
	case 106: return "AliasObj710p";
	case 107: return "Cvtpgd1310";
	case 108: return "Cvtpgd1310p";
	case 109: return "Utc1400_C";
	case 110: return "Utc1400_CPP";
	case 111: return "Utc1400_C_Std";
	case 112: return "Utc1400_CPP_Std";
	case 113: return "Utc1400_LTCG_C";
	case 114: return "Utc1400_LTCG_CPP";
	case 115: return "Utc1400_POGO_I_C";
	case 116: return "Utc1400_POGO_I_CPP";
	case 117: return "Utc1400_POGO_O_C";
	case 118: return "Utc1400_POGO_O_CPP";
	case 119: return "Cvtpgd1400";
	case 120: return "Linker800";
	case 121: return "Cvtomf800";
	case 122: return "Export800";
	case 123: return "Implib800";
	case 124: return "Cvtres800";
	case 125: return "Masm800";
	case 126: return "AliasObj800";
	case 127: return "PhoenixPrerelease";
	case 128: return "Utc1400_CVTCIL_C";
	case 129: return "Utc1400_CVTCIL_CPP";
	case 130: return "Utc1400_LTCG_MSIL";
	case 131: return "Utc1500_C";
	case 132: return "Utc1500_CPP";
	case 133: return "Utc1500_C_Std";
	case 134: return "Utc1500_CPP_Std";
	case 135: return "Utc1500_CVTCIL_C";
	case 136: return "Utc1500_CVTCIL_CPP";
	case 137: return "Utc1500_LTCG_C";
	case 138: return "Utc1500_LTCG_CPP";
	case 139: return "Utc1500_LTCG_MSIL";
	case 140: return "Utc1500_POGO_I_C";
	case 141: return "Utc1500_POGO_I_CPP";
	case 142: return "Utc1500_POGO_O_C";
	case 143: return "Utc1500_POGO_O_CPP";

	case 144: return "Cvtpgd1500";
	case 145: return "Linker900";
	case 146: return "Export900";
	case 147: return "Implib900";
	case 148: return "Cvtres900";
	case 149: return "Masm900";
	case 150: return "AliasObj900";
	case 151: return "Resource900";

	case 152: return "AliasObj1000";
	case 154: return "Cvtres1000";
	case 155: return "Export1000";
	case 156: return "Implib1000";
	case 157: return "Linker1000";
	case 158: return "Masm1000";

	case 170: return "Utc1600_C";
	case 171: return "Utc1600_CPP";
	case 172: return "Utc1600_CVTCIL_C";
	case 173: return "Utc1600_CVTCIL_CPP";
	case 174: return "Utc1600_LTCG_C ";
	case 175: return "Utc1600_LTCG_CPP";
	case 176: return "Utc1600_LTCG_MSIL";
	case 177: return "Utc1600_POGO_I_C";
	case 178: return "Utc1600_POGO_I_CPP";
	case 179: return "Utc1600_POGO_O_C";
	case 180: return "Utc1600_POGO_O_CPP";

	case 183: return "Linker1010";
	case 184: return "Export1010";
	case 185: return "Implib1010";
	case 186: return "Cvtres1010";
	case 187: return "Masm1010";
	case 188: return "AliasObj1010";

	case 199: return "AliasObj1100";
	case 201: return "Cvtres1100";
	case 202: return "Export1100";
	case 203: return "Implib1100";
	case 204: return "Linker1100";
	case 205: return "Masm1100";

	case 206: return "Utc1700_C";
	case 207: return "Utc1700_CPP";
	case 208: return "Utc1700_CVTCIL_C";
	case 209: return "Utc1700_CVTCIL_CPP";
	case 210: return "Utc1700_LTCG_C ";
	case 211: return "Utc1700_LTCG_CPP";
	case 212: return "Utc1700_LTCG_MSIL";
	case 213: return "Utc1700_POGO_I_C";
	case 214: return "Utc1700_POGO_I_CPP";
	case 215: return "Utc1700_POGO_O_C";
	case 216: return "Utc1700_POGO_O_CPP";

	case 219: return "Cvtres1200";
	case 220: return "Export1200";
	case 221: return "Implib1200";
	case 222: return "Linker1200";
	case 223:
		return "Masm1200";
		// Speculation
	case 224: return "AliasObj1200";

	case 237: return "Cvtres1210";
	case 238: return "Export1210";
	case 239: return "Implib1210";
	case 240: return "Linker1210";
	case 241:
		return "Masm1210";
		// Speculation
	case 242: return "Utc1810_C";
	case 243: return "Utc1810_CPP";
	case 244: return "Utc1810_CVTCIL_C";
	case 245: return "Utc1810_CVTCIL_CPP";
	case 246: return "Utc1810_LTCG_C ";
	case 247: return "Utc1810_LTCG_CPP";
	case 248: return "Utc1810_LTCG_MSIL";
	case 249: return "Utc1810_POGO_I_C";
	case 250: return "Utc1810_POGO_I_CPP";
	case 251: return "Utc1810_POGO_O_C";
	case 252: return "Utc1810_POGO_O_CPP";

	case 255: return "Cvtres1400";
	case 256: return "Export1400";
	case 257: return "Implib1400";
	case 258: return "Linker1400";
	case 259: return "Masm1400";

	case 260: return "Utc1900_C";
	case 261:
		return "Utc1900_CPP";
		// Speculation
	case 262: return "Utc1900_CVTCIL_C";
	case 263: return "Utc1900_CVTCIL_CPP";
	case 264: return "Utc1900_LTCG_C ";
	case 265: return "Utc1900_LTCG_CPP";
	case 266: return "Utc1900_LTCG_MSIL";
	case 267: return "Utc1900_POGO_I_C";
	case 268: return "Utc1900_POGO_I_CPP";
	case 269: return "Utc1900_POGO_O_C";
	case 270: return "Utc1900_POGO_O_CPP";
	default: return "Unknown";
	}
}

void PE_(bin_pe_init_rich_info)(RzBinPEObj *bin) {
	if (!bin->rich_entries) {
		bin->rich_entries = rz_list_newf(free);
	}
	bin->rich_header_offset = bin->nt_header_offset;
	ut64 off = bin->nt_header_offset - sizeof(ut32);
	ut32 magic = 0x68636952; // Rich
	if (off % sizeof(ut32)) {
		return;
	}

	ut32 tmp;
	while (rz_buf_read_le32_at(bin->b, off, &tmp) && tmp != magic && off) {
		off -= sizeof(ut32);
	}

	if (!off) {
		return;
	}

	ut32 mask;
	if (!rz_buf_read_le32_at(bin->b, off + sizeof(ut32), &mask)) {
		return;
	}

	magic = 0x536E6144; // DanS
	off -= sizeof(ut32);

	ut32 data;
	while (rz_buf_read_le32_at(bin->b, off, &data) && data != magic && data ^ mask && off > 0x80) {
		Pe_image_rich_entry *entry = RZ_NEW0(Pe_image_rich_entry);
		if (!entry) {
			return;
		}
		entry->timesUsed = data ^ mask;
		off -= sizeof(ut32);
		if (!rz_buf_read_le32_at(bin->b, off, &data)) {
			free(entry);
			return;
		}
		data ^= mask;
		entry->productId = data >> 16;
		entry->minVersion = data & 0xFFFF;
		entry->productName = _known_product_ids(entry->productId);
		off -= sizeof(ut32);
		rz_list_append(bin->rich_entries, entry);
	}
	bin->rich_header_offset = off + sizeof(ut32);
}

static char *_resource_lang_str(int id) {
	switch (id) {
	case 0x00: return "LANG_NEUTRAL";
	case 0x7f: return "LANG_INVARIANT";
	case 0x36: return "LANG_AFRIKAANS";
	case 0x1c: return "LANG_ALBANIAN ";
	case 0x01: return "LANG_ARABIC";
	case 0x2b: return "LANG_ARMENIAN";
	case 0x4d: return "LANG_ASSAMESE";
	case 0x2c: return "LANG_AZERI";
	case 0x2d: return "LANG_BASQUE";
	case 0x23: return "LANG_BELARUSIAN";
	case 0x45: return "LANG_BENGALI";
	case 0x02: return "LANG_BULGARIAN";
	case 0x03: return "LANG_CATALAN";
	case 0x04: return "LANG_CHINESE";
	case 0x1a: return "LANG_CROATIAN";
	case 0x05: return "LANG_CZECH";
	case 0x06: return "LANG_DANISH";
	case 0x65: return "LANG_DIVEHI";
	case 0x13: return "LANG_DUTCH";
	case 0x09: return "LANG_ENGLISH";
	case 0x25: return "LANG_ESTONIAN";
	case 0x38: return "LANG_FAEROESE";
	case 0x29: return "LANG_FARSI";
	case 0x0b: return "LANG_FINNISH";
	case 0x0c: return "LANG_FRENCH";
	case 0x56: return "LANG_GALICIAN";
	case 0x37: return "LANG_GEORGIAN";
	case 0x07: return "LANG_GERMAN";
	case 0x08: return "LANG_GREEK";
	case 0x47: return "LANG_GUJARATI";
	case 0x0d: return "LANG_HEBREW";
	case 0x39: return "LANG_HINDI";
	case 0x0e: return "LANG_HUNGARIAN";
	case 0x0f: return "LANG_ICELANDIC";
	case 0x21: return "LANG_INDONESIAN";
	case 0x10: return "LANG_ITALIAN";
	case 0x11: return "LANG_JAPANESE";
	case 0x4b: return "LANG_KANNADA";
	case 0x60: return "LANG_KASHMIRI";
	case 0x3f: return "LANG_KAZAK";
	case 0x57: return "LANG_KONKANI";
	case 0x12: return "LANG_KOREAN";
	case 0x40: return "LANG_KYRGYZ";
	case 0x26: return "LANG_LATVIAN";
	case 0x27: return "LANG_LITHUANIAN";
	case 0x2f: return "LANG_MACEDONIAN";
	case 0x3e: return "LANG_MALAY";
	case 0x4c: return "LANG_MALAYALAM";
	case 0x58: return "LANG_MANIPURI";
	case 0x4e: return "LANG_MARATHI";
	case 0x50: return "LANG_MONGOLIAN";
	case 0x61: return "LANG_NEPALI";
	case 0x14: return "LANG_NORWEGIAN";
	case 0x48: return "LANG_ORIYA";
	case 0x15: return "LANG_POLISH";
	case 0x16: return "LANG_PORTUGUESE";
	case 0x46: return "LANG_PUNJABI";
	case 0x18: return "LANG_ROMANIAN";
	case 0x19: return "LANG_RUSSIAN";
	case 0x4f: return "LANG_SANSKRIT";
	case 0x59: return "LANG_SINDHI";
	case 0x1b: return "LANG_SLOVAK";
	case 0x24: return "LANG_SLOVENIAN";
	case 0x0a: return "LANG_SPANISH ";
	case 0x41: return "LANG_SWAHILI";
	case 0x1d: return "LANG_SWEDISH";
	case 0x5a: return "LANG_SYRIAC";
	case 0x49: return "LANG_TAMIL";
	case 0x44: return "LANG_TATAR";
	case 0x4a: return "LANG_TELUGU";
	case 0x1e: return "LANG_THAI";
	case 0x1f: return "LANG_TURKISH";
	case 0x22: return "LANG_UKRAINIAN";
	case 0x20: return "LANG_URDU";
	case 0x43: return "LANG_UZBEK";
	case 0x2a: return "LANG_VIETNAMESE";
	case 0x3c: return "LANG_GAELIC";
	case 0x3a: return "LANG_MALTESE";
	case 0x28: return "LANG_MAORI";
	case 0x17: return "LANG_RHAETO_ROMANCE";
	case 0x3b: return "LANG_SAAMI";
	case 0x2e: return "LANG_SORBIAN";
	case 0x30: return "LANG_SUTU";
	case 0x31: return "LANG_TSONGA";
	case 0x32: return "LANG_TSWANA";
	case 0x33: return "LANG_VENDA";
	case 0x34: return "LANG_XHOSA";
	case 0x35: return "LANG_ZULU";
	case 0x8f: return "LANG_ESPERANTO";
	case 0x90: return "LANG_WALON";
	case 0x91: return "LANG_CORNISH";
	case 0x92: return "LANG_WELSH";
	case 0x93: return "LANG_BRETON";
	default: return "UNKNOWN";
	}
}

static char *_resource_type_str(int type) {
	const char *typeName;
	switch (type) {
	case 1:
		typeName = "CURSOR";
		break;
	case 2:
		typeName = "BITMAP";
		break;
	case 3:
		typeName = "ICON";
		break;
	case 4:
		typeName = "MENU";
		break;
	case 5:
		typeName = "DIALOG";
		break;
	case 6:
		typeName = "STRING";
		break;
	case 7:
		typeName = "FONTDIR";
		break;
	case 8:
		typeName = "FONT";
		break;
	case 9:
		typeName = "ACCELERATOR";
		break;
	case 10:
		typeName = "RCDATA";
		break;
	case 11:
		typeName = "MESSAGETABLE";
		break;
	case 12:
		typeName = "GROUP_CURSOR";
		break;
	case 14:
		typeName = "GROUP_ICON";
		break;
	case 16:
		typeName = "VERSION";
		break;
	case 17:
		typeName = "DLGINCLUDE";
		break;
	case 19:
		typeName = "PLUGPLAY";
		break;
	case 20:
		typeName = "VXD";
		break;
	case 21:
		typeName = "ANICURSOR";
		break;
	case 22:
		typeName = "ANIICON";
		break;
	case 23:
		typeName = "HTML";
		break;
	case 24:
		typeName = "MANIFEST";
		break;
	default: return rz_str_newf("UNKNOWN (%d)", type);
	}
	return strdup(typeName);
}

static int read_image_resource_directory_entry(RzBuffer *b, ut64 addr, Pe_image_resource_directory_entry *entry) {
	st64 tmp = rz_buf_tell(b);
	if (tmp < 0) {
		return -1;
	}

	if (rz_buf_seek(b, addr, RZ_BUF_SET) < 0) {
		return -1;
	}

	if (!rz_buf_read_le32(b, &entry->u1.Name) || !rz_buf_read_le32(b, &entry->u2.OffsetToData)) {
		return -1;
	}

	if (rz_buf_seek(b, tmp, RZ_BUF_SET) < 0) {
		return -1;
	}

	return sizeof(Pe_image_resource_directory_entry);
}

static int read_image_resource_data_entry(RzBuffer *b, ut64 addr, Pe_image_resource_data_entry *entry) {
	st64 o_addr = rz_buf_tell(b);
	if (rz_buf_seek(b, addr, RZ_BUF_SET) < 0) {
		return -1;
	}
	ut8 buf[sizeof(Pe_image_resource_data_entry)];
	rz_buf_read(b, buf, sizeof(Pe_image_resource_data_entry));
	PE_READ_STRUCT_FIELD(entry, Pe_image_resource_data_entry, OffsetToData, 32);
	PE_READ_STRUCT_FIELD(entry, Pe_image_resource_data_entry, Size, 32);
	PE_READ_STRUCT_FIELD(entry, Pe_image_resource_data_entry, CodePage, 32);
	PE_READ_STRUCT_FIELD(entry, Pe_image_resource_data_entry, Reserved, 32);
	rz_buf_seek(b, o_addr, RZ_BUF_SET);
	return sizeof(Pe_image_resource_data_entry);
}

static void _parse_resource_directory(RzBinPEObj *bin, Pe_image_resource_directory *dir, ut64 offDir, int type, int id, HtUU *dirs, const char *resource_name) {
	char *resourceEntryName = NULL;
	int index = 0;
	ut32 totalRes = dir->NumberOfNamedEntries + dir->NumberOfIdEntries;
	ut64 rsrc_base = bin->resource_directory_offset;
	ut64 off;
	if (totalRes > RZ_PE_MAX_RESOURCES) {
		return;
	}
	for (index = 0; index < totalRes; index++) {
		Pe_image_resource_directory_entry entry;
		off = rsrc_base + offDir + sizeof(*dir) + index * sizeof(entry);
		if (ht_uu_find(dirs, off, NULL)) {
			break;
		}
		ht_uu_insert(dirs, off, 1);
		if (off > bin->size || off + sizeof(entry) > bin->size) {
			break;
		}
		if (read_image_resource_directory_entry(bin->b, off, &entry) < 0) {
			RZ_LOG_ERROR("read resource entry\n");
			break;
		}
		if (entry.u1.Name >> 31) {
			int i;
			ut16 buf;
			ut32 NameOffset = entry.u1.Name & 0x7fffffff;
			if (!rz_buf_read_le16_at(bin->b, bin->resource_directory_offset + NameOffset, &buf)) {
				break;
			}
			ut16 resourceEntryNameLength = rz_read_le16(&buf);
			resourceEntryName = calloc(resourceEntryNameLength + 1, 1);
			if (resourceEntryName) {
				for (i = 0; i < resourceEntryNameLength; i++) { /* Convert Unicode to ASCII */
					ut8 byte;
					int r = rz_buf_read_at(bin->b, bin->resource_directory_offset + NameOffset + 2 + (i * 2), &byte, sizeof(ut8));
					if (r != sizeof(ut8) || !byte) {
						RZ_FREE(resourceEntryName);
						break;
					}
					resourceEntryName[i] = byte;
				}
			}
		}
		if (entry.u2.OffsetToData >> 31) {
			// detect here malicious file trying to making us infinite loop
			Pe_image_resource_directory identEntry;
			ut32 OffsetToDirectory = entry.u2.OffsetToData & 0x7fffffff;
			off = rsrc_base + OffsetToDirectory;
			int len = read_image_resource_directory(bin->b, off, &identEntry);
			if (len < 1 || len != sizeof(Pe_image_resource_directory)) {
				RZ_LOG_ERROR("parsing resource directory\n");
			}
			_parse_resource_directory(bin, &identEntry, OffsetToDirectory, type, entry.u1.Name & 0xffff, dirs, resourceEntryName);
			RZ_FREE(resourceEntryName);
			continue;
		}
		RZ_FREE(resourceEntryName);

		Pe_image_resource_data_entry *data = RZ_NEW0(Pe_image_resource_data_entry);
		if (!data) {
			break;
		}
		off = rsrc_base + entry.u2.OffsetToData;
		if (off > bin->size || off + sizeof(*data) > bin->size) {
			free(data);
			break;
		}
		if (read_image_resource_data_entry(bin->b, off, data) != sizeof(*data)) {
			RZ_LOG_ERROR("read (resource data entry)\n");
			free(data);
			break;
		}
		if (type == PE_RESOURCE_ENTRY_VERSION) {
			char key[64];
			int counter = 0;
			Sdb *sdb = sdb_new0();
			if (!sdb) {
				free(data);
				sdb_free(sdb);
				continue;
			}
			PE_DWord data_paddr = PE_(bin_pe_rva_to_paddr)(bin, data->OffsetToData);
			if (!data_paddr) {
				RZ_LOG_INFO("bad RVA in resource data entry\n");
				free(data);
				sdb_free(sdb);
				continue;
			}
			PE_DWord cur_paddr = data_paddr;
			if ((cur_paddr & 0x3) != 0) {
				RZ_LOG_INFO("not aligned version info address\n");
				free(data);
				sdb_free(sdb);
				continue;
			}
			while (cur_paddr < (data_paddr + data->Size) && cur_paddr < bin->size) {
				PE_VS_VERSIONINFO *vs_VersionInfo = Pe_r_bin_pe_parse_version_info(bin, cur_paddr);
				if (vs_VersionInfo) {
					snprintf(key, 30, "VS_VERSIONINFO%d", counter++);
					sdb_ns_set(sdb, key, Pe_r_bin_store_resource_version_info(vs_VersionInfo));
				} else {
					break;
				}
				if (vs_VersionInfo->wLength < 1) {
					// Invalid version length
					break;
				}
				cur_paddr += vs_VersionInfo->wLength;
				free_VS_VERSIONINFO(vs_VersionInfo);
				align32(cur_paddr);
			}
			sdb_ns_set(bin->kv, "vs_version_info", sdb);
		}
		rz_pe_resource *rs = RZ_NEW0(rz_pe_resource);
		if (!rs) {
			free(data);
			break;
		}
		/* Compare compileTimeStamp to resource timestamp to figure out if DOS date or POSIX date */
		if (rz_time_stamp_is_dos_format((ut32)sdb_num_get(bin->kv, "image_file_header.TimeDateStamp"), dir->TimeDateStamp)) {
			rs->timestr = rz_time_stamp_to_str(rz_time_dos_time_stamp_to_posix(dir->TimeDateStamp));
		} else {
			rs->timestr = rz_time_stamp_to_str(dir->TimeDateStamp);
		}
		rs->type = _resource_type_str(type);
		rs->language = strdup(_resource_lang_str(entry.u1.Name & 0x3ff));
		rs->data = data;
		if (resource_name) {
			rs->name = strdup(resource_name);
		} else {
			rs->name = rz_str_newf("%d", id);
		}
		rz_list_append(bin->resources, rs);
	}
}

static void _store_resource_sdb(RzBinPEObj *bin) {
	RzListIter *iter;
	rz_pe_resource *rs;
	int index = 0;
	ut64 vaddr = 0;
	char *key;
	Sdb *sdb = sdb_new0();
	if (!sdb) {
		return;
	}
	char tmpbuf[64];
	rz_list_foreach (bin->resources, iter, rs) {
		key = rz_strf(tmpbuf, "resource.%d.timestr", index);
		sdb_set(sdb, key, rs->timestr);
		key = rz_strf(tmpbuf, "resource.%d.vaddr", index);
		vaddr = PE_(bin_pe_rva_to_va)(bin, rs->data->OffsetToData);
		sdb_num_set(sdb, key, vaddr);
		key = rz_strf(tmpbuf, "resource.%d.name", index);
		sdb_set(sdb, key, rs->name);
		key = rz_strf(tmpbuf, "resource.%d.size", index);
		sdb_num_set(sdb, key, rs->data->Size);
		key = rz_strf(tmpbuf, "resource.%d.type", index);
		sdb_set(sdb, key, rs->type);
		key = rz_strf(tmpbuf, "resource.%d.language", index);
		sdb_set(sdb, key, rs->language);
		index++;
	}
	sdb_ns_set(bin->kv, "pe_resource", sdb);
}

RZ_API void PE_(bin_pe_parse_resource)(RzBinPEObj *bin) {
	int index = 0;
	ut64 off = 0, rsrc_base = bin->resource_directory_offset;
	Pe_image_resource_directory *rs_directory = bin->resource_directory;
	ut32 curRes = 0;
	int totalRes = 0;
	HtUUOptions opt = { 0 };
	HtUU *dirs = ht_uu_new_opt(&opt); // to avoid infinite loops
	if (!dirs) {
		return;
	}
	if (!rs_directory) {
		ht_uu_free(dirs);
		return;
	}
	curRes = rs_directory->NumberOfNamedEntries;
	totalRes = curRes + rs_directory->NumberOfIdEntries;
	if (totalRes > RZ_PE_MAX_RESOURCES) {
		RZ_LOG_ERROR("Cannot parse resource directory\n");
		ht_uu_free(dirs);
		return;
	}
	for (index = 0; index < totalRes; index++) {
		Pe_image_resource_directory_entry typeEntry;
		off = rsrc_base + sizeof(*rs_directory) + index * sizeof(typeEntry);
		ht_uu_insert(dirs, off, 1);
		if (off > bin->size || off + sizeof(typeEntry) > bin->size) {
			break;
		}
		if (read_image_resource_directory_entry(bin->b, off, &typeEntry) < 0) {
			RZ_LOG_ERROR("read resource directory entry\n");
			break;
		}
		if (typeEntry.u2.OffsetToData >> 31) {
			Pe_image_resource_directory identEntry;
			ut32 OffsetToDirectory = typeEntry.u2.OffsetToData & 0x7fffffff;
			off = rsrc_base + OffsetToDirectory;
			int len = read_image_resource_directory(bin->b, off, &identEntry);
			if (len != sizeof(identEntry)) {
				RZ_LOG_ERROR("parsing resource directory\n");
			}
			(void)_parse_resource_directory(bin, &identEntry, OffsetToDirectory, typeEntry.u1.Name & 0xffff, 0, dirs, NULL);
		}
	}
	ht_uu_free(dirs);
	_store_resource_sdb(bin);
}
