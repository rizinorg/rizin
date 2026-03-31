// SPDX-FileCopyrightText: 2008-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2019 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pe.h"

typedef struct {
	char shortname[8];
	ut32 value;
	ut16 secnum;
	ut16 symtype;
	ut8 symclass;
	ut8 numaux;
} SymbolRecord;

static void parse_symbol_record(SymbolRecord *record, const ut8 *buf, size_t index) {
	memcpy(record->shortname, buf + index, sizeof(record->shortname));
	index += sizeof(record->shortname);
	record->value = rz_read_at_le32(buf, index);
	index += sizeof(ut32);
	record->secnum = rz_read_at_le16(buf, index);
	index += sizeof(ut16);
	record->symtype = rz_read_at_le16(buf, index);
	index += sizeof(ut16);
	record->symclass = buf[index];
	index++;
	record->numaux = buf[index];
}

static struct rz_bin_pe_export_t *parse_symbol_table(RzBinPEObj *bin, struct rz_bin_pe_export_t *exports, int sz) {
	ut64 sym_tbl_off, num = 0;
	const int srsz = COFF_SYMBOL_SIZE; // symbol record size
	struct rz_bin_pe_section_t *sections = NULL;
	struct rz_bin_pe_export_t *exp = NULL;
	struct rz_bin_pe_export_t *new_exports = NULL;
	const size_t export_t_sz = sizeof(struct rz_bin_pe_export_t);
	int bufsz, i, shsz;
	SymbolRecord sr;
	ut64 text_off = 0LL;
	ut64 text_rva = 0LL;
	int textn = 0;
	int exports_sz;
	int symctr = 0;
	ut8 *buf = NULL;

	if (!bin || !bin->nt_headers) {
		return NULL;
	}

	sym_tbl_off = bin->nt_headers->file_header.PointerToSymbolTable;
	num = bin->nt_headers->file_header.NumberOfSymbols;
	shsz = bufsz = num * srsz;
	if (bufsz < 1 || bufsz > bin->size) {
		return NULL;
	}
	buf = calloc(num, srsz);
	if (!buf) {
		return NULL;
	}
	exports_sz = export_t_sz * num;
	if (exports) {
		int osz = sz;
		sz += exports_sz;
		new_exports = realloc(exports, sz + export_t_sz);
		if (!new_exports) {
			free(buf);
			return NULL;
		}
		exports = new_exports;
		new_exports = NULL;
		exp = (struct rz_bin_pe_export_t *)(((const ut8 *)exports) + osz);
	} else {
		sz = exports_sz;
		exports = malloc(sz + export_t_sz);
		exp = exports;
	}

	sections = bin->sections;
	for (i = 0; i < bin->num_sections; i++) {
		// XXX search by section with +x permission since the section can be left blank
		if (!strcmp((char *)sections[i].name, ".text")) {
			text_rva = sections[i].vaddr;
			text_off = sections[i].paddr;
			textn = i + 1;
		}
	}
	symctr = 0;
	if (rz_buf_read_at(bin->b, sym_tbl_off, (ut8 *)buf, bufsz) > 0) {
		for (i = 0; i < shsz; i += srsz) {
			// sr = (SymbolRecord*) (buf + i);
			if (i + sizeof(sr) >= bufsz) {
				break;
			}
			parse_symbol_record(&sr, buf, i);
			// RZ_LOG_INFO("SECNUM %d\n", sr.secnum);
			if (sr.secnum == textn) {
				if (sr.symtype == 32) {
					char shortname[9];
					memcpy(shortname, sr.shortname, 8);
					shortname[8] = 0;
					if (*shortname) {
						strncpy((char *)exp[symctr].name, shortname, PE_NAME_LENGTH - 1);
					} else {
						char *longname, name[128];
						ut32 idx = rz_read_le32(buf + i + 4);
						if (rz_buf_read_at(bin->b, sym_tbl_off + idx + shsz, (ut8 *)name, 128)) { // == 128) {
							longname = name;
							name[sizeof(name) - 1] = 0;
							strncpy((char *)exp[symctr].name, longname, PE_NAME_LENGTH - 1);
						} else {
							sprintf((char *)exp[symctr].name, "unk_%d", symctr);
						}
					}
					exp[symctr].name[PE_NAME_LENGTH] = '\0';
					exp[symctr].libname[0] = '\0';
					exp[symctr].vaddr = PE_(bin_pe_rva_to_va)(bin, text_rva + sr.value);
					exp[symctr].paddr = text_off + sr.value;
					exp[symctr].ordinal = symctr;
					exp[symctr].forwarder[0] = 0;
					exp[symctr].last = 0;
					symctr++;
				}
			}
		} // for
	} // if read ok
	exp[symctr].last = 1;
	free(buf);
	return exports;
}

static int read_image_export_directory(RzBuffer *b, ut64 addr, PE_(image_export_directory) * export_dir) {
	st64 o_addr = rz_buf_tell(b);
	if (rz_buf_seek(b, addr, RZ_BUF_SET) < 0) {
		return -1;
	}
	ut8 buf[sizeof(PE_(image_export_directory))];
	rz_buf_read(b, buf, sizeof(buf));
	PE_READ_STRUCT_FIELD(export_dir, PE_(image_export_directory), Characteristics, 32);
	PE_READ_STRUCT_FIELD(export_dir, PE_(image_export_directory), TimeDateStamp, 32);
	PE_READ_STRUCT_FIELD(export_dir, PE_(image_export_directory), MajorVersion, 16);
	PE_READ_STRUCT_FIELD(export_dir, PE_(image_export_directory), MinorVersion, 16);
	PE_READ_STRUCT_FIELD(export_dir, PE_(image_export_directory), Name, 32);
	PE_READ_STRUCT_FIELD(export_dir, PE_(image_export_directory), Base, 32);
	PE_READ_STRUCT_FIELD(export_dir, PE_(image_export_directory), NumberOfFunctions, 32);
	PE_READ_STRUCT_FIELD(export_dir, PE_(image_export_directory), NumberOfNames, 32);
	PE_READ_STRUCT_FIELD(export_dir, PE_(image_export_directory), AddressOfFunctions, 32);
	PE_READ_STRUCT_FIELD(export_dir, PE_(image_export_directory), AddressOfNames, 32);
	PE_READ_STRUCT_FIELD(export_dir, PE_(image_export_directory), AddressOfOrdinals, 32);
	rz_buf_seek(b, o_addr, RZ_BUF_SET);
	return sizeof(PE_(image_export_directory));
}

int PE_(bin_pe_init_exports)(RzBinPEObj *bin) {
	PE_(image_data_directory) *data_dir_export = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_EXPORT];
	PE_DWord export_dir_paddr = PE_(bin_pe_rva_to_paddr)(bin, data_dir_export->VirtualAddress);
	if (!export_dir_paddr) {
		// This export-dir-paddr should only appear in DLL files
		// RZ_LOG_INFO("Warning: Cannot find the paddr of the export directory\n");
		return false;
	}
	// sdb_setn (DB, "hdr.exports_directory", export_dir_paddr);
	// RZ_LOG_INFO("Pexports paddr at 0x%"PFMT64x"\n", export_dir_paddr);
	if (!(bin->export_directory = malloc(sizeof(PE_(image_export_directory))))) {
		rz_sys_perror("malloc (export directory)");
		return false;
	}
	if (read_image_export_directory(bin->b, export_dir_paddr, bin->export_directory) < 0) {
		RZ_LOG_INFO("read (export directory)\n");
		RZ_FREE(bin->export_directory);
		return false;
	}
	return true;
}

struct rz_bin_pe_export_t *PE_(rz_bin_pe_get_exports)(RzBinPEObj *bin) {
	rz_return_val_if_fail(bin, NULL);
	struct rz_bin_pe_export_t *exp, *exports = NULL;
	PE_Word function_ordinal = 0;
	PE_VWord functions_paddr, names_paddr, ordinals_paddr, function_rva, name_vaddr, name_paddr;
	char function_name[PE_NAME_LENGTH + 1], forwarder_name[PE_NAME_LENGTH + 1];
	char dll_name[PE_NAME_LENGTH + 1];
	PE_(image_data_directory) * data_dir_export;
	PE_VWord export_dir_rva;
	int n, i, export_dir_size;
	st64 exports_sz = 0;

	if (!bin->data_directory) {
		return NULL;
	}
	data_dir_export = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_EXPORT];
	export_dir_rva = data_dir_export->VirtualAddress;
	export_dir_size = data_dir_export->Size;
	PE_VWord *func_rvas = NULL;
	PE_Word *ordinals = NULL;
	if (bin->export_directory) {
		if (bin->export_directory->NumberOfFunctions + 1 <
			bin->export_directory->NumberOfFunctions) {
			// avoid integer overflow
			return NULL;
		}
		exports_sz = (bin->export_directory->NumberOfFunctions + 1) * sizeof(struct rz_bin_pe_export_t);
		// we cant exit with export_sz > bin->size, us rz_bin_pe_export_t is 256+256+8+8+8+4 bytes is easy get over file size
		// to avoid fuzzing we can abort on export_directory->NumberOfFunctions>0xffff
		if (exports_sz < 0 || bin->export_directory->NumberOfFunctions + 1 > 0xffff) {
			return NULL;
		}
		if (!(exports = malloc(exports_sz))) {
			return NULL;
		}
		if (rz_buf_read_at(bin->b, PE_(bin_pe_rva_to_paddr)(bin, bin->export_directory->Name), (ut8 *)dll_name, PE_NAME_LENGTH) < 1) {
			// we dont stop if dll name cant be read, we set dllname to null and continue
			RZ_LOG_INFO("read (dll name)\n");
			dll_name[0] = '\0';
		}
		functions_paddr = PE_(bin_pe_rva_to_paddr)(bin, bin->export_directory->AddressOfFunctions);
		names_paddr = PE_(bin_pe_rva_to_paddr)(bin, bin->export_directory->AddressOfNames);
		ordinals_paddr = PE_(bin_pe_rva_to_paddr)(bin, bin->export_directory->AddressOfOrdinals);

		const size_t names_sz = bin->export_directory->NumberOfNames * sizeof(PE_Word);
		const size_t funcs_sz = bin->export_directory->NumberOfFunctions * sizeof(PE_VWord);
		ordinals = malloc(names_sz);
		func_rvas = malloc(funcs_sz);
		if (!ordinals || !func_rvas) {
			goto beach;
		}
		int r = rz_buf_read_at(bin->b, ordinals_paddr, (ut8 *)ordinals, names_sz);
		if (r != names_sz) {
			goto beach;
		}
		r = rz_buf_read_at(bin->b, functions_paddr, (ut8 *)func_rvas, funcs_sz);
		if (r != funcs_sz) {
			goto beach;
		}
		for (i = 0; i < bin->export_directory->NumberOfFunctions; i++) {
			// get vaddr from AddressOfFunctions array
			function_rva = rz_read_at_ble32((ut8 *)func_rvas, i * sizeof(PE_VWord), bin->big_endian);
			// have exports by name?
			if (bin->export_directory->NumberOfNames > 0) {
				// search for value of i into AddressOfOrdinals
				name_vaddr = 0;
				for (n = 0; n < bin->export_directory->NumberOfNames; n++) {
					PE_Word fo = rz_read_at_ble16((ut8 *)ordinals, n * sizeof(PE_Word), bin->big_endian);
					// if exist this index into AddressOfOrdinals
					if (i == fo) {
						function_ordinal = fo;
						// get the VA of export name  from AddressOfNames
						if (!rz_buf_read_le32_at(bin->b, names_paddr + n * sizeof(PE_VWord), &name_vaddr)) {
							goto beach;
						}
						break;
					}
				}
				// have an address into name_vaddr?
				if (name_vaddr) {
					// get the name of the Export
					name_paddr = PE_(bin_pe_rva_to_paddr)(bin, name_vaddr);
					if (rz_buf_read_at(bin->b, name_paddr, (ut8 *)function_name, PE_NAME_LENGTH) < 1) {
						RZ_LOG_INFO("read (function name)\n");
						exports[i].last = 1;
						return exports;
					}
				} else { // No name export, get the ordinal
					function_ordinal = i;
					snprintf(function_name, PE_NAME_LENGTH, "Ordinal_%i", i + bin->export_directory->Base);
				}
			} else { // if export by name dont exist, get the ordinal taking in mind the Base value.
				snprintf(function_name, PE_NAME_LENGTH, "Ordinal_%i", i + bin->export_directory->Base);
			}
			// check if VA are into export directory, this mean a forwarder export
			if (function_rva >= export_dir_rva && function_rva < (export_dir_rva + export_dir_size)) {
				// if forwarder, the VA point to Forwarded name
				if (rz_buf_read_at(bin->b, PE_(bin_pe_rva_to_paddr)(bin, function_rva), (ut8 *)forwarder_name, PE_NAME_LENGTH) < 1) {
					exports[i].last = 1;
					return exports;
				}
			} else { // no forwarder export
				snprintf(forwarder_name, PE_NAME_LENGTH, "NONE");
			}
			dll_name[PE_NAME_LENGTH] = '\0';
			function_name[PE_NAME_LENGTH] = '\0';
			exports[i].vaddr = PE_(bin_pe_rva_to_va)(bin, function_rva);
			exports[i].paddr = PE_(bin_pe_rva_to_paddr)(bin, function_rva);
			exports[i].ordinal = function_ordinal + bin->export_directory->Base;
			memcpy(exports[i].forwarder, forwarder_name, PE_NAME_LENGTH);
			exports[i].forwarder[PE_NAME_LENGTH] = '\0';
			memcpy(exports[i].name, function_name, PE_NAME_LENGTH);
			exports[i].name[PE_NAME_LENGTH] = '\0';
			memcpy(exports[i].libname, dll_name, PE_NAME_LENGTH);
			exports[i].libname[PE_NAME_LENGTH] = '\0';
			exports[i].last = 0;
		}
		exports[i].last = 1;
		free(ordinals);
		free(func_rvas);
	}
	exp = parse_symbol_table(bin, exports, exports_sz - sizeof(struct rz_bin_pe_export_t));
	if (exp) {
		exports = exp;
	}
	return exports;
beach:
	free(exports);
	free(ordinals);
	free(func_rvas);
	return NULL;
}
