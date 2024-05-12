// SPDX-FileCopyrightText: 2008-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2019 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pe.h"

int PE_(read_image_import_directory)(RzBuffer *b, ut64 addr, PE_(image_import_directory) * import_dir) {
	st64 o_addr = rz_buf_tell(b);
	if (rz_buf_seek(b, addr, RZ_BUF_SET) < 0) {
		return -1;
	}
	ut8 buf[sizeof(PE_(image_import_directory))];
	rz_buf_read(b, buf, sizeof(buf));
	PE_READ_STRUCT_FIELD(import_dir, PE_(image_import_directory), Characteristics, 32);
	PE_READ_STRUCT_FIELD(import_dir, PE_(image_import_directory), TimeDateStamp, 32);
	PE_READ_STRUCT_FIELD(import_dir, PE_(image_import_directory), ForwarderChain, 32);
	PE_READ_STRUCT_FIELD(import_dir, PE_(image_import_directory), Name, 32);
	PE_READ_STRUCT_FIELD(import_dir, PE_(image_import_directory), FirstThunk, 32);
	rz_buf_seek(b, o_addr, RZ_BUF_SET);
	return sizeof(PE_(image_import_directory));
}

int PE_(read_image_delay_import_directory)(RzBuffer *b, ut64 addr, PE_(image_delay_import_directory) * directory) {
	st64 o_addr = rz_buf_tell(b);
	if (rz_buf_seek(b, addr, RZ_BUF_SET) < 0) {
		return -1;
	}
	ut8 buf[sizeof(PE_(image_delay_import_directory))];
	rz_buf_read(b, buf, sizeof(buf));
	PE_READ_STRUCT_FIELD(directory, PE_(image_delay_import_directory), Attributes, 32);
	PE_READ_STRUCT_FIELD(directory, PE_(image_delay_import_directory), Name, 32);
	PE_READ_STRUCT_FIELD(directory, PE_(image_delay_import_directory), ModulePlugin, 32);
	PE_READ_STRUCT_FIELD(directory, PE_(image_delay_import_directory), DelayImportAddressTable, 32);
	PE_READ_STRUCT_FIELD(directory, PE_(image_delay_import_directory), DelayImportNameTable, 32);
	PE_READ_STRUCT_FIELD(directory, PE_(image_delay_import_directory), BoundDelayImportTable, 32);
	PE_READ_STRUCT_FIELD(directory, PE_(image_delay_import_directory), UnloadDelayImportTable, 32);
	PE_READ_STRUCT_FIELD(directory, PE_(image_delay_import_directory), TimeStamp, 32);
	rz_buf_seek(b, o_addr, RZ_BUF_SET);
	return sizeof(PE_(image_delay_import_directory));
}

static char *resolveModuleOrdinal(Sdb *sdb, const char *module, int ordinal) {
	Sdb *db = sdb;
	char tmpbuf[32];
	char *foo = sdb_get(db, rz_strf(tmpbuf, "%d", ordinal));
	if (foo && *foo) {
		return foo;
	} else {
		free(foo); // should never happen
	}
	return NULL;
}

static int bin_pe_parse_imports(RzBinPEObj *bin,
	struct rz_bin_pe_import_t **importp, int *nimp,
	const char *dll_name,
	PE_DWord OriginalFirstThunk,
	PE_DWord FirstThunk) {
	char import_name[PE_NAME_LENGTH + 1];
	char name[PE_NAME_LENGTH + 1];
	PE_Word import_hint, import_ordinal = 0;
	PE_DWord import_table = 0, off = 0;
	int i = 0, len;
	Sdb *db = NULL;
	char *sdb_module = NULL;
	char *symname = NULL;
	char *filename = NULL;
	char *symdllname = NULL;

	if (!dll_name || !*dll_name || *dll_name == '0') {
		return 0;
	}

	if (!(off = PE_(bin_pe_rva_to_paddr)(bin, OriginalFirstThunk)) &&
		!(off = PE_(bin_pe_rva_to_paddr)(bin, FirstThunk))) {
		return 0;
	}
	do {
		if (import_ordinal >= UT16_MAX) {
			break;
		}
		if (off + i * sizeof(PE_DWord) > bin->size) {
			break;
		}
		if (!RZ_BUF_READ_PE_DWORD_AT(bin->b, off + i * sizeof(PE_DWord), &import_table)) {
			RZ_LOG_INFO("read (import table)\n");
			goto error;
		} else if (import_table) {
			if (import_table & ILT_MASK1) {
				import_ordinal = import_table & ILT_MASK2;
				import_hint = 0;
				snprintf(import_name, PE_NAME_LENGTH, "Ordinal_%i", import_ordinal);
				free(symdllname);
				strncpy(name, dll_name, sizeof(name) - 1);
				name[sizeof(name) - 1] = 0;
				symdllname = strdup(name);

				// remove the trailling ".dll"
				size_t len = strlen(symdllname);
				rz_str_case(symdllname, 0);
				len = len < 4 ? 0 : len - 4;
				symdllname[len] = 0;

				if (!sdb_module || strcmp(symdllname, sdb_module)) {
					sdb_free(db);
					if (db) {
						sdb_free(db);
					}
					db = NULL;
					free(sdb_module);
					sdb_module = strdup(symdllname);
					filename = rz_str_newf("%s.sdb", symdllname);
					if (filename && rz_file_exists(filename)) {
						db = sdb_new(NULL, filename, 0);
					} else {
						char *formats_dir = rz_path_system(RZ_SDB_FORMAT);
						free(filename);
						filename = rz_str_newf(RZ_JOIN_3_PATHS("%s", "dll", "%s.sdb"), formats_dir, symdllname);
						free(formats_dir);
						if (rz_file_exists(filename)) {
							db = sdb_new(NULL, filename, 0);
						}
					}
				}
				if (db) {
					symname = resolveModuleOrdinal(db, symdllname, import_ordinal);
					if (symname) {
						snprintf(import_name, PE_NAME_LENGTH, "%s", symname);
						RZ_FREE(symname);
					}
				} else {
					RZ_LOG_INFO("Cannot find %s\n", filename);
				}
				RZ_FREE(filename);
			} else {
				import_ordinal++;
				const ut64 off = PE_(bin_pe_rva_to_paddr)(bin, import_table);
				if (off > bin->size || (off + sizeof(PE_Word)) > bin->size) {
					RZ_LOG_INFO("off > bin->size\n");
					goto error;
				}
				if (!rz_buf_read_le16_at(bin->b, off, &import_hint)) {
					RZ_LOG_INFO("read import hint at 0x%08" PFMT64x "\n", off);
					goto error;
				}
				name[0] = '\0';
				len = rz_buf_read_at(bin->b, off + sizeof(PE_Word), (ut8 *)name, PE_NAME_LENGTH);
				if (len < 1) {
					RZ_LOG_INFO("read (import name)\n");
					goto error;
				} else if (!*name) {
					break;
				}
				name[PE_NAME_LENGTH] = '\0';
				int len = snprintf(import_name, sizeof(import_name), "%s", name);
				if (len >= sizeof(import_name)) {
					RZ_LOG_WARN("Import name '%s' has been truncated.\n", import_name);
				}
			}
			struct rz_bin_pe_import_t *new_importp = realloc(*importp, (*nimp + 1) * sizeof(struct rz_bin_pe_import_t));
			if (!new_importp) {
				rz_sys_perror("realloc (import)");
				goto error;
			}
			*importp = new_importp;
			memcpy((*importp)[*nimp].name, import_name, PE_NAME_LENGTH);
			(*importp)[*nimp].name[PE_NAME_LENGTH] = '\0';
			memcpy((*importp)[*nimp].libname, dll_name, PE_NAME_LENGTH);
			(*importp)[*nimp].libname[PE_NAME_LENGTH] = '\0';
			(*importp)[*nimp].vaddr = PE_(bin_pe_rva_to_va)(bin, FirstThunk + i * sizeof(PE_DWord));
			(*importp)[*nimp].paddr = PE_(bin_pe_rva_to_paddr)(bin, FirstThunk) + i * sizeof(PE_DWord);
			(*importp)[*nimp].hint = import_hint;
			(*importp)[*nimp].ordinal = import_ordinal;
			(*importp)[*nimp].last = 0;
			(*nimp)++;
			i++;
		}
	} while (import_table);

	if (db) {
		sdb_free(db);
		db = NULL;
	}
	free(symdllname);
	free(sdb_module);
	return i;

error:
	if (db) {
		sdb_free(db);
		db = NULL;
	}
	free(symdllname);
	free(sdb_module);
	return false;
}

struct rz_bin_pe_import_t *PE_(rz_bin_pe_get_imports)(RzBinPEObj *bin) {
	struct rz_bin_pe_import_t *imps, *imports = NULL;
	char dll_name[PE_NAME_LENGTH + 1];
	int nimp = 0;
	ut64 off; // used to cache value
	PE_DWord dll_name_offset = 0;
	PE_DWord paddr = 0;
	PE_DWord import_func_name_offset;
	PE_(image_import_directory)
	curr_import_dir;
	PE_(image_delay_import_directory)
	curr_delay_import_dir;

	if (!bin) {
		return NULL;
	}
	if (bin->import_directory_offset >= bin->size) {
		return NULL;
	}
	if (bin->import_directory_offset + 20 > bin->size) {
		return NULL;
	}

	off = bin->import_directory_offset;
	if (off < bin->size && off > 0) {
		ut64 last;
		int idi = 0;
		if (off + sizeof(PE_(image_import_directory)) > bin->size) {
			return NULL;
		}
		int r = PE_(read_image_import_directory)(bin->b, bin->import_directory_offset + idi * sizeof(curr_import_dir), &curr_import_dir);
		if (r < 0) {
			return NULL;
		}

		if (bin->import_directory_size < 1) {
			return NULL;
		}
		if (off + bin->import_directory_size > bin->size) {
			// why chopping instead of returning and cleaning?
			RZ_LOG_INFO("read (import directory too big)\n");
			bin->import_directory_size = bin->size - bin->import_directory_offset;
		}
		last = bin->import_directory_offset + bin->import_directory_size;
		while (r == sizeof(curr_import_dir) && bin->import_directory_offset + (idi + 1) * sizeof(curr_import_dir) <= last && (curr_import_dir.FirstThunk != 0 || curr_import_dir.Name != 0 || curr_import_dir.TimeDateStamp != 0 || curr_import_dir.Characteristics != 0 || curr_import_dir.ForwarderChain != 0)) {
			int rr;
			dll_name_offset = curr_import_dir.Name;
			paddr = PE_(bin_pe_rva_to_paddr)(bin, dll_name_offset);
			if (paddr > bin->size) {
				goto beach;
			}
			if (paddr + PE_NAME_LENGTH > bin->size) {
				rr = rz_buf_read_at(bin->b, paddr, (ut8 *)dll_name, bin->size - paddr);
				if (rr != bin->size - paddr) {
					goto beach;
				}
				dll_name[bin->size - paddr] = '\0';
			} else {
				rr = rz_buf_read_at(bin->b, paddr, (ut8 *)dll_name, PE_NAME_LENGTH);
				if (rr != PE_NAME_LENGTH) {
					goto beach;
				}
				dll_name[PE_NAME_LENGTH] = '\0';
			}
			if (!bin_pe_parse_imports(bin, &imports, &nimp, dll_name,
				    curr_import_dir.Characteristics,
				    curr_import_dir.FirstThunk)) {
				break;
			}
			idi++;
			r = PE_(read_image_import_directory)(bin->b, bin->import_directory_offset + idi * sizeof(curr_import_dir), &curr_import_dir);
			if (r < 0) {
				free(imports);
				return NULL;
			}
		}
	}
	off = bin->delay_import_directory_offset;
	if (off < bin->size && off > 0) {
		if (off + sizeof(PE_(image_delay_import_directory)) > bin->size) {
			goto beach;
		}
		int didi;
		for (didi = 0;; didi++) {
			int r = PE_(read_image_delay_import_directory)(bin->b, off + didi * sizeof(curr_delay_import_dir),
				&curr_delay_import_dir);
			if (r != sizeof(curr_delay_import_dir)) {
				goto beach;
			}
			if ((curr_delay_import_dir.Name == 0) || (curr_delay_import_dir.DelayImportAddressTable == 0)) {
				break;
			}
			if (!curr_delay_import_dir.Attributes) {
				dll_name_offset = PE_(bin_pe_rva_to_paddr)(bin, curr_delay_import_dir.Name - PE_(rz_bin_pe_get_image_base)(bin));
				import_func_name_offset = curr_delay_import_dir.DelayImportNameTable - PE_(rz_bin_pe_get_image_base)(bin);
			} else {
				dll_name_offset = PE_(bin_pe_rva_to_paddr)(bin, curr_delay_import_dir.Name);
				import_func_name_offset = curr_delay_import_dir.DelayImportNameTable;
			}
			if (dll_name_offset > bin->size || dll_name_offset + PE_NAME_LENGTH > bin->size) {
				goto beach;
			}
			int rr = rz_buf_read_at(bin->b, dll_name_offset, (ut8 *)dll_name, PE_NAME_LENGTH);
			if (rr < 5) {
				goto beach;
			}
			dll_name[PE_NAME_LENGTH] = '\0';
			if (!bin_pe_parse_imports(bin, &imports, &nimp, dll_name, import_func_name_offset,
				    curr_delay_import_dir.DelayImportAddressTable)) {
				break;
			}
		}
	}
beach:
	if (nimp) {
		imps = realloc(imports, (nimp + 1) * sizeof(struct rz_bin_pe_import_t));
		if (!imps) {
			rz_sys_perror("realloc (import)");
			free(imports);
			return NULL;
		}
		imports = imps;
		imports[nimp].last = 1;
	}
	return imports;
}

int PE_(bin_pe_init_imports)(RzBinPEObj *bin) {
	PE_(image_data_directory) *data_dir_import = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_IMPORT];
	PE_(image_data_directory) *data_dir_delay_import = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];

	PE_DWord import_dir_paddr = PE_(bin_pe_rva_to_paddr)(bin, data_dir_import->VirtualAddress);
	PE_DWord import_dir_offset = PE_(bin_pe_rva_to_paddr)(bin, data_dir_import->VirtualAddress);
	PE_DWord delay_import_dir_offset = PE_(bin_pe_rva_to_paddr)(bin, data_dir_delay_import->VirtualAddress);

	PE_(image_import_directory) *import_dir = NULL;
	PE_(image_import_directory) *new_import_dir = NULL;
	PE_(image_import_directory) *curr_import_dir = NULL;

	PE_(image_delay_import_directory) *delay_import_dir = NULL;
	PE_(image_delay_import_directory) *new_delay_import_dir = NULL;
	PE_(image_delay_import_directory) *curr_delay_import_dir = NULL;

	int dir_size = sizeof(PE_(image_import_directory));
	int delay_import_size = sizeof(PE_(image_delay_import_directory));
	int indx = 0;
	int rr;
	int import_dir_size = data_dir_import->Size;
	int delay_import_dir_size = data_dir_delay_import->Size;
	/// HACK to modify import size because of begin 0.. this may report wrong info con corkami tests
	if (!import_dir_size) {
		// asume 1 entry for each
		import_dir_size = data_dir_import->Size = 0xffff;
	}
	if (!delay_import_dir_size) {
		data_dir_delay_import->Size = 0xffff;
	}
	int maxidsz = RZ_MIN((PE_DWord)bin->size, import_dir_offset + import_dir_size);
	maxidsz -= import_dir_offset;
	if (maxidsz < 0) {
		maxidsz = 0;
	}
	// int maxcount = maxidsz/ sizeof (struct rz_bin_pe_import_t);

	RZ_FREE(bin->import_directory);
	if (import_dir_paddr != 0) {
		if (import_dir_size < 1 || import_dir_size > maxidsz) {
			RZ_LOG_INFO("Invalid import directory size: 0x%x is now 0x%x\n", import_dir_size, maxidsz);
			import_dir_size = maxidsz;
		}
		bin->import_directory_offset = import_dir_offset;
		do {
			new_import_dir = (PE_(image_import_directory) *)realloc(import_dir, ((1 + indx) * dir_size));
			if (!new_import_dir) {
				rz_sys_perror("malloc (import directory)");
				RZ_FREE(import_dir);
				break; //
				//			goto fail;
			}
			import_dir = new_import_dir;
			new_import_dir = NULL;
			curr_import_dir = import_dir + indx;
			if (PE_(read_image_import_directory)(bin->b, import_dir_offset + indx * dir_size, curr_import_dir) <= 0) {
				RZ_LOG_INFO("read (import directory)\n");
				RZ_FREE(import_dir);
				break; // return false;
			}
			if (((2 + indx) * dir_size) > import_dir_size) {
				break; // goto fail;
			}
			indx++;
		} while (curr_import_dir->FirstThunk != 0 || curr_import_dir->Name != 0 ||
			curr_import_dir->TimeDateStamp != 0 || curr_import_dir->Characteristics != 0 ||
			curr_import_dir->ForwarderChain != 0);

		bin->import_directory = import_dir;
		bin->import_directory_size = import_dir_size;
	}

	indx = 0;
	if (rz_buf_size(bin->b) > 0) {
		if ((delay_import_dir_offset != 0) && (delay_import_dir_offset < (ut32)rz_buf_size(bin->b))) {
			ut64 off;
			bin->delay_import_directory_offset = delay_import_dir_offset;
			do {
				indx++;
				off = indx * delay_import_size;
				if (off >= rz_buf_size(bin->b)) {
					RZ_LOG_INFO("Cannot find end of import symbols\n");
					break;
				}
				new_delay_import_dir = (PE_(image_delay_import_directory) *)realloc(
					delay_import_dir, (indx * delay_import_size) + 1);
				if (!new_delay_import_dir) {
					rz_sys_perror("malloc (delay import directory)");
					free(delay_import_dir);
					return false;
				}
				delay_import_dir = new_delay_import_dir;
				curr_delay_import_dir = delay_import_dir + (indx - 1);
				rr = PE_(read_image_delay_import_directory)(bin->b, delay_import_dir_offset + (indx - 1) * delay_import_size,
					curr_delay_import_dir);
				if (rr != dir_size) {
					RZ_LOG_INFO("read (delay import directory)\n");
					goto fail;
				}
			} while (curr_delay_import_dir->Name != 0);
			bin->delay_import_directory = delay_import_dir;
		}
	}

	return true;
fail:
	RZ_FREE(import_dir);
	bin->import_directory = import_dir;
	free(delay_import_dir);
	return false;
}
