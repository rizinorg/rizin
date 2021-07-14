// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 dso <dso@rice.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_msg_digest.h>
#include <rz_util/rz_log.h>
#include "i/private.h"

// maybe too big sometimes? 2KB of stack eaten here..
#define RZ_STRING_SCAN_BUFFER_SIZE 2048
#define RZ_STRING_MAX_UNI_BLOCKS   4

static RzBinClass *__getClass(RzBinFile *bf, const char *name) {
	rz_return_val_if_fail(bf && bf->o && bf->o->classes_ht && name, NULL);
	return ht_pp_find(bf->o->classes_ht, name, NULL);
}

static RzBinSymbol *__getMethod(RzBinFile *bf, const char *klass, const char *method) {
	rz_return_val_if_fail(bf && bf->o && bf->o->methods_ht && klass && method, NULL);
	const char *name = sdb_fmt("%s::%s", klass, method);
	return ht_pp_find(bf->o->methods_ht, name, NULL);
}

static RzBinString *__stringAt(RzBinFile *bf, RzList *ret, ut64 addr) {
	if (addr != 0 && addr != UT64_MAX) {
		return ht_up_find(bf->o->strings_db, addr, NULL);
	}
	return NULL;
}

static void print_string(RzBinFile *bf, RzBinString *string, int raw, PJ *pj) {
	rz_return_if_fail(bf && string);

	int mode = bf->strmode;
	ut64 addr, vaddr;
	RzBin *bin = bf->rbin;
	if (!bin) {
		return;
	}
	const char *section_name, *type_string;
	RzIO *io = bin->iob.io;
	if (!io) {
		return;
	}
	RzBinSection *s = rz_bin_get_section_at(bf->o, string->paddr, false);
	if (s) {
		string->vaddr = s->vaddr + (string->paddr - s->paddr);
	}
	section_name = s ? s->name : "";
	type_string = rz_bin_string_type(string->type);
	vaddr = addr = bf->o ? rz_bin_object_get_vaddr(bf->o, string->paddr, string->vaddr) : UT64_MAX;

	// If raw string dump mode, use printf to dump directly to stdout.
	//  PrintfCallback temp = io->cb_printf;
	switch (mode) {
	case RZ_MODE_JSON: {
		if (pj) {
			pj_o(pj);
			pj_kn(pj, "vaddr", vaddr);
			pj_kn(pj, "paddr", string->paddr);
			pj_kn(pj, "ordinal", string->ordinal);
			pj_kn(pj, "size", string->size);
			pj_kn(pj, "length", string->length);
			pj_ks(pj, "section", section_name);
			pj_ks(pj, "type", type_string);
			pj_ks(pj, "string", string->string);
			pj_end(pj);
		}
	} break;
	case RZ_MODE_SIMPLEST:
		io->cb_printf("%s\n", string->string);
		break;
	case RZ_MODE_SIMPLE:
		if (raw == 2) {
			io->cb_printf("0x%08" PFMT64x " %s\n", addr, string->string);
		} else {
			io->cb_printf("%s\n", string->string);
		}
		break;
	case RZ_MODE_RIZINCMD: {
		char *f_name, *nstr;
		f_name = strdup(string->string);
		rz_name_filter(f_name, 512, true);
		if (bin->prefix) {
			nstr = rz_str_newf("%s.str.%s", bin->prefix, f_name);
			io->cb_printf("f %s.str.%s %u @ 0x%08" PFMT64x "\n"
				      "Cs %u @ 0x%08" PFMT64x "\n",
				bin->prefix, f_name, string->size, addr,
				string->size, addr);
		} else {
			nstr = rz_str_newf("str.%s", f_name);
			io->cb_printf("f str.%s %u @ 0x%08" PFMT64x "\n"
				      "Cs %u @ 0x%08" PFMT64x "\n",
				f_name, string->size, addr,
				string->size, addr);
		}
		free(nstr);
		free(f_name);
		break;
	}
	case RZ_MODE_PRINT:
		io->cb_printf("%03u 0x%08" PFMT64x " 0x%08" PFMT64x " %3u %3u "
			      "(%s) %5s %s\n",
			string->ordinal, string->paddr, vaddr,
			string->length, string->size,
			section_name, type_string, string->string);
		break;
	}
}

static int string_scan_range(RzList *list, RzBinFile *bf, int min,
	const ut64 from, const ut64 to, int type, int raw, RzBinSection *section) {
	RzBin *bin = bf->rbin;
	ut8 tmp[RZ_STRING_SCAN_BUFFER_SIZE];
	ut64 str_start, needle = from;
	int count = 0, i, rc, runes;
	int str_type = RZ_STRING_TYPE_DETECT;

	// if list is null it means its gonna dump
	rz_return_val_if_fail(bf, -1);

	if (type == -1) {
		type = RZ_STRING_TYPE_DETECT;
	}
	if (from == to) {
		return 0;
	}
	if (from > to) {
		eprintf("Invalid range to find strings 0x%" PFMT64x " .. 0x%" PFMT64x "\n", from, to);
		return -1;
	}
	int len = to - from;
	ut8 *buf = calloc(len, 1);
	if (!buf || !min) {
		free(buf);
		return -1;
	}
	st64 vdelta = 0, pdelta = 0;
	RzBinSection *s = NULL;
	bool ascii_only = false;
	PJ *pj = NULL;
	if (bf->strmode == RZ_MODE_JSON && !list) {
		pj = pj_new();
		if (pj) {
			pj_a(pj);
		}
	}
	rz_buf_read_at(bf->buf, from, buf, len);
	// may oobread
	while (needle < to) {
		if (bin && bin->consb.is_breaked) {
			if (bin->consb.is_breaked()) {
				break;
			}
		}
		rc = rz_utf8_decode(buf + needle - from, to - needle, NULL);
		if (!rc) {
			needle++;
			continue;
		}
		if (type == RZ_STRING_TYPE_DETECT) {
			char *w = (char *)buf + needle + rc - from;
			if ((to - needle) > 5 + rc) {
				bool is_wide32 = (needle + rc + 2 < to) && (!w[0] && !w[1] && !w[2] && w[3] && !w[4]);
				if (is_wide32) {
					str_type = RZ_STRING_TYPE_WIDE32;
				} else {
					bool is_wide = needle + rc + 4 < to && !w[0] && w[1] && !w[2] && w[3] && !w[4];
					str_type = is_wide ? RZ_STRING_TYPE_WIDE : RZ_STRING_TYPE_ASCII;
				}
			} else {
				str_type = RZ_STRING_TYPE_ASCII;
			}
		} else if (type == RZ_STRING_TYPE_UTF8) {
			str_type = RZ_STRING_TYPE_ASCII; // initial assumption
		} else {
			str_type = type;
		}
		runes = 0;
		str_start = needle;

		/* Eat a whole C string */
		for (i = 0; i < sizeof(tmp) - 4 && needle < to; i += rc) {
			RzRune r = { 0 };

			if (str_type == RZ_STRING_TYPE_WIDE32) {
				rc = rz_utf32le_decode(buf + needle - from, to - needle, &r);
				if (rc) {
					rc = 4;
				}
			} else if (str_type == RZ_STRING_TYPE_WIDE) {
				rc = rz_utf16le_decode(buf + needle - from, to - needle, &r);
				if (rc == 1) {
					rc = 2;
				}
			} else {
				rc = rz_utf8_decode(buf + needle - from, to - needle, &r);
				if (rc > 1) {
					str_type = RZ_STRING_TYPE_UTF8;
				}
			}

			/* Invalid sequence detected */
			if (!rc || (ascii_only && r > 0x7f)) {
				needle++;
				break;
			}

			needle += rc;

			if (rz_isprint(r) && r != '\\') {
				if (str_type == RZ_STRING_TYPE_WIDE32) {
					if (r == 0xff) {
						r = 0;
					}
				}
				rc = rz_utf8_encode(tmp + i, r);
				runes++;
				/* Print the escape code */
			} else if (r && r < 0x100 && strchr("\b\v\f\n\r\t\a\033\\", (char)r)) {
				if ((i + 32) < sizeof(tmp) && r < 93) {
					tmp[i + 0] = '\\';
					tmp[i + 1] = "       abtnvfr             e  "
						     "                              "
						     "                              "
						     "  \\"[r];
				} else {
					// string too long
					break;
				}
				rc = 2;
				runes++;
			} else {
				/* \0 marks the end of C-strings */
				break;
			}
		}

		tmp[i++] = '\0';

		if (runes < min && runes >= 2 && str_type == RZ_STRING_TYPE_ASCII && needle < to) {
			// back up past the \0 to the last char just in case it starts a wide string
			needle -= 2;
		}
		if (runes >= min) {
			// reduce false positives
			int j, num_blocks, *block_list;
			int *freq_list = NULL, expected_ascii, actual_ascii, num_chars;
			if (str_type == RZ_STRING_TYPE_ASCII) {
				for (j = 0; j < i; j++) {
					char ch = tmp[j];
					if (ch != '\n' && ch != '\r' && ch != '\t') {
						if (!IS_PRINTABLE(tmp[j])) {
							continue;
						}
					}
				}
			}
			switch (str_type) {
			case RZ_STRING_TYPE_UTF8:
			case RZ_STRING_TYPE_WIDE:
			case RZ_STRING_TYPE_WIDE32:
				num_blocks = 0;
				block_list = rz_utf_block_list((const ut8 *)tmp, i - 1,
					str_type == RZ_STRING_TYPE_WIDE ? &freq_list : NULL);
				if (block_list) {
					for (j = 0; block_list[j] != -1; j++) {
						num_blocks++;
					}
				}
				if (freq_list) {
					num_chars = 0;
					actual_ascii = 0;
					for (j = 0; freq_list[j] != -1; j++) {
						num_chars += freq_list[j];
						if (!block_list[j]) { // ASCII
							actual_ascii = freq_list[j];
						}
					}
					free(freq_list);
					expected_ascii = num_blocks ? num_chars / num_blocks : 0;
					if (actual_ascii > expected_ascii) {
						ascii_only = true;
						needle = str_start;
						free(block_list);
						continue;
					}
				}
				free(block_list);
				if (num_blocks > RZ_STRING_MAX_UNI_BLOCKS) {
					continue;
				}
			}
			RzBinString *bs = RZ_NEW0(RzBinString);
			if (!bs) {
				break;
			}
			bs->type = str_type;
			bs->length = runes;
			bs->size = needle - str_start;
			bs->ordinal = count++;
			// TODO: move into adjust_offset
			switch (str_type) {
			case RZ_STRING_TYPE_WIDE:
				if (str_start - from > 1) {
					const ut8 *p = buf + str_start - 2 - from;
					if (p[0] == 0xff && p[1] == 0xfe) {
						str_start -= 2; // \xff\xfe
					}
				}
				break;
			case RZ_STRING_TYPE_WIDE32:
				if (str_start - from > 3) {
					const ut8 *p = buf + str_start - 4 - from;
					if (p[0] == 0xff && p[1] == 0xfe) {
						str_start -= 4; // \xff\xfe\x00\x00
					}
				}
				break;
			}
			if (!s) {
				if (section) {
					s = section;
				} else if (bf->o) {
					s = rz_bin_get_section_at(bf->o, str_start, false);
				}
				if (s) {
					vdelta = s->vaddr;
					pdelta = s->paddr;
				}
			}
			bs->paddr = str_start;
			bs->vaddr = str_start - pdelta + vdelta;
			bs->string = rz_str_ndup((const char *)tmp, i);
			if (list) {
				rz_list_append(list, bs);
				if (bf->o) {
					ht_up_insert(bf->o->strings_db, bs->vaddr, bs);
				}
			} else {
				print_string(bf, bs, raw, pj);
				rz_bin_string_free(bs);
			}
			if (from == 0 && to == bf->size) {
				/* force lookup section at the next one */
				s = NULL;
			}
		}
		ascii_only = false;
	}
	free(buf);
	if (pj) {
		pj_end(pj);
		if (bin) {
			RzIO *io = bin->iob.io;
			if (io) {
				io->cb_printf("%s", pj_string(pj));
			}
		}
		pj_free(pj);
	}
	return count;
}

static bool __isDataSection(RzBinFile *a, RzBinSection *s) {
	if (s->has_strings || s->is_data) {
		return true;
	}
	// Rust
	return strstr(s->name, "_const") != NULL;
}

static void get_strings_range(RzBinFile *bf, RzList *list, int min, int raw, ut64 from, ut64 to, RzBinSection *section) {
	rz_return_if_fail(bf && bf->buf);

	RzBinPlugin *plugin = rz_bin_file_cur_plugin(bf);

	if (!raw && (!plugin || !plugin->info)) {
		return;
	}
	if (!min) {
		min = plugin ? plugin->minstrlen : 4;
	}
	/* Some plugins return zero, fix it up */
	if (!min) {
		min = 4;
	}
	if (min < 0) {
		return;
	}
	if (!bf->rbin->is_debugger) {
		if (!to || to > rz_buf_size(bf->buf)) {
			to = rz_buf_size(bf->buf);
		}
		if (!to) {
			return;
		}
	}
	if (raw != 2) {
		ut64 size = to - from;
		// in case of dump ignore here
		if (bf->rbin->maxstrbuf && size && size > bf->rbin->maxstrbuf) {
			if (bf->rbin->verbose) {
				eprintf("WARNING: bin_strings buffer is too big (0x%08" PFMT64x "). Use -zzz or set bin.maxstrbuf (RZ_BIN_MAXSTRBUF) in rizin (rz_bin)\n",
					size);
			}
			return;
		}
	}
	int type;
	const char *enc = bf->rbin->strenc;
	if (!enc) {
		type = RZ_STRING_TYPE_DETECT;
	} else if (!strcmp(enc, "latin1")) {
		type = RZ_STRING_TYPE_ASCII;
	} else if (!strcmp(enc, "utf8")) {
		type = RZ_STRING_TYPE_UTF8;
	} else if (!strcmp(enc, "utf16le")) {
		type = RZ_STRING_TYPE_WIDE;
	} else if (!strcmp(enc, "utf32le")) {
		type = RZ_STRING_TYPE_WIDE32;
	} else { // TODO utf16be, utf32be
		eprintf("ERROR: encoding %s not supported\n", enc);
		return;
	}
	string_scan_range(list, bf, min, from, to, type, raw, section);
}

RZ_IPI RzBinFile *rz_bin_file_new(RzBin *bin, const char *file, ut64 file_sz, int rawstr, int fd, const char *xtrname, Sdb *sdb, bool steal_ptr) {
	ut32 bf_id;
	if (!rz_id_pool_grab_id(bin->ids->pool, &bf_id)) {
		return NULL;
	}
	RzBinFile *bf = RZ_NEW0(RzBinFile);
	if (bf) {
		bf->id = bf_id;
		bf->rbin = bin;
		bf->file = file ? strdup(file) : NULL;
		bf->rawstr = rawstr;
		bf->fd = fd;
		bf->curxtr = xtrname ? rz_bin_get_xtrplugin_by_name(bin, xtrname) : NULL;
		bf->sdb = sdb;
		bf->size = file_sz;
		bf->xtr_data = rz_list_newf((RzListFree)rz_bin_xtrdata_free);
		bf->xtr_obj = NULL;
		bf->sdb = sdb_new0();
	}
	return bf;
}

RZ_IPI void rz_bin_file_free(void /*RzBinFile*/ *_bf) {
	if (!_bf) {
		return;
	}
	RzBinFile *bf = _bf;
	if (bf->rbin->cur == bf) {
		bf->rbin->cur = NULL;
	}
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(bf);
	// Binary format objects are connected to the
	// RzBinObject, so the plugin must destroy the
	// format data first
	if (plugin && plugin->destroy) {
		plugin->destroy(bf);
	}
	rz_buf_free(bf->buf);
	if (bf->curxtr && bf->curxtr->destroy && bf->xtr_obj) {
		bf->curxtr->free_xtr((void *)(bf->xtr_obj));
	}
	free(bf->file);
	rz_bin_object_free(bf->o);
	rz_list_free(bf->xtr_data);
	if (bf->id != -1) {
		// TODO: use rz_storage api
		rz_id_pool_kick_id(bf->rbin->ids->pool, bf->id);
	}
	free(bf);
}

static RzBinPlugin *get_plugin_from_buffer(RzBin *bin, const char *pluginname, RzBuffer *buf) {
	RzBinPlugin *plugin = bin->force ? rz_bin_get_binplugin_by_name(bin, bin->force) : NULL;
	if (plugin) {
		return plugin;
	}
	plugin = pluginname ? rz_bin_get_binplugin_by_name(bin, pluginname) : NULL;
	if (plugin) {
		return plugin;
	}
	plugin = rz_bin_get_binplugin_by_buffer(bin, buf);
	if (plugin) {
		return plugin;
	}
	return rz_bin_get_binplugin_by_name(bin, "any");
}

RZ_API bool rz_bin_file_object_new_from_xtr_data(RzBin *bin, RzBinFile *bf, RzBinObjectLoadOptions *opts, RzBinXtrData *data) {
	rz_return_val_if_fail(bin && bf && data, false);

	ut64 offset = data->offset;
	ut64 sz = data->size;

	RzBinPlugin *plugin = get_plugin_from_buffer(bin, NULL, data->buf);
	bf->buf = rz_buf_ref(data->buf);

	RzBinObject *o = rz_bin_object_new(bf, plugin, opts, offset, sz);
	if (!o) {
		return false;
	}
	// size is set here because the reported size of the object depends on
	// if loaded from xtr plugin or partially read
	if (!o->size) {
		o->size = sz;
	}
	bf->narch = data->file_count;
	if (!o->info) {
		o->info = RZ_NEW0(RzBinInfo);
	}
	free(o->info->file);
	free(o->info->arch);
	free(o->info->machine);
	free(o->info->type);
	o->info->file = strdup(bf->file);
	o->info->arch = strdup(data->metadata->arch);
	o->info->machine = strdup(data->metadata->machine);
	o->info->type = strdup(data->metadata->type);
	o->info->bits = data->metadata->bits;
	o->info->has_crypto = bf->o->info->has_crypto;
	data->loaded = true;
	return true;
}

static bool xtr_metadata_match(RzBinXtrData *xtr_data, const char *arch, int bits) {
	if (!xtr_data->metadata || !xtr_data->metadata->arch) {
		return false;
	}
	const char *iter_arch = xtr_data->metadata->arch;
	int iter_bits = xtr_data->metadata->bits;
	return bits == iter_bits && !strcmp(iter_arch, arch) && !xtr_data->loaded;
}

RZ_IPI RzBinFile *rz_bin_file_new_from_buffer(RzBin *bin, const char *file, RzBuffer *buf, int rawstr, RzBinObjectLoadOptions *opts, int fd, const char *pluginname) {
	rz_return_val_if_fail(bin && file && buf, NULL);

	RzBinFile *bf = rz_bin_file_new(bin, file, rz_buf_size(buf), rawstr, fd, pluginname, NULL, false);
	if (bf) {
		RzListIter *item = rz_list_append(bin->binfiles, bf);
		bf->buf = rz_buf_ref(buf);
		RzBinPlugin *plugin = get_plugin_from_buffer(bin, pluginname, bf->buf);
		RzBinObject *o = rz_bin_object_new(bf, plugin, opts, 0, rz_buf_size(bf->buf));
		if (!o) {
			rz_list_delete(bin->binfiles, item);
			return NULL;
		}
		// size is set here because the reported size of the object depends on
		// if loaded from xtr plugin or partially read
		if (!o->size) {
			o->size = rz_buf_size(buf);
		}
	}
	return bf;
}

RZ_API RzBinFile *rz_bin_file_find_by_arch_bits(RzBin *bin, const char *arch, int bits) {
	RzListIter *iter;
	RzBinFile *binfile = NULL;
	RzBinXtrData *xtr_data;

	rz_return_val_if_fail(bin && arch, NULL);

	rz_list_foreach (bin->binfiles, iter, binfile) {
		RzListIter *iter_xtr;
		if (!binfile->xtr_data) {
			continue;
		}
		// look for sub-bins in Xtr Data and Load if we need to
		rz_list_foreach (binfile->xtr_data, iter_xtr, xtr_data) {
			if (xtr_metadata_match(xtr_data, arch, bits)) {
				if (!rz_bin_file_object_new_from_xtr_data(bin, binfile, &xtr_data->obj_opts, xtr_data)) {
					return NULL;
				}
				return binfile;
			}
		}
	}
	return binfile;
}

RZ_IPI RzBinFile *rz_bin_file_find_by_id(RzBin *bin, ut32 bf_id) {
	RzBinFile *bf;
	RzListIter *iter;
	rz_list_foreach (bin->binfiles, iter, bf) {
		if (bf->id == bf_id) {
			return bf;
		}
	}
	return NULL;
}

RZ_API ut64 rz_bin_file_delete_all(RzBin *bin) {
	rz_return_val_if_fail(bin, 0);
	ut64 counter = rz_list_length(bin->binfiles);
	RzListIter *it;
	RzBinFile *bf;
	rz_list_foreach (bin->binfiles, it, bf) {
		RzEventBinFileDel ev = { bf };
		rz_event_send(bin->event, RZ_EVENT_BIN_FILE_DEL, &ev);
	}
	rz_list_purge(bin->binfiles);
	bin->cur = NULL;
	return counter;
}

RZ_API bool rz_bin_file_delete(RzBin *bin, RzBinFile *bf) {
	rz_return_val_if_fail(bin && bf, false);
	RzListIter *it = rz_list_find_ptr(bin->binfiles, bf);
	rz_return_val_if_fail(it, false); // calling del on a bf not in the bin is a programming error
	if (bin->cur == bf) {
		bin->cur = NULL;
	}
	RzEventBinFileDel ev = { bf };
	rz_event_send(bin->event, RZ_EVENT_BIN_FILE_DEL, &ev);
	rz_list_delete(bin->binfiles, it);
	return true;
}

RZ_API RzBinFile *rz_bin_file_find_by_fd(RzBin *bin, ut32 bin_fd) {
	RzListIter *iter;
	RzBinFile *bf;

	rz_return_val_if_fail(bin, NULL);

	rz_list_foreach (bin->binfiles, iter, bf) {
		if (bf->fd == bin_fd) {
			return bf;
		}
	}
	return NULL;
}

RZ_API RzBinFile *rz_bin_file_find_by_name(RzBin *bin, const char *name) {
	RzListIter *iter;
	RzBinFile *bf;

	rz_return_val_if_fail(bin && name, NULL);

	rz_list_foreach (bin->binfiles, iter, bf) {
		if (bf->file && !strcmp(bf->file, name)) {
			return bf;
		}
	}
	return NULL;
}

RZ_API bool rz_bin_file_set_cur_by_id(RzBin *bin, ut32 bin_id) {
	RzBinFile *bf = rz_bin_file_find_by_id(bin, bin_id);
	return bf ? rz_bin_file_set_cur_binfile(bin, bf) : false;
}

RZ_API bool rz_bin_file_set_cur_by_fd(RzBin *bin, ut32 bin_fd) {
	RzBinFile *bf = rz_bin_file_find_by_fd(bin, bin_fd);
	return bf ? rz_bin_file_set_cur_binfile(bin, bf) : false;
}

RZ_IPI bool rz_bin_file_set_obj(RzBin *bin, RzBinFile *bf, RzBinObject *obj) {
	rz_return_val_if_fail(bin && bf, false);
	bin->file = bf->file;
	bin->cur = bf;
	bin->narch = bf->narch;
	if (obj) {
		bf->o = obj;
	} else {
		obj = bf->o;
	}
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(bf);
	if (bin->minstrlen < 1) {
		bin->minstrlen = plugin ? plugin->minstrlen : bin->minstrlen;
	}
	if (obj) {
		if (!obj->info) {
			return false;
		}
		if (!obj->info->lang) {
			obj->info->lang = rz_bin_lang_tostring(obj->lang);
		}
	}
	return true;
}

RZ_API bool rz_bin_file_set_cur_binfile(RzBin *bin, RzBinFile *bf) {
	rz_return_val_if_fail(bin && bf, false);
	return rz_bin_file_set_obj(bin, bf, bf->o);
}

RZ_API bool rz_bin_file_set_cur_by_name(RzBin *bin, const char *name) {
	rz_return_val_if_fail(bin && name, false);
	RzBinFile *bf = rz_bin_file_find_by_name(bin, name);
	return rz_bin_file_set_cur_binfile(bin, bf);
}

RZ_IPI RzBinFile *rz_bin_file_xtr_load_buffer(RzBin *bin, RzBinXtrPlugin *xtr, const char *filename, RzBuffer *buf, RzBinObjectLoadOptions *obj_opts, int idx, int fd, int rawstr) {
	rz_return_val_if_fail(bin && xtr && buf, NULL);

	RzBinFile *bf = rz_bin_file_find_by_name(bin, filename);
	if (!bf) {
		bf = rz_bin_file_new(bin, filename, rz_buf_size(buf), rawstr, fd, xtr->name, bin->sdb, false);
		if (!bf) {
			return NULL;
		}
		rz_list_append(bin->binfiles, bf);
		if (!bin->cur) {
			bin->cur = bf;
		}
	}
	rz_list_free(bf->xtr_data);
	bf->xtr_data = NULL;
	if (xtr->extractall_from_buffer) {
		bf->xtr_data = xtr->extractall_from_buffer(bin, buf);
	} else if (xtr->extractall_from_bytes) {
		ut64 sz = 0;
		const ut8 *bytes = rz_buf_data(buf, &sz);
		eprintf("TODO: Implement extractall_from_buffer in '%s' xtr.bin plugin\n", xtr->name);
		bf->xtr_data = xtr->extractall_from_bytes(bin, bytes, sz);
	}
	if (bf->xtr_data) {
		RzListIter *iter;
		RzBinXtrData *x;
		//populate xtr_data with baddr and laddr that will be used later on
		//rz_bin_file_object_new_from_xtr_data
		rz_list_foreach (bf->xtr_data, iter, x) {
			x->obj_opts = *obj_opts;
		}
	}
	bf->loadaddr = obj_opts->loadaddr;
	return bf;
}

// XXX deprecate this function imho.. wee can just access bf->buf directly
RZ_IPI bool rz_bin_file_set_bytes(RzBinFile *bf, const ut8 *bytes, ut64 sz, bool steal_ptr) {
	rz_return_val_if_fail(bf && bytes, false);
	rz_buf_free(bf->buf);
	if (steal_ptr) {
		bf->buf = rz_buf_new_with_pointers(bytes, sz, true);
	} else {
		bf->buf = rz_buf_new_with_bytes(bytes, sz);
	}
	return bf->buf != NULL;
}

RZ_API RzBinPlugin *rz_bin_file_cur_plugin(RzBinFile *bf) {
	return (bf && bf->o) ? bf->o->plugin : NULL;
}

// TODO: searchStrings() instead
RZ_IPI RzList *rz_bin_file_get_strings(RzBinFile *bf, int min, int dump, int raw) {
	rz_return_val_if_fail(bf, NULL);
	RzListIter *iter;
	RzBinSection *section;
	RzList *ret = dump ? NULL : rz_list_newf(rz_bin_string_free);

	if (!raw && bf && bf->o && bf->o->sections && !rz_list_empty(bf->o->sections)) {
		RzBinObject *o = bf->o;
		rz_list_foreach (o->sections, iter, section) {
			if (__isDataSection(bf, section)) {
				get_strings_range(bf, ret, min, raw, section->paddr,
					section->paddr + section->size, section);
			}
		}
		rz_list_foreach (o->sections, iter, section) {
			/* load objc/swift strings */
			const int bits = (bf->o && bf->o->info) ? bf->o->info->bits : 32;
			const int cfstr_size = (bits == 64) ? 32 : 16;
			const int cfstr_offs = (bits == 64) ? 16 : 8;
			if (strstr(section->name, "__cfstring")) {
				int i;
				// XXX do not walk if bin.strings == 0
				ut8 *p;
				if (section->size > bf->size) {
					continue;
				}
				ut8 *sbuf = malloc(section->size);
				if (!sbuf) {
					continue;
				}
				rz_buf_read_at(bf->buf, section->paddr + cfstr_offs, sbuf, section->size);
				for (i = 0; i < section->size; i += cfstr_size) {
					ut8 *buf = sbuf;
					p = buf + i;
					if ((i + ((bits == 64) ? 8 : 4)) >= section->size) {
						break;
					}
					ut64 cfstr_vaddr = section->vaddr + i;
					ut64 cstr_vaddr = (bits == 64) ? rz_read_le64(p) : rz_read_le32(p);
					RzBinString *s = __stringAt(bf, ret, cstr_vaddr);
					if (s) {
						RzBinString *bs = RZ_NEW0(RzBinString);
						if (bs) {
							bs->type = s->type;
							bs->length = s->length;
							bs->size = s->size;
							bs->ordinal = s->ordinal;
							bs->vaddr = cfstr_vaddr;
							bs->paddr = cfstr_vaddr; // XXX should be paddr instead
							bs->string = rz_str_newf("cstr.%s", s->string);
							rz_list_append(ret, bs);
							ht_up_insert(o->strings_db, bs->vaddr, bs);
						}
					}
				}
				free(sbuf);
			}
		}
	} else {
		get_strings_range(bf, ret, min, raw, 0, bf->size, NULL);
	}
	return ret;
}

RZ_API ut64 rz_bin_file_get_baddr(RzBinFile *bf) {
	if (bf && bf->o) {
		return bf->o->opts.baseaddr;
	}
	return UT64_MAX;
}

RZ_API bool rz_bin_file_close(RzBin *bin, int bd) {
	rz_return_val_if_fail(bin, false);
	RzBinFile *bf = rz_id_storage_take(bin->ids, bd);
	if (bf) {
		// file_free removes the fd already.. maybe its unnecessary
		rz_id_storage_delete(bin->ids, bd);
		rz_bin_file_free(bf);
		return true;
	}
	return false;
}

static inline bool add_file_hash(RzMsgDigest *md, const char *name, RzList *list) {
	char hash[128];
	const ut8 *digest = NULL;
	RzMsgDigestSize digest_size = 0;

	digest = rz_msg_digest_get_result(md, name, &digest_size);
	if (!digest) {
		return false;
	}

	rz_hex_bin2str(digest, digest_size, hash);

	RzBinFileHash *fh = RZ_NEW0(RzBinFileHash);
	if (!fh) {
		eprintf("Cannot allocate file hash\n");
		return false;
	}

	fh->type = strdup(name);
	fh->hex = strdup(hash);
	rz_list_push(list, fh);
	return true;
}

RZ_API RzList *rz_bin_file_compute_hashes(RzBin *bin, RzBinFile *bf, ut64 limit) {
	rz_return_val_if_fail(bin && bf && bf->o, NULL);
	ut64 buf_len = 0, r = 0;
	RzBinObject *o = bf->o;
	RzList *file_hashes = NULL;
	ut8 *buf = NULL;
	RzMsgDigest *md = NULL;
	const size_t blocksize = 64000;

	RzIODesc *iod = rz_io_desc_get(bin->iob.io, bf->fd);
	if (!iod) {
		return NULL;
	}

	buf_len = rz_io_desc_size(iod);
	// By SLURP_LIMIT normally cannot compute ...
	if (buf_len > limit) {
		if (bin->verbose) {
			eprintf("Warning: rz_bin_file_hash: file exceeds bin.hashlimit\n");
		}
		return NULL;
	}

	buf = malloc(blocksize);
	if (!buf) {
		eprintf("Cannot allocate computation buffer\n");
		return NULL;
	}

	file_hashes = rz_list_newf((RzListFree)rz_bin_file_hash_free);
	if (!file_hashes) {
		eprintf("Cannot allocate list\n");
		goto rz_bin_file_compute_hashes_bad;
	}

	md = rz_msg_digest_new();
	if (!md) {
		goto rz_bin_file_compute_hashes_bad;
	}

	if (!rz_msg_digest_configure(md, "md5") ||
		!rz_msg_digest_configure(md, "sha1") ||
		!rz_msg_digest_configure(md, "sha256")) {
		goto rz_bin_file_compute_hashes_bad;
	}
	if (!rz_msg_digest_init(md)) {
		goto rz_bin_file_compute_hashes_bad;
	}

	while (r + blocksize < buf_len) {
		rz_io_desc_seek(iod, r, RZ_IO_SEEK_SET);
		int b = rz_io_desc_read(iod, buf, blocksize);
		if (b < 0) {
			RZ_LOG_ERROR("rz_io_desc_read: can't read\n");
			goto rz_bin_file_compute_hashes_bad;
		} else if (!rz_msg_digest_update(md, buf, b)) {
			goto rz_bin_file_compute_hashes_bad;
		}
		r += b;
	}
	if (r < buf_len) {
		rz_io_desc_seek(iod, r, RZ_IO_SEEK_SET);
		const size_t rem_len = buf_len - r;
		int b = rz_io_desc_read(iod, buf, rem_len);
		if (b < 1) {
			RZ_LOG_ERROR("rz_io_desc_read: can't read\n");
		} else if (!rz_msg_digest_update(md, buf, b)) {
			goto rz_bin_file_compute_hashes_bad;
		}
	}

	if (!rz_msg_digest_final(md)) {
		goto rz_bin_file_compute_hashes_bad;
	}

	if (!add_file_hash(md, "md5", file_hashes) ||
		!add_file_hash(md, "sha1", file_hashes) ||
		!add_file_hash(md, "sha256", file_hashes)) {
		goto rz_bin_file_compute_hashes_bad;
	}

	if (o->plugin && o->plugin->hashes) {
		RzList *plugin_hashes = o->plugin->hashes(bf);
		rz_list_join(file_hashes, plugin_hashes);
		rz_list_free(plugin_hashes);
	}

	// TODO: add here more rows
	free(buf);
	rz_msg_digest_free(md);
	return file_hashes;

rz_bin_file_compute_hashes_bad:
	free(buf);
	rz_msg_digest_free(md);
	rz_list_free(file_hashes);
	return NULL;
}

// Set new hashes to current RzBinInfo, caller should free the returned RzList
RZ_API RzList *rz_bin_file_set_hashes(RzBin *bin, RzList /*<RzBinFileHash*/ *new_hashes) {
	rz_return_val_if_fail(bin && bin->cur && bin->cur->o && bin->cur->o->info, NULL);
	RzBinFile *bf = bin->cur;
	RzBinInfo *info = bf->o->info;

	RzList *prev_hashes = info->file_hashes;
	info->file_hashes = new_hashes;

	return prev_hashes;
}

RZ_IPI RzBinClass *rz_bin_class_new(const char *name, const char *super, int view) {
	rz_return_val_if_fail(name, NULL);
	RzBinClass *c = RZ_NEW0(RzBinClass);
	if (c) {
		c->name = strdup(name);
		c->super = super ? strdup(super) : NULL;
		c->methods = rz_list_new();
		c->fields = rz_list_new();
		c->visibility = view;
	}
	return c;
}

RZ_IPI void rz_bin_class_free(RzBinClass *k) {
	if (k && k->name) {
		free(k->name);
		free(k->super);
		rz_list_free(k->methods);
		rz_list_free(k->fields);
		free(k->visibility_str);
		free(k);
	}
}

RZ_API RzBinClass *rz_bin_file_add_class(RzBinFile *bf, const char *name, const char *super, int view) {
	rz_return_val_if_fail(name && bf && bf->o, NULL);
	RzBinClass *c = __getClass(bf, name);
	if (c) {
		if (super) {
			free(c->super);
			c->super = strdup(super);
		}
		return c;
	}
	c = rz_bin_class_new(name, super, view);
	if (c) {
		// XXX. no need for a list, the ht is iterable too
		c->index = rz_list_length(bf->o->classes);
		rz_list_append(bf->o->classes, c);
		ht_pp_insert(bf->o->classes_ht, name, c);
	}
	return c;
}

RZ_API RzBinSymbol *rz_bin_file_add_method(RzBinFile *bf, const char *klass, const char *method, int nargs) {
	rz_return_val_if_fail(bf, NULL);

	RzBinClass *c = rz_bin_file_add_class(bf, klass, NULL, 0);
	if (!c) {
		eprintf("Cannot allocate class %s\n", klass);
		return NULL;
	}
	RzBinSymbol *sym = __getMethod(bf, klass, method);
	if (!sym) {
		sym = RZ_NEW0(RzBinSymbol);
		if (sym) {
			sym->name = strdup(method);
			rz_list_append(c->methods, sym);
			const char *name = sdb_fmt("%s::%s", klass, method);
			ht_pp_insert(bf->o->methods_ht, name, sym);
		}
	}
	return sym;
}

RZ_API RzBinField *rz_bin_file_add_field(RzBinFile *binfile, const char *classname, const char *name) {
	//TODO: add_field into class
	//eprintf ("TODO add field: %s \n", name);
	return NULL;
}

RZ_API RzList *rz_bin_file_get_trycatch(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->plugin, NULL);
	if (bf->o->plugin->trycatch) {
		return bf->o->plugin->trycatch(bf);
	}
	return NULL;
}

RZ_API RzList *rz_bin_file_get_symbols(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	RzBinObject *o = bf->o;
	return o ? (RzList *)rz_bin_object_get_symbols(o) : NULL;
}
