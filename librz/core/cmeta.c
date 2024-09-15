// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 thestr4ng3r <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

RZ_IPI void rz_core_spaces_print(RzCore *core, RzSpaces *spaces, RzCmdStateOutput *state) {
	const RzSpace *cur = rz_spaces_current(spaces);
	rz_cmd_state_output_array_start(state);
	RzSpace *s;
	PJ *pj = state->d.pj;
	RzSpaceIter it;
	rz_spaces_foreach(spaces, it, s) {
		int count = rz_spaces_count(spaces, s->name);
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_o(pj);
			pj_ks(pj, "name", s->name);
			pj_ki(pj, "count", count);
			pj_kb(pj, "selected", cur == s);
			pj_end(pj);
			break;
		case RZ_OUTPUT_MODE_QUIET:
			rz_cons_printf("%s\n", s->name);
			break;
		case RZ_OUTPUT_MODE_RIZIN:
			rz_cons_printf("%s %s\n", spaces->name, s->name);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("%5d %c %s\n", count,
				(!cur || cur == s) ? '*' : '.', s->name);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	rz_cmd_state_output_array_end(state);
	if (state->mode == RZ_OUTPUT_MODE_RIZIN && rz_spaces_current(spaces)) {
		rz_cons_printf("%s %s # current\n", spaces->name, rz_spaces_current_name(spaces));
	}
}

static char *meta_string_escape(RzCore *core, RzAnalysisMetaItem *mi) {
	char *esc_str = NULL;
	RzStrEscOptions opt = { 0 };
	opt.show_asciidot = false;
	opt.esc_bslash = core->print->esc_bslash;
	switch (mi->subtype) {
	case RZ_STRING_ENC_UTF16LE:
	case RZ_STRING_ENC_UTF16BE:
	case RZ_STRING_ENC_UTF32LE:
	case RZ_STRING_ENC_UTF32BE:
	case RZ_STRING_ENC_UTF8:
		// All strings that are put into the metadata are already converted
		esc_str = rz_str_escape_utf8(mi->str, &opt);
		break;
	case RZ_STRING_ENC_IBM037:
	case RZ_STRING_ENC_IBM290:
	case RZ_STRING_ENC_EBCDIC_UK:
	case RZ_STRING_ENC_EBCDIC_US:
	case RZ_STRING_ENC_EBCDIC_ES:
	case RZ_STRING_ENC_8BIT:
		esc_str = rz_str_escape_8bit(mi->str, false, &opt);
		break;
	default:
		rz_warn_if_reached();
	}
	return esc_str;
}

RZ_IPI void rz_core_meta_print(RzCore *core, RzAnalysisMetaItem *d, ut64 start, ut64 size, bool show_full, RzCmdStateOutput *state) {
	if (rz_spaces_current(&core->analysis->meta_spaces) &&
		rz_spaces_current(&core->analysis->meta_spaces) != d->space) {
		return;
	}
	PJ *pj = state->d.pj;
	RzOutputMode mode = state->mode;
	char *pstr, *base64_str;
	char *str = NULL;
	if (d->str) {
		if (d->type == RZ_META_TYPE_STRING) {
			str = meta_string_escape(core, d);
		} else {
			str = rz_str_escape(d->str);
		}
	}
	if (str || d->type == RZ_META_TYPE_DATA) {
		if (d->type == RZ_META_TYPE_STRING && !*str) {
			free(str);
			return;
		}
		if (!str) {
			pstr = "";
		} else if (d->type == RZ_META_TYPE_FORMAT) {
			pstr = str;
		} else if (d->type == RZ_META_TYPE_STRING) {
			pstr = str;
		} else if (d->type == RZ_META_TYPE_VARTYPE) {
			// Sanitize (don't escape) Ct comments so we can see "char *", etc.
			free(str);
			str = rz_str_dup(d->str);
			rz_str_sanitize(str);
			pstr = str;
		} else if (d->type != RZ_META_TYPE_COMMENT) {
			rz_name_filter(str, 0, true);
			pstr = str;
		} else {
			pstr = d->str;
		}
		switch (mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_o(pj);
			pj_kn(pj, "offset", start);
			pj_ks(pj, "type", rz_meta_type_to_string(d->type));

			if (d->type == RZ_META_TYPE_HIGHLIGHT) {
				pj_k(pj, "color");
				ut8 r = 0, g = 0, b = 0, A = 0;
				const char *esc = strchr(d->str, '\x1b');
				if (esc) {
					rz_cons_rgb_parse(esc, &r, &g, &b, &A);
					char *rgb_str = rz_cons_rgb_tostring(r, g, b);
					base64_str = rz_base64_encode_dyn((const ut8 *)rgb_str, strlen(rgb_str));
					if (d->type == RZ_META_TYPE_STRING && base64_str) {
						pj_s(pj, base64_str);
					} else {
						pj_s(pj, rgb_str);
					}
					free(base64_str);
					free(rgb_str);
				} else {
					pj_s(pj, str);
				}
			} else {
				pj_k(pj, "name");
				if (d->type == RZ_META_TYPE_STRING && (base64_str = rz_base64_encode_dyn((const ut8 *)d->str, strlen(d->str)))) {
					pj_s(pj, base64_str);
					free(base64_str);
				} else {
					pj_s(pj, rz_str_get(str));
				}
			}
			if (d->type == RZ_META_TYPE_DATA) {
				pj_kn(pj, "size", size);
			} else if (d->type == RZ_META_TYPE_STRING) {
				const char *enc = rz_str_enc_as_string(d->subtype);
				pj_ks(pj, "enc", enc);
				pj_kb(pj, "ascii", rz_str_is_ascii(d->str));
			}
			pj_end(pj);
			break;
		case RZ_OUTPUT_MODE_RIZIN:
		default:
			switch (d->type) {
			case RZ_META_TYPE_COMMENT: {
				const char *type = rz_meta_type_to_string(d->type);
				char *s = sdb_encode((const ut8 *)pstr, -1);
				if (!s) {
					s = rz_str_dup(pstr);
				}
				if (mode == RZ_OUTPUT_MODE_RIZIN) {
					if (!strcmp(type, "CCu")) {
						rz_cons_printf("%s base64:%s @ 0x%08" PFMT64x "\n",
							type, s, start);
					} else {
						rz_cons_printf("%s %s @ 0x%08" PFMT64x "\n",
							type, pstr, start);
					}
				} else {
					if (!strcmp(type, "CCu")) {
						char *mys = rz_str_escape(pstr);
						rz_cons_printf("0x%08" PFMT64x " %s \"%s\"\n",
							start, type, mys);
						free(mys);
					} else {
						rz_cons_printf("0x%08" PFMT64x " %s \"%s\"\n",
							start, type, pstr);
					}
				}
				free(s);
			} break;
			case RZ_META_TYPE_STRING:
				if (mode == RZ_OUTPUT_MODE_RIZIN) {
					char cmd[] = "Cs#";
					switch (d->subtype) {
					case RZ_STRING_ENC_8BIT:
					case RZ_STRING_ENC_UTF8:
						cmd[2] = d->subtype;
						break;
					case RZ_STRING_ENC_UTF16LE:
					case RZ_STRING_ENC_UTF16BE:
						cmd[2] = 'w';
						break;
					case RZ_STRING_ENC_UTF32LE:
					case RZ_STRING_ENC_UTF32BE:
						cmd[2] = 'W';
						break;
					default:
						cmd[2] = 0;
					}
					rz_cons_printf("%s %" PFMT64u " @ 0x%08" PFMT64x " # %s\n",
						cmd, size, start, pstr);
				} else {
					const char *enc;
					if (d->subtype == RZ_STRING_ENC_8BIT) {
						enc = rz_str_is_ascii(d->str) ? "ascii" : "8bit";
					} else {
						enc = rz_str_enc_as_string(d->subtype);
					}
					if (show_full || mode == RZ_OUTPUT_MODE_LONG) {
						rz_cons_printf("0x%08" PFMT64x " %s[%" PFMT64u "] \"%s\"\n",
							start, enc, size, pstr);
					} else if (mode == RZ_OUTPUT_MODE_STANDARD) {
						rz_cons_printf("%s[%" PFMT64u "] \"%s\"\n",
							enc, size, pstr);
					} else {
						rz_cons_printf("\"%s\"\n", pstr);
					}
				}
				break;
			case RZ_META_TYPE_HIDE:
			case RZ_META_TYPE_DATA:
				if (mode == RZ_OUTPUT_MODE_RIZIN) {
					rz_cons_printf("%s %" PFMT64u " @ 0x%08" PFMT64x "\n",
						rz_meta_type_to_string(d->type),
						size, start);
				} else {
					if (show_full || mode == RZ_OUTPUT_MODE_LONG) {
						const char *dtype = d->type == RZ_META_TYPE_HIDE ? "hidden" : "data";
						rz_cons_printf("0x%08" PFMT64x " %s %s %" PFMT64u "\n",
							start, dtype,
							rz_meta_type_to_string(d->type), size);
					} else {
						rz_cons_printf("%" PFMT64u "\n", size);
					}
				}
				break;
			case RZ_META_TYPE_MAGIC:
			case RZ_META_TYPE_FORMAT:
				if (mode == RZ_OUTPUT_MODE_RIZIN) {
					rz_cons_printf("%s %" PFMT64u " %s @ 0x%08" PFMT64x "\n",
						rz_meta_type_to_string(d->type),
						size, pstr, start);
				} else {
					if (show_full || mode == RZ_OUTPUT_MODE_LONG) {
						const char *dtype = d->type == RZ_META_TYPE_MAGIC ? "magic" : "format";
						rz_cons_printf("0x%08" PFMT64x " %s %" PFMT64u " %s\n",
							start, dtype, size, pstr);
					} else {
						rz_cons_printf("%" PFMT64u " %s\n", size, pstr);
					}
				}
				break;
			case RZ_META_TYPE_VARTYPE:
				if (mode == RZ_OUTPUT_MODE_RIZIN) {
					rz_cons_printf("%s %s @ 0x%08" PFMT64x "\n",
						rz_meta_type_to_string(d->type), pstr, start);
				} else {
					rz_cons_printf("0x%08" PFMT64x " %s\n", start, pstr);
				}
				break;
			case RZ_META_TYPE_HIGHLIGHT: {
				ut8 r = 0, g = 0, b = 0, A = 0;
				const char *esc = strchr(d->str, '\x1b');
				rz_cons_rgb_parse(esc, &r, &g, &b, &A);
				rz_cons_printf("%s rgb:%02x%02x%02x @ 0x%08" PFMT64x "\n",
					rz_meta_type_to_string(d->type), r, g, b, start);
				// TODO: d->size
			} break;
			default:
				if (mode == RZ_OUTPUT_MODE_RIZIN) {
					rz_cons_printf("%s %" PFMT64u " 0x%08" PFMT64x " # %s\n",
						rz_meta_type_to_string(d->type),
						size, start, pstr);
				} else {
					// TODO: use b64 here
					rz_cons_printf("0x%08" PFMT64x " array[%" PFMT64u "] %s %s\n",
						start, size,
						rz_meta_type_to_string(d->type), pstr);
				}
				break;
			}
			break;
		}
		if (str) {
			free(str);
		}
	}
}

typedef struct {
	RzAnalysisMetaType type;
	const RzSpace *space;

	RzPVector /*<RzIntervalNode *>*/ *result;
} CollectCtx;

static bool item_matches_filter(RzAnalysisMetaItem *item, RzAnalysisMetaType type, RZ_NULLABLE const RzSpace *space) {
	return (type == RZ_META_TYPE_ANY || item->type == type) && (!space || item->space == space);
}

static bool collect_nodes_cb(RzIntervalNode *node, void *user) {
	CollectCtx *ctx = user;
	if (item_matches_filter(node->data, ctx->type, ctx->space)) {
		rz_pvector_push(ctx->result, node);
	}
	return true;
}

static RzPVector /*<RzIntervalNode *>*/ *collect_nodes_at(RzAnalysis *analysis, RzAnalysisMetaType type, RZ_NULLABLE const RzSpace *space, ut64 addr) {
	CollectCtx ctx = {
		.type = type,
		.space = space,
		.result = rz_pvector_new(NULL)
	};
	if (!ctx.result) {
		return NULL;
	}
	rz_interval_tree_all_at(&analysis->meta, addr, collect_nodes_cb, &ctx);
	return ctx.result;
}

RZ_IPI void rz_core_meta_print_list_at(RzCore *core, ut64 addr, RzCmdStateOutput *state) {
	RzPVector *nodes = collect_nodes_at(core->analysis, RZ_META_TYPE_ANY,
		rz_spaces_current(&core->analysis->meta_spaces), addr);
	if (!nodes) {
		return;
	}
	rz_cmd_state_output_array_start(state);
	void **it;
	rz_pvector_foreach (nodes, it) {
		RzIntervalNode *node = *it;
		rz_core_meta_print(core, node->data, node->start, rz_meta_node_size(node), true, state);
	}
	rz_pvector_free(nodes);
	rz_cmd_state_output_array_end(state);
}

static void print_meta_list(RzCore *core, RzAnalysisMetaType type, ut64 addr, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn = NULL;
	if (addr != UT64_MAX) {
		fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0);
		if (!fcn) {
			return;
		}
	}
	RzIntervalTreeIter it;
	RzAnalysisMetaItem *item;
	rz_interval_tree_foreach (&core->analysis->meta, it, item) {
		RzIntervalNode *node = rz_interval_tree_iter_get(&it);
		if (type != RZ_META_TYPE_ANY && item->type != type) {
			continue;
		}
		if (fcn && !rz_analysis_function_contains(fcn, node->start)) {
			continue;
		}
		rz_core_meta_print(core, item, node->start, rz_meta_node_size(node), true, state);
	}
}

RZ_IPI void rz_core_meta_print_list_all(RzCore *core, RzAnalysisMetaType type, RzCmdStateOutput *state) {
	rz_cmd_state_output_array_start(state);
	print_meta_list(core, type, UT64_MAX, state);
	rz_cmd_state_output_array_end(state);
}

RZ_IPI void rz_core_meta_print_list_in_function(RzCore *core, RzAnalysisMetaType type, ut64 addr, RzCmdStateOutput *state) {
	rz_cmd_state_output_array_start(state);
	print_meta_list(core, type, addr, state);
	rz_cmd_state_output_array_end(state);
}

RZ_IPI void rz_core_meta_append(RzCore *core, const char *newcomment, RzAnalysisMetaType mtype, ut64 addr) {
	const char *comment = rz_meta_get_string(core->analysis, mtype, addr);
	char *nc = rz_str_dup(newcomment);
	rz_str_unescape(nc);
	if (comment) {
		char *text = rz_str_newf("%s %s", comment, nc);
		if (text) {
			rz_meta_set_string(core->analysis, mtype, addr, text);
			free(text);
		} else {
			rz_sys_perror("malloc");
		}
	} else {
		rz_meta_set_string(core->analysis, mtype, addr, nc);
	}
	free(nc);
}

RZ_IPI void rz_core_meta_editor(RzCore *core, RzAnalysisMetaType mtype, ut64 addr) {
	const char *comment = rz_meta_get_string(core->analysis, mtype, addr);
	char *out = rz_core_editor(core, NULL, comment);
	if (out) {
		rz_meta_del(core->analysis, mtype, addr, 1);
		rz_meta_set_string(core->analysis, mtype, addr, out);
		free(out);
	}
}

/**
 * RzCoreMetaString
 * @{
 */

static bool meta_string_8bit_add(RzCore *core, ut64 addr, size_t limit, ut8 **name, size_t *name_len) {
	rz_return_val_if_fail(limit && name && name_len, false);
	*name = malloc(limit + 1);
	if (!*name) {
		return false;
	}
	if (!rz_io_read_at(core->io, addr, *name, limit)) {
		RZ_FREE(*name);
		return false;
	}
	(*name)[limit] = '\0';
	*name_len = strlen((char *)*name);
	return true;
}

static bool meta_string_guess_add(RzCore *core, ut64 addr, size_t limit, char **name_out, size_t *name_len, RzDetectedString **ds, RzStrEnc encoding) {
	rz_return_val_if_fail(limit && name_out && name_len && ds, false);
	char *name = malloc(limit + 1);
	if (!name) {
		return false;
	}
	RzBin *bin = core->bin;
	RzBinFile *bf = rz_bin_cur(bin);
	RzBinObject *obj = rz_bin_cur_object(bin);
	if (!bf || !obj || !bin) {
		free(name);
		return false;
	}
	bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");
	RzUtilStrScanOptions scan_opt = {
		.buf_size = bin->str_search_cfg.buffer_size,
		.max_uni_blocks = bin->str_search_cfg.max_uni_blocks,
		.min_str_length = bin->str_search_cfg.min_length,
		.prefer_big_endian = big_endian,
		.check_ascii_freq = bin->str_search_cfg.check_ascii_freq,
	};
	RzList *str_list = rz_list_new();
	if (!str_list) {
		free(name);
		return false;
	}
	ut64 paddr = rz_io_v2p(core->io, addr);
	int count = rz_scan_strings(bf->buf, str_list, &scan_opt, paddr, paddr + limit, encoding);
	if (count <= 0) {
		rz_list_free(str_list);
		free(name);
		return false;
	}
	*ds = rz_list_first(str_list);
	rz_list_free(str_list);
	rz_str_ncpy(name, (*ds)->string, limit);
	name[limit] = '\0';
	*name_out = name;
	return true;
}

/**
 * \brief add a string to RzCore
 *
 * \param core RzCore of core that will be add to
 * \param addr string's address
 * \param size string's max size
 * \param encoding string's encoding
 * \param name string's value, or null that will be autodetect at \p addr
 * \return is add successful?
 */
RZ_API bool rz_core_meta_string_add(RzCore *core, ut64 addr, ut64 size, RzStrEnc encoding, RZ_NULLABLE const char *name) {
	char *guessname = NULL;
	size_t name_len = 0;
	ut64 limit = size ? size : core->blocksize;
	size_t n = 0;
	bool result = false;
	if (encoding == RZ_STRING_ENC_8BIT || encoding == RZ_STRING_ENC_UTF8) {
		if (!meta_string_8bit_add(core, addr, limit, (ut8 **)&guessname, &name_len)) {
			goto out;
		}
		n = size == 0 ? name_len + 1 : size;
	} else {
		RzDetectedString *ds = NULL;
		if (!meta_string_guess_add(core, addr, limit, &guessname, &name_len, &ds, encoding)) {
			return false;
		}
		if (!ds) {
			goto out;
		}
		encoding = ds->type;
		n = ds->size;
	}
	if (!name) {
		result = rz_meta_set_with_subtype(core->analysis, RZ_META_TYPE_STRING, encoding, addr, n, guessname);
	} else {
		result = rz_meta_set_with_subtype(core->analysis, RZ_META_TYPE_STRING, encoding, addr, n, name);
	}
out:
	free(guessname);
	return result;
}

/**
 * \brief add a pascal string to RzCore
 *
 * \param core RzCore of core that will be add to
 * \param addr string's address
 * \param size string's max size
 * \param encoding string's encoding
 * \param name string's value, or null that will be autodetect at \p addr
 * \return is add successful?
 */
RZ_API bool rz_core_meta_pascal_string_add(RzCore *core, ut64 addr, RzStrEnc encoding, RZ_NULLABLE const char *name) {
	rz_return_val_if_fail(encoding == RZ_STRING_ENC_8BIT || encoding == RZ_STRING_ENC_UTF8, false);
	// We shall read the first byte and it will be the size of the 8-bit or UTF-8 string
	RzBinFile *bf = rz_bin_cur(core->bin);
	if (!bf) {
		return false;
	}
	ut8 size;
	ut64 paddr = rz_io_v2p(core->io, addr);
	if (!rz_buf_read8_at(bf->buf, paddr, &size)) {
		return false;
	}
	// Note the offset is off by one since the first byte was the size of the string
	if (!rz_core_meta_string_add(core, core->offset + 1, size, encoding, NULL)) {
		return false;
	}
	return true;
}

/**@{*/
