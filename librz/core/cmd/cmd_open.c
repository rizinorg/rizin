// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_debug.h>
#include <rz_core.h>
#include <rz_io.h>

struct open_list_ascii_data_t {
	RzPrint *p;
	int fdsz;
};

static const char *help_msg_o[] = {
	"Usage: o", "[com- ] [file] ([offset])", "",
	"o", " [file] 0x4000 rwx", "map file at 0x4000",
	"o", " [file]", "open [file] file in read-only",
	"o", "", "list opened files",
	"o*", "", "list opened files in rizin commands",
	"o+", " [file]", "open file in read-write mode",
	"o-", " 1", "close file descriptor 1",
	"o--", "", "close all opened files",
	"o.", "", "show current filename (or o.q/oq to get the fd)",
	"oC", " [len]", "open a malloc://[len] copying the bytes from current offset",
	"o=", "", "list opened files (ascii-art bars)",
	"oL", "", "list all IO plugins registered",
	"oa", "[-] [A] [B] [filename]", "Specify arch and bits for given file",
	"ob", "[?] [lbdos] [...]", "list opened binary files backed by fd",
	"oc", " [file]", "open core file, like relaunching rizin",
	"oi", "[-|idx]", "alias for o, but using index instead of fd",
	"oj", "[?]	", "list opened files in JSON format",
	"om", "[?]", "create, list, remove IO maps",
	"on", " [file] 0x4000", "map raw file at 0x4000 (no rz_bin involved)",
	"oo", "[?+bcdnm]", "reopen current file (see oo?) (reload in rw or debugger)",
	"op", "[r|n|p|fd]", "select priorized file by fd (see ob), opn/opp/opr = next/previous/rotate",
	"oq", "", "list all open files",
	"ou", "[fd]", "select fd to use",
	"ox", " fd fdx", "exchange the descs of fd and fdx and keep the mapping",
	NULL
};

static const char *help_msg_o_star[] = {
	"Usage:", "o* [> files.rz]", "",
	"o*", "", "list opened files in rizin commands", NULL
};

static const char *help_msg_oa[] = {
	"Usage:", "oba [addr] ([filename])", " # load bininfo and update flags",
	"oba", " [addr]", "Open bin info from the given address",
	"oba", " [addr] [baddr]", "Open file and load bin info at given address",
	"oba", " [addr] [/abs/filename]", "Open file and load bin info at given address",
	NULL
};

static const char *help_msg_ob[] = {
	"Usage:", "ob", " # List open binary files backed by fd",
	"ob", " [bfid]", "Switch to open given objid",
	"ob", "", "List opened binary files and objid",
	"ob*", "", "List opened binary files and objid (rizin commands)",
	"ob-", "*", "Delete all binfiles",
	"ob-", "[objid]", "Delete binfile by binobjid",
	"ob.", " ([addr])", "Show bfid at current address",
	"ob=", "", "Show ascii art table having the list of open files",
	"obL", "", "Same as iL or Li",
	"oba", " [addr] [baddr]", "Open file and load bin info at given address",
	"oba", " [addr] [filename]", "Open file and load bin info at given address",
	"oba", " [addr]", "Open bin info from the given address",
	"obf", " ([file])", "Load bininfo for current file (useful for rizin -n)",
	"obj", "", "List opened binary files and objid (JSON format)",
	"obn", " [name]", "Select binfile by name",
	"obo", " [fd]", "Switch to open binfile by fd number",
	"obr", " [baddr]", "Rebase current bin object",
	"obR", " [baddr]", "Reload the current buffer for setting of the bin (use once only)",
	NULL
};

static const char *help_msg_oj[] = {
	"Usage:", "oj [~{}]", " # Use ~{} to indent the JSON",
	"oj", "", "list opened files in JSON format", NULL
};

static const char *help_msg_om[] = {
	"Usage:", "om[-] [arg]", " # map opened files",
	"om", " [fd]", "list all defined IO maps for a specific fd",
	"om", " fd vaddr [size] [paddr] [rwx] [name]", "create new io map",
	"om", "", "list all defined IO maps",
	"om*", "", "list all maps in rizin commands format",
	"om-", "mapid", "remove the map with corresponding id",
	"om-*", "", "remove all maps",
	"om-..", "", "hud view of all the maps to select the one to remove",
	"om.", "", "show map, that is mapped to current offset",
	"om=", "", "list all maps in ascii art",
	"oma", " [fd]", "create a map covering all VA for given fd",
	"omb", " mapid addr", "relocate map with corresponding id",
	"omb.", " addr", "relocate current map",
	"omf", " [mapid] rwx", "change flags/perms for current/given map",
	"omfg", "[+-]rwx", "change flags/perms for all maps (global)",
	"omj", "", "list all maps in json format",
	"omm", " [fd]", "create default map for given fd. (omm `oq`)",
	"omn", " mapaddr [name]", "set/delete name for map which spans mapaddr",
	"omn.", "([-|name])", "show/set/delete name for current map",
	"omni", " mapid [name]", "set/delete name for map with mapid",
	"omo", " fd", "map the given fd with lowest priority",
	"omp", " mapid", "prioritize map with corresponding id",
	"ompb", " [fd]", "prioritize maps of the bin associated with the binid",
	"ompd", " mapid", "deprioritize map with corresponding id",
	"ompf", " [fd]", "prioritize map by fd",
	"omq", "", "list all maps and their fds",
	"omqq", "", "list all maps addresses (See $MM to get the size)",
	"omr", " mapid newsize", "resize map with corresponding id",
	"omt", "[q] [query]", "list maps using table api",
	NULL
};

static const char *help_msg_oo[] = {
	"Usage:", "oo[-] [arg]", " # map opened files",
	"oo", "", "reopen current file",
	"oo+", "", "reopen in read-write",
	"oob", " [baddr]", "reopen loading rbin info (change base address?)",
	"ooc", "", "reopen core with current file",
	"ood", "", "reopen in debug mode",
	"oom", "", "reopen in malloc://",
	"oon", "", "reopen without loading rbin info",
	"oon+", "", "reopen in read-write mode without loading rbin info",
	"oonn", "", "reopen without loading rbin info, but with header flags",
	"oonn+", "", "reopen in read-write mode without loading rbin info, but with",
	NULL
};

static const char *help_msg_oo_plus[] = {
	"Usage:", "oo+", " # reopen in read-write",
	NULL
};

static const char *help_msg_oob[] = {
	"Usage:", "oob", " # reopen loading rbin info",
	NULL
};

static const char *help_msg_ood[] = {
	"Usage:", "ood", " # Debug (re)open commands",
	"ood", " [args]", " # reopen in debug mode (with args)",
	"oodf", " [file]", " # reopen in debug mode using the given file",
	"oodr", " [rz-run]", " # same as dor ..;ood",
	NULL
};

static const char *help_msg_oon[] = {
	"Usage:", "oon[+]", " # reopen without loading rbin info",
	"oon", "", "reopen without loading rbin info",
	"oon+", "", "reopen in read-write mode without loading rbin info",
	NULL
};

static const char *help_msg_oonn[] = {
	"Usage:", "oonn", " # reopen without loading rbin info, but with header flags",
	"oonn", "", "reopen without loading rbin info, but with header flags",
	"oonn+", "", "reopen in read-write mode without loading rbin info, but with",
	NULL
};

static bool core_bin_reload(RzCore *r, const char *file, ut64 baseaddr) {
	RzCoreFile *cf = rz_core_file_cur(r);
	if (!cf) {
		return false;
	}
	RzBinFile *obf = rz_bin_file_find_by_fd(r->bin, cf->fd);
	if (!obf) {
		return false;
	}
	RzBinFile *nbf = rz_bin_reload(r->bin, obf, baseaddr);
	if (!nbf) {
		return false;
	}
	rz_core_bin_apply_all_info(r, nbf);
	return true;
}

// HONOR bin.at
static void cmd_open_bin(RzCore *core, const char *input) {
	const char *value = NULL;
	ut32 binfile_num = -1;
	RzCmdStateOutput state = { 0 };

	switch (input[1]) {
	case 'L': // "obL"
		state.mode = RZ_OUTPUT_MODE_STANDARD;
		rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_STANDARD);
		rz_core_bin_plugins_print(core->bin, &state);
		rz_cmd_state_output_print(&state);
		rz_cmd_state_output_fini(&state);
		break;
	case '\0': // "ob"
	case 'q': // "obj"
	case 'j': // "obj"
	case '*': // "ob*"
		rz_core_bin_list(core, input[1]);
		if (input[1] == 'j') {
			rz_cons_newline();
		}
		break;
	case '.': // "ob."
	{
		const char *arg = rz_str_trim_head_ro(input + 2);
		ut64 at = core->offset;
		if (*arg) {
			at = rz_num_math(core->num, arg);
			if (at == 0 && *arg != '0') {
				at = core->offset;
			}
		}
		RzBinFile *bf = rz_bin_file_at(core->bin, at);
		if (bf) {
			rz_cons_printf("%d\n", bf->id);
		}
	} break;
	case 'a': // "oba"
		if ('?' == input[2]) {
			rz_core_cmd_help(core, help_msg_oa);
			break;
		}
		if (input[2] && input[3]) {
			char *arg = strdup(input + 3);
			char *filename = strchr(arg, ' ');
			if (filename && *filename && (filename[1] == '/' || filename[1] == '.')) {
				int saved_fd = rz_io_fd_get_current(core->io);
				RzIODesc *desc = rz_io_open(core->io, filename + 1, RZ_PERM_R, 0);
				if (desc) {
					*filename = 0;
					ut64 addr = rz_num_math(core->num, arg);
					RzBinOptions opt;
					rz_core_bin_options_init(core, &opt, desc->fd, addr, 0);
					RzBinFile *bf = rz_bin_open_io(core->bin, &opt);
					rz_io_desc_close(desc);
					rz_core_bin_apply_all_info(core, bf);
					rz_io_use_fd(core->io, saved_fd);
				} else {
					eprintf("Cannot open %s\n", filename + 1);
				}
			} else if (filename && *filename) {
				ut64 baddr = rz_num_math(core->num, filename);
				ut64 addr = rz_num_math(core->num, input + 2); // mapaddr
				int fd = rz_io_fd_get_current(core->io);
				RzIODesc *desc = rz_io_desc_get(core->io, fd);
				if (desc) {
					RzBinOptions opt;
					opt.sz = 1024 * 1024 * 1;
					rz_core_bin_options_init(core, &opt, desc->fd, baddr, addr);
					RzBinFile *bf = rz_bin_open_io(core->bin, &opt);
					rz_core_bin_apply_all_info(core, bf);
				} else {
					eprintf("No file to load bin from?\n");
				}
			} else {
				ut64 addr = rz_num_math(core->num, input + 2);
				int fd = rz_io_fd_get_current(core->io);
				RzIODesc *desc = rz_io_desc_get(core->io, fd);
				if (desc) {
					RzBinOptions opt;
					opt.sz = 1024 * 1024 * 1;
					rz_core_bin_options_init(core, &opt, desc->fd, addr, addr);
					RzBinFile *bf = rz_bin_open_io(core->bin, &opt);
					rz_core_bin_apply_all_info(core, bf);
				} else {
					eprintf("No file to load bin from?\n");
				}
			}
			free(arg);
		} else {
			RzList *ofiles = rz_id_storage_list(core->io->files);
			RzIODesc *desc;
			RzListIter *iter;
			RzList *files = rz_list_newf(NULL);
			rz_list_foreach (ofiles, iter, desc) {
				rz_list_append(files, (void *)(size_t)desc->fd);
			}

			void *_fd;
			rz_list_foreach (files, iter, _fd) {
				int fd = (size_t)_fd;
				RzBinOptions opt;
				rz_core_bin_options_init(core, &opt, fd, core->offset, 0);
				RzBinFile *bf = rz_bin_open_io(core->bin, &opt);
				rz_core_bin_apply_all_info(core, bf);
				break;
			}
			rz_list_free(files);
		}
		break;
	case ' ': // "ob "
	{
		ut32 id;
		int n;
		const char *tmp;
		char *v;
		v = input[2] ? strdup(input + 2) : NULL;
		if (!v) {
			eprintf("Invalid arguments");
			break;
		}
		n = rz_str_word_set0(v);
		if (n < 1 || n > 2) {
			eprintf("Usage: ob [file|objid]\n");
			free(v);
			break;
		}
		tmp = rz_str_word_get0(v, 0);
		id = *v && rz_is_valid_input_num_value(core->num, tmp)
			? rz_get_input_num_value(core->num, tmp)
			: UT32_MAX;
		if (n != 2) {
			binfile_num = id;
		}
		rz_core_bin_raise(core, binfile_num);
		free(v);
		break;
	}
	case 'r': // "obr"
		rz_core_bin_rebase(core, rz_num_math(core->num, input + 3));
		rz_core_bin_apply_all_info(core, rz_bin_cur(core->bin));
		break;
	case 'R': // "obR"
		// XXX: this will reload the bin using the buffer.
		// An assumption is made that assumes there is an underlying
		// plugin that will be used to load the bin (e.g. malloc://)
		// TODO: Might be nice to reload a bin at a specified offset?
		core_bin_reload(core, NULL, input[2] ? rz_num_math(core->num, input + 3) : 0);
		rz_core_block_read(core);
		break;
	case 'f':
		if (input[2] == ' ') {
			rz_core_cmdf(core, "oba 0 %s", input + 3);
		} else {
			rz_core_bin_load(core, NULL, UT64_MAX);
		}
		break;
	case 'o': // "obo"
		if (input[2] == ' ') {
			ut32 fd = rz_num_math(core->num, input + 3);
			RzBinFile *bf = rz_bin_file_find_by_fd(core->bin, fd);
			if (!bf || !rz_core_bin_raise(core, bf->id)) {
				eprintf("Invalid RzBinFile.id number.\n");
			}
		} else {
			eprintf("Usage: obb [bfid]\n");
		}
		break;
	case '-': // "ob-"
		if (input[2] == '*') {
			rz_bin_file_delete_all(core->bin);
		} else {
			ut32 id;
			value = rz_str_trim_head_ro(input + 2);
			if (!value) {
				eprintf("Invalid argument\n");
				break;
			}
			id = (*value && rz_is_valid_input_num_value(core->num, value)) ? rz_get_input_num_value(core->num, value) : UT32_MAX;
			RzBinFile *bf = rz_bin_file_find_by_id(core->bin, id);
			if (!bf || !rz_core_bin_delete(core, bf)) {
				eprintf("Cannot find an RzBinFile associated with that id.\n");
			}
		}
		break;
	case '=': // "ob="
	{
		RzListIter *iter;
		RzList *list = rz_list_newf((RzListFree)rz_listinfo_free);
		RzBinFile *bf = NULL;
		RzBin *bin = core->bin;
		if (!bin) {
			return;
		}
		rz_list_foreach (bin->binfiles, iter, bf) {
			char temp[64];
			RzInterval inter = (RzInterval){ bf->o->opts.baseaddr, bf->o->size };
			RzListInfo *info = rz_listinfo_new(bf->file, inter, inter, -1, sdb_itoa(bf->fd, temp, 10));
			if (!info) {
				break;
			}
			rz_list_append(list, info);
		}
		RzTable *table = rz_core_table(core);
		rz_table_visual_list(table, list, core->offset, core->blocksize,
			rz_cons_get_size(NULL), rz_config_get_i(core->config, "scr.color"));
		char *table_text = rz_table_tostring(table);
		rz_cons_printf("\n%s\n", table_text);
		rz_free(table_text);
		rz_table_free(table);
		rz_list_free(list);
	} break;
	case '?': // "ob?"
		rz_core_cmd_help(core, help_msg_ob);
		break;
	}
}

// TODO: discuss the output format
static void map_list(RzIO *io, int mode, RzPrint *print, int fd) {
	if (!io || !print || !print->cb_printf) {
		return;
	}
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = pj_new();
		if (!pj) {
			return;
		}
		pj_a(pj);
	}
	char *om_cmds = NULL;

	void **it;
	RzPVector *maps = rz_io_maps(io);
	rz_pvector_foreach (maps, it) {
		RzIOMap *map = *it;
		if (fd >= 0 && map->fd != fd) {
			continue;
		}
		switch (mode) {
		case 'q':
			if (fd == -2) {
				print->cb_printf("0x%08" PFMT64x "\n", rz_io_map_get_from(map));
			} else {
				print->cb_printf("%d %d\n", map->fd, map->id);
			}
			break;
		case 'j':
			pj_o(pj);
			pj_ki(pj, "map", map->id);
			pj_ki(pj, "fd", map->fd);
			pj_kn(pj, "delta", map->delta);
			pj_kn(pj, "from", rz_io_map_get_from(map));
			pj_kn(pj, "to", rz_itv_end(map->itv));
			pj_ks(pj, "perm", rz_str_rwx_i(map->perm));
			pj_ks(pj, "name", rz_str_get(map->name));
			pj_end(pj);
			break;
		case 1:
		case '*':
		case 'r': {
			// Need FIFO order here
			char *om_cmd = rz_str_newf("om %d 0x%08" PFMT64x " 0x%08" PFMT64x " 0x%08" PFMT64x " %s%s%s\n",
				map->fd, rz_io_map_get_from(map), map->itv.size, map->delta, rz_str_rwx_i(map->perm),
				map->name ? " " : "", rz_str_get(map->name));
			if (om_cmd) {
				om_cmds = rz_str_prepend(om_cmds, om_cmd);
				free(om_cmd);
			}
			break;
		}
		default:
			print->cb_printf("%2d fd: %i +0x%08" PFMT64x " 0x%08" PFMT64x
					 " - 0x%08" PFMT64x " %s %s\n",
				map->id, map->fd,
				map->delta, rz_io_map_get_from(map), rz_io_map_get_to(map),
				rz_str_rwx_i(map->perm), rz_str_get(map->name));
			break;
		}
	}
	if (om_cmds) {
		print->cb_printf("%s", om_cmds);
		free(om_cmds);
	}
	if (mode == 'j') {
		pj_end(pj);
		print->cb_printf("%s\n", pj_string(pj));
		pj_free(pj);
	}
}

static void cmd_omfg(RzCore *core, const char *input) {
	input = rz_str_trim_head_ro(input);
	if (input) {
		int perm = *input
			? (*input == '+' || *input == '-')
				? rz_str_rwx(input + 1)
				: rz_str_rwx(input)
			: 7;
		void **it;
		RzPVector *maps = rz_io_maps(core->io);
		switch (*input) {
		case '+':
			rz_pvector_foreach (maps, it) {
				RzIOMap *map = *it;
				map->perm |= perm;
			}
			break;
		case '-':
			rz_pvector_foreach (maps, it) {
				RzIOMap *map = *it;
				map->perm &= ~perm;
			}
			break;
		default:
			rz_pvector_foreach (maps, it) {
				RzIOMap *map = *it;
				map->perm = perm;
			}
			break;
		}
	}
}

static void cmd_omf(RzCore *core, const char *input) {
	char *arg = strdup(rz_str_trim_head_ro(input));
	if (!arg) {
		return;
	}
	char *sp = strchr(arg, ' ');
	RzPVector *maps = rz_io_maps(core->io);
	if (sp) {
		// change perms of Nth map
		*sp++ = 0;
		int id = rz_num_math(core->num, arg);
		int perm = (*sp) ? rz_str_rwx(sp) : RZ_PERM_RWX;
		void **it;
		rz_pvector_foreach (maps, it) {
			RzIOMap *map = *it;
			if (map->id == id) {
				map->perm = perm;
				break;
			}
		}
	} else {
		// change perms of current map
		int perm = (arg && *arg) ? rz_str_rwx(arg) : RZ_PERM_RWX;
		void **it;
		rz_pvector_foreach (maps, it) {
			RzIOMap *map = *it;
			if (rz_itv_contain(map->itv, core->offset)) {
				map->perm = perm;
			}
		}
	}
	free(arg);
}

static void rz_core_cmd_omt(RzCore *core, const char *arg) {
	RzTable *t = rz_table_new();

	rz_table_set_columnsf(t, "nnnnnnnss", "id", "fd", "pa", "pa_end", "size", "va", "va_end", "perm", "name", NULL);

	void **it;
	RzPVector *maps = rz_io_maps(core->io);
	rz_pvector_foreach (maps, it) {
		RzIOMap *m = *it;
		ut64 va = rz_itv_begin(m->itv);
		ut64 va_end = rz_itv_end(m->itv);
		ut64 pa = m->delta;
		ut64 pa_size = rz_itv_size(m->itv);
		ut64 pa_end = pa + pa_size;
		const char *name = m->name ? m->name : "";
		rz_table_add_rowf(t, "ddxxxxxss", m->id, m->fd, pa, pa_end, pa_size, va, va_end, rz_str_rwx_i(m->perm), name);
	}

	t->showFancy = true;
	if (rz_table_query(t, arg)) {
		char *ts = rz_table_tostring(t);
		rz_cons_printf("%s", ts);
		free(ts);
	}
	rz_table_free(t);
}

RZ_IPI int rz_om_oldinput(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	ut64 fd = 0LL;
	ut32 id = 0;
	ut64 addr = 0;
	char *s = NULL, *p = NULL, *q = NULL;
	ut64 new;
	RzIOMap *map = NULL;
	const char *P;
	PJ *pj;

	switch (input[0]) {
	case '.': // "om."
		map = rz_io_map_get(core->io, core->offset);
		if (map) {
			if (input[1] == 'j') { // "om.j"
				pj = pj_new();
				if (!pj) {
					return 1;
				}
				pj_o(pj);
				pj_ki(pj, "map", map->id);
				pj_ki(pj, "fd", map->fd);
				pj_kn(pj, "delta", map->delta);
				pj_kn(pj, "from", rz_io_map_get_from(map));
				pj_kn(pj, "to", rz_itv_end(map->itv));
				pj_ks(pj, "perm", rz_str_rwx_i(map->perm));
				pj_ks(pj, "name", rz_str_get(map->name));
				pj_end(pj);

				core->print->cb_printf("%s\n", pj_string(pj));

				pj_free(pj);
			} else {
				core->print->cb_printf("%2d fd: %i +0x%08" PFMT64x " 0x%08" PFMT64x
						       " - 0x%08" PFMT64x " %s %s\n",
					map->id, map->fd,
					map->delta, rz_io_map_get_from(map), rz_io_map_get_to(map),
					rz_str_rwx_i(map->perm), rz_str_get(map->name));
			}
		}
		break;
	case 'r': // "omr"
		if (input[1] != ' ') {
			break;
		}
		P = strchr(input + 2, ' ');
		if (P) {
			id = (ut32)rz_num_math(core->num, input + 2); // mapid
			new = rz_num_math(core->num, P + 1);
			rz_io_map_resize(core->io, id, new);
		}
		break;
	case 'o': // "omo"
		if (input[1] == ' ') {
			rz_core_cmdf(core, "om %s 0x%08" PFMT64x " $s r omo", input + 1, core->offset);
		} else {
			rz_core_cmd0(core, "om `oq.` $B $s r");
		}
		rz_core_cmd0(core, "ompd `omq.`");
		break;
	case 'p':
		switch (input[1]) {
		case 'd': // "ompf"
			id = rz_num_math(core->num, input + 2); // mapid
			if (rz_io_map_exists_for_id(core->io, id)) {
				rz_io_map_depriorize(core->io, id);
			} else {
				eprintf("Cannot find any map with mapid %d\n", id);
			}
			break;
		case 'f': // "ompf"
			fd = rz_num_math(core->num, input + 2);
			if (!rz_io_map_priorize_for_fd(core->io, (int)fd)) {
				eprintf("Cannot prioritize any map for fd %d\n", (int)fd);
			}
			break;
		case 'b': // "ompb"
			id = (ut32)rz_num_math(core->num, input + 3);
			if (!rz_bin_file_set_cur_by_id(core->bin, id)) {
				eprintf("Cannot prioritize bin with fd %d\n", id);
			}
			break;
		case ' ': // "omp"
			id = rz_num_math(core->num, input + 2); // mapid
			if (rz_io_map_exists_for_id(core->io, id)) {
				rz_io_map_priorize(core->io, id);
				rz_core_block_read(core);
			} else {
				eprintf("Cannot find any map with mapid %d\n", id);
			}
			break;
		}
		break;
	case 't': // "omt"
		switch (input[1]) {
		case 'q': // "omtq"
		{
			const char *arg = rz_str_trim_head_ro(input + 2);
			char *query = rz_str_newf("%s%squiet", arg, *arg ? ":" : "");
			if (query) {
				rz_core_cmd_omt(core, query);
			}
			free(query);
			break;
		}
		default:
			rz_core_cmd_omt(core, input + 1);
			break;
		}
		break;
	case ' ': // "om"
		s = strdup(input + 1);
		if (!s) {
			break;
		}
		if (strchr(s, ' ')) {
			int fd = 0, rwx = 0;
			ut64 size = 0, vaddr = 0, paddr = 0;
			const char *name = NULL;
			bool rwx_arg = false;
			RzIODesc *desc = NULL;
			int words = rz_str_word_set0(s);
			switch (words) {
			case 6:
				name = rz_str_word_get0(s, 5);
			case 5:
				// TODO: this needs some love because it is not optimal.
				rwx = rz_str_rwx(rz_str_word_get0(s, 4));
				rwx_arg = true;
			case 4:
				paddr = rz_num_math(core->num, rz_str_word_get0(s, 3));
			case 3:
				size = rz_num_math(core->num, rz_str_word_get0(s, 2));
			case 2:
				vaddr = rz_num_math(core->num, rz_str_word_get0(s, 1));
			case 1:
				fd = rz_num_math(core->num, rz_str_word_get0(s, 0));
			}
			if (fd < 3) {
				eprintf("wrong fd, it must be greater than 3\n");
				break;
			}
			desc = rz_io_desc_get(core->io, fd);
			if (desc) {
				if (!size) {
					size = rz_io_fd_size(core->io, fd);
				}
				map = rz_io_map_add(core->io, fd, rwx_arg ? rwx : desc->perm, paddr, vaddr, size);
				rz_io_map_set_name(map, name);
			}
		} else {
			int fd = rz_io_fd_get_current(core->io);
			if (rz_io_desc_get(core->io, fd)) {
				map_list(core->io, 0, core->print, fd);
			} else {
				eprintf("Invalid fd %d\n", (int)fd);
			}
		}
		RZ_FREE(s);
		break;
	case 'n': // "omn"
		if (input[1] == '.') { // "omn."
			RzIOMap *map = rz_io_map_get(core->io, core->offset);
			if (map) {
				switch (input[2]) {
				case '-':
					rz_io_map_del_name(map);
					break;
				case 0:
					rz_cons_printf("%s\n", map->name);
					break;
				default:
					rz_io_map_set_name(map, rz_str_trim_head_ro(input + 2));
					break;
				}
			}
		} else {
			bool use_id = (input[1] == 'i') ? true : false;
			s = strdup(use_id ? &input[2] : &input[1]);
			if (!s) {
				break;
			}
			p = s;

			while (*s == ' ') {
				s++;
			}
			if (*s == '\0') {
				s = p;
				break;
			}
			if (!(q = strchr(s, ' '))) {
				if (use_id) {
					id = (ut32)rz_num_math(core->num, s);
					map = rz_io_map_resolve(core->io, id);
				} else {
					addr = rz_num_math(core->num, s);
					map = rz_io_map_get(core->io, addr);
				}
				rz_io_map_del_name(map);
				s = p;
				break;
			}
			*q = '\0';
			q++;
			if (use_id) {
				id = (ut32)rz_num_math(core->num, s);
				map = rz_io_map_resolve(core->io, id);
			} else {
				addr = rz_num_math(core->num, s);
				map = rz_io_map_get(core->io, addr);
			}
			if (*q) {
				rz_io_map_set_name(map, q);
			} else {
				rz_io_map_del_name(map);
			}
			s = p;
		}
		break;
	case 'm': // "omm"
	{
		ut32 fd = input[1] ? rz_num_math(core->num, input + 1) : rz_io_fd_get_current(core->io);
		RzIODesc *desc = rz_io_desc_get(core->io, fd);
		if (desc) {
			ut64 size = rz_io_desc_size(desc);
			map = rz_io_map_add(core->io, fd, desc->perm, 0, 0, size);
			rz_io_map_set_name(map, desc->name);
		} else {
			eprintf("Usage: omm [fd]\n");
		}
	} break;
	case 'f': // "omf"
		switch (input[1]) {
		case 'g': // "omfg"
			cmd_omfg(core, input + 2);
			break;
		case ' ': // "omf"
			cmd_omf(core, input + 2);
			break;
		default:
			rz_core_cmd_help(core, help_msg_om);
			break;
		}
		break;
	case '\0': // "om"
	case 'j': // "omj"
	case '*': // "om*"
	case 'q': // "omq"
		if (input[0] && input[1] == '.') {
			map = rz_io_map_get(core->io, core->offset);
			if (map) {
				core->print->cb_printf("%i\n", map->id);
			}
		} else {
			if (input[0] && input[1] == 'q') { // "omqq"
				map_list(core->io, input[0], core->print, -2);
			} else {
				map_list(core->io, input[0], core->print, -1);
			}
		}
		break;
	default:
	case '?':
		rz_core_cmd_help(core, help_msg_om);
		break;
	}
	RZ_FREE(s);
	rz_core_block_read(core);
	return 0;
}

static bool reopen_in_malloc_cb(void *user, void *data, ut32 id) {
	RzIO *io = (RzIO *)user;
	RzIODesc *desc = (RzIODesc *)data;

	if (rz_io_desc_is_blockdevice(desc) || rz_io_desc_is_dbg(desc)) {
		return true;
	}

	if (strstr(desc->uri, "://")) {
		return true;
	}

	ut64 size = rz_io_desc_size(desc);

	char *uri = rz_str_newf("malloc://%" PFMT64u, size);
	if (!uri) {
		return false;
	}

	ut8 *buf = malloc(size);
	// if malloc fails, we can just abort the loop by returning false
	if (!buf) {
		free(uri);
		return false;
	}

	RzIODesc *ndesc = rz_io_open_nomap(io, uri, RZ_PERM_RW, 0);
	free(uri);
	if (!ndesc) {
		free(buf);
		return false;
	}

	rz_io_desc_read_at(desc, 0LL, buf, (int)size); // that cast o_O
	rz_io_desc_write_at(ndesc, 0LL, buf, (int)size);
	free(buf);
	rz_io_desc_exchange(io, desc->fd, ndesc->fd);

	rz_io_desc_close(desc);
	return true;
}

RZ_API void rz_core_file_reopen_in_malloc(RzCore *core) {
	if (core && core->io && core->io->files) {
		rz_id_storage_foreach(core->io->files, reopen_in_malloc_cb, core->io);
	}
}

static bool init_desc_list_visual_cb(void *user, void *data, ut32 id) {
	struct open_list_ascii_data_t *u = (struct open_list_ascii_data_t *)user;
	RzIODesc *desc = (RzIODesc *)data;
	ut64 sz = rz_io_desc_size(desc);
	if (sz > u->fdsz) {
		u->fdsz = sz;
	}
	return true;
}

static bool desc_list_visual_cb(void *user, void *data, ut32 id) {
	struct open_list_ascii_data_t *u = (struct open_list_ascii_data_t *)user;
	RzPrint *p = u->p;
	RzIODesc *desc = (RzIODesc *)data;
	ut64 sz = rz_io_desc_size(desc);
	rz_cons_printf("%2d %c %s 0x%08" PFMT64x " ", desc->fd,
		(desc->io && (desc->io->desc == desc)) ? '*' : '-', rz_str_rwx_i(desc->perm), sz);
	int flags = p->flags;
	p->flags &= ~RZ_PRINT_FLAGS_HEADER;
	rz_print_progressbar(p, sz * 100 / u->fdsz, rz_cons_get_size(NULL) - 40);
	p->flags = flags;
	rz_cons_printf(" %s\n", desc->uri);
	return true;
}

static bool desc_list_quiet2_cb(void *user, void *data, ut32 id) {
	RzPrint *p = (RzPrint *)user;
	RzIODesc *desc = (RzIODesc *)data;
	p->cb_printf("%d\n", desc->fd);
	return false;
}

static bool desc_list_quiet_cb(void *user, void *data, ut32 id) {
	RzPrint *p = (RzPrint *)user;
	RzIODesc *desc = (RzIODesc *)data;
	p->cb_printf("%d\n", desc->fd);
	return true;
}

static bool desc_list_cb(void *user, void *data, ut32 id) {
	RzPrint *p = (RzPrint *)user;
	RzIODesc *desc = (RzIODesc *)data;
	p->cb_printf("%2d %c %s 0x%08" PFMT64x " %s\n", desc->fd,
		(desc->io && (desc->io->desc == desc)) ? '*' : '-',
		rz_str_rwx_i(desc->perm), rz_io_desc_size(desc), desc->uri);
	return true;
}

static bool desc_list_json_cb(void *user, void *data, ut32 id) {
	PJ *pj = (PJ *)user;
	RzIODesc *desc = (RzIODesc *)data;
	// TODO: from is always 0? See librz/core/file.c:945
	ut64 from = 0LL;
	pj_o(pj);
	pj_kb(pj, "raised", desc->io && (desc->io->desc == desc));
	pj_kN(pj, "fd", desc->fd);
	pj_ks(pj, "uri", desc->uri);
	pj_kn(pj, "from", from);
	pj_kb(pj, "writable", desc->perm & RZ_PERM_W);
	pj_kN(pj, "size", rz_io_desc_size(desc));
	pj_end(pj);
	return true;
}

RZ_IPI int rz_cmd_open(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	int perms = RZ_PERM_R;
	ut64 baddr = rz_config_get_i(core->config, "bin.baddr");
	ut64 addr = 0LL;
	int argc, fd = -1;
	RzCoreFile *file;
	RzIODesc *desc;
	bool write = false;
	const char *ptr = NULL;
	char **argv = NULL;

	switch (*input) {
	case 'n': // "on"
		if (input[1] == '*') {
			rz_core_raw_file_print(core);
			return 0;
		}
		if (input[1] == '+') { // "on+"
			write = true;
			perms |= RZ_PERM_W;
			if (input[2] != ' ') {
				eprintf("Usage: on+ file [addr] [rwx]\n");
				return 0;
			}
			ptr = input + 3;
		} else if (input[1] == ' ') {
			ptr = input + 2;
		} else {
			eprintf("Usage: on file [addr] [rwx]\n");
			return 0;
		}
		argv = rz_str_argv(ptr, &argc);
		if (!argc) {
			eprintf("Usage: on%s file [addr] [rwx]\n", write ? "+" : "");
			rz_str_argv_free(argv);
			return 0;
		}
		ptr = argv[0];
		if (argc == 2) {
			if (rz_num_is_valid_input(core->num, argv[1])) {
				addr = rz_num_math(core->num, argv[1]);
			} else {
				perms = rz_str_rwx(argv[1]);
			}
		}
		if (argc == 3) {
			addr = rz_num_math(core->num, argv[1]);
			perms = rz_str_rwx(argv[2]);
		}
		if (!strcmp(ptr, "-")) {
			ptr = "malloc://512";
		}
		if ((desc = rz_io_open_at(core->io, ptr, perms, 0644, addr, NULL))) {
			fd = desc->fd;
		}
		if (fd == -1) {
			eprintf("Cannot open file '%s'\n", ptr);
		}
		rz_str_argv_free(argv);
		core->num->value = fd;
		rz_core_block_read(core);
		return 0;
	case '+': // "o+"
		perms |= RZ_PERM_W;
		/* fallthrough */
	case ' ': // "o" "o "
		ptr = input + 1;
		argv = rz_str_argv(ptr, &argc);
		if (argc == 0) {
			eprintf("Usage: o (uri://)[/path/to/file] (addr)\n");
			rz_str_argv_free(argv);
			return 0;
		}
		if (argv) {
			// Unescape spaces from the path
			rz_str_path_unescape(argv[0]);
			if (argc == 2) {
				if (rz_num_is_valid_input(core->num, argv[1])) {
					addr = rz_num_math(core->num, argv[1]);
				} else {
					perms = rz_str_rwx(argv[1]);
				}
			}
			if (argc == 3) {
				addr = rz_num_math(core->num, argv[1]);
				perms = rz_str_rwx(argv[2]);
			}
		}
		{
			const char *argv0 = argv ? argv[0] : ptr;
			if ((file = rz_core_file_open(core, argv0, perms, addr))) {
				fd = file->fd;
				core->num->value = fd;
				if (addr == 0) { // if no baddr defined, use the one provided by the file
					addr = UT64_MAX;
				}
				rz_core_bin_load(core, argv0, addr);
				if (*input == '+') { // "o+"
					RzIODesc *desc = rz_io_desc_get(core->io, fd);
					if (desc && (desc->perm & RZ_PERM_W)) {
						void **it;
						rz_pvector_foreach (&file->maps, it) {
							RzIOMap *map = *it;
							map->perm |= RZ_PERM_WX;
						}
					} else {
						eprintf("Error: %s is not writable\n", argv0);
					}
				}
			} else {
				eprintf("cannot open file %s\n", argv0);
			}
			rz_str_argv_free(argv);
		}
		rz_core_block_read(core);
		return 0;
	}

	switch (*input) {
	case 'q': // "oq"
		if (input[1] == '.') {
			rz_id_storage_foreach(core->io->files, desc_list_quiet2_cb, core->print);
		} else {
			rz_id_storage_foreach(core->io->files, desc_list_quiet_cb, core->print);
		}
		break;
	case '\0': // "o"
		rz_id_storage_foreach(core->io->files, desc_list_cb, core->print);
		break;
	case '*': // "o*"
		if ('?' == input[1]) {
			rz_core_cmd_help(core, help_msg_o_star);
			break;
		}
		rz_core_file_print(core, RZ_OUTPUT_MODE_RIZIN);
		break;
	case 'j': // "oj"
		if ('?' == input[1]) {
			rz_core_cmd_help(core, help_msg_oj);
			break;
		}
		PJ *pj = pj_new();
		pj_a(pj);
		rz_id_storage_foreach(core->io->files, desc_list_json_cb, pj);
		pj_end(pj);
		core->print->cb_printf("%s\n", pj_string(pj));
		pj_free(pj);
		break;
	case 'i': // "oi"
		switch (input[1]) {
		case ' ': // "oi "
		{
			RzListIter *iter = NULL;
			RzCoreFile *f;
			int nth = rz_num_math(core->num, input + 2);
			int count = 0;
			rz_list_foreach (core->files, iter, f) {
				if (count == nth) {
					rz_io_use_fd(core->io, f->fd);
					break;
				}
				count++;
			}
		} break;
		case '-': // "oi-"
		{
			RzListIter *iter = NULL;
			RzCoreFile *f;
			int nth = rz_num_math(core->num, input + 2);
			int count = 0;
			rz_list_foreach (core->files, iter, f) {
				if (count == nth) {
					rz_core_file_close_fd(core, f->fd);
					break;
				}
				count++;
			}
		} break;
		case 'j': // "oij"
			rz_core_file_print(core, RZ_OUTPUT_MODE_JSON);
			break;
		case '*': // "oi*"
			rz_core_file_print(core, RZ_OUTPUT_MODE_RIZIN);
			break;
		case 0: // "oi"
			break;
			rz_core_file_print(core, RZ_OUTPUT_MODE_STANDARD);
		}
		break;
	case 'b': // "ob"
		cmd_open_bin(core, input);
		break;
	case '.': // "o."
		if (input[1] == 'q') { // "o.q" // same as oq
			RzIOMap *map = rz_io_map_get(core->io, core->offset);
			if (map) {
				rz_cons_printf("%d\n", map->fd);
			}
		} else {
			RzIOMap *map = rz_io_map_get(core->io, core->offset);
			if (map) {
				RzIODesc *desc = rz_io_desc_get(core->io, map->fd);
				if (desc) {
					rz_cons_printf("%s\n", desc->uri);
				}
			}
		}
		break;
	case 'C': // "oC"
	{
		int len = rz_num_math(core->num, input + 1);
		if (len < 1) {
			len = core->blocksize;
		}
		char *uri = rz_str_newf("malloc://%d", len);
		ut8 *data = calloc(len, 1);
		rz_io_read_at(core->io, core->offset, data, len);
		if ((file = rz_core_file_open(core, uri, RZ_PERM_RWX, 0))) {
			fd = file->fd;
			core->num->value = fd;
			rz_core_bin_load(core, uri, 0);
			RzIODesc *desc = rz_io_desc_get(core->io, fd);
			if (desc) {
				// TODO: why rz_io_desc_write() fails?
				rz_io_desc_write_at(desc, 0, data, len);
			}
		} else {
			eprintf("Cannot %s\n", uri);
		}
		free(uri);
		free(data);
	} break;
	case 'm': // "om"
		rz_om_oldinput(core, input + 1);
		break;
	case 'o': // "oo"
		switch (input[1]) {
		case 'm': // "oom"
			rz_core_file_reopen_in_malloc(core);
			break;
		case 'd': // "ood" : reopen in debugger
			if (input[2] == 'r') { // "oodr"
				rz_core_cmdf(core, "dor %s", input + 3);
				rz_core_file_reopen_debug(core, "");
			} else if (input[2] == 'f') { // "oodf"
				char **argv = NULL;
				int addr = 0;
				argv = rz_str_argv(input + 3, &argc);
				if (argc == 0) {
					eprintf("Usage: oodf (uri://)[/path/to/file] (addr)\n");
					rz_str_argv_free(argv);
					return 0;
				}
				if (argc == 2) {
					if (rz_num_is_valid_input(core->num, argv[1])) {
						addr = rz_num_math(core->num, argv[1]);
					}
				}
				rz_core_file_reopen_remote_debug(core, argv[0], addr);
				rz_str_argv_free(argv);
			} else if ('?' == input[2]) {
				rz_core_cmd_help(core, help_msg_ood);
			} else {
				rz_core_file_reopen_debug(core, input + 2);
			}
			break;
		case 'c': // "oob" : reopen with bin info
			rz_core_cmd0(core, "oc `o.`");
			break;
		case 'b': // "oob" : reopen with bin info
			if ('?' == input[2]) {
				rz_core_cmd_help(core, help_msg_oob);
			} else {
				rz_core_file_reopen(core, input + 2, 0, 2);
			}
			break;
		case 'n': // "oon"
			switch (input[2]) {
			case 0: // "oon"
				rz_core_file_reopen(core, NULL, 0, 0);
				break;
			case '+': // "oon+"
				rz_core_file_reopen(core, NULL, RZ_PERM_RW, 0);
				break;
			case 'n': // "oonn"
				if ('?' == input[3] || !core->file) {
					rz_core_cmd_help(core, help_msg_oonn);
					break;
				}
				RzIODesc *desc = rz_io_desc_get(core->io, core->file->fd);
				if (desc) {
					perms = core->io->desc->perm;
					if (input[3] == '+') {
						perms |= RZ_PERM_RW;
					}
					char *fname = strdup(desc->name);
					if (fname) {
						rz_core_bin_load_structs(core, fname);
						rz_core_file_reopen(core, fname, perms, 0);
						free(fname);
					}
					break;
				}
				break;
			case '?':
			default:
				rz_core_cmd_help(core, help_msg_oon);
				break;
			}
			break;
		case '+': // "oo+"
			if ('?' == input[2]) {
				rz_core_cmd_help(core, help_msg_oo_plus);
			} else if (core && core->io && core->io->desc) {
				int fd;
				int perms = RZ_PERM_RW;
				if ((ptr = strrchr(input, ' ')) && ptr[1]) {
					fd = (int)rz_num_math(core->num, ptr + 1);
				} else {
					fd = core->io->desc->fd;
					perms |= core->io->desc->perm;
				}
				rz_core_io_file_reopen(core, fd, perms);
			}
			break;
		case '\0': // "oo"
			if (core && core->io && core->io->desc) {
				int fd;
				if ((ptr = strrchr(input, ' ')) && ptr[1]) {
					fd = (int)rz_num_math(core->num, ptr + 1);
				} else {
					fd = core->io->desc->fd;
				}
				rz_core_io_file_open(core, fd);
			}
			break;
		case '?':
		default:
			rz_core_cmd_help(core, help_msg_oo);
			break;
		}
		break;
	case 'c': // "oc"
		if (input[1] == '?') {
			eprintf("Usage: oc [file]\n");
		} else if (input[1] && input[2]) {
			if (core->tasks.current_task != core->tasks.main_task) {
				eprintf("This command can only be executed on the main task!\n");
				return 0;
			}
			// memleak? loses all settings
			// if load fails does not fallbacks to previous file
			rz_core_task_sync_end(&core->tasks);
			rz_core_fini(core);
			rz_core_init(core);
			rz_core_task_sync_begin(&core->tasks);
			if (!rz_core_file_open(core, input + 2, RZ_PERM_R, 0)) {
				eprintf("Cannot open file\n");
			}
			(void)rz_core_bin_load(core, NULL, baddr);
		} else {
			eprintf("Missing argument\n");
		}
		break;
	case 'x': // "ox"
		if (input[1] && input[1] != '?') {
			int fd, fdx;
			fd = fdx = -1;
			char *ptr, *inp = strdup(input);
			if ((ptr = strrchr(inp, ' '))) {
				fdx = (int)rz_num_math(core->num, ptr + 1);
				*ptr = '\0';
				if ((ptr = strchr(inp, ' '))) {
					fd = rz_num_math(core->num, ptr + 1);
				}
			}
			free(inp);
			if ((fdx == -1) || (fd == -1) || (fdx == fd)) {
				break;
			}
			rz_io_desc_exchange(core->io, fd, fdx);
			rz_core_block_read(core);
		} else {
			eprintf("Usage: ox [fd] [fdx] - exchange two file descriptors\n");
		}
		break;
	case '?': // "o?"
	default:
		rz_core_cmd_help(core, help_msg_o);
		break;
	}
	return 0;
}

RZ_IPI RzCmdStatus rz_open_close_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_num_is_valid_input(NULL, argv[1])) {
		RZ_LOG_ERROR("Invalid fd: %s\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	int fd = (int)rz_num_math(NULL, argv[1]);
	if (!rz_core_file_close_fd(core, fd)) {
		RZ_LOG_ERROR("Unable to find file descriptor %d\n", fd);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_close_all_handler(RzCore *core, int argc, const char **argv) {
	rz_core_file_close_fd(core, -1);
	rz_io_close_all(core->io);
	rz_bin_file_delete_all(core->bin);

	// TODO: Move to a-- ?
	rz_analysis_purge(core->analysis);
	// TODO: Move to f-- ?
	rz_flag_unset_all(core->flags);
	RZ_LOG_INFO("Close all files\n");
	return RZ_CMD_STATUS_OK;
}
RZ_IPI RzCmdStatus rz_open_list_ascii_handler(RzCore *core, int argc, const char **argv) {
	struct open_list_ascii_data_t data = { 0 };
	data.p = core->print;
	data.fdsz = 0;
	rz_id_storage_foreach(core->io->files, init_desc_list_visual_cb, &data);
	rz_id_storage_foreach(core->io->files, desc_list_visual_cb, &data);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_arch_bits_handler(RzCore *core, int argc, const char **argv) {
	const char *filename = argc > 3 ? argv[3] : NULL;
	ut16 bits = rz_num_math(core->num, argv[2]);
	const char *arch = argv[1];

	int res = rz_core_bin_set_arch_bits(core, filename, arch, bits);
	return res ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_open_use_handler(RzCore *core, int argc, const char **argv) {
	RzListIter *iter = NULL;
	RzCoreFile *f;

	int fdnum = rz_num_math(NULL, argv[1]);
	rz_list_foreach (core->files, iter, f) {
		if (f->fd == fdnum) {
			core->file = f;
			rz_io_use_fd(core->io, fdnum);
			RzBinFile *bf = rz_bin_file_find_by_fd(core->bin, fdnum);
			if (!bf) {
				RZ_LOG_ERROR("Could not find binfile with fd %d\n", fdnum);
				return RZ_CMD_STATUS_ERROR;
			}
			rz_core_bin_raise(core, bf->id);
			rz_core_block_read(core);
			RZ_LOG_INFO("Switched to fd %d (%s)\n", fdnum, bf->file);
			return RZ_CMD_STATUS_OK;
		}
	}
	RZ_LOG_ERROR("Could not find any opened file with fd %d\n", fdnum);
	return RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus prioritize_file(RzCore *core, int fd) {
	if (fd <= 0) {
		RZ_LOG_ERROR("Wrong file descriptor %d\n", fd);
		return RZ_CMD_STATUS_ERROR;
	}
	int curfd = rz_io_fd_get_current(core->io);
	if (fd == curfd) {
		return RZ_CMD_STATUS_OK;
	}

	if (!rz_io_use_fd(core->io, fd)) {
		RZ_LOG_ERROR("Could not use IO fd %d\n", fd);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_block_read(core);
	RzBinFile *bf = rz_bin_file_find_by_fd(core->bin, fd);
	if (bf && !rz_core_bin_raise(core, bf->id)) {
		RZ_LOG_ERROR("Could not use bin id %d\n", bf->id);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_prioritize_handler(RzCore *core, int argc, const char **argv) {
	int fd = atoi(argv[1]);
	return prioritize_file(core, fd);
}

RZ_IPI RzCmdStatus rz_open_prioritize_next_handler(RzCore *core, int argc, const char **argv) {
	int fd = rz_io_fd_get_next(core->io, rz_io_fd_get_current(core->io));
	return prioritize_file(core, fd);
}

RZ_IPI RzCmdStatus rz_open_prioritize_prev_handler(RzCore *core, int argc, const char **argv) {
	int fd = rz_io_fd_get_prev(core->io, rz_io_fd_get_current(core->io));
	return prioritize_file(core, fd);
}

RZ_IPI RzCmdStatus rz_open_prioritize_next_rotate_handler(RzCore *core, int argc, const char **argv) {
	int fd = rz_io_fd_get_next(core->io, rz_io_fd_get_current(core->io));
	if (fd == -1) {
		fd = rz_io_fd_get_lowest(core->io);
	}
	return prioritize_file(core, fd) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_open_maps_remove_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_num_is_valid_input(NULL, argv[1])) {
		RZ_LOG_ERROR("Invalid map id '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	ut32 map_id = rz_num_math(NULL, argv[1]);
	if (!rz_io_map_del(core->io, map_id)) {
		RZ_LOG_ERROR("Could not delete IO map %d\n", map_id);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_remove_all_handler(RzCore *core, int argc, const char **argv) {
	rz_io_map_reset(core->io);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_ascii_handler(RzCore *core, int argc, const char **argv) {
	RzList *list = rz_list_newf((RzListFree)rz_listinfo_free);
	if (!list) {
		return RZ_CMD_STATUS_ERROR;
	}
	void **it;
	RzPVector *maps = rz_io_maps(core->io);
	rz_pvector_foreach_prev(maps, it) {
		RzIOMap *map = *it;
		char temp[32];
		rz_strf(temp, "%d", map->fd);
		RzListInfo *info = rz_listinfo_new(map->name, map->itv, map->itv, map->perm, temp);
		if (!info) {
			break;
		}
		rz_list_append(list, info);
	}
	RzTable *table = rz_core_table(core);
	rz_table_visual_list(table, list, core->offset, core->blocksize,
		rz_cons_get_size(NULL), rz_config_get_i(core->config, "scr.color"));
	char *tablestr = rz_table_tostring(table);
	rz_cons_printf("%s", tablestr);
	rz_table_free(table);
	rz_list_free(list);
	free(tablestr);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_all_fd_handler(RzCore *core, int argc, const char **argv) {
	ut32 fd = argc > 1 ? rz_num_math(NULL, argv[1]) : rz_io_fd_get_current(core->io);
	RzIODesc *desc = rz_io_desc_get(core->io, fd);
	if (!desc) {
		RZ_LOG_ERROR("Could not find any file descriptor with fd %d\n", fd);
		return RZ_CMD_STATUS_ERROR;
	}
	RzIOMap *map = rz_io_map_add(core->io, fd, desc->perm, 0, 0, UT64_MAX);
	if (!map) {
		RZ_LOG_ERROR("Could not create a IO map for file descriptor %d\n", fd);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_io_map_set_name(map, desc->name);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_relocate_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_num_is_valid_input(NULL, argv[1])) {
		RZ_LOG_ERROR("Invalid map id '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_num_is_valid_input(core->num, argv[2])) {
		RZ_LOG_ERROR("Invalid address '%s'\n", argv[2]);
		return RZ_CMD_STATUS_ERROR;
	}
	ut32 map_id = (ut32)rz_num_math(NULL, argv[1]);
	ut64 addr = rz_num_math(core->num, argv[2]);
	if (!rz_io_map_remap(core->io, map_id, addr)) {
		RZ_LOG_ERROR("Could not relocate map with id %d to %" PFMT64x "\n", map_id, addr);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_relocate_current_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_num_is_valid_input(core->num, argv[2])) {
		RZ_LOG_ERROR("Invalid address '%s'\n", argv[2]);
		return RZ_CMD_STATUS_ERROR;
	}
	RzIOMap *map = rz_io_map_get(core->io, core->offset);
	if (!map) {
		RZ_LOG_ERROR("Could not find any IO map at current offset\n");
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 addr = rz_num_math(core->num, argv[2]);
	if (!rz_io_map_remap(core->io, map->id, addr)) {
		RZ_LOG_ERROR("Could not relocate map with id %d to %" PFMT64x "\n", map->id, addr);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_resize_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_num_is_valid_input(NULL, argv[1])) {
		RZ_LOG_ERROR("Invalid map id '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_num_is_valid_input(core->num, argv[2])) {
		RZ_LOG_ERROR("Invalid size '%s'\n", argv[2]);
		return RZ_CMD_STATUS_ERROR;
	}
	ut32 map_id = (ut32)rz_num_math(NULL, argv[1]);
	ut64 size = rz_num_math(core->num, argv[2]);
	if (!rz_io_map_resize(core->io, map_id, size)) {
		RZ_LOG_ERROR("Could not resize map with id %d to %" PFMT64x "\n", map_id, size);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}
