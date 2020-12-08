// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_debug.h>

static const char *help_msg_o[] = {
	"Usage: o","[com- ] [file] ([offset])","",
	"o"," [file] 0x4000 rwx", "map file at 0x4000",
	"o"," [file]","open [file] file in read-only",
	"o","","list opened files",
	"o","-1","close file descriptor 1",
	"o*","","list opened files in rizin commands",
	"o+"," [file]","open file in read-write mode",
	"o-","!*","close all opened files",
	"o--","","close all files, analysis, binfiles, flags, same as !rizin --",
	"o.","","show current filename (or o.q/oq to get the fd)",
	"o:"," [len]","open a malloc://[len] copying the bytes from current offset",
	"o=","","list opened files (ascii-art bars)",
	"oL","","list all IO plugins registered",
	"oa","[-] [A] [B] [filename]","Specify arch and bits for given file",
	"ob","[?] [lbdos] [...]","list opened binary files backed by fd",
	"oc"," [file]","open core file, like relaunching rizin",
	"of"," [file]","open file and map it at addr 0 as read-only",
	"oi","[-|idx]","alias for o, but using index instead of fd",
	"oj","[?]	","list opened files in JSON format",
	"om","[?]","create, list, remove IO maps",
	"on"," [file] 0x4000","map raw file at 0x4000 (no rz_bin involved)",
	"oo","[?+bcdnm]","reopen current file (see oo?) (reload in rw or debugger)",
	"op","[r|n|p|fd]", "select priorized file by fd (see ob), opn/opp/opr = next/previous/rotate",
	"oq","","list all open files",
	"ox", " fd fdx", "exchange the descs of fd and fdx and keep the mapping",
	NULL
};

static const char *help_msg_o_[] = {
	"Usage: o-","[#!*]", "",
	"o-*","","close all opened files",
	"o-!","","close all files except the current one",
	"o-3","","close fd=3",
	NULL
};

static const char *help_msg_op[] = {
	"Usage:", "op[rnp] [fd]", "",
	"opr", "", "open next file rotating",
	"opn", "", "open next file",
	"opp", "", "open previous file",
	"op", " [fd]", "open priorizing fd",
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
	"oma"," [fd]", "create a map covering all VA for given fd",
	"omb", " mapid addr", "relocate map with corresponding id",
	"omb.", " addr", "relocate current map",
	"omf", " [mapid] rwx", "change flags/perms for current/given map",
	"omfg", "[+-]rwx", "change flags/perms for all maps (global)",
	"omj", "", "list all maps in json format",
	"omm"," [fd]", "create default map for given fd. (omm `oq`)",
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
	"omt", " [query]", "list maps using table api",
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
	"oodr", " [rz_run]", " # same as dor ..;ood",
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

// HONOR bin.at
static void cmd_open_bin(RzCore *core, const char *input) {
	const char *value = NULL;
	ut32 binfile_num = -1;

	switch (input[1]) {
	case 'L': // "obL"
		rz_core_cmd0 (core, "iL");
		break;
	case '\0': // "ob"
	case 'q': // "obj"
	case 'j': // "obj"
	case '*': // "ob*"
		rz_core_bin_list (core, input[1]);
		break;
	case '.': // "ob."
		{
			const char *arg = rz_str_trim_head_ro (input + 2);
			ut64 at = core->offset;
			if (*arg) {
				at = rz_num_math (core->num, arg);
				if (at == 0 && *arg != '0') {
					at = core->offset;
				}
			}
			RzBinFile *bf = rz_bin_file_at (core->bin, at);
			if (bf) {
				rz_cons_printf ("%d\n", bf->id);
			}
		}
		break;
	case 'a': // "oba"
		if ('?' == input[2]) {
			rz_core_cmd_help (core, help_msg_oa);
			break;
		}
		if (input[2] && input[3]) {
			char *arg = strdup (input + 3);
			char *filename = strchr (arg, ' ');
			if (filename && *filename && (filename[1] == '/' || filename[1] == '.')) {
				int saved_fd = rz_io_fd_get_current (core->io);
				RzIODesc *desc = rz_io_open (core->io, filename + 1, RZ_PERM_R, 0);
				if (desc) {
					*filename = 0;
					ut64 addr = rz_num_math (core->num, arg);
					RzBinOptions opt;
					rz_bin_options_init (&opt, desc->fd, addr, 0, core->bin->rawstr);
					rz_bin_open_io (core->bin, &opt);
					rz_io_desc_close (desc);
					rz_core_cmd0 (core, ".is*");
					rz_io_use_fd (core->io, saved_fd);
				} else {
					eprintf ("Cannot open %s\n", filename + 1);
				}
			} else if (filename && *filename) {
				ut64 baddr = rz_num_math (core->num, filename);
				ut64 addr = rz_num_math (core->num, input + 2); // mapaddr
				int fd = rz_io_fd_get_current (core->io);
				RzIODesc *desc = rz_io_desc_get (core->io, fd);
				if (desc) {
					RzBinOptions opt;
					opt.baseaddr = baddr;
					opt.loadaddr = addr;
					opt.sz = 1024*1024*1;
					rz_bin_options_init (&opt, desc->fd, baddr, addr, core->bin->rawstr);
					rz_bin_open_io (core->bin, &opt);
					rz_core_cmd0 (core, ".is*");
				} else {
					eprintf ("No file to load bin from?\n");
				}
			} else {
				ut64 addr = rz_num_math (core->num, input + 2);
				int fd = rz_io_fd_get_current (core->io);
				RzIODesc *desc = rz_io_desc_get (core->io, fd);
				if (desc) {
					RzBinOptions opt;
					opt.baseaddr = addr;
					opt.loadaddr = addr;
					opt.sz = 1024 * 1024 * 1;
					rz_bin_options_init (&opt, desc->fd, addr, addr, core->bin->rawstr);
					rz_bin_open_io (core->bin, &opt);
					rz_core_cmd0 (core, ".is*");
				} else {
					eprintf ("No file to load bin from?\n");
				}
			}
			free (arg);
		} else {
			RzList *ofiles = rz_id_storage_list (core->io->files);
			RzIODesc *desc;
			RzListIter *iter;
			RzList *files = rz_list_newf (NULL);
			rz_list_foreach (ofiles, iter, desc) {
				rz_list_append (files, (void*)(size_t)desc->fd);
			}
		
			void *_fd;
			rz_list_foreach (files, iter, _fd) {
				int fd = (size_t)_fd;
				RzBinOptions opt;
				rz_bin_options_init (&opt, fd, core->offset, 0, core->bin->rawstr);
				rz_bin_open_io (core->bin, &opt);
				rz_core_cmd0 (core, ".ies*");
				break;
			}
			rz_list_free (files);
		}
		break;
	case ' ': // "ob "
	{
		ut32 id;
		int n;
		const char *tmp;
		char *v;
		v = input[2] ? strdup (input + 2) : NULL;
		if (!v) {
			eprintf ("Invalid arguments");
			break;
		}
		n = rz_str_word_set0 (v);
		if (n < 1 || n > 2) {
			eprintf ("Usage: ob [file|objid]\n");
			free (v);
			break;
		}
		tmp = rz_str_word_get0 (v, 0);
		id = *v && rz_is_valid_input_num_value (core->num, tmp)
			? rz_get_input_num_value (core->num, tmp): UT32_MAX;
		if (n == 2) {
			tmp = rz_str_word_get0 (v, 1);
		} else {
			binfile_num = id;
		}
		rz_core_bin_raise (core, binfile_num);
		free (v);
		break;
	}
	case 'r': // "obr"
		rz_core_bin_rebase (core, rz_num_math (core->num, input + 3));
		rz_core_cmd0 (core, ".is*");
		break;
	case 'f':
		if (input[2] == ' ') {
			rz_core_cmdf (core, "oba 0 %s", input + 3);
		} else {
			rz_core_bin_load (core, NULL, UT64_MAX);
			value = input[2] ? input + 2 : NULL;
		}
		break;
	case 'o': // "obo"
		if (input[2] == ' ') {
			ut32 fd = rz_num_math (core->num, input + 3);
			RzBinFile *bf = rz_bin_file_find_by_fd (core->bin, fd);
			if (!bf || !rz_core_bin_raise (core, bf->id)) {
				eprintf ("Invalid RzBinFile.id number.\n");
			}
		} else {
			eprintf ("Usage: obb [bfid]\n");
		}
		break;
	case '-': // "ob-"
		if (input[2] == '*') {
			rz_bin_file_delete_all (core->bin);
		} else {
			ut32 id;
			value = rz_str_trim_head_ro (input + 2);
			if (!value) {
				eprintf ("Invalid argument\n");
				break;
			}
			id = (*value && rz_is_valid_input_num_value (core->num, value)) ?
					rz_get_input_num_value (core->num, value) : UT32_MAX;
			RzBinFile *bf = rz_bin_file_find_by_id (core->bin, id);
			if (!bf) {
				eprintf ("Invalid binid\n");
				break;
			}
			if (!rz_core_bin_delete (core, bf->id)) {
				eprintf ("Cannot find an RzBinFile associated with that id.\n");
			}
		}
		break;
	case '=': // "ob="
		{
			RzListIter *iter;
			RzList *list = rz_list_newf ((RzListFree) rz_listinfo_free);
			RzBinFile *bf = NULL;
			RzBin *bin = core->bin;
			if (!bin) {
				return;
			}
			rz_list_foreach (bin->binfiles, iter, bf) {
				char temp[4];
				RzInterval inter = (RzInterval) {bf->o->baddr, bf->o->size};
				RzListInfo *info = rz_listinfo_new (bf->file, inter, inter, -1,  sdb_itoa (bf->fd, temp, 10));
				if (!info) {
					break;
				}
				rz_list_append (list, info);
			}
			RTable *table = rz_core_table (core);
			rz_table_visual_list (table, list, core->offset, core->blocksize,
				rz_cons_get_size (NULL), rz_config_get_i (core->config, "scr.color"));
			char *table_text = rz_table_tostring (table);
			rz_cons_printf ("\n%s\n", table_text);
			rz_free (table_text);
			rz_table_free (table);
			rz_list_free (list);
		} break;
	case '?': // "ob?"
		rz_core_cmd_help (core, help_msg_ob);
		break;
	}
}

// TODO: discuss the output format
static void map_list(RzIO *io, int mode, RzPrint *print, int fd) {
	PJ *pj;
	if (!io || !print || !print->cb_printf) {
		return;
	}
	if (mode == 'j') {
		pj = pj_new ();
		if (!pj) {
			return;
		}
		pj_a (pj);
	}
	char *om_cmds = NULL;

	void **it;
	rz_pvector_foreach_prev (&io->maps, it) { //this must be prev (LIFO)
		RzIOMap *map = *it;
		if (fd >= 0 && map->fd != fd) {
			continue;
		}
		switch (mode) {
		case 'q':
			if (fd == -2) {
				print->cb_printf ("0x%08"PFMT64x"\n", rz_io_map_get_from (map));
			} else {
				print->cb_printf ("%d %d\n", map->fd, map->id);
			}
			break;
		case 'j':
			pj_o (pj);
			pj_ki (pj, "map", map->id);
			pj_ki (pj, "fd", map->fd);
			pj_kn (pj, "delta", map->delta);
			pj_kn (pj, "from", rz_io_map_get_from (map));
			pj_kn (pj, "to", rz_itv_end (map->itv));
			pj_ks (pj, "perm", rz_str_rwx_i (map->perm));
			pj_ks (pj, "name", rz_str_get2 (map->name));
			pj_end (pj);
			break;
		case 1:
		case '*':
		case 'r': {
			// Need FIFO order here
			char *om_cmd = rz_str_newf ("om %d 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" %s%s%s\n",
					map->fd, rz_io_map_get_from (map), map->itv.size, map->delta, rz_str_rwx_i(map->perm),
					map->name ? " " : "", rz_str_get2 (map->name));
			if (om_cmd) {
				om_cmds = rz_str_prepend (om_cmds, om_cmd);
				free (om_cmd);
			}
			break;
		}
		default:
			print->cb_printf ("%2d fd: %i +0x%08"PFMT64x" 0x%08"PFMT64x
					" - 0x%08"PFMT64x" %s %s\n", map->id, map->fd,
					map->delta, rz_io_map_get_from (map), rz_io_map_get_to (map),
					rz_str_rwx_i (map->perm), rz_str_get2 (map->name));
			break;
		}
	}
	if (om_cmds) {
		print->cb_printf ("%s", om_cmds);
		free (om_cmds);
	}
	if (mode == 'j') {
		pj_end (pj);
		print->cb_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
}

static void cmd_omfg(RzCore *core, const char *input) {
	input = rz_str_trim_head_ro (input);
	if (input) {
		int perm = *input
		? (*input == '+' || *input == '-')
			? rz_str_rwx (input + 1)
			: rz_str_rwx (input)
		: 7;
		void **it;
		switch (*input) {
		case '+':
			rz_pvector_foreach (&core->io->maps, it) {
				RzIOMap *map = *it;
				map->perm |= perm;
			}
			break;
		case '-':
			rz_pvector_foreach (&core->io->maps, it) {
				RzIOMap *map = *it;
				map->perm &= ~perm;
			}
			break;
		default:
			rz_pvector_foreach (&core->io->maps, it) {
				RzIOMap *map = *it;
				map->perm = perm;
			}
			break;
		}
	}
}

static void cmd_omf(RzCore *core, const char *input) {
	char *arg = strdup (rz_str_trim_head_ro (input));
	if (!arg) {
		return;
	}
	char *sp = strchr (arg, ' ');
	if (sp) {
		// change perms of Nth map
		*sp++ = 0;
		int id = rz_num_math (core->num, arg);
		int perm = (*sp)? rz_str_rwx (sp): RZ_PERM_RWX;
		void **it;
		rz_pvector_foreach (&core->io->maps, it) {
			RzIOMap *map = *it;
			if (map->id == id) {
				map->perm = perm;
				break;
			}
		}
	} else {
		// change perms of current map
		int perm = (arg && *arg)? rz_str_rwx (arg): RZ_PERM_RWX;
		void **it;
		rz_pvector_foreach (&core->io->maps, it) {
			RzIOMap *map = *it;
			if (rz_itv_contain (map->itv, core->offset)) {
				map->perm = perm;
			}
		}
	}
	free (arg);
}

static void rz_core_cmd_omt(RzCore *core, const char *arg) {
	RTable *t = rz_table_new ();

	rz_table_set_columnsf (t, "nnnnnnnss", "id", "fd", "pa", "pa_end", "size", "va", "va_end", "perm", "name", NULL);

	void **it;
	rz_pvector_foreach (&core->io->maps, it) {
		RzIOMap *m = *it;
		ut64 va = rz_itv_begin (m->itv);
		ut64 va_end = rz_itv_end (m->itv);
		ut64 pa = m->delta;
		ut64 pa_size = rz_itv_size (m->itv);
		ut64 pa_end = pa + pa_size;
		const char *name = m->name? m->name: "";
		rz_table_add_rowf (t, "ddxxxxxss", m->id, m->fd, pa, pa_end, pa_size, va, va_end, rz_str_rwx_i (m->perm), name);
	}

	if (rz_table_query (t, arg)) {
		char *ts = rz_table_tofancystring (t);
		rz_cons_printf ("%s", ts);
		free (ts);
	}
	rz_table_free (t);
}

static void cmd_open_map(RzCore *core, const char *input) {
	ut64 fd = 0LL;
	ut32 id = 0;
	ut64 addr = 0;
	char *s = NULL, *p = NULL, *q = NULL;
	ut64 new;
	RzIOMap *map = NULL;
	const char *P;
	PJ *pj;

	switch (input[1]) {
	case '.': // "om."
		map = rz_io_map_get (core->io, core->offset);
		if (map) {
			if (input[2] == 'j') { // "om.j"
				pj = pj_new ();
				if (!pj) {
					return;
				}
				pj_o (pj);
				pj_ki (pj, "map", map->id);
				pj_ki (pj, "fd", map->fd);
				pj_kn (pj, "delta", map->delta);
				pj_kn (pj, "from", rz_io_map_get_from (map));
				pj_kn (pj, "to", rz_itv_end (map->itv));
				pj_ks (pj, "perm", rz_str_rwx_i (map->perm));
				pj_ks (pj, "name", rz_str_get2 (map->name));
				pj_end (pj);

				core->print->cb_printf ("%s\n", pj_string (pj));

				pj_free (pj);
			} else {
				core->print->cb_printf ("%2d fd: %i +0x%08"PFMT64x" 0x%08"PFMT64x
					" - 0x%08"PFMT64x" %s %s\n", map->id, map->fd,
					map->delta, rz_io_map_get_from (map), rz_io_map_get_to (map),
					rz_str_rwx_i (map->perm), rz_str_get2 (map->name));
			}
		}
		break;
	case 'r': // "omr"
		if (input[2] != ' ') {
			break;
		}
		P = strchr (input+3, ' ');
		if (P) {
			id = (ut32)rz_num_math (core->num, input+3);	//mapid
			new = rz_num_math (core->num, P+1);
			rz_io_map_resize (core->io, id, new);
		}
		break;
	case 'b': // "omb"
		if (input[2] == '.') {
			RzIOMap *map = rz_io_map_get (core->io, core->offset);
			if (map) {
				ut64 dst = rz_num_math (core->num, input + 3);
				rz_io_map_remap (core->io, map->id, dst);
			}
		} else {
			if (input[2] != ' ') {
				break;
			}
			P = strchr (input + 3, ' ');
			if (P) {
				id = (ut32)rz_num_math (core->num, input+3);	//mapid
				new = rz_num_math (core->num, P + 1);
				rz_io_map_remap (core->io, id, new);
			}
		}
		break;
	case 'o': // "omo"
		if (input[2] == ' ') {
			rz_core_cmdf (core, "om %s 0x%08" PFMT64x " $s r omo", input + 2, core->offset);
		} else {
			rz_core_cmd0 (core, "om `oq.` $B $s r");
		}
		rz_core_cmd0 (core, "ompd `omq.`");
		break;
	case 'p':
		switch (input[2]) {
		case 'd': // "ompf"
			id = rz_num_math (core->num, input + 3);		//mapid
			if (rz_io_map_exists_for_id (core->io, id)) {
				rz_io_map_depriorize (core->io, id);
			} else {
				eprintf ("Cannot find any map with mapid %d\n", id);
			}
			break;
		case 'f': // "ompf"
			fd = rz_num_math (core->num, input + 3);
			if (!rz_io_map_priorize_for_fd (core->io, (int)fd)) {
				eprintf ("Cannot prioritize any map for fd %d\n", (int)fd);
			}
			break;
		case 'b': // "ompb"
			id = (ut32)rz_num_math (core->num, input + 4);
			if (!rz_bin_file_set_cur_by_id (core->bin, id)) {
				eprintf ("Cannot prioritize bin with fd %d\n", id);
			}
			break;
		case ' ': // "omp"
			id = rz_num_math (core->num, input + 3);		//mapid
			if (rz_io_map_exists_for_id (core->io, id)) {
				rz_io_map_priorize (core->io, id);
				rz_core_block_read (core);
			} else {
				eprintf ("Cannot find any map with mapid %d\n", id);
			}
			break;
		}
		break;
	case 't': // "omt"
		rz_core_cmd_omt (core, input + 2);
		break;
	case ' ': // "om"
		s = strdup (input + 2);
		if (!s) {
			break;
		}
		if (strchr (s, ' ')) {
			int fd = 0, rwx = 0;
			ut64 size = 0, vaddr = 0, paddr = 0;
			const char *name = NULL;
			bool rwx_arg = false;
			RzIODesc *desc = NULL;
			int words = rz_str_word_set0 (s);
			switch (words) {
			case 6:
				name = rz_str_word_get0 (s, 5);
			case 5:
				//TODO: this needs some love because it is not optimal.
				rwx = rz_str_rwx (rz_str_word_get0 (s, 4));
				rwx_arg = true;
			case 4:
				paddr = rz_num_math (core->num, rz_str_word_get0 (s, 3));
			case 3:
				size = rz_num_math (core->num, rz_str_word_get0 (s, 2));
			case 2:
				vaddr = rz_num_math (core->num, rz_str_word_get0 (s, 1));
			case 1:
				fd = rz_num_math (core->num, rz_str_word_get0 (s, 0));
			}
			if (fd < 3) {
				eprintf ("wrong fd, it must be greater than 3\n");
				break;
			}
			desc = rz_io_desc_get (core->io, fd);
			if (desc) {
				if (!size) {
					size = rz_io_fd_size (core->io, fd);
				}
				map = rz_io_map_add (core->io, fd, rwx_arg ? rwx : desc->perm, paddr, vaddr, size);
				rz_io_map_set_name (map, name);
			}
		} else {
			int fd = rz_io_fd_get_current (core->io);
			if (rz_io_desc_get (core->io, fd)) {
				map_list (core->io, 0, core->print, fd);
			} else {
				eprintf ("Invalid fd %d\n", (int)fd);
			}
		}
		RZ_FREE (s);
		break;
	case 'n': // "omn"
		if (input[2] == '.') { // "omn."
			RzIOMap *map = rz_io_map_get (core->io, core->offset);
			if (map) {
				switch (input[3]) {
				case '-':
					rz_io_map_del_name (map);
					break;
				case 0:
					rz_cons_printf ("%s\n", map->name);
					break;
				default:
					rz_io_map_set_name (map, rz_str_trim_head_ro (input + 3));
					break;
				}
			}
		} else {
			bool use_id = (input[2] == 'i') ? true : false;
			s = strdup ( use_id ? &input[3] : &input[2]);
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
			if (!(q = strchr (s, ' '))) {
				if (use_id) {
					id = (ut32)rz_num_math (core->num, s);
					map = rz_io_map_resolve (core->io, id);
				} else {
					addr = rz_num_math (core->num, s);
					map = rz_io_map_get (core->io, addr);
				}
				rz_io_map_del_name (map);
				s = p;
				break;
			}
			*q = '\0';
			q++;
			if (use_id) {
				id = (ut32)rz_num_math (core->num, s);
				map = rz_io_map_resolve (core->io, id);
			} else {
				addr = rz_num_math (core->num, s);
				map = rz_io_map_get (core->io, addr);
			}
			if (*q) {
				rz_io_map_set_name (map, q);
			} else {
				rz_io_map_del_name (map);
			}
			s = p;
		}
		break;
	case 'a': // "oma"
		{
			ut32 fd = input[2]? rz_num_math (core->num, input + 2): rz_io_fd_get_current (core->io);
			RzIODesc *desc = rz_io_desc_get (core->io, fd);
			if (desc) {
				map = rz_io_map_add (core->io, fd, desc->perm, 0, 0, UT64_MAX);
				rz_io_map_set_name (map, desc->name);
			} else {
				eprintf ("Usage: omm [fd]\n");
			}
		}
		break;
	case 'm': // "omm"
		{
			ut32 fd = input[2]? rz_num_math (core->num, input + 2): rz_io_fd_get_current (core->io);
			RzIODesc *desc = rz_io_desc_get (core->io, fd);
			if (desc) {
				ut64 size = rz_io_desc_size (desc);
				map = rz_io_map_add (core->io, fd, desc->perm, 0, 0, size);
				rz_io_map_set_name (map, desc->name);
			} else {
				eprintf ("Usage: omm [fd]\n");
			}
		}
		break;
	case '-': // "om-"
		if (!strcmp (input + 2, "..")) {
			rz_core_cmd0 (core, "om-`om~...`~[0]");
		} else if (input[2] == '*') {
			rz_io_map_reset (core->io);
		} else {
			rz_io_map_del (core->io, rz_num_math (core->num, input + 2));
		}
		break;
	case 'f': // "omf"
		switch (input[2]) {
		case 'g': // "omfg"
			cmd_omfg (core, input + 3);
			break;
		case ' ': // "omf"
			cmd_omf (core, input + 3);
			break;
		default:
			rz_core_cmd_help (core, help_msg_om);
			break;
		}
		break;
	case '\0': // "om"
	case 'j': // "omj"
	case '*': // "om*"
	case 'q': // "omq"
		if (input[1] && input[2] == '.') {
			map = rz_io_map_get (core->io, core->offset);
			if (map) {
				core->print->cb_printf ("%i\n", map->id);
			}
		} else {
			if (input[1] && input[2] == 'q') { // "omqq"
				map_list (core->io, input[1], core->print, -2);
			} else {
				map_list (core->io, input[1], core->print, -1);
			}
		}
		break;
	case '=': // "om="
		{
		RzList *list = rz_list_newf ((RzListFree) rz_listinfo_free);
		if (!list) {
			return;
		}
		void **it;
		rz_pvector_foreach_prev (&core->io->maps, it) {
			RzIOMap *map = *it;
			char temp[32];
			snprintf (temp, sizeof (temp), "%d", map->fd);
			RzListInfo *info = rz_listinfo_new (map->name, map->itv, map->itv, map->perm, temp);
			if (!info) {
				break;
			}
			rz_list_append (list, info);
		}
		RTable *table = rz_core_table (core);
		rz_table_visual_list (table, list, core->offset, core->blocksize,
			rz_cons_get_size (NULL), rz_config_get_i (core->config, "scr.color"));
		char *tablestr = rz_table_tostring (table);
		rz_cons_printf ("\n%s\n", tablestr);
		rz_table_free (table);
		rz_list_free (list);
		free (tablestr);
		} break;
	default:
	case '?':
		rz_core_cmd_help (core, help_msg_om);
		break;
	}
	RZ_FREE (s);
	rz_core_block_read (core);
}

static bool reopen_in_malloc_cb(void *user, void *data, ut32 id) {
	RzIO *io = (RzIO *)user;
	RzIODesc *desc = (RzIODesc *)data;

	if (rz_io_desc_is_blockdevice (desc) || rz_io_desc_is_dbg (desc)) {
		return true;
	}

	if (strstr (desc->uri, "://")) {
		return true;
	}

	ut64 size = rz_io_desc_size (desc);

	char *uri = rz_str_newf ("malloc://%"PFMT64u, size);
	if (!uri) {
		return false;
	}

	ut8 *buf = malloc (size);
// if malloc fails, we can just abort the loop by returning false
	if (!buf) {
		free (uri);
		return false;
	}

	RzIODesc *ndesc = rz_io_open_nomap (io, uri, RZ_PERM_RW, 0);
	free (uri);
	if (!ndesc) {
		free (buf);
		return false;
	}

	rz_io_desc_read_at (desc, 0LL, buf, (int)size);	//that cast o_O
	rz_io_desc_write_at (ndesc, 0LL, buf, (int)size);
	free (buf);
	rz_io_desc_exchange (io, desc->fd, ndesc->fd);

	rz_io_desc_close (desc);
	return true;
}

RZ_API void rz_core_file_reopen_in_malloc(RzCore *core) {
	if (core && core->io && core->io->files) {
		rz_id_storage_foreach (core->io->files, reopen_in_malloc_cb, core->io);
	}
}

static RzList *__save_old_sections(RzCore *core) {
	RzList *sections = rz_bin_get_sections (core->bin);
	RzListIter *it;
	RzBinSection *sec;
	RzList *old_sections = rz_list_new ();

	// Return an empty list
	if (!sections) {
		eprintf ("WARNING: No sections found, functions and flags won't be rebased");
		return old_sections;
	}

	old_sections->free = sections->free;
	rz_list_foreach (sections, it, sec) {
		RzBinSection *old_sec = RZ_NEW0 (RzBinSection);
		if (!old_sec) {
			break;
		}
		*old_sec = *sec;
		old_sec->name = strdup (sec->name);
		old_sec->format = NULL;
		rz_list_append (old_sections, old_sec);
	}
	return old_sections;
}

struct __rebase_struct {
	RzCore *core;
	RzList *old_sections;
	ut64 old_base;
	ut64 diff;
	int type;
};

#define __is_inside_section(item_addr, section)\
	(item_addr >= old_base + section->vaddr && item_addr <= old_base + section->vaddr + section->vsize)

static bool __rebase_flags(RzFlagItem *flag, void *user) {
	struct __rebase_struct *reb = user;
	ut64 old_base = reb->old_base;
	RzListIter *it;
	RzBinSection *sec;
	// Only rebase flags that were in the rebased sections, otherwise it will take too long
	rz_list_foreach (reb->old_sections, it, sec) {
		if (__is_inside_section (flag->offset, sec)) {
			rz_flag_set (reb->core->flags, flag->name, flag->offset + reb->diff, flag->size);
			break;
		}
	}
	return true;
}

static bool __rebase_refs_i(void *user, const ut64 k, const void *v) {
	struct __rebase_struct *reb = (void *)user;
	RzAnalysisRef *ref = (RzAnalysisRef *)v;
	ref->addr += reb->diff;
	ref->at += reb->diff;
	if (reb->type) {
		rz_analysis_xrefs_set (reb->core->analysis, ref->addr, ref->at, ref->type);
	} else {
		rz_analysis_xrefs_set (reb->core->analysis, ref->at, ref->addr, ref->type);
	}
	return true;
}

static bool __rebase_refs(void *user, const ut64 k, const void *v) {
	HtUP *ht = (HtUP *)v;
	ht_up_foreach (ht, __rebase_refs_i, user);
	return true;
}

static void __rebase_everything(RzCore *core, RzList *old_sections, ut64 old_base) {
	RzListIter *it, *itit, *ititit;
	RzAnalysisFunction *fcn;
	ut64 new_base = core->bin->cur->o->baddr_shift;
	RzBinSection *old_section;
	ut64 diff = new_base - old_base;
	if (!diff) {
		return;
	}
	// FUNCTIONS
	rz_list_foreach (core->analysis->fcns, it, fcn) {
		rz_list_foreach (old_sections, itit, old_section) {
			if (!__is_inside_section (fcn->addr, old_section)) {
				continue;
			}
				rz_analysis_function_rebase_vars (core->analysis, fcn);
			rz_analysis_function_relocate (fcn, fcn->addr + diff);
			RzAnalysisBlock *bb;
			ut64 new_sec_addr = new_base + old_section->vaddr;
			rz_list_foreach (fcn->bbs, ititit, bb) {
				if (bb->addr >= new_sec_addr && bb->addr <= new_sec_addr + old_section->vsize) {
					// Todo: Find better way to check if bb was already rebased
					continue;
				}
				rz_analysis_block_relocate (bb, bb->addr + diff, bb->size);
				if (bb->jump != UT64_MAX) {
					bb->jump += diff;
				}
				if (bb->fail != UT64_MAX) {
					bb->fail += diff;
				}
			}
			break;
		}
	}

	// FLAGS
	struct __rebase_struct reb = {
		core,
		old_sections,
		old_base,
		diff
	};
	rz_flag_foreach (core->flags, __rebase_flags, &reb);

	// META
	rz_meta_rebase (core->analysis, diff);

	// REFS
	HtUP *old_refs = core->analysis->dict_refs;
	HtUP *old_xrefs = core->analysis->dict_xrefs;
	core->analysis->dict_refs = NULL;
	core->analysis->dict_xrefs = NULL;
	rz_analysis_xrefs_init (core->analysis);
	reb.type = 0;
	ht_up_foreach (old_refs, __rebase_refs, &reb);
	reb.type = 1;
	ht_up_foreach (old_xrefs, __rebase_refs, &reb);
	ht_up_free (old_refs);
	ht_up_free (old_xrefs);

	// BREAKPOINTS
	rz_debug_bp_rebase (core->dbg, old_base, new_base);
}

RZ_API void rz_core_file_reopen_remote_debug(RzCore *core, char *uri, ut64 addr) {
	RzCoreFile *ofile = core->file;
	RzIODesc *desc;
	RzCoreFile *file;
	int fd;

	if (!ofile || !(desc = rz_io_desc_get (core->io, ofile->fd)) || !desc->uri) {
		eprintf ("No file open?\n");
		return;
	}

	RzList *old_sections = __save_old_sections (core);
	ut64 old_base = core->bin->cur->o->baddr_shift;
	int bits = core->rasm->bits;
	rz_config_set_i (core->config, "asm.bits", bits);
	rz_config_set_i (core->config, "cfg.debug", true);
	// Set referer as the original uri so we could return to it with `oo`
	desc->referer = desc->uri;
	desc->uri = strdup (uri);

	if ((file = rz_core_file_open (core, uri, RZ_PERM_R | RZ_PERM_W, addr))) {
		fd = file->fd;
		core->num->value = fd;
		// if no baddr is defined, use the one provided by the file
		if (addr == 0) {
			desc = rz_io_desc_get (core->io, file->fd);
			if (desc->plugin->isdbg) {
				addr = rz_debug_get_baddr(core->dbg, desc->name);
			} else {
				addr = rz_bin_get_baddr (file->binb.bin);
			}
		}
		rz_core_bin_load (core, uri, addr);
	} else {
		eprintf ("cannot open file %s\n", uri);
		rz_list_free (old_sections);
		return;
	}
	rz_core_block_read (core);
	if (rz_config_get_i (core->config, "dbg.rebase")) {
		__rebase_everything (core, old_sections, old_base);
	}
	rz_list_free (old_sections);
	rz_core_cmd0 (core, "sr PC");
}

RZ_API void rz_core_file_reopen_debug(RzCore *core, const char *args) {
	RzCoreFile *ofile = core->file;
	RzIODesc *desc;

	if (!ofile || !(desc = rz_io_desc_get (core->io, ofile->fd)) || !desc->uri) {
		eprintf ("No file open?\n");
		return;
	}

	// Reopen the original file as read only since we can't open native debug while the
	// file is open with write permissions
	if (!(desc->plugin && desc->plugin->isdbg) && (desc->perm & RZ_PERM_W)) {
		eprintf ("Cannot debug file (%s) with permissions set to 0x%x.\n"
			"Reopening the original file in read-only mode.\n", desc->name, desc->perm);
		rz_io_reopen (core->io, ofile->fd, RZ_PERM_R, 644);
		desc = rz_io_desc_get (core->io, ofile->fd);
	}

	RzBinFile *bf = rz_bin_file_find_by_fd (core->bin, ofile->fd);
	char *binpath = (bf && bf->file) ? strdup (bf->file) : NULL;
	if (!binpath) {
		if (rz_file_exists (desc->name)) {
			binpath = strdup (desc->name);
		}
	}
	if (!binpath) {
		/* fallback to oo */
		(void)rz_core_cmd0 (core, "oo");
		return;
	}

	RzList *old_sections = __save_old_sections (core);
	ut64 old_base = core->bin->cur->o->baddr_shift;
	int bits = core->rasm->bits;
	char *bin_abspath = rz_file_abspath (binpath);
	char *escaped_path = rz_str_arg_escape (bin_abspath);
	char *newfile = rz_str_newf ("dbg://%s %s", escaped_path, args);
	desc->uri = newfile;
	desc->referer = NULL;
	rz_config_set_i (core->config, "asm.bits", bits);
	rz_config_set_i (core->config, "cfg.debug", true);
	rz_core_file_reopen (core, newfile, 0, 2);
	if (rz_config_get_i (core->config, "dbg.rebase")) {
		__rebase_everything (core, old_sections, old_base);
	}
	rz_list_free (old_sections);
	rz_core_cmd0 (core, "sr PC");
	free (bin_abspath);
	free (escaped_path);
	free (binpath);
}

static int fdsz = 0;

static bool init_desc_list_visual_cb(void *user, void *data, ut32 id) {
	RzIODesc *desc = (RzIODesc *)data;
	ut64 sz = rz_io_desc_size (desc);
	if (sz > fdsz) {
		fdsz = sz;
	}
	return true;
}

static bool desc_list_visual_cb(void *user, void *data, ut32 id) {
	RzPrint *p = (RzPrint *)user;
	RzIODesc *desc = (RzIODesc *)data;
	ut64 sz = rz_io_desc_size (desc);
	rz_cons_printf ("%2d %c %s 0x%08"PFMT64x" ", desc->fd,
			(desc->io && (desc->io->desc == desc)) ? '*' : '-', rz_str_rwx_i (desc->perm), sz);
	int flags = p->flags;
	p->flags &= ~RZ_PRINT_FLAGS_HEADER;
	rz_print_progressbar (p, sz * 100 / fdsz, rz_cons_get_size (NULL) - 40);
	p->flags = flags;
	rz_cons_printf (" %s\n", desc->uri);
#if 0
	RzIOMap *map;
	SdbListIter *iter;
	if (desc->io && desc->io->va && desc->io->maps) {
		ls_foreach_prev (desc->io->maps, iter, map) {
			if (map->fd == desc->fd) {
				p->cb_printf ("  +0x%"PFMT64x" 0x%"PFMT64x
					" - 0x%"PFMT64x" : %s : %s : %s\n", map->delta,
					map->from, map->to, rz_str_rwx_i (map->flags), "",
					rz_str_get2 (map));
			}
		}
	}
#endif
	return true;
}

static bool desc_list_quiet2_cb(void *user, void *data, ut32 id) {
	RzPrint *p = (RzPrint *)user;
	RzIODesc *desc = (RzIODesc *)data;
	p->cb_printf ("%d\n", desc->fd);
	return false;
}

static bool desc_list_quiet_cb(void *user, void *data, ut32 id) {
	RzPrint *p = (RzPrint *)user;
	RzIODesc *desc = (RzIODesc *)data;
	p->cb_printf ("%d\n", desc->fd);
	return true;
}

static bool desc_list_cb(void *user, void *data, ut32 id) {
	RzPrint *p = (RzPrint *)user;
	RzIODesc *desc = (RzIODesc *)data;
	p->cb_printf ("%2d %c %s 0x%08"PFMT64x" %s\n", desc->fd,
			(desc->io && (desc->io->desc == desc)) ? '*' : '-',
			rz_str_rwx_i (desc->perm), rz_io_desc_size (desc), desc->uri);
	return true;
}

static bool desc_list_json_cb(void *user, void *data, ut32 id) {
	PJ *pj = (PJ *)user;
	RzIODesc *desc = (RzIODesc *)data;
	// TODO: from is always 0? See librz/core/file.c:945
	ut64 from = 0LL;
	pj_o (pj);
	pj_kb (pj, "raised", desc->io && (desc->io->desc == desc));
	pj_kN (pj, "fd", desc->fd);
	pj_ks (pj, "uri", desc->uri);
	pj_kn (pj, "from", from);
	pj_kb (pj, "writable", desc->perm & RZ_PERM_W);
	pj_kN (pj, "size", rz_io_desc_size (desc));
	pj_end (pj);
	return true;
}

static bool cmd_op(RzCore *core, char mode, int fd) {
	int cur_fd = rz_io_fd_get_current (core->io);
	int next_fd = cur_fd;
	switch (mode) {
	case 0:
		next_fd = fd;
		break;
	case 'n':
		next_fd = rz_io_fd_get_next (core->io, cur_fd);
		break;
	case 'p':
		next_fd = rz_io_fd_get_prev (core->io, cur_fd);
		break;
	case 'r':
		next_fd = rz_io_fd_get_next (core->io, cur_fd);
		if (next_fd == -1) {
			next_fd = rz_io_fd_get_lowest (core->io);
		}
		break;
	}
	if (next_fd >= 0 && next_fd != cur_fd && rz_io_use_fd (core->io, next_fd)) {
		RzBinFile *bf = rz_bin_file_find_by_fd (core->bin, next_fd);
		if (bf && rz_core_bin_raise (core, bf->id)) {
			rz_core_block_read (core);
			return true;
		}
		eprintf ("Invalid RzBinFile.id number.\n");
	}
	return false;
}

RZ_IPI int rz_cmd_open(void *data, const char *input) {
	RzCore *core = (RzCore*)data;
	int perms = RZ_PERM_R;
	ut64 baddr = rz_config_get_i (core->config, "bin.baddr");
	ut64 addr = 0LL;
	int argc, fd = -1;
	RzCoreFile *file;
	RzIODesc *desc;
	bool write = false;
	const char *ptr = NULL;
	char **argv = NULL;

	switch (*input) {
	case 'a':
		switch (input[1]) {
		case '*': // "oa*"
			{
				RzListIter *iter;
				RzBinFile *bf = NULL;
				rz_list_foreach (core->bin->binfiles, iter, bf) {
					if (bf && bf->o && bf->o->info) {
						eprintf ("oa %s %d %s\n", bf->o->info->arch, bf->o->info->bits, bf->file);
					}
				}
				return 1;
			}
		case '?': // "oa?"
		case ' ': // "oa "
			{
				int i;
				char *ptr = strdup (input+2);
				const char *arch = NULL;
				ut16 bits = 0;
				const char *filename = NULL;
				i = rz_str_word_set0 (ptr);
				if (i < 2) {
					eprintf ("Missing argument\n");
					free (ptr);
					return 0;
				}
				if (i == 3) {
					filename = rz_str_word_get0 (ptr, 2);
				}
				bits = rz_num_math (core->num, rz_str_word_get0 (ptr, 1));
				arch = rz_str_word_get0 (ptr, 0);
				rz_core_bin_set_arch_bits (core, filename, arch, bits);
				RzBinFile *file = rz_bin_file_find_by_name (core->bin, filename);
				if (!file) {
					eprintf ("Cannot find file %s\n", filename);
					free (ptr);
					return 0;
				}
				if (file->o && file->o->info) {
					file->o->info->arch = strdup(arch);
					file->o->info->bits = bits;
					rz_core_bin_set_env (core, file);
				}
				free (ptr);
				return 1;
			}
		break;
		default:
			eprintf ("Usage: oa[-][arch] [bits] [filename]\n");
			return 0;
	}
	case 'n': // "on"
		if (input[1] == '*') {
			rz_core_file_list (core, 'n');
			return 0;
		}
		if (input[1] == '+') { // "on+"
			write = true;
			perms |= RZ_PERM_W;
			if (input[2] != ' ') {
				eprintf ("Usage: on+ file [addr] [rwx]\n");
				return 0;
			}
			ptr = input + 3;
		} else if (input[1] == ' ') {
			ptr = input + 2;
		} else {
			eprintf ("Usage: on file [addr] [rwx]\n");
			return 0;
		}
		argv = rz_str_argv (ptr, &argc);
		if (!argc) {
			eprintf ("Usage: on%s file [addr] [rwx]\n", write?"+":"");
			rz_str_argv_free (argv);
			return 0;
		}
		ptr = argv[0];
		if (argc == 2) {
			if (rz_num_is_valid_input (core->num, argv[1])) {
				addr = rz_num_math (core->num, argv[1]);
			} else {
				perms = rz_str_rwx (argv[1]);
			}
		}
		if (argc == 3) {
			addr = rz_num_math (core->num, argv[1]);
			perms = rz_str_rwx (argv[2]);
		}
		if (!strcmp (ptr, "-")) {
			ptr = "malloc://512";
		}
		if ((desc = rz_io_open_at (core->io, ptr, perms, 0644, addr))) {
			fd = desc->fd;
		}
		if (fd == -1) {
			eprintf ("Cannot open file '%s'\n", ptr);
		}
		rz_str_argv_free (argv);
		core->num->value = fd;
		rz_core_block_read (core);
		return 0;
#if 1
	// XXX projects use the of command, but i think we should deprecate it... keeping it for now
	case 'f': // "of"
		ptr = rz_str_trim_head_ro (input + 2);
		argv = rz_str_argv (ptr, &argc);
		if (argc == 0) {
			eprintf ("Usage: of [filename] (rwx)\n");
			rz_str_argv_free (argv);
			return 0;
		} else if (argc == 2) {
			perms = rz_str_rwx (argv[1]);
		}
		fd = rz_io_fd_open (core->io, argv[0], perms, 0);
		core->num->value = fd;
		rz_str_argv_free (argv);
		return 0;
#else
		{
			if ((input[1] == 's') && (input[2] == ' ')) {
				silence = true;
				input++;
			}
			addr = 0; // honor bin.baddr ?
			const char *argv0 = rz_str_trim_head_ro (input + 2);
			if ((file = rz_core_file_open (core, argv0, perms, addr))) {
				fd = file->fd;
				if (!silence) {
					eprintf ("%d\n", fd);
				}
				rz_core_bin_load (core, argv0, baddr);
			} else {
				eprintf ("cannot open file %s\n", argv0);
			}
			rz_str_argv_free (argv);
		}
		rz_core_block_read (core);
		return 0;
		break;
#endif
	case 'p': // "op"
		/* handle prioritize */
		if (input[1]) {
			switch (input[1]) {
			case 'r': // "opr" - open next file + rotate if not found
			case 'n': // "opn" - open next file
			case 'p': // "opp" - open previous file
				if (!cmd_op (core, input[1], -1)) {
					eprintf ("Cannot find file\n");
				}
				break;
			case ' ':
				{
					int fd = rz_num_math (core->num, input + 1);
					if (fd >= 0 || input[1] == '0') {
						cmd_op (core, 0, fd);
					} else {
						eprintf ("Invalid fd number\n");
					}
				}
				break;
			default:
				rz_core_cmd_help (core, help_msg_op);
				break;
			}
		} else {
			if (core->io && core->io->desc) {
				rz_cons_printf ("%d\n", core->io->desc->fd);
			}
		}
		return 0;
		break;
	case '+': // "o+"
		perms |= RZ_PERM_W;
		/* fallthrough */
	case ' ': // "o" "o "
		ptr = input + 1;
		argv = rz_str_argv (ptr, &argc);
		if (argc == 0) {
			eprintf ("Usage: o (uri://)[/path/to/file] (addr)\n");
			rz_str_argv_free (argv);
			return 0;
		}
		if (argv) {
			// Unescape spaces from the path
			rz_str_path_unescape (argv[0]);
			if (argc == 2) {
				if (rz_num_is_valid_input (core->num, argv[1])) {
					addr = rz_num_math (core->num, argv[1]);
				} else {
					perms = rz_str_rwx (argv[1]);
				}
			}
			if (argc == 3) {
				addr = rz_num_math (core->num, argv[1]);
				perms = rz_str_rwx (argv[2]);
			}
		}
		{
			const char *argv0 = argv ? argv[0] : ptr;
			if ((file = rz_core_file_open (core, argv0, perms, addr))) {
				fd = file->fd;
				core->num->value = fd;
				if (addr == 0) { // if no baddr defined, use the one provided by the file
					addr = UT64_MAX;
				}
				rz_core_bin_load (core, argv0, addr);
				if (*input == '+') { // "o+"
					RzIODesc *desc = rz_io_desc_get (core->io, fd);
					if (desc && (desc->perm & RZ_PERM_W)) {
						void **it;
						rz_pvector_foreach_prev (&core->io->maps, it) {
							RzIOMap *map = *it;
							if (map->fd == fd) {
								map->perm |= RZ_PERM_WX;
							}
						}
					} else {
						eprintf ("Error: %s is not writable\n", argv0);
					}
				}
			} else {
				eprintf ("cannot open file %s\n", argv0);
			}
			rz_str_argv_free (argv);
		}
		rz_core_block_read (core);
		return 0;
	}

	switch (*input) {
	case '=': // "o="
		fdsz = 0;
		rz_id_storage_foreach (core->io->files, init_desc_list_visual_cb, core->print);
		rz_id_storage_foreach (core->io->files, desc_list_visual_cb, core->print);
		break;
	case 'q': // "oq"
		if (input[1] == '.') {
			rz_id_storage_foreach (core->io->files, desc_list_quiet2_cb, core->print);
		} else {
			rz_id_storage_foreach (core->io->files, desc_list_quiet_cb, core->print);
		}
		break;
	case '\0': // "o"
		rz_id_storage_foreach (core->io->files, desc_list_cb, core->print);
		break;
	case '*': // "o*"
		if ('?' == input[1]) {
			rz_core_cmd_help (core, help_msg_o_star);
			break;
		}
		rz_core_file_list (core, (int)(*input));
		break;
	case 'j': // "oj"
		if ('?' == input[1]) {
			rz_core_cmd_help (core, help_msg_oj);
			break;
		}
		PJ *pj = pj_new ();
		pj_a (pj);
		rz_id_storage_foreach (core->io->files, desc_list_json_cb, pj);
		pj_end (pj);
		core->print->cb_printf ("%s\n", pj_string (pj));
		pj_free (pj);
		break;
	case 'L': // "oL"
		if (rz_sandbox_enable (0)) {
			eprintf ("This command is disabled in sandbox mode\n");
			return 0;
		}
		if (input[1] == ' ') {
			if (rz_lib_open (core->lib, input + 2) == -1) {
				eprintf ("Oops\n");
			}
		} else {
			if ('j' == input[1]) {
				rz_io_plugin_list_json (core->io);
			} else {
				rz_io_plugin_list (core->io);
			}
		}
		break;
	case 'i': // "oi"
		switch (input[1]) {
		case ' ': // "oi "
			{
				RzListIter *iter = NULL;
				RzCoreFile *f;
				int nth = rz_num_math (core->num, input + 2);
				int count = 0;
				rz_list_foreach (core->files, iter, f) {
					if (count == nth) {
						rz_io_use_fd (core->io, f->fd);
						break;
					}
					count++;
				}
			}
			break;
		case '-': // "oi-"
			{
				RzListIter *iter = NULL;
				RzCoreFile *f;
				int nth = rz_num_math (core->num, input + 2);
				int count = 0;
				rz_list_foreach (core->files, iter, f) {
					if (count == nth) {
						rz_core_file_close_fd (core, f->fd);
						break;
					}
					count++;
				}
			}
			break;
		case 'j': // "oij"
		case '*': // "oi*"
		case 0: // "oi"
			rz_core_file_list (core, input[1]);
			break;
		}
		break;
	case 'u': { // "ou"
		RzListIter *iter = NULL;
		RzCoreFile *f;
		core->switch_file_view = 0;
		int num = atoi (input + 2);

		rz_list_foreach (core->files, iter, f) {
			if (f->fd == num) {
				core->file = f;
			}
		}
		rz_io_use_fd (core->io, num);
		RzBinFile *bf = rz_bin_file_find_by_fd (core->bin, num);
		if (bf) {
			rz_core_bin_raise (core, bf->id);
			rz_core_block_read (core);
		}
		break;
	}
	case 'b': // "ob"
		cmd_open_bin (core, input);
		break;
	case '-': // "o-"
		switch (input[1]) {
		case '!': // "o-!"
			rz_core_file_close_all_but (core);
			break;
		case '*': // "o-*"
			rz_core_file_close_fd (core, -1);
			rz_io_close_all (core->io);
			rz_bin_file_delete_all (core->bin);
			if (core->files) {
				rz_list_purge (core->files);
			}
			break;
		case '-': // "o--"
			eprintf ("All core files, io, analysis and flags info purged.\n");
			rz_core_file_close_fd (core, -1);
			rz_io_close_all (core->io);
			rz_bin_file_delete_all (core->bin);

			// TODO: Move to a-- ?
			rz_analysis_purge (core->analysis);
			// TODO: Move to f-- ?
			rz_flag_unset_all (core->flags);
			// TODO: rbin?
			break;
		default:
			{
				int fd = (int)rz_num_math (core->num, input + 1);
				if (!rz_core_file_close_fd (core, fd)) {
					eprintf ("Unable to find file descriptor %d\n", fd);
				}
			}
			break;
		case 0:
		case '?':
			rz_core_cmd_help (core, help_msg_o_);
		}
		break;
	case '.': // "o."
		if (input[1] == 'q') { // "o.q" // same as oq
			RzIOMap *map = rz_io_map_get (core->io, core->offset);
			if (map) {
				rz_cons_printf ("%d\n", map->fd);
			}
		} else {
			RzIOMap *map = rz_io_map_get (core->io, core->offset);
			if (map) {
				RzIODesc *desc = rz_io_desc_get (core->io, map->fd);
				if (desc) {
					rz_cons_printf ("%s\n", desc->uri);
				}
			}
		}
		break;
	case ':': // "o:"
		{
			int len = rz_num_math (core->num, input + 1);
			if (len < 1) {
				len = core->blocksize;
			}
			char *uri = rz_str_newf ("malloc://%d", len);
			ut8 *data = calloc (len, 1);
			rz_io_read_at (core->io, core->offset, data, len);
			if ((file = rz_core_file_open (core, uri, RZ_PERM_RWX, 0))) {
				fd = file->fd;
				core->num->value = fd;
				rz_core_bin_load (core, uri, 0);
				RzIODesc *desc = rz_io_desc_get (core->io, fd);
				if (desc) {
					// TODO: why rz_io_desc_write() fails?
					rz_io_desc_write_at (desc, 0, data, len);
				}
			} else {
				eprintf ("Cannot %s\n", uri);
			}
			free (uri);
			free (data);
		}
		break;
	case 'm': // "om"
		cmd_open_map (core, input);
		break;
	case 'o': // "oo"
		switch (input[1]) {
		case 'm': // "oom"
			rz_core_file_reopen_in_malloc (core);
			break;
		case 'd': // "ood" : reopen in debugger
			if (input[2] == 'r') { // "oodr"
				rz_core_cmdf (core, "dor %s", input + 3);
				rz_core_file_reopen_debug (core, "");
			} else if (input[2] == 'f') { // "oodf"
				char **argv = NULL;
				int addr = 0;
				argv = rz_str_argv (input + 3, &argc);
				if (argc == 0) {
					eprintf ("Usage: oodf (uri://)[/path/to/file] (addr)\n");
					rz_str_argv_free (argv);
					return 0;
				}
				if (argc == 2) {
					if (rz_num_is_valid_input (core->num, argv[1])) {
						addr = rz_num_math (core->num, argv[1]);
					}
				}
				rz_core_file_reopen_remote_debug (core, argv[0], addr);
				rz_str_argv_free (argv);
			} else if ('?' == input[2]) {
				rz_core_cmd_help (core, help_msg_ood);
			} else {
				rz_core_file_reopen_debug (core, input + 2);
			}
			break;
		case 'c': // "oob" : reopen with bin info
			rz_core_cmd0 (core, "oc `o.`");
			break;
		case 'b': // "oob" : reopen with bin info
			if ('?' == input[2]) {
				rz_core_cmd_help (core, help_msg_oob);
			} else {
				rz_core_file_reopen (core, input + 2, 0, 2);
			}
			break;
		case 'n': // "oon"
			switch (input[2]) {
			case 0: // "oon"
				rz_core_file_reopen (core, NULL, 0, 0);
				break;
			case '+': // "oon+"
				rz_core_file_reopen (core, NULL, RZ_PERM_RW, 0);
				break;
			case 'n': // "oonn"
				if ('?' == input[3] || !core->file) {
					rz_core_cmd_help (core, help_msg_oonn);
					break;
				}
				RzIODesc *desc = rz_io_desc_get (core->io, core->file->fd);
				if (desc) {
					perms = core->io->desc->perm;
					if (input[3] == '+') {
						perms |= RZ_PERM_RW;
					}
					char *fname = strdup (desc->name);
					if (fname) {
						rz_core_bin_load_structs (core, fname);
						rz_core_file_reopen (core, fname, perms, 0);
						free (fname);
					}
					break;
				}
				break;
			case '?':
			default:
				rz_core_cmd_help (core, help_msg_oon);
				break;
			}
			break;
		case '+': // "oo+"
			if ('?' == input[2]) {
				rz_core_cmd_help (core, help_msg_oo_plus);
			} else if (core && core->io && core->io->desc) {
				int fd;
				int perms = RZ_PERM_RW;
				if ((ptr = strrchr (input, ' ')) && ptr[1]) {
					fd = (int)rz_num_math (core->num, ptr + 1);
				} else {
					fd = core->io->desc->fd;
					perms |= core->io->desc->perm;
				}
				if (rz_io_reopen (core->io, fd, perms, 644)) {
					void **it;
					rz_pvector_foreach_prev (&core->io->maps, it) {
						RzIOMap *map = *it;
						if (map->fd == fd) {
							map->perm |= RZ_PERM_WX;
						}
					}
				}
			}
			break;
		case '\0': // "oo"
			if (core && core->io && core->io->desc) {
				int fd;
				if ((ptr = strrchr (input, ' ')) && ptr[1]) {
					fd = (int)rz_num_math (core->num, ptr + 1);
				} else {
					fd = core->io->desc->fd;
				}
				if (rz_config_get_i (core->config, "cfg.debug")) {
					RzBinFile *bf = rz_bin_cur (core->bin);
					if (bf && rz_file_exists (bf->file)) {
						// Escape spaces so that o's argv parse will detect the path properly
						char *file = rz_str_path_escape (bf->file);
						// Backup the baddr and sections that were already rebased to
						// revert the rebase after the debug session is closed
						ut64 orig_baddr = core->bin->cur->o->baddr_shift;
						RzList *orig_sections = __save_old_sections (core);

						rz_core_cmd0 (core, "ob-*");
						rz_io_close_all (core->io);
						rz_config_set (core->config, "cfg.debug", "false");
						rz_core_cmdf (core, "o %s", file);

						rz_core_block_read (core);
						__rebase_everything (core, orig_sections, orig_baddr);
						rz_list_free (orig_sections);
						free (file);
					} else {
						eprintf ("Nothing to do.\n");
					}
				} else {
					rz_io_reopen (core->io, fd, RZ_PERM_R, 644);
				}
			}
			break;
		case '?':
		default:
			 rz_core_cmd_help (core, help_msg_oo);
			 break;
		}
		break;
	case 'c': // "oc"
		if (input[1] == '?') {
			eprintf ("Usage: oc [file]\n");
		} else if (input[1] && input[2]) {
			if (rz_sandbox_enable (0)) {
				eprintf ("This command is disabled in sandbox mode\n");
				return 0;
			}
			if (core->tasks.current_task != core->tasks.main_task) {
				eprintf ("This command can only be executed on the main task!\n");
				return 0;
			}
			// memleak? loses all settings
			// if load fails does not fallbacks to previous file
			rz_core_task_sync_end (&core->tasks);
			rz_core_fini (core);
			rz_core_init (core);
			rz_core_task_sync_begin (&core->tasks);
			if (!rz_core_file_open (core, input + 2, RZ_PERM_R, 0)) {
				eprintf ("Cannot open file\n");
			}
			(void)rz_core_bin_load (core, NULL, baddr);
		} else {
			eprintf ("Missing argument\n");
		}
		break;
	case 'x': // "ox"
		if (input[1] && input[1] != '?') {
			int fd, fdx;
			fd = fdx = -1;
			char *ptr, *inp = strdup (input);
			if ((ptr = strrchr (inp, ' '))) {
				fdx = (int)rz_num_math (core->num, ptr + 1);
				*ptr = '\0';
				if ((ptr = strchr (inp, ' '))) {
					fd = rz_num_math (core->num, ptr + 1);
				}
			}
			if ((fdx == -1) || (fd == -1) || (fdx == fd)) {
				free (inp);
				break;
			}
			rz_io_desc_exchange (core->io, fd, fdx);
			rz_core_block_read (core);
		} else {
			eprintf ("Usage: ox [fd] [fdx] - exchange two file descriptors\n");
		}
		break;
	case '?': // "o?"
	default:
		rz_core_cmd_help (core, help_msg_o);
		break;
	}
	return 0;
}
