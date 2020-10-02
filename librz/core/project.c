/* radare - LGPL - Copyright 2010-2020 - pancake, maijin */

#include <rz_types.h>
#include <rz_list.h>
#include <rz_flag.h>
#include <rz_core.h>
#define USE_R2 1
#include <spp/spp.h>

static bool is_valid_project_name(const char *name) {
	int i;
	if (rz_str_endswith (name, ".zip")) {
		return false;
	}
	for (i = 0; name[i]; i++) {
		switch (name[i]) {
		case '\\': // for w32
		case '.':
		case '_':
		case ':':
		case '-':
			continue;
		}
		if (name[i] >= 'a' && name[i] <= 'z') {
			continue;
		}
		if (name[i] >= 'A' && name[i] <= 'Z') {
			continue;
		}
		if (IS_DIGIT (name[i])) {
			continue;
		}
		return false;
	}
	return true;
}

static char *get_project_script_path(RzCore *core, const char *file) {
	const char *magic = "# r2 rdb project file";
	char *data, *prjfile;
	if (rz_file_is_abspath (file)) {
		prjfile = strdup (file);
	} else {
		if (!is_valid_project_name (file)) {
			return NULL;
		}
		prjfile = rz_file_abspath (rz_config_get (core->config, "dir.projects"));
		prjfile = rz_str_append (prjfile, RZ_SYS_DIR);
		prjfile = rz_str_append (prjfile, file);
		if (!rz_file_exists (prjfile) || rz_file_is_directory (prjfile)) {
			prjfile = rz_str_append (prjfile, RZ_SYS_DIR "rc");
		}
	}
	data = rz_file_slurp (prjfile, NULL);
	if (data) {
		if (strncmp (data, magic, strlen (magic))) {
			RZ_FREE (prjfile);
		}
	}
	free (data);
	return prjfile;
}

static int make_projects_directory(RzCore *core) {
	char *prjdir = rz_file_abspath (rz_config_get (core->config, "dir.projects"));
	int ret = rz_sys_mkdirp (prjdir);
	if (!ret) {
		eprintf ("Cannot mkdir dir.projects\n");
	}
	free (prjdir);
	return ret;
}

RZ_API bool rz_core_is_project(RzCore *core, const char *name) {
	bool ret = false;
	if (name && *name && *name != '.') {
		char *path = get_project_script_path (core, name);
		if (!path) {
			return false;
		}
		if (rz_str_endswith (path, RZ_SYS_DIR "rc") && rz_file_exists (path)) {
			ret = true;
		} else {
			path = rz_str_append (path, ".d");
			if (rz_file_is_directory (path)) {
				ret = true;
			}
		}
		free (path);
	}
	return ret;
}

RZ_API int rz_core_project_cat(RzCore *core, const char *name) {
	char *path = get_project_script_path (core, name);
	if (path) {
		char *data = rz_file_slurp (path, NULL);
		if (data) {
			rz_cons_println (data);
			free (data);
		}
	}
	free (path);
	return 0;
}

RZ_API int rz_core_project_list(RzCore *core, int mode) {
	PJ *pj = NULL;
	RzListIter *iter;
	RzList *list;

	char *foo, *path = rz_file_abspath (rz_config_get (core->config, "dir.projects"));
	if (!path) {
		return 0;
	}
	list = rz_sys_dir (path);
	switch (mode) {
	case 'j':
		pj = pj_new ();
		if (!pj) {
			break;
		}
		pj_a (pj);
		rz_list_foreach (list, iter, foo) {
			// todo. escape string
			if (rz_core_is_project (core, foo)) {
				pj_s (pj, foo);
			}
		}
		pj_end (pj);
		rz_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
		break;
	default:
		rz_list_foreach (list, iter, foo) {
			if (rz_core_is_project (core, foo)) {
				rz_cons_println (foo);
			}
		}
		break;
	}
	rz_list_free (list);
	free (path);
	return 0;
}

static inline void remove_project_file(char * path) {
		if (rz_file_exists (path)) {
			rz_file_rm (path);
			eprintf ("rm %s\n", path);
		}
}

static inline void remove_notes_file(char *prjDir) {
		char *notes_txt = rz_str_newf ("%s%s%s", prjDir, RZ_SYS_DIR, "notes.txt");
		if (rz_file_exists (notes_txt)) {
			rz_file_rm (notes_txt);
			eprintf ("rm %s\n", notes_txt);
		}
		free(notes_txt);
}

static inline void remove_rop_directory(char *prjDir) {
		char *rop_d = rz_str_newf ("%s%s%s", prjDir, RZ_SYS_DIR, "rop.d");

		if (rz_file_is_directory (rop_d)) {
			char *f;
			RzListIter *iter;
			RzList *files = rz_sys_dir (rop_d);
			rz_list_foreach (files, iter, f) {
				char *filepath = rz_str_append (strdup (rop_d), RZ_SYS_DIR);
				filepath = rz_str_append (filepath, f);
				if (!rz_file_is_directory (filepath)) {
					eprintf ("rm %s\n", filepath);
					rz_file_rm (filepath);
				}

				free (filepath);
			}

			rz_file_rm (rop_d);
			eprintf ("rm %s\n", rop_d);
			rz_list_free (files);
		}

		free (rop_d);
}
RZ_API int rz_core_project_delete(RzCore *core, const char *prjfile) {
	if (rz_sandbox_enable (0)) {
		eprintf ("Cannot delete project in sandbox mode\n");
		return 0;
	}
	char *path = get_project_script_path (core, prjfile);
	if (!path) {
		eprintf ("Invalid project name '%s'\n", prjfile);
		return false;
	}
	if (rz_core_is_project (core, prjfile)) {
		char *prjDir = rz_file_dirname (path);
		if (!prjDir) {
			eprintf ("Cannot resolve directory\n");
			free (path);
			return false;
		}
		remove_project_file (path);
		remove_notes_file (prjDir);
		remove_rop_directory (prjDir);
		// remove directory only if it's empty
		rz_file_rm (prjDir);
		free (prjDir);
	}
	free (path);
	return 0;
}

static bool load_project_rop(RzCore *core, const char *prjfile) {
	char *path, *db = NULL, *path_ns;
	bool found = 0;
	SdbListIter *it;
	SdbNs *ns;

	if (!prjfile || !*prjfile) {
		return false;
	}

	Sdb *rop_db = sdb_ns (core->sdb, "rop", false);
	Sdb *nop_db = sdb_ns (rop_db, "nop", false);
	Sdb *mov_db = sdb_ns (rop_db, "mov", false);
	Sdb *const_db = sdb_ns (rop_db, "const", false);
	Sdb *arithm_db = sdb_ns (rop_db, "arithm", false);
	Sdb *arithmct_db = sdb_ns (rop_db, "arithm_ct", false);

	char *rcPath = get_project_script_path (core, prjfile);
	char *prjDir = rz_file_dirname (rcPath);

	if (rz_str_endswith (prjfile, RZ_SYS_DIR "rc")) {
		// XXX
		eprintf ("ENDS WITH\n");
		path = strdup (prjfile);
		path[strlen (path) - 3] = 0;
	} else if (rz_file_fexists ("%s" RZ_SYS_DIR "rc", prjDir, prjfile)) {
		path = rz_str_newf ("%s" RZ_SYS_DIR, prjDir, prjfile);
	} else {
		if (*prjfile == RZ_SYS_DIR[0]) {
			db = rz_str_newf ("%s.d", prjfile);
			if (!db) {
				free (prjDir);
				free (rcPath);
				return false;
			}
			path = strdup (db);
		} else {
			db = rz_str_newf ("%s" RZ_SYS_DIR "%s.d", prjDir, prjfile);
			if (!db) {
				free (prjDir);
				free (rcPath);
				return false;
			}
			path = rz_file_abspath (db);
		}
	}
	if (!path) {
		free (db);
		free (prjDir);
		free (rcPath);
		return false;
	}
	if (rop_db) {
		ls_foreach (core->sdb->ns, it, ns){
			if (ns->sdb == rop_db) {
				ls_delete (core->sdb->ns, it);
				found = true;
				break;
			}
		}
	}
	if (!found) {
		sdb_free (rop_db);
	}
	rop_db = sdb_new (path, "rop", 0);
	if (!rop_db) {
		free (db);
		free (path);
		free (prjDir);
		free (rcPath);
		return false;
	}
	sdb_ns_set (core->sdb, "rop", rop_db);

	path_ns = rz_str_newf ("%s" RZ_SYS_DIR "rop", prjDir);
	if (!rz_file_exists (path_ns)) {
		path_ns = rz_str_append (path_ns, ".sdb");
	}
	nop_db = sdb_new (path_ns, "nop", 0);
	sdb_ns_set (rop_db, "nop", nop_db);

	mov_db = sdb_new (path_ns, "mov", 0);
	sdb_ns_set (rop_db, "mov", mov_db);

	const_db = sdb_new (path_ns, "const", 0);
	sdb_ns_set (rop_db, "const", const_db);

	arithm_db = sdb_new (path_ns, "arithm", 0);
	sdb_ns_set (rop_db, "arithm", arithm_db);

	arithmct_db = sdb_new (path_ns, "arithm_ct", 0);
	sdb_ns_set (rop_db, "arithm_ct", arithmct_db);

	free (path);
	free (path_ns);
	free (db);
	free (prjDir);
	free (rcPath);
	return true;
}

RZ_API void rz_core_project_execute_cmds(RzCore *core, const char *prjfile) {
	char *str = rz_core_project_notes_file (core, prjfile);
	char *data = rz_file_slurp (str, NULL);
	if (!data) {
		free (str);
		return;
	}
	Output out;
	out.fout = NULL;
	out.cout = rz_strbuf_new (NULL);
	rz_strbuf_init (out.cout);
	struct Proc proc;
	spp_proc_set (&proc, "spp", 1);
	spp_eval (data, &out);
	free (data);
	data = strdup (rz_strbuf_get (out.cout));
	char *bol = strtok (data, "\n");
	while (bol) {
		if (bol[0] == ':') {
			rz_core_cmd0 (core, bol + 1);
		}
		bol = strtok (NULL, "\n");
	}
	free (data);
	free (str);
}

/*** vvv thready ***/

typedef struct {
	RzCore *core;
	char *prjName;
	char *rcPath;
} ProjectState;

static RzThreadFunctionRet project_load_background(RzThread *th) {
	ProjectState *ps = th->user;
	rz_core_project_load (ps->core, ps->prjName, ps->rcPath);
	free (ps->prjName);
	free (ps->rcPath);
	free (ps);
	return RZ_TH_STOP;
}

RZ_API RzThread *rz_core_project_load_bg(RzCore *core, const char *prjName, const char *rcPath) {
	ProjectState *ps = RZ_NEW (ProjectState);
	ps->core = core;
	ps->prjName = strdup (prjName);
	ps->rcPath = strdup (rcPath);
	RzThread *th = rz_th_new (project_load_background, ps, false);
	if (th) {
		rz_th_start (th, true);
		char thname[16] = {0};
		size_t thlen = RZ_MIN (strlen(prjName), sizeof(thname) - 1);
		strncpy (thname, prjName, thlen);
		thname[15] = 0;
		rz_th_setname (th, thname);
	}
	return th;
}

/*** ^^^ thready ***/

static ut64 getProjectLaddr(RzCore *core, const char *prjfile) {
	ut64 laddr = 0;
	char *buf = rz_file_slurp (prjfile, NULL);
	char *pos;
	if (buf) {
		if ((pos = strstr(buf, "\"e bin.laddr = "))) {
			laddr = rz_num_math (NULL, pos + 15);
		}
		free (buf);
	}
	return laddr;
}

RZ_API bool rz_core_project_open(RzCore *core, const char *prjfile, bool thready) {
	bool askuser = true;
	int ret, close_current_session = 1;
	char *oldbin;
	const char *newbin;
	ut64 mapaddr = 0;
	if (!prjfile || !*prjfile) {
		return false;
	}
	if (thready) {
		eprintf ("Loading projects in a thread has been deprecated. Use tasks\n");
		return false;
	}
	char *prj = get_project_script_path (core, prjfile);
	if (!prj) {
		eprintf ("Invalid project name '%s'\n", prjfile);
		return false;
	}
	char *filepath = rz_core_project_info (core, prj);
	// eprintf ("OPENING (%s) from %s\n", prj, rz_config_get (core->config, "file.path"));
	/* if it is not an URI */
	if (!filepath) {
		eprintf ("Cannot retrieve information for project '%s'\n", prj);
		free (prj);
		return false;
	}

	if (!filepath[0]) {
		goto cookiefactory;
	}
	if (!strstr (filepath, "://")) {
		/* check if path exists */
		if (!rz_file_exists (filepath)) {
			eprintf ("Cannot find file '%s'\n", filepath);
			free (prj);
			free (filepath);
			return false;
		}
	}
 cookiefactory:
	;
	const char *file_path = rz_config_get (core->config, "file.path");
	if (!file_path || !*file_path) {
		file_path = rz_config_get (core->config, "file.lastpath");
	}
	oldbin = strdup (file_path);
	if (!strcmp (prjfile, rz_config_get (core->config, "prj.name"))) {
		// eprintf ("Reloading project\n");
		askuser = false;
#if 0
		free (prj);
		free (filepath);
		return false;
#endif
	}
	if (askuser) {
		if (rz_cons_is_interactive ()) {
			close_current_session = rz_cons_yesno ('y', "Close current session? (Y/n)");
		}
	}
	if (close_current_session) {
		// delete
		rz_core_file_close_fd (core, -1);
		rz_io_close_all (core->io);
		rz_anal_purge (core->anal);
		rz_flag_unset_all (core->flags);
		rz_bin_file_delete_all (core->bin);
		// open new file
		// TODO: handle read/read-write mode
		if (filepath[0]) {
			/* Old-style project without embedded on commands to open all files.  */
			if (!rz_core_file_open (core, filepath, 0, UT64_MAX)) {
				eprintf ("Cannot open file '%s'\n", filepath);
				ret = false;
				goto beach;
			}
		}
	}
	mapaddr = getProjectLaddr (core, prj);
	if (mapaddr) {
		rz_config_set_i (core->config, "bin.laddr", mapaddr);
	}
	if (filepath[0] && close_current_session && rz_config_get_i (core->config, "file.info")) {
		mapaddr = rz_config_get_i (core->config, "file.offset");
		(void)rz_core_bin_load (core, filepath, mapaddr? mapaddr: UT64_MAX);
	}
	/* load sdb stuff in here */
	ret = rz_core_project_load (core, prjfile, prj);
	if (filepath[0]) {
		newbin = rz_config_get (core->config, "file.path");
		if (!newbin || !*newbin) {
			newbin = rz_config_get (core->config, "file.lastpath");
		}
		if (strcmp (oldbin, newbin)) {
			eprintf ("WARNING: file.path changed: %s => %s\n", oldbin, newbin);
		}
	}
beach:
	free (oldbin);
	free (filepath);
	free (prj);
	return ret;
}

RZ_API char *rz_core_project_info(RzCore *core, const char *prjfile) {
	FILE *fd;
	char buf[256], *file = NULL;
	char *prj = get_project_script_path (core, prjfile);
	if (!prj) {
		eprintf ("Invalid project name '%s'\n", prjfile);
		return NULL;
	}
	fd = rz_sandbox_fopen (prj, "r");
	if (fd) {
		for (;;) {
			if (!fgets (buf, sizeof (buf), fd)) {
				break;
			}
			if (feof (fd)) {
				break;
			}
			if (!strncmp (buf, "\"e file.path = ", 15)) {
				buf[strlen (buf) - 2] = 0;
				file = rz_str_new (buf + 15);
				break;
			}
			if (!strncmp (buf, "\"e file.lastpath = ", 19)) {
				buf[strlen (buf) - 2] = 0;
				file = rz_str_new (buf + 19);
				break;
			}
			// TODO: deprecate before 1.0
			if (!strncmp (buf, "e file.path = ", 14)) {
				buf[strlen (buf) - 1] = 0;
				file = rz_str_new (buf + 14);
				break;
			}
		}
		fclose (fd);
	} else {
		eprintf ("Cannot open project info (%s)\n", prj);
	}
#if 0
	if (file) {
		rz_cons_printf ("Project: %s\n", prj);
		rz_cons_printf ("FilePath: %s\n", file);
	}
#endif
	free (prj);
	return file;
}

static int fdc;		//this is a ugly, remove it, when we have $fd

static bool store_files_and_maps (RzCore *core, RzIODesc *desc, ut32 id) {
	RzList *maps = NULL;
	RzListIter *iter;
	RzIOMap *map;
	if (desc) {
		// reload bin info
		rz_cons_printf ("\"obf %s\"\n", desc->uri);
		rz_cons_printf ("\"ofs \\\"%s\\\" %s\"\n", desc->uri, rz_str_rwx_i (desc->perm));
		if ((maps = rz_io_map_get_for_fd (core->io, id))) {
			rz_list_foreach (maps, iter, map) {
				rz_cons_printf ("om %d 0x%"PFMT64x" 0x%"PFMT64x" 0x%"PFMT64x" %s%s%s\n", fdc,
					map->itv.addr, map->itv.size, map->delta, rz_str_rwx_i (map->perm),
					map->name ? " " : "", map->name ? map->name : "");
			}
			rz_list_free (maps);
		}
		fdc++;
	}
	return true;
}

static bool simple_project_save_script(RzCore *core, const char *file, int opts) {
	char *filename, *hl, *ohl = NULL;
	int fd, fdold;

	if (!file || * file == '\0') {
		return false;
	}

	filename = rz_str_word_get_first (file);
	fd = rz_sandbox_open (file, O_BINARY | O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd == -1) {
		free (filename);
		return false;
	}

	hl = rz_cons_singleton ()->highlight;
	if (hl) {
		ohl = strdup (hl);
		rz_cons_highlight (NULL);
	}

	fdold = rz_cons_singleton ()->fdout;
	rz_cons_singleton ()->fdout = fd;
	rz_cons_singleton ()->context->is_interactive = false; // NOES must use api

	rz_str_write (fd, "# r2 rdb project file\n");

	if (opts & RZ_CORE_PRJ_EVAL) {
		rz_str_write (fd, "# eval\n");
		rz_config_list (core->config, NULL, true);
		rz_cons_flush ();
	}

	if (opts & RZ_CORE_PRJ_FCNS) {
		rz_str_write (fd, "# functions\n");
		rz_str_write (fd, "fs functions\n");
		rz_core_cmd (core, "afl*", 0);
		rz_cons_flush ();
	}

	if (opts & RZ_CORE_PRJ_FLAGS) {
		rz_str_write (fd, "# flags\n");
		rz_core_cmd (core, "f.**", 0);
		rz_cons_flush ();
	}
	if (opts & RZ_CORE_PRJ_META) {
		rz_str_write (fd, "# meta\n");
		rz_meta_print_list_all (core->anal, RZ_META_TYPE_ANY, 1);
		rz_cons_flush ();
		rz_core_cmd (core, "fV*", 0);
		rz_cons_flush ();
	}
	if (opts & RZ_CORE_PRJ_XREFS) {
		rz_str_write (fd, "# xrefs\n");
		rz_core_cmd (core, "ax*", 0);
		rz_cons_flush ();
	}


	rz_cons_singleton ()->fdout = fdold;
	rz_cons_singleton ()->context->is_interactive = true;

	if (ohl) {
		rz_cons_highlight (ohl);
		free (ohl);
	}

	close (fd);
	free (filename);

	return true;
}

static bool project_save_script(RzCore *core, const char *file, int opts) {
	char *filename, *hl, *ohl = NULL;
	int fd, fdold;

	if (!file || *file == '\0') {
		return false;
	}

	filename = rz_str_word_get_first (file);
	fd = rz_sandbox_open (file, O_BINARY | O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd == -1) {
		free (filename);
		return false;
	}

	hl = rz_cons_singleton ()->highlight;
	if (hl) {
		ohl = strdup (hl);
		rz_cons_highlight (NULL);
	}
	fdold = rz_cons_singleton ()->fdout;
	rz_cons_singleton ()->fdout = fd;
	rz_cons_singleton ()->context->is_interactive = false;
	rz_str_write (fd, "# r2 rdb project file\n");
	if (!core->bin->is_debugger && !rz_config_get_i (core->config, "asm.emu")) {
		if (core->bin->file) {
			char *fpath = rz_file_abspath (core->bin->file);
			if (fpath) {
				char *reopen = rz_str_newf ("\"o %s\"\n", fpath);
				if (reopen) {
					rz_str_write (fd, reopen);
					free (reopen);
					free (fpath);
				}
			}
		}
		
	}
	// Set file.path and file.lastpath to empty string to signal
	// new behaviour to project load routine (see io maps below).
	rz_config_set (core->config, "file.path", "");
	rz_config_set (core->config, "file.lastpath", "");
	if (opts & RZ_CORE_PRJ_EVAL) {
		rz_str_write (fd, "# eval\n");
		rz_config_list (core->config, NULL, true);
		rz_cons_flush ();
	}

	if (opts & RZ_CORE_PRJ_FCNS) {
		rz_str_write (fd, "# functions\n");
		rz_str_write (fd, "fs functions\n");
		rz_core_cmd (core, "afl*", 0);
		rz_cons_flush ();
	}

	if (opts & RZ_CORE_PRJ_FLAGS) {
		rz_str_write (fd, "# flags\n");
		rz_flag_space_push (core->flags, NULL);
		rz_flag_list (core->flags, true, NULL);
		rz_flag_space_pop (core->flags);
		rz_cons_flush ();
	}
	if (opts & RZ_CORE_PRJ_IO_MAPS && core->io && core->io->files) {
		fdc = 3;
		rz_id_storage_foreach (core->io->files, (RIDStorageForeachCb)store_files_and_maps, core);
		rz_cons_flush ();
	}
	{
		rz_core_cmd (core, "fz*", 0);
		rz_cons_flush ();
	}
	if (opts & RZ_CORE_PRJ_META) {
		rz_str_write (fd, "# meta\n");
		rz_meta_print_list_all (core->anal, RZ_META_TYPE_ANY, 1);
		rz_cons_flush ();
		rz_core_cmd (core, "fV*", 0);
		rz_cons_flush ();
	}
	if (opts & RZ_CORE_PRJ_XREFS) {
		rz_core_cmd (core, "ax*", 0);
		rz_cons_flush ();
	}
	if (opts & RZ_CORE_PRJ_FLAGS) {
		rz_core_cmd (core, "f.**", 0);
		rz_cons_flush ();
	}
	if (opts & RZ_CORE_PRJ_DBG_BREAK) {
		rz_core_cmd (core, "db*", 0);
		rz_cons_flush ();
	}
	if (opts & RZ_CORE_PRJ_ANAL_HINTS) {
		rz_core_cmd (core, "ah*", 0);
		rz_cons_flush ();
	}
	if (opts & RZ_CORE_PRJ_ANAL_TYPES) {
		rz_str_write (fd, "# types\n");
		rz_core_cmd (core, "t*", 0);
		rz_cons_flush ();
	}
	if (opts & RZ_CORE_PRJ_ANAL_MACROS) {
		rz_str_write (fd, "# macros\n");
		rz_core_cmd (core, "(*", 0);
		rz_str_write (fd, "# aliases\n");
		rz_core_cmd (core, "$*", 0);
		rz_cons_flush ();
	}
	if (opts & RZ_CORE_PRJ_ANAL_SEEK) {
		rz_cons_printf ("# seek\n"
			"s 0x%08"PFMT64x "\n", core->offset);
		rz_cons_flush ();
	}

	rz_cons_singleton ()->fdout = fdold;
	rz_cons_singleton ()->context->is_interactive = true;

	if (ohl) {
		rz_cons_highlight (ohl);
		free (ohl);
	}

	close (fd);
	free (filename);

	return true;
}

// TODO: rename to rz_core_project_save_script
RZ_API bool rz_core_project_save_script(RzCore *core, const char *file, int opts) {
	return project_save_script (core, file, opts);
}

#define TRANSITION 1

RZ_API bool rz_core_project_save(RzCore *core, const char *prjName) {
	bool scr_null = false;
	bool ret = true;
	char *scriptPath, *prjDir;
	SdbListIter *it;
	SdbNs *ns;
	char *oldPrjName = NULL;

	if (!prjName || !*prjName) {
		return false;
	}
	scriptPath = get_project_script_path (core, prjName);
	if (!scriptPath) {
		eprintf ("Invalid project name '%s'\n", prjName);
		return false;
	}
	if (rz_str_endswith (scriptPath, RZ_SYS_DIR "rc")) {
		/* new project format */
		prjDir = rz_file_dirname (scriptPath);
	} else {
		prjDir = rz_str_newf ("%s.d", scriptPath);
	}
	if (rz_file_exists (scriptPath)) {
		if (rz_file_is_directory (scriptPath)) {
			eprintf ("WTF. rc is a directory?\n");
		}
		if (rz_str_endswith (prjDir, ".d")) {
			eprintf ("Upgrading project...\n");
#if TRANSITION
			rz_file_rm (scriptPath);
			rz_sys_mkdirp (prjDir);
			eprintf ("Please remove: rm -rf %s %s.d\n", prjName, prjName);
			char *rc = rz_str_newf ("%s" RZ_SYS_DIR "rc", prjDir);
			if (!rc) {
				free (prjDir);
				free (scriptPath);
				return false;
			}
			free (scriptPath);
			scriptPath = rc;
			free (prjDir);
			prjDir = rz_file_dirname (scriptPath);
#endif
		}
	}
	if (!prjDir) {
		prjDir = strdup (prjName);
	}
	if (!rz_file_exists (prjDir)) {
		rz_sys_mkdirp (prjDir);
	}
	if (rz_config_get_i (core->config, "scr.null")) {
		rz_config_set_i (core->config, "scr.null", false);
		scr_null = true;
	}
	make_projects_directory (core);

	Sdb *rop_db = sdb_ns (core->sdb, "rop", false);
	if (rop_db) {
		/* set filepath for all the rop sub-dbs */
		ls_foreach (rop_db->ns, it, ns) {
			char *rop_path = rz_str_newf ("%s" RZ_SYS_DIR "rop.d" RZ_SYS_DIR "%s", prjDir, ns->name);
			sdb_file (ns->sdb, rop_path);
			sdb_sync (ns->sdb);
			free (rop_path);
		}
	}

	const char *oldPrjNameC = rz_config_get (core->config, "prj.name");
	if (oldPrjNameC) {
		oldPrjName = strdup (oldPrjNameC);
	}
	rz_config_set (core->config, "prj.name", prjName);
	if (rz_config_get_i (core->config, "prj.simple")) {
		if (!simple_project_save_script (core, scriptPath, RZ_CORE_PRJ_ALL)) {
			eprintf ("Cannot open '%s' for writing\n", prjName);
			ret = false;
		}
	} else {
		if (!project_save_script (core, scriptPath, RZ_CORE_PRJ_ALL)) {
			eprintf ("Cannot open '%s' for writing\n", prjName);
			ret = false;
		}
	}

	if (rz_config_get_i (core->config, "prj.files")) {
		eprintf ("TODO: prj.files: support copying more than one file into the project directory\n");
		char *binFile = rz_core_project_info (core, prjName);
		const char *binFileName = rz_file_basename (binFile);
		char *prjBinDir = rz_str_newf ("%s" RZ_SYS_DIR "bin", prjDir);
		char *prjBinFile = rz_str_newf ("%s" RZ_SYS_DIR "%s", prjBinDir, binFileName);
		rz_sys_mkdirp (prjBinDir);
		if (!rz_file_copy (binFile, prjBinFile)) {
			eprintf ("Warning: Cannot copy '%s' into '%s'\n", binFile, prjBinFile);
		}
		free (prjBinFile);
		free (prjBinDir);
		free (binFile);
	}
	if (rz_config_get_i (core->config, "prj.git")) {
		char *cwd = rz_sys_getdir ();
		char *gitDir = rz_str_newf ("%s" RZ_SYS_DIR ".git", prjDir);
		if (rz_sys_chdir (prjDir)) {
			if (!rz_file_is_directory (gitDir)) {
				rz_sys_cmd ("git init");
			}
			rz_sys_cmd ("git add * ; git commit -a");
		} else {
			eprintf ("Cannot chdir %s\n", prjDir);
		}
		rz_sys_chdir (cwd);
		free (gitDir);
		free (cwd);
	}
	if (rz_config_get_i (core->config, "prj.zip")) {
		char *cwd = rz_sys_getdir ();
		const char *prjName = rz_file_basename (prjDir);
		if (rz_sys_chdir (prjDir)) {
			if (!strchr (prjName, '\'')) {
				rz_sys_chdir ("..");
				rz_sys_cmdf ("rm -f '%s.zip'; zip -r '%s'.zip '%s'",
					prjName, prjName, prjName);
			} else {
				eprintf ("Command injection attempt?\n");
			}
		} else {
			eprintf ("Cannot chdir %s\n", prjDir);
		}
		rz_sys_chdir (cwd);
		free (cwd);
	}
	// LEAK : not always in heap free (prjName);
	free (prjDir);
	if (scr_null) {
		rz_config_set_i (core->config, "scr.null", true);
	}
	if (!ret && oldPrjName) {
		// reset prj.name on fail
		rz_config_set (core->config, "prj.name", oldPrjName);
	}
	free (scriptPath);
	free (oldPrjName);
	return ret;
}

RZ_API char *rz_core_project_notes_file(RzCore *core, const char *prjName) {
	char *notes_txt;
	const char *prjdir = rz_config_get (core->config, "dir.projects");
	char *prjpath = rz_file_abspath (prjdir);
	notes_txt = rz_str_newf ("%s"RZ_SYS_DIR "%s"RZ_SYS_DIR "notes.txt", prjpath, prjName);
	free (prjpath);
	return notes_txt;
}

RZ_API bool rz_core_project_load(RzCore *core, const char *prjName, const char *rcpath) {
	const bool cfg_fortunes = rz_config_get_i (core->config, "cfg.fortunes");
	const bool scr_interactive = rz_cons_is_interactive ();
	const bool scr_prompt = rz_config_get_i (core->config, "scr.prompt");
	(void) load_project_rop (core, prjName);
	bool ret = rz_core_cmd_file (core, rcpath);
	rz_config_set_i (core->config, "cfg.fortunes", cfg_fortunes);
	rz_config_set_i (core->config, "scr.interactive", scr_interactive);
	rz_config_set_i (core->config, "scr.prompt", scr_prompt);
	rz_config_bump (core->config, "asm.arch");
	return ret;
}
