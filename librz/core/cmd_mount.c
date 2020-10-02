/* radare - LGPL - Copyright 2009-2019 // pancake */

static const char *help_msg_m[] = {
	"Usage:", "m[-?*dgy] [...] ", "Mountpoints management",
	"m", " /mnt ext2 0", "Mount ext2 fs at /mnt with delta 0 on IO",
	"m", " /mnt", "Mount fs at /mnt with autodetect fs and current offset",
	"m", "", "List all mountpoints in human readable format",
	"m*", "", "Same as above, but in r2 commands",
	"m-/", "", "Umount given path (/)",
	"mL", "", "List filesystem plugins (Same as Lm)",
	"mc", " [file]", "Cat: Show the contents of the given file",
	"md", " /", "List directory contents for path",
	"mf", "[?] [o|n]", "Search files for given filename or for offset",
	"mg", " /foo", "Get fs file/dir and dump it to disk",
	"mi", " /foo/bar", "Get offset and size of given file",
	"mj", "", "List mounted filesystems in JSON",
	"mo", " /foo/bar", "Open given file into a malloc://",
	"mp", " msdos 0", "Show partitions in msdos format at offset 0",
	"mp", "", "List all supported partition types",
	"ms", " /mnt", "Open filesystem prompt at /mnt",
	"mw", " [file] [data]", "Write data into file", // TODO: add mwf
	"my", "", "Yank contents of file into clipboard",
	//"TODO: support multiple mountpoints and RFile IO's (need io+core refactorn",
	NULL
};

static void cmd_mount_init(RzCore *core, RzCmdDesc *parent) {
	DEFINE_CMD_DESCRIPTOR (core, m);
}

static int cmd_mkdir(void *data, const char *input) {
	char *res = rz_syscmd_mkdir (input);
	if (res) {
		rz_cons_print (res);
		free (res);
	}
	return 0;
}

static int cmd_mv(void *data, const char *input) {
	return rz_syscmd_mv (input)? 1: 0;
}

static char *cwd = NULL;
#define av_max 1024

static const char *t2s(const char ch) {
	switch (ch) {
	case 'f': return "file";
	case 'd': return "directory";
	case 'm': return "mountpoint";
	}
	return "unknown";
}

static void cmd_mount_ls (RzCore *core, const char *input) {
	bool isJSON = *input == 'j';
	RzListIter *iter;
	RzFSFile *file;
	RzFSRoot *root;
	input = rz_str_trim_head_ro (input + isJSON);
	RzList *list = rz_fs_dir (core->fs, input);
	PJ *pj = NULL;
	if (isJSON) {
		pj = pj_new ();
		pj_a (pj);
	}
	if (list) {
		rz_list_foreach (list, iter, file) {
			if (isJSON) {
				pj_o (pj);
				pj_ks (pj, "type", t2s(file->type));
				pj_ks (pj, "name", file->name);
				pj_end (pj);
			} else {
				rz_cons_printf ("%c %s\n", file->type, file->name);
			}
		}
		rz_list_free (list);
	}
	const char *path = *input? input: "/";
	rz_list_foreach (core->fs->roots, iter, root) {
		// TODO: adjust contents between //
		if (!strncmp (path, root->path, strlen (path))) {
			char *base = strdup (root->path);
			char *ls = (char *)rz_str_lchr (base, '/');
			if (ls) {
				ls++;
				*ls = 0;
			}
			// TODO: adjust contents between //
			if (!strcmp (path, base)) {
				if (isJSON) {
					pj_o (pj);
					pj_ks (pj, "path", root->path);
					pj_ks (pj, "type", "mountpoint");
					pj_end (pj);
				} else {
					rz_cons_printf ("m %s\n", root->path); //  (root->path && root->path[0]) ? root->path + 1: "");
				}
			}
			free (base);
		}
	}
	if (isJSON) {
		pj_end (pj);
		rz_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
}

static int cmd_mount(void *data, const char *_input) {
	ut64 off = 0;
	char *input, *oinput, *ptr, *ptr2;
	RzList *list;
	RzListIter *iter;
	RzFSFile *file;
	RzFSRoot *root;
	RzFSPlugin *plug;
	RzFSPartition *part;
	RzCore *core = (RzCore *)data;

	if (!strncmp ("kdir", _input, 4)) {
		return cmd_mkdir (data, _input);
	}
	if (!strncmp ("v", _input, 1)) {
		return cmd_mv (data, _input);
	}
	input = oinput = strdup (_input);

	switch (*input) {
	case ' ':
		input = (char *)rz_str_trim_head_ro (input + 1);
		ptr = strchr (input, ' ');
		if (ptr) {
			*ptr = 0;
			ptr = (char *)rz_str_trim_head_ro (ptr + 1);
			ptr2 = strchr (ptr, ' ');
			if (ptr2) {
				*ptr2 = 0;
				off = rz_num_math (core->num, ptr2+1);
			}
			input = (char *)rz_str_trim_head_ro (input);
			ptr = (char*)rz_str_trim_head_ro (ptr);

			const char *mountp = input;
			const char *fstype = ptr;
			if (*mountp != '/') {
				if (*fstype != '/') {
					eprintf ("Invalid mountpoint\n");
					return 0;
				}
				mountp = ptr;
				fstype = input;
			}

			if (!rz_fs_mount (core->fs, fstype, mountp, off)) {
				eprintf ("Cannot mount %s\n", input);
			}
		} else {
			if (!(ptr = rz_fs_name (core->fs, core->offset))) {
				eprintf ("Unknown filesystem type\n");
			}
			if (!rz_fs_mount (core->fs, ptr, input, core->offset)) {
				eprintf ("Cannot mount %s\n", input);
			}
			free (ptr);
		}
		break;
	case '-':
		rz_fs_umount (core->fs, input+1);
		break;
	case 'j':
		{
			PJ *pj = pj_new ();
			pj_o (pj);
			pj_k (pj, "mountpoints");
			pj_a (pj);
			rz_list_foreach (core->fs->roots, iter, root) {
				pj_o (pj);
				pj_ks (pj, "path", root->path);
				pj_ks (pj, "plugin", root->p->name);
				pj_kn (pj, "offset", root->delta);
				pj_end (pj);
			}
			pj_end (pj);
			pj_k (pj, "plugins");
			pj_a (pj);
			rz_list_foreach (core->fs->plugins, iter, plug) {
				pj_o (pj);
				pj_ks (pj, "name", plug->name);
				pj_ks (pj, "description", plug->desc);
				pj_end (pj);
			}

			pj_end (pj);
			pj_end (pj);
			rz_cons_printf ("%s\n", pj_string (pj));
			pj_free (pj);
		}
		break;
	case '*':
		rz_list_foreach (core->fs->roots, iter, root) {
			rz_cons_printf ("m %s %s 0x%"PFMT64x"\n",
				root-> path, root->p->name, root->delta);
		}
		break;
	case '\0':
		rz_list_foreach (core->fs->roots, iter, root) {
			rz_cons_printf ("%s\t0x%"PFMT64x"\t%s\n",
				root->p->name, root->delta, root->path);
		}
		break;
	case 'L': // "mL" list of plugins
		rz_list_foreach (core->fs->plugins, iter, plug) {
			rz_cons_printf ("%10s  %s\n", plug->name, plug->desc);
		}
		break;
	case 'l': // "ml"
	case 'd': // "md" 
		cmd_mount_ls (core, input + 1);
		break;
	case 'p':
		input++;
		if (*input == ' ') {
			input++;
		}
		ptr = strchr (input, ' ');
		if (ptr) {
			*ptr = 0;
			off = rz_num_math (core->num, ptr+1);
		}
		list = rz_fs_partitions (core->fs, input, off);
		if (list) {
			rz_list_foreach (list, iter, part) {
				rz_cons_printf ("%d %02x 0x%010"PFMT64x" 0x%010"PFMT64x"\n",
					part->number, part->type,
					part->start, part->start+part->length);
			}
			rz_list_free (list);
		} else {
			eprintf ("Cannot read partition\n");
		}
		break;
	case 'o': //"mo"
		input++;
		if (input[0]==' ') {
			input++;
		}
		file = rz_fs_open (core->fs, input, false);
		if (file) {
			rz_fs_read (core->fs, file, 0, file->size);
			char *uri = rz_str_newf ("malloc://%d", file->size);
			RzIODesc *fd = rz_io_open (core->io, uri, RZ_PERM_RW, 0);
			if (fd) {
				rz_io_desc_write (fd, file->data, file->size);
			}
		} else {
			eprintf ("Cannot open file\n");
		}
		break;
	case 'i':
		input++;
		if (input[0]==' ') {
			input++;
		}
		file = rz_fs_open (core->fs, input, false);
		if (file) {
			// XXX: dump to file or just pipe?
			rz_fs_read (core->fs, file, 0, file->size);
			rz_cons_printf ("f file %d 0x%08"PFMT64x"\n", file->size, file->off);
			rz_fs_close (core->fs, file);
		} else {
			eprintf ("Cannot open file\n");
		}
		break;
	case 'c': // "mc"
		input++;
		if (*input == ' ') {
			input++;
		}
		ptr = strchr (input, ' ');
		if (ptr) {
			*ptr++ = 0;
		} else {
			ptr = "./";
		}
		file = rz_fs_open (core->fs, input, false);
		if (file) {
			rz_fs_read (core->fs, file, 0, file->size);
			rz_cons_memcat ((const char *)file->data, file->size);
			rz_fs_close (core->fs, file);
			rz_cons_memcat ("\n", 1);
		} else if (!rz_fs_dir_dump (core->fs, input, ptr)) {
			eprintf ("Cannot open file\n");
		}
		break;
	case 'g': // "mg"
		input++;
		if (*input == ' ') {
			input++;
		}
		ptr = strchr (input, ' ');
		if (ptr) {
			*ptr++ = 0;
		} else {
			ptr = "./";
		}
		file = rz_fs_open (core->fs, input, false);
		if (file) {
			char *localFile = strdup (input);
			char *slash = (char *)rz_str_rchr (localFile, NULL, '/');
			if (slash) {
				memmove (localFile, slash + 1, strlen (slash));
			}
			rz_fs_read (core->fs, file, 0, file->size);
			rz_file_dump (localFile, file->data, file->size, false);
			rz_fs_close (core->fs, file);
			eprintf ("File '%s' created.\n", localFile);
			free (localFile);
		} else if (!rz_fs_dir_dump (core->fs, input, ptr)) {
			eprintf ("Cannot open file\n");
		}
		break;
	case 'f':
		input++;
		switch (*input) {
		case '?':
			rz_cons_printf (
			"Usage: mf[no] [...]\n"
			" mfn /foo *.c       ; search files by name in /foo path\n"
			" mfo /foo 0x5e91    ; search files by offset in /foo path\n"
			);
			break;
		case 'n':
			input++;
			if (*input == ' ')
				input++;
			ptr = strchr (input, ' ');
			if (ptr) {
				*ptr++ = 0;
				list = rz_fs_find_name (core->fs, input, ptr);
				rz_list_foreach (list, iter, ptr) {
					rz_str_trim_path (ptr);
					printf ("%s\n", ptr);
				}
				//XXX: rz_list_purge (list);
			} else eprintf ("Unknown store path\n");
			break;
		case 'o':
			input++;
			if (*input == ' ')
				input++;
			ptr = strchr (input, ' ');
			if (ptr) {
				*ptr++ = 0;
				ut64 off = rz_num_math (core->num, ptr);
				list = rz_fs_find_off (core->fs, input, off);
				rz_list_foreach (list, iter, ptr) {
					rz_str_trim_path (ptr);
					printf ("%s\n", ptr);
				}
				//XXX: rz_list_purge (list);
			} else eprintf ("Unknown store path\n");
			break;
		}
		break;
	case 's': // "ms"
		if (core->http_up) {
			free (oinput);
			return false;
		}
		input++;
		if (input[0] == ' ') {
			input++;
		}
		rz_cons_set_raw (false);
		{
			RzFSShell shell = {
				.cwd = &cwd,
				.set_prompt = rz_line_set_prompt,
				.readline = rz_line_readline,
				.hist_add = rz_line_hist_add
			};
			core->rfs = &shell;
			core->autocomplete_type = AUTOCOMPLETE_MS;
			rz_core_autocomplete_reload (core);
			rz_fs_shell_prompt (&shell, core->fs, input);
			core->autocomplete_type = AUTOCOMPLETE_DEFAULT;
			rz_core_autocomplete_reload (core);
			RZ_FREE (cwd);
		}
		break;
	case 'w':
		if (input[1] == ' ') {
			char *args = rz_str_trim_dup (input + 1);
			char *arg = strchr (args, ' ');
			if (arg) {
				data = arg + 1;
			} else {
				data = "";
				// touch and truncate
			}
			RzFSFile *f = rz_fs_open (core->fs, args, true);
			if (f) {
				rz_fs_write (core->fs, f, 0, (const ut8 *)data, strlen (data));
				rz_fs_close (core->fs, f);
				rz_fs_file_free (f);
			}
			free (args);
		} else {
			eprintf ("Usage: mw [file] ([data])\n");
		}
		break;
	case 'y':
		eprintf ("TODO\n");
		break;
	case '?':
		rz_core_cmd_help (core, help_msg_m);
		break;
	}
	free (oinput);
	return 0;
}
