/* rizin - LGPL - Copyright 2009-2020 - pancake */

#include <rz_core.h>

static const char *fortunes[] = {
	"tips", "fun", "nsfw", "creepy"
};

static char *getFortuneFile(RzCore *core, const char *type) {
	return rz_str_newf (RZ_JOIN_3_PATHS ("%s", RZ_FORTUNES, "fortunes.%s"),
		rz_sys_prefix (NULL), type);
}

RZ_API void rz_core_fortune_list_types(void) {
	size_t i;
	for (i = 0; i < RZ_ARRAY_SIZE (fortunes); i++) {
		rz_cons_printf ("%s\n", fortunes[i]);
	}
}

RZ_API void rz_core_fortune_list(RzCore *core) {
	// TODO: use file.fortunes // can be dangerous in sandbox mode
	const char *types = (char *)rz_config_get (core->config, "cfg.fortunes.type");
	size_t i, j;
	for (i = 0; i < RZ_ARRAY_SIZE (fortunes); i++) {
		if (strstr (types, fortunes[i])) {
			char *file = getFortuneFile (core, fortunes[i]);
			char *str = rz_file_slurp (file, NULL);
			if (!str) {
				free (file);
				continue;
			}
			for (j = 0; str[j]; j++) {
				if (str[j] == '\n') {
					if (i < j) {
						str[j] = '\0';
						rz_cons_printf ("%s\n", str + i);
					}
					i = j + 1;
				}
			}
			free (str);
			free (file);
		}
	}
}

static char *getrandomline(RzCore *core) {
	size_t i;
	const char *types = (char *)rz_config_get (core->config, "cfg.fortunes.type");
	char *line = NULL, *templine;
	for (i = 0; i < RZ_ARRAY_SIZE (fortunes); i++) {
		if (strstr (types, fortunes[i])) {
			int lines = 0;
			char *file = getFortuneFile(core, fortunes[i]);
			templine = rz_file_slurp_random_line_count (file, &lines);
			if (templine && *templine) {
				free (line);
				line = templine;
			}
			free (file);
		}
	}
	return line;
}

RZ_API void rz_core_fortune_print_random(RzCore *core) {
	// TODO: use file.fortunes // can be dangerous in sandbox mode
	char *line = getrandomline (core);
	if (!line) {
		line = getrandomline (core);
	}
	if (line) {
		if (rz_config_get_i (core->config, "cfg.fortunes.clippy")) {
			rz_core_clippy (core, line);
		} else {
			rz_cons_printf (" -- %s\n", line);
		}
		if (rz_config_get_i (core->config, "cfg.fortunes.tts")) {
			rz_sys_tts (line, true);
		}
		free (line);
	}
}
