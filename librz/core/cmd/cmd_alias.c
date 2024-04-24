// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_cmd.h"
#include "rz_core.h"

RZ_IPI RzCmdStatus rz_alias_handler(RzCore *core, int argc, const char **argv) {
	const char *input = argc > 1 ? argv[1] : "";
	int i = strlen(input);
	char *buf = malloc(i + 2);
	if (!buf) {
		return RZ_CMD_STATUS_ERROR;
	}
	*buf = '$'; // prefix aliases with a dollar
	memcpy(buf + 1, input, i + 1);
	char *q = strchr(buf, ' ');
	char *def = strchr(buf, '=');
	char *desc = strchr(buf, '?');
	char *nonl = strchr(buf, 'n');

	int defmode = 0;
	if (def && def > buf) {
		char *prev = def - 1;
		switch (*prev) {
		case ':':
			defmode = *prev;
			*prev = 0;
			break;
		case '+':
			defmode = *prev;
			*prev = 0;
			break;
		case '-':
			defmode = *prev;
			*prev = 0;
			break;
		}
	}

	/* create alias */
	if ((def && q && (def < q)) || (def && !q)) {
		*def++ = 0;
		size_t len = strlen(def);
		if (defmode) {
			ut64 at = rz_num_math(core->num, def);
			switch (defmode) {
			case ':':
				rz_flag_set(core->flags, buf + 1, at, 1);
				return RZ_CMD_STATUS_OK;
			case '+':
				at = rz_num_get(core->num, buf + 1) + at;
				rz_flag_set(core->flags, buf + 1, at, 1);
				return RZ_CMD_STATUS_OK;
			case '-':
				at = rz_num_get(core->num, buf + 1) - at;
				rz_flag_set(core->flags, buf + 1, at, 1);
				return RZ_CMD_STATUS_OK;
			}
		}
		/* Remove quotes */
		if (len > 0 && (def[0] == '\'') && (def[len - 1] == '\'')) {
			def[len - 1] = 0x00;
			def++;
		}
		if (!q || (q && q > def)) {
			if (*def) {
				if (!strcmp(def, "-")) {
					char *v = rz_cmd_alias_get(core->rcmd, buf, 0);
					char *n = rz_core_editor(core, NULL, v);
					if (n) {
						rz_cmd_alias_set(core->rcmd, buf, n, 0);
						free(n);
					}
				} else {
					rz_cmd_alias_set(core->rcmd, buf, def, 0);
				}
			} else {
				rz_cmd_alias_del(core->rcmd, buf);
			}
		}
		/* Show command for alias */
	} else if (desc && !q) {
		*desc = 0;
		char *v = rz_cmd_alias_get(core->rcmd, buf, 0);
		if (v) {
			if (nonl == desc + 1) {
				rz_cons_print(v);
			} else {
				rz_cons_println(v);
			}
		} else {
			RZ_LOG_ERROR("core: unknown key '%s'\n", buf);
			free(buf);
			return RZ_CMD_STATUS_ERROR;
		}
	} else if (!buf[1]) {
		int i, count = 0;
		char **keys = rz_cmd_alias_keys(core->rcmd, &count);
		for (i = 0; i < count; i++) {
			rz_cons_println(keys[i]);
		}
	} else {
		/* Execute alias */
		if (q) {
			*q = 0;
		}
		char *v = rz_cmd_alias_get(core->rcmd, buf, 0);
		if (v) {
			if (*v == '$') {
				rz_cons_strcat(v + 1);
				rz_cons_newline();
			} else if (q) {
				char *out = rz_str_newf("%s %s", v, q + 1);
				rz_core_cmd0(core, out);
				free(out);
			} else {
				rz_core_cmd0(core, v);
			}
		} else {
			RzFlagItem *flag = rz_flag_get(core->flags, buf + 1);
			if (flag) {
				rz_core_seek(core, rz_flag_item_get_offset(flag), true);
			} else {
				RZ_LOG_ERROR("core: unknown alias '%s'\n", buf + 1);
				free(buf);
				return RZ_CMD_STATUS_ERROR;
			}
		}
	}
	free(buf);
	return RZ_CMD_STATUS_OK;
}

static void list_aliases(RzCore *core, bool base64) {
	int i, count = 0;
	char **keys = rz_cmd_alias_keys(core->rcmd, &count);
	for (i = 0; i < count; i++) {
		char *v = rz_cmd_alias_get(core->rcmd, keys[i], 0);
		if (base64) {
			char *q = rz_base64_encode_dyn((const ut8 *)v, strlen(v));
			rz_cons_printf("%s=base64:%s\n", keys[i], q);
			free(q);
		} else {
			rz_cons_printf("%s=%s\n", keys[i], v);
		}
	}
}

RZ_IPI RzCmdStatus rz_alias_list_cmd_base64_handler(RzCore *core, int argc, const char **argv) {
	list_aliases(core, true);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_alias_list_cmd_plain_handler(RzCore *core, int argc, const char **argv) {
	list_aliases(core, false);
	return RZ_CMD_STATUS_OK;
}
