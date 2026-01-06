// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2021 maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_num.h>
#include <rz_util/rz_graph_drawable.h>
#include <rz_util/rz_log.h>

#include "../core_private.h"

static bool callback_foreach_kv(void *user, const SdbKv *kv) {
	rz_cons_printf("%s=%s\n", sdbkv_key(kv), sdbkv_value(kv));
	return true;
}

RZ_IPI RzCmdStatus rz_query_sdb_get_set_handler(RzCore *core, int argc, const char **argv) {
	Sdb *sdb = core->sdb;
	if (!sdb) {
		RZ_LOG_ERROR("SDB is NULL.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	if (argc == 1) {
		sdb_foreach(sdb, callback_foreach_kv, NULL);
		return RZ_CMD_STATUS_OK;
	}
	rz_core_kuery_print(core, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_query_shell_sdb_handler(RzCore *core, int argc, const char **argv) {
	char buf[1024], *out;
	Sdb *sdb = core->sdb;
	if (!sdb) {
		RZ_LOG_ERROR("SDB is NULL.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (core->http_up) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_cons_is_interactive()) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc > 1) {
		char *n, *o, *p = rz_str_dup(argv[1]);
		// TODO: slash split here? or inside sdb_ns ?
		for (n = o = p; n; o = n) {
			n = strchr(o, '/'); // SDB_NS_SEPARATOR NAMESPACE
			if (n) {
				*n++ = 0;
			}
			sdb = sdb_ns(sdb, o, 1);
		}
		free(p);
	}
	if (!sdb) {
		sdb = core->sdb;
	}
	RzLine *line = core->cons->line;
	if (!line->sdbshell_hist) {
		line->sdbshell_hist = rz_list_newf(free);
	}
	RzList *sdb_hist = line->sdbshell_hist;
	rz_line_set_hist_callback(line, &rz_line_hist_sdb_up, &rz_line_hist_sdb_down);
	for (;;) {
		rz_line_set_prompt(line, "[sdb]> ");
		if (rz_cons_fgets(buf, sizeof(buf), 0, NULL) < 1) {
			break;
		}
		if (!*buf) {
			break;
		}
		if (sdb_hist) {
			if ((rz_list_length(sdb_hist) == 1) || (rz_list_length(sdb_hist) > 1 && strcmp(rz_list_get_n(sdb_hist, 1), buf))) {
				rz_list_insert(sdb_hist, 1, rz_str_dup(buf));
			}
			line->sdbshell_hist_iter = sdb_hist->head;
		}
		out = sdb_querys(sdb, NULL, 0, buf);
		if (out) {
			rz_cons_println(out);
			rz_cons_flush();
		}
	}
	rz_line_set_hist_callback(core->cons->line, &rz_line_hist_cmd_up, &rz_line_hist_cmd_down);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_sdb_namespace_dump_handler(RzCore *core, int argc, const char **argv) {
	const char *filename = argv[1];
	const char *namespace = argv[2];
	Sdb *db = sdb_ns_path(core->sdb, namespace, 0);
	if (!db) {
		RZ_LOG_ERROR("core: Cannot find sdb '%s'\n", namespace);
		return RZ_CMD_STATUS_ERROR;
	}
	sdb_file(db, filename);
	sdb_sync(db);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_sdb_namespace_load_handler(RzCore *core, int argc, const char **argv) {
	const char *filename = argv[1];
	const char *namespace = argv[2];
	if (!rz_file_exists(filename)) {
		RZ_LOG_ERROR("Cannot open file\n");
		return RZ_CMD_STATUS_ERROR;
	}
	Sdb *db = sdb_ns_path(core->sdb, namespace, 1);
	if (!db) {
		RZ_LOG_ERROR("Cannot find sdb '%s'\n", namespace);
		return RZ_CMD_STATUS_ERROR;
	}
	Sdb *newdb = sdb_new(NULL, filename, 0);
	if (!newdb) {
		RZ_LOG_ERROR("Cannot open sdb '%s'\n", filename);
		return RZ_CMD_STATUS_ERROR;
	}
	sdb_drain(db, newdb);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_query_dump_json_handler(RzCore *core, int argc, const char **argv) {
	char *out, *tofree;
	Sdb *sdb = core->sdb;
	char *cur_pos = NULL, *cur_cmd = NULL, *next_cmd = NULL;
	char *temp_pos = NULL, *temp_cmd = NULL;

	tofree = out = sdb_querys(sdb, NULL, 0, "analysis/**");
	if (!out) {
		rz_cons_println("No Output from sdb");
		return RZ_CMD_STATUS_ERROR;
	}
	PJ *pj = pj_new();
	if (!pj) {
		free(out);
		return RZ_CMD_STATUS_ERROR;
	}
	pj_o(pj);
	pj_ko(pj, "analysis");
	pj_ka(pj, "cur_cmd");

	while (*out) {
		cur_pos = strchr(out, '\n');
		if (!cur_pos) {
			break;
		}
		cur_cmd = rz_str_ndup(out, cur_pos - out);
		pj_s(pj, cur_cmd);

		free(next_cmd);
		next_cmd = rz_str_newf("analysis/%s/*", cur_cmd);
		char *query_result = sdb_querys(sdb, NULL, 0, next_cmd);

		if (!query_result) {
			out = cur_pos + 1;
			continue;
		}

		char *temp = query_result;
		while (*temp) {
			temp_pos = strchr(temp, '\n');
			if (!temp_pos) {
				break;
			}
			temp_cmd = rz_str_ndup(temp, temp_pos - temp);
			pj_s(pj, temp_cmd);
			free(temp_cmd);
			temp = temp_pos + 1;
		}
		out = cur_pos + 1;
		free(query_result);
	}
	pj_end(pj);
	pj_end(pj);
	pj_end(pj);
	rz_cons_println(pj_string(pj));
	pj_free(pj);
	RZ_FREE(next_cmd);
	free(next_cmd);
	free(cur_cmd);
	free(tofree);
	return RZ_CMD_STATUS_OK;
}
