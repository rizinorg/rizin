// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_cons.h>
#include "i/private.h"

/**
 * \brief Set the prompt and return the input contents
 * \param cons The cons instance
 * \param str Prompt string
 * \param txt Optional text already shown in the prompt
 * \returns contents of the prompt input
 */
RZ_API RZ_OWN char *rz_cons_prompt(RZ_NONNULL RzCons *cons, RZ_NONNULL const char *str, RZ_NULLABLE const char *txt) {
	rz_return_val_if_fail(cons && str, NULL);
	char cmd[1024];
	char *res = NULL;
	char *oprompt = rz_str_dup(cons->line->prompt);
	rz_cons_show_cursor(cons, true);
	if (txt && *txt) {
		free(cons->line->contents);
		cons->line->contents = rz_str_dup(txt);
	} else {
		RZ_FREE(cons->line->contents);
	}
	*cmd = '\0';
	rz_line_set_prompt(cons->line, str);
	if (rz_cons_fgets(cons, cmd, sizeof(cmd), 0, NULL) < 0) {
		*cmd = '\0';
	}
	// line[strlen(line)-1]='\0';
	if (*cmd) {
		res = rz_str_dup(cmd);
	}
	rz_line_set_prompt(cons->line, oprompt);
	free(oprompt);
	RZ_FREE(cons->line->contents);
	return res;
}
