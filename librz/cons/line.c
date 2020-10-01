/* radare - LGPL - Copyright 2007-2019 - pancake */

#include <rz_util.h>
#include <rz_cons.h>

static RLine rz_line_instance;
#define I rz_line_instance

RZ_API RLine *rz_line_singleton(void) {
	return &rz_line_instance;
}

RZ_API RLine *rz_line_new(void) {
	I.hist_up = NULL;
	I.hist_down = NULL;
	I.prompt = strdup ("> ");
	I.contents = NULL;
	I.enable_vi_mode = false;
	I.clipboard = NULL;
	I.kill_ring = rz_list_newf (NULL);
	I.kill_ring_ptr = -1;
#if __WINDOWS__
	I.vtmode = rz_cons_is_vtcompat ();
#else
	I.vtmode = 2;
#endif
	if (!rz_line_dietline_init ()) {
		eprintf ("error: rz_line_dietline_init\n");
	}
	rz_line_completion_init (&I.completion, 4096);
	return &I;
}

RZ_API void rz_line_free(void) {
	// XXX: prompt out of the heap?
	free ((void *)I.prompt);
	I.prompt = NULL;
	rz_line_hist_free ();
	rz_line_completion_fini (&I.completion);
}

RZ_API void rz_line_clipboard_push (const char *str) {
	I.kill_ring_ptr += 1;
	rz_list_insert (I.kill_ring, I.kill_ring_ptr, strdup (str));
}

// handle const or dynamic prompts?
RZ_API void rz_line_set_prompt(const char *prompt) {
	free (I.prompt);
	I.prompt = strdup (prompt);
	RzCons *cons = rz_cons_singleton ();
	I.cb_fkey = cons->cb_fkey;
}

// handle const or dynamic prompts?
RZ_API char *rz_line_get_prompt(void) {
	return strdup (I.prompt);
}

RZ_API void rz_line_completion_init(RLineCompletion *completion, size_t args_limit) {
	completion->run = NULL;
	completion->run_user = NULL;
	completion->args_limit = args_limit;
	rz_pvector_init (&completion->args, free);
}

RZ_API void rz_line_completion_fini(RLineCompletion *completion) {
	rz_line_completion_clear (completion);
}

RZ_API void rz_line_completion_push(RLineCompletion *completion, const char *str) {
	rz_return_if_fail (completion && str);
	if (completion->quit) {
	        return;
	}
	if (rz_pvector_len (&completion->args) < completion->args_limit) {
		char *s = strdup (str);
		if (s) {
			rz_pvector_push (&completion->args, (void *)s);
		}
	} else {
	        completion->quit = true;
	        eprintf ("WARNING: Maximum completion capacity reached, increase scr.maxtab");
	}
}

RZ_API void rz_line_completion_set(RLineCompletion *completion, int argc, const char **argv) {
	rz_return_if_fail (completion && (argc >= 0));
	rz_line_completion_clear (completion);
	if (argc > completion->args_limit) {
                eprintf ("WARNING: Maximum completion capacity reached, increase scr.maxtab");
	}
	size_t count = R_MIN (argc, completion->args_limit);
	rz_pvector_reserve (&completion->args, count);
	int i;
	for (i = 0; i < count; i++) {
		rz_line_completion_push (completion, argv[i]);
	}
}

RZ_API void rz_line_completion_clear(RLineCompletion *completion) {
	rz_return_if_fail (completion);
	completion->quit = false;
	rz_pvector_clear (&completion->args);
}

#include "dietline.c"
