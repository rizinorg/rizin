/* SH */

// TODO: use popen for {{pipe/endpipe}}

static TAG_CALLBACK(sh_default) {
#if HAVE_FORK
	int r = system (buf);
	if (errno) {
		printf ("system '%s' (%d) failed: %s\n", buf, r, strerror (errno));
	}
#endif
	return 0;
}

static int sh_pipe_enabled = 0;
static char *sh_pipe_cmd = NULL;

static TAG_CALLBACK(sh_pipe) {
	sh_pipe_enabled = 1;
	free (sh_pipe_cmd);
	sh_pipe_cmd = strdup (buf);
	return 0;
}

static TAG_CALLBACK(sh_endpipe) {
	sh_pipe_enabled = 0;
	free (sh_pipe_cmd);
	sh_pipe_cmd = NULL;
	return 0;
}

static PUT_CALLBACK(sh_fputs) {
	if (sh_pipe_enabled) {
		char str[1024]; // XXX
		sprintf (str, "echo '%s' | %s", buf, sh_pipe_cmd); // XXX
#if HAVE_FORK
		int r = system (str);
		if (errno) {
			printf ("system '%s' (%d) failed: %s\n", str, r, strerror (errno));
		}
#endif
	} else {
		out_printf (out, "%s", buf);
	}
	return 0;
}

static struct Tag sh_tags[] = {
	{ "pipe", sh_pipe },
	{ "endpipe", sh_endpipe },
	{ NULL, sh_default },
	{ NULL }
};

static struct Arg sh_args[] = {
	{ NULL }
};

DLL_LOCAL struct Proc sh_proc = {
	.name = "sh",
	.tags = (struct Tag **)sh_tags,
	.args = (struct Arg **)sh_args,
	.eof = NULL,
	.token = NULL,
	.tag_pre = "{{",
	.tag_post = "}}",
	.fputs = sh_fputs,
	.multiline = "\\\n",
	.default_echo = 1,
	.chop = 0,
	.tag_begin = 0,
};
