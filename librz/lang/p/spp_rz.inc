/* SPP-RZ, a template programming language with rizin integration */

#include <rz_util.h>

static char *spp_rz_var_get(char *var) {
	return rz_sys_getenv(var);
}

static int spp_rz_var_set(const char *var, const char *val) {
	return rz_sys_setenv(var, val);
}

static TAG_CALLBACK(spp_rz_set) {
	char *eq, *val = "";
	if (!state->echo[state->ifl]) {
		return 0;
	}
	for (eq = buf; eq[0]; eq++) {
		switch (eq[0]) {
		case '-':
		case '.':
			eq[0] = '_';
			break;
		}
	}
	eq = strchr(buf, ' ');
	if (eq) {
		*eq = '\0';
		val = eq + 1;
	}
	if (spp_rz_var_set(buf, val) == -1) {
		fprintf(stderr, "Invalid variable name '%s' at line %d\n", buf, state->lineno);
	}
	return 0;
}

static TAG_CALLBACK(spp_rz_get) {
	if (!state->echo[state->ifl]) {
		return 0;
	}
	char *var = spp_rz_var_get(buf);
	if (var) {
		rz_cons_printf("%s", var);
		free(var);
	}
	return 0;
}

static TAG_CALLBACK(spp_rz_getrandom) {
	if (!state->echo[state->ifl]) {
		return 0;
	}
	// XXX srsly? this is pretty bad random
	srandom(rz_sys_getpid()); // TODO: change this to be portable
	int max = atoi(buf);
	if (max > 0) {
		max = (int)(rand() % max);
	}
	rz_cons_printf("%d", max);
	return 0;
}

static TAG_CALLBACK(spp_rz_add) {
	char *eq = strchr(buf, ' ');
	int ret = 0;
	if (!state->echo[state->ifl]) {
		return 0;
	}
	if (eq) {
		*eq = '\0';
		char *var = spp_rz_var_get(buf);
		if (var) {
			ret = atoi(var);
		}
		ret += atoi(eq + 1);
		char res[32];
		snprintf(res, sizeof(res), "%d", ret);
		rz_sys_setenv(buf, res);
		free(var);
	} else {
		eprintf("/* syntax error */\n");
	}
	return 0;
}

static TAG_CALLBACK(spp_rz_sub) {
	char *eq = strchr(buf, ' ');
	char *var;
	int ret = 0;
	if (!state->echo[state->ifl]) {
		return 0;
	}
	if (eq) {
		*eq = '\0';
		var = spp_rz_var_get(buf);
		ret = var ? atoi(var) : 0;
		ret -= atoi(eq + 1);
		rz_sys_setenv(buf, eq + 1);
	} else {
		/* syntax error */
	}
	return ret;
}

static TAG_CALLBACK(spp_rz_trace) {
	if (state->echo[state->ifl]) {
		fprintf(stderr, "%.1000s\n", buf);
	}
	return 0;
}

/* TODO: deprecate */
static TAG_CALLBACK(spp_rz_echo) {
	if (state->echo[state->ifl]) {
		rz_cons_printf("%s", buf);
	}
	// TODO: add variable replacement here?? not necessary, done by {{get}}
	return 0;
}

static TAG_CALLBACK(spp_rz_error) {
	if (!state->echo[state->ifl]) {
		return 0;
	}
	fprintf(stderr, "ERROR: %s (line=%d)\n", buf, state->lineno);
	return -1;
}

static TAG_CALLBACK(spp_rz_warning) {
	if (!state->echo[state->ifl]) {
		return 0;
	}
	fprintf(stderr, "WARNING: %s (line=%d)\n", buf, state->lineno);
	return 0;
}

static TAG_CALLBACK(spp_rz_rz) {
	char *str = Glang->cmd_str(Glang->user, buf);
	if (str) {
		rz_cons_printf("%s", str);
		free(str);
	}
	return 0;
}

static TAG_CALLBACK(spp_rz_system) {
	if (!state->echo[state->ifl]) {
		return 0;
	}
	char *str = rz_sys_cmd_str(buf, NULL, NULL);
	if (str) {
		rz_cons_printf("%s", str);
		free(str);
	}
	return 0;
}

static TAG_CALLBACK(spp_rz_include) {
	if (!state->echo[state->ifl]) {
		return 0;
	}
	char *incdir = getenv("SPP_INCDIR");
	if (incdir) {
		char *b = strdup(incdir);
		if (!b) {
			return 0;
		}
		char *p = realloc(b, strlen(b) + strlen(buf) + 3);
		if (p) {
			b = p;
			strcat(b, "/");
			strcat(b, buf);
			spp_file(b, out);
		}
		free(b);
	} else {
		spp_file(buf, out);
	}
	return 0;
}

static TAG_CALLBACK(spp_rz_if) {
	char *var = spp_rz_var_get(buf);
	state->echo[state->ifl + 1] = (var && *var != '0' && *var != '\0') ? 1 : 0;
	free(var);
	return 1;
}

/* {{ ifeq $path / }} */
static TAG_CALLBACK(spp_rz_ifeq) {
	char *value = buf;
	char *eq = strchr(buf, ' ');
	if (eq) {
		*eq = '\0';
		value = spp_rz_var_get(value);
		if (value && !strcmp(value, eq + 1)) {
			state->echo[state->ifl + 1] = 1;
		} else {
			state->echo[state->ifl + 1] = 0;
		}
		free(value);
	} else {
		value = spp_rz_var_get(buf);
		if (!value || !*value) {
			state->echo[state->ifl + 1] = 1;
		} else {
			state->echo[state->ifl + 1] = 0;
		}
		free(value);
	}
	return 1;
}

static TAG_CALLBACK(spp_rz_hex) {
	size_t i;
	for (i = 0; buf[i]; i++) {
		if (isdigit(buf[i])) {
			int ch, b = buf[i + 2];
			buf[i + 2] = '\0';
			sscanf(buf + i, "%02x", &ch);
			rz_cons_printf("%c", ch & 0xff);
			buf[i + 2] = b;
			buf = buf + 2;
		}
	}
	return 0;
}

static TAG_CALLBACK(spp_rz_grepline) {
	FILE *fd;
	char b[1024];
	int line;

	if (!state->echo[state->ifl]) {
		return 1;
	}
	char *ptr = strchr(buf, ' ');
	if (ptr) {
		*ptr = '\0';
		fd = fopen(buf, "r");
		line = atoi(ptr + 1);
		if (fd) {
			while (!feof(fd) && line--) {
				if (!fgets(b, 1023, fd)) {
					break;
				}
			}
			fclose(fd);
			rz_cons_printf("%s", b);
		} else {
			eprintf("Unable to open '%s'\n", buf);
		}
	}
	return 0;
}

static TAG_CALLBACK(spp_rz_else) {
	state->echo[state->ifl] = state->echo[state->ifl] ? 0 : 1;
	return 0;
}

static TAG_CALLBACK(spp_rz_ifnot) {
	spp_rz_if(state, out, buf);
	spp_rz_else(state, out, buf);
	return 1;
}

static TAG_CALLBACK(spp_rz_ifin) {
	char *var, *ptr;
	if (!state->echo[state->ifl]) {
		return 1;
	}
	ptr = strchr(buf, ' ');
	state->echo[state->ifl + 1] = 0;
	if (ptr) {
		*ptr = '\0';
		var = getenv(buf);
		if (strstr(ptr + 1, var)) {
			state->echo[state->ifl + 1] = 1;
		}
	}
	return 1;
}

static TAG_CALLBACK(spp_rz_endif) {
	return -1;
}

static TAG_CALLBACK(spp_rz_default) {
	if (!state->echo[state->ifl]) {
		return 0;
	}
	if (buf[-1] != ';') { /* commented tag */
		fprintf(stderr, "WARNING: invalid command: '%s' at line %d\n", buf, state->lineno);
	}
	return 0;
}

#if HAVE_SYSTEM
static FILE *spp_rz_pipe_fd = NULL;
#endif

static TAG_CALLBACK(spp_rz_pipe) {
#if HAVE_SYSTEM
	spp_rz_pipe_fd = popen(buf, "w");
#endif
	return 0;
}

static char *spp_rz_switch_str = NULL;

static TAG_CALLBACK(spp_rz_switch) {
	char *var = spp_rz_var_get(buf);
	if (var) {
		spp_rz_switch_str = var;
	} else {
		spp_rz_switch_str = strdup("");
		free(var);
	}
	return 1;
}

static TAG_CALLBACK(spp_rz_case) {
	state->echo[state->ifl] = strcmp(buf, spp_rz_switch_str) ? 0 : 1;
	return 0;
}

static TAG_CALLBACK(spp_rz_endswitch) {
	free(spp_rz_switch_str);
	spp_rz_switch_str = NULL;
	return -1;
}

static TAG_CALLBACK(spp_rz_endpipe) {
#if HAVE_SYSTEM
	/* TODO: Get output here */
	int ret = 0, len = 0;
	int outlen = 4096;
	char *str = (char *)malloc(4096);
	char *tstr;
	if (!str) {
		return 0;
	}
	do {
		len += ret;
		ret = fread(str + len, 1, 1023, spp_rz_pipe_fd);
		if (ret + 1024 > outlen) {
			outlen += 4096;
			tstr = realloc(str, outlen);
			if (!tstr) {
				fprintf(stderr, "Out of memory.\n");
				break;
			}
			str = tstr;
		}
	} while (ret > 0);
	str[len] = '\0';
	rz_cons_printf("%s", str);
	if (spp_rz_pipe_fd) {
		pclose(spp_rz_pipe_fd);
	}
	spp_rz_pipe_fd = NULL;
	free(str);
#endif
	return 0;
}

static PUT_CALLBACK(spp_rz_fputs) {
#if HAVE_SYSTEM
	if (spp_rz_pipe_fd) {
		fprintf(spp_rz_pipe_fd, "%s", buf);
	} else
#endif
	{
		rz_cons_printf("%s", buf);
	}
	return 0;
}

static SppTag spp_rz_tags[] = {
	{ "get", spp_rz_get },
	{ "hex", spp_rz_hex },
	{ "getrandom", spp_rz_getrandom },
	{ "grepline", spp_rz_grepline },
	{ "set", spp_rz_set },
	{ "add", spp_rz_add },
	{ "sub", spp_rz_sub },
	{ "switch", spp_rz_switch },
	{ "case", spp_rz_case },
	{ "endswitch", spp_rz_endswitch },
	{ "echo", spp_rz_echo },
	{ "error", spp_rz_error },
	{ "warning", spp_rz_warning },
	{ "trace", spp_rz_trace },
	{ "ifin", spp_rz_ifin },
	{ "ifnot", spp_rz_ifnot },
	{ "ifeq", spp_rz_ifeq },
	{ "if", spp_rz_if },
	{ "else", spp_rz_else },
	{ "endif", spp_rz_endif },
	{ "pipe", spp_rz_pipe },
	{ "endpipe", spp_rz_endpipe },
	{ "include", spp_rz_include },
	{ "system", spp_rz_system },
	{ "rz", spp_rz_rz },
	{ "rizin", spp_rz_rz },
	{ NULL, spp_rz_default },
	{ NULL }
};

static ARG_CALLBACK(spp_rz_arg_i) {
	rz_sys_setenv("SPP_INCDIR", arg);
	return 0;
}

static ARG_CALLBACK(spp_rz_arg_d) {
	/* TODO: Handle error */
	char *eq = strchr(arg, '=');
	if (eq) {
		*eq = '\0';
		spp_rz_var_set(arg, eq + 1);
	} else {
		spp_rz_var_set(arg, "");
	}
	return 0;
}

static struct Arg spp_rz_args[] = {
	{ "-I", "add include directory", 1, spp_rz_arg_i },
	{ "-D", "define value of variable", 1, spp_rz_arg_d },
	{ NULL }
};

DLL_LOCAL SppProc spp_rz_proc = {
	.name = "spprz",
	.tags = (struct Tag **)spp_rz_tags,
	.args = (struct Arg **)spp_rz_args,
	.token = " ",
	.eof = NULL,
	.tag_pre = "{",
	.tag_post = "}",
	.chop = 1,
	.fputs = spp_rz_fputs,
	.multiline = NULL,
	.default_echo = 1,
	.tag_begin = 0,
};
