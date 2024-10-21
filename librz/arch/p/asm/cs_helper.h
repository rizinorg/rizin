// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#pragma GCC diagnostic ignored "-Wenum-compare"
#pragma GCC diagnostic ignored "-Wenum-conversion"
#define CAPSTONE_SYSTEMZ_COMPAT_HEADER
#include <capstone/capstone.h>

typedef struct {
	cs_mode omode;
	int obits;
	csh handle;
} CapstoneContext;

#define CAPSTONE_PLUGIN_INIT(name) \
	static bool name##_init(void **user) { \
		CapstoneContext *ctx = RZ_NEW0(CapstoneContext); \
		if (!ctx) { \
			return false; \
		} \
		ctx->omode = -1; \
		ctx->handle = 0; \
		*user = ctx; \
		return true; \
	}

#define CAPSTONE_PLUGIN_FINI(name) \
	static bool name##_fini(void *p) { \
		if (!p) { \
			return true; \
		} \
		CapstoneContext *ctx = (CapstoneContext *)p; \
\
		if (ctx->handle) { \
			cs_close(&ctx->handle); \
		} \
		free(ctx); \
		return true; \
	}

#define CAPSTONE_PLUGIN_MNEMONICS(name) \
	static char *name##_mnemonics(RzAsm *a, int id, bool json) { \
		if (!a->plugin_data) { \
			return NULL; \
		} \
		CapstoneContext *ctx = (CapstoneContext *)a->plugin_data; \
		int i; \
		a->cur->disassemble(a, NULL, NULL, -1); \
		if (id != -1) { \
			const char *vname = cs_insn_name(ctx->handle, id); \
			if (json) { \
				return vname ? rz_str_newf("[\"%s\"]\n", vname) : NULL; \
			} \
			return rz_str_dup(vname); \
		} \
		RzStrBuf *buf = rz_strbuf_new(""); \
		if (json) { \
			rz_strbuf_append(buf, "["); \
		} \
		for (i = 1;; i++) { \
			const char *op = cs_insn_name(ctx->handle, i); \
			if (!op) { \
				break; \
			} \
			if (json) { \
				rz_strbuf_append(buf, "\""); \
			} \
			rz_strbuf_append(buf, op); \
			if (json) { \
				if (cs_insn_name(ctx->handle, i + 1)) { \
					rz_strbuf_append(buf, "\","); \
				} else { \
					rz_strbuf_append(buf, "\"]\n"); \
				} \
			} else { \
				rz_strbuf_append(buf, "\n"); \
			} \
		} \
		return rz_strbuf_drain(buf); \
	}

#define CAPSTONE_DEFINE_PLUGIN_FUNCTIONS(name) \
	CAPSTONE_PLUGIN_INIT(name) \
	CAPSTONE_PLUGIN_FINI(name) \
	CAPSTONE_PLUGIN_MNEMONICS(name)
