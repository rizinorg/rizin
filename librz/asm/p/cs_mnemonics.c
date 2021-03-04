// SPDX-License-Identifier: LGPL-3.0-only

static char *mnemonics(RzAsm *a, int id, bool json) {
	int i;
	a->cur->disassemble(a, NULL, NULL, -1);
	if (id != -1) {
		const char *name = cs_insn_name(cd, id);
		if (json) {
			return name ? rz_str_newf("[\"%s\"]\n", name) : NULL;
		}
		return name ? strdup(name) : NULL;
	}
	RzStrBuf *buf = rz_strbuf_new("");
	if (json) {
		rz_strbuf_append(buf, "[");
	}
	for (i = 1;; i++) {
		const char *op = cs_insn_name(cd, i);
		if (!op) {
			break;
		}
		if (json) {
			rz_strbuf_append(buf, "\"");
		}
		rz_strbuf_append(buf, op);
		if (json) {
			if (cs_insn_name(cd, i + 1)) {
				rz_strbuf_append(buf, "\",");
			} else {
				rz_strbuf_append(buf, "\"]\n");
			}
		} else {
			rz_strbuf_append(buf, "\n");
		}
	}
	return rz_strbuf_drain(buf);
}
