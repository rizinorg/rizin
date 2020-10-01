/* radare - LGPL - Copyright 2009-2019 - pancake, nibble, Adam Pridgen <dso@rice.edu || adam.pridgen@thecoverofnight.com> */

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#include "../../shlr/java/class.h"
#include "../../shlr/java/code.h"

#define IFDBG_BIN_JAVA if (0)

static Sdb *DB = NULL;
static void add_bin_obj_to_sdb(RBinJavaObj *bin);
static int add_sdb_bin_obj(const char *key, RBinJavaObj *bin_obj);

static int init(void *user) {
	IFDBG_BIN_JAVA eprintf("Calling plugin init = %d.\n", DB? 1: 0);
	if (!DB) {
		IFDBG_BIN_JAVA eprintf("plugin DB beeing initted.\n");
		DB = sdb_new ("bin.java", NULL, 0);
	} else {
		IFDBG_BIN_JAVA eprintf("plugin DB already initted.\n");
	}
	return 0;
}

static int fini(void *user) {
	IFDBG_BIN_JAVA eprintf("Calling plugin fini = %d.\n", DB? 1: 0);
	if (!DB) {
		IFDBG_BIN_JAVA eprintf("plugin DB already uninited.\n");
	} else {
		IFDBG_BIN_JAVA eprintf("plugin DB beeing uninited.\n");
		sdb_free (DB);
		DB = NULL;
	}
	return 0;
}

static int add_sdb_bin_obj(const char *key, RBinJavaObj *bin_obj) {
	int result = false;
	char *addr, value[1024] = {
		0
	};
	addr = sdb_itoa ((ut64) (size_t) bin_obj, value, 16);
	if (key && bin_obj && DB) {
		IFDBG_BIN_JAVA eprintf("Adding %s:%s to the bin_objs db\n", key, addr);
		sdb_set (DB, key, addr, 0);
		result = true;
	}
	return result;
}

static void add_bin_obj_to_sdb(RBinJavaObj *bin) {
	if (!bin) {
		return;
	}
	char *jvcname = rz_bin_java_build_obj_key (bin);
	add_sdb_bin_obj (jvcname, bin);
	bin->AllJavaBinObjs = DB;
	free (jvcname);
}

static Sdb *get_sdb(RBinFile *bf) {
	RBinObject *o = bf->o;
	struct rz_bin_java_obj_t *bin;
	if (!o) {
		return NULL;
	}
	bin = (struct rz_bin_java_obj_t *) o->bin_obj;
	if (bin->kv) {
		return bin->kv;
	}
	return NULL;
}

static bool load_buffer(RBinFile * bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	struct rz_bin_java_obj_t *tmp_bin_obj = NULL;
	RBuffer *tbuf = rz_buf_ref (buf);
	tmp_bin_obj = rz_bin_java_new_buf (tbuf, loadaddr, sdb);
	if (!tmp_bin_obj) {
		return false;
	}
	*bin_obj = tmp_bin_obj;
	add_bin_obj_to_sdb (tmp_bin_obj);
	if (bf && bf->file) {
		tmp_bin_obj->file = strdup (bf->file);
	}
	rz_buf_free (tbuf);
	return true;
}

static void destroy(RBinFile *bf) {
	rz_bin_java_free ((struct rz_bin_java_obj_t *) bf->o->bin_obj);
	sdb_free (DB);
	DB = NULL;
}

static RzList *entries(RBinFile *bf) {
	return rz_bin_java_get_entrypoints (bf->o->bin_obj);
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

static RzList *classes(RBinFile *bf) {
	return rz_bin_java_get_classes ((struct rz_bin_java_obj_t *) bf->o->bin_obj);
}

static RzList *symbols(RBinFile *bf) {
	return rz_bin_java_get_symbols ((struct rz_bin_java_obj_t *) bf->o->bin_obj);
}

static RzList *strings(RBinFile *bf) {
	return rz_bin_java_get_strings ((struct rz_bin_java_obj_t *) bf->o->bin_obj);
}

static RBinInfo *info(RBinFile *bf) {
	RBinJavaObj *jo = bf->o->bin_obj;
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->lang = (jo && jo->lang) ? jo->lang : "java";
	ret->file = strdup (bf->file);
	ret->type = strdup ("JAVA CLASS");
	ret->bclass = rz_bin_java_get_version (bf->o->bin_obj);
	ret->has_va = 0;
	// ret->has_lit = true;
	ret->rclass = strdup ("class");
	ret->os = strdup ("any");
	ret->subsystem = strdup ("any");
	ret->machine = strdup ("jvm");
	ret->arch = strdup ("java");
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 4 | 8; /* LineNums | Syms */
	return ret;
}

static bool check_buffer(RBuffer *b) {
	if (rz_buf_size (b) > 32) {
		ut8 buf[4];
		rz_buf_read_at (b, 0, buf, sizeof (buf));
		if (!memcmp (buf, "\xca\xfe\xba\xbe", 4)) {
			int off = rz_buf_read_be32_at (b, 4 * sizeof (int));
			int version = rz_buf_read_be16_at (b, 6);
			if (off > 0 && version < 1024) {
				return true;
			}
		}
	}
	return false;
}

static int retdemangle(const char *str) {
	return R_BIN_NM_JAVA;
}

static RBinAddr *binsym(RBinFile *bf, int sym) {
	return rz_bin_java_get_entrypoint (bf->o->bin_obj, sym);
}

static R_BORROW RzList *lines(RBinFile *bf) {
	return NULL;
#if 0
	char *file = bf->file? strdup (bf->file): strdup ("");
	RzList *list = rz_list_newf (free);
	// XXX the owner of this list should be the plugin, so we are leaking here
	file = rz_str_replace (file, ".class", ".java", 0);
	/*
	   int i;
	   RBinJavaObj *b = bf->o->bin_obj;
	   for (i=0; i<b->lines.count; i++) {
	        RBinDwarfRow *row = R_NEW0(RBinDwarfRow);
	        rz_bin_dwarf_line_new (row, b->lines.addr[i], file, b->lines.line[i]);
	        rz_list_append (list, row);
	   }*/
	free (file);
	return list;
#endif
}

static RzList *sections(RBinFile *bf) {
	return rz_bin_java_get_sections (bf->o->bin_obj);
}

static RzList *imports(RBinFile *bf) {
	return rz_bin_java_get_imports (bf->o->bin_obj);
}

static RzList *fields(RBinFile *bf) {
	return NULL;// rz_bin_java_get_fields (bf->o->bin_obj);
}

static RzList *libs(RBinFile *bf) {
	return rz_bin_java_get_lib_names (bf->o->bin_obj);
}

RBinPlugin rz_bin_plugin_java = {
	.name = "java",
	.desc = "java bin plugin",
	.license = "LGPL3",
	.init = init,
	.fini = fini,
	.get_sdb = &get_sdb,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = binsym,
	.entries = &entries,
	.sections = sections,
	.symbols = symbols,
	.imports = &imports,
	.strings = &strings,
	.info = &info,
	.fields = fields,
	.libs = libs,
	.lines = &lines,
	.classes = classes,
	.demangle_type = retdemangle,
	.minstrlen = 3,
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_java,
	.version = R2_VERSION
};
#endif
