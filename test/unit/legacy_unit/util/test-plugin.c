#include <rz_lib.h>

int cb_1(struct rz_lib_plugin_t *obj, void *a, void *b) {
	int (*fun)() = a; /* points to 'ptr' */
	int num = *(int *)b;

	fun(); /* indirect calls ptr() */
	eprintf("Plugin value: 0x%x\n", num);
	return 0;
}

int cb_1_end(struct rz_lib_plugin_t *obj, void *a, void *b) {
	printf("==> Plugin '%s' unloaded (file=%s)\n", obj->handler->desc, obj->file);
	return 0;
}

int cb_2(struct rz_lib_plugin_t *obj, void *a, void *b) {
	eprintf("Plugin '%s' unloaded\n", obj->handler->desc);
	return 0;
}

int cb_2_end(struct rz_lib_plugin_t *obj, void *a, void *b) {
	eprintf("==> Plugin 'disassembler' unloaded\n");
	return 0;
}

int ptr() {
	eprintf("Data pointer passed properly\n");
	return 0;
}

int main(int argc, char **argv) {
	RzLib *lib = rz_lib_new("rizin_plugin", "rizin_plugin_function");
	rz_lib_add_handler(lib, 1, "example plugin handler", &cb_1, &cb_1_end, &ptr);
	rz_lib_add_handler(lib, 2, "disassembler plugin handler", &cb_2, &cb_2_end, &ptr);
	rz_lib_add_handler(lib, 3, "file headers parser plugin handler", &cb_2, &cb_2_end, &ptr);

	rz_lib_openfile(lib, "./plugin." RZ_LIB_EXT);
	if (rz_lib_already_loaded(lib, "./plugin." RZ_LIB_EXT))
		eprintf("Plugin opened correctly\n");
	else
		eprintf("Cannot open plugin\n");
	rz_lib_list(lib);

	printf("  --- closing './plugin." RZ_LIB_EXT "' ---\n");
	rz_lib_closefile(lib, "./plugin." RZ_LIB_EXT);
	rz_lib_list(lib);
	printf("  ---\n");

	rz_lib_closefile(lib, "./plugin." RZ_LIB_EXT);
	rz_lib_free(lib);

	return 0;
}
