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
	int ret;
	RzLib *lib = rz_lib_new("rizin_plugin");
	rz_lib_add_handler(lib, 1, "example plugin handler", &cb_1, &cb_1_end, &ptr);
	rz_lib_add_handler(lib, 2, "disassembler plugin handler", &cb_2, &cb_2_end, &ptr);
	rz_lib_add_handler(lib, 3, "file headers parser plugin handler", &cb_2, &cb_2_end, &ptr);

	ret = rz_lib_open(lib, "./plugin." RZ_LIB_EXT);
	if (ret == -1)
		eprintf("Cannot open plugin\n");
	else
		eprintf("Plugin opened correctly\n");
	rz_lib_list(lib);

	printf("  --- closing './plugin." RZ_LIB_EXT "' ---\n");
	rz_lib_close(lib, "./plugin." RZ_LIB_EXT);
	rz_lib_list(lib);
	printf("  ---\n");

	rz_lib_close(lib, "./plugin." RZ_LIB_EXT);
	rz_lib_free(lib);

	return 0;
}
