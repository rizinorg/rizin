#include <stdio.h>
#include <rz_core.h>

int main(int argc, char **argv) {
	RzCore *core = rz_core_new();
	rz_cons_printf(core->cons, "hello %s\n", argv[0]);
	rz_cons_flush(core->cons);
	rz_core_free(core);
	return 0;
}
