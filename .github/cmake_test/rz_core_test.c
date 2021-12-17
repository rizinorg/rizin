#include <stdio.h>
#include <rz_core.h>

int main(int argc, char **argv) {
	RzCore *core = rz_core_new();
	rz_cons_printf("hello %s\n", argv[0]);
	rz_cons_flush();
	rz_core_free(core);
	return 0;
}
