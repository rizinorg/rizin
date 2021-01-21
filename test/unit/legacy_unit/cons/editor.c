#include <rz_cons.h>

int main(int argc, char **argv) {
	rz_cons_editor(argc > 1 ? argv[1] : NULL);
	return 0;
}
