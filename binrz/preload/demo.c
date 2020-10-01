#include <stdio.h>
#include <dlfcn.h>

int main(int argc, char **argv) {
	void *a = dlopen(NULL, RTLD_LAZY);
	void *m = dlsym (a, "rz_main_rizin");
	if (m) {
		int (*r2main)(int argc, char **argv) = m;
		return r2main (argc, argv);
	}
	return 0;
}
