/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */
#include "rz_util.h"

int test_flist () {
	int i;
	void **it = rz_flist_new (3);
	char *pos = NULL;

	for (i=0;i<9999;i++) {
		rz_flist_set (it, i, "foo");
	}

	rz_flist_delete (it, 1);

	rz_flist_foreach (it, pos) {
		printf("%s\n", pos);
	}

	rz_flist_free(it);

	return 0;
}

int main() {
	return test_flist();
}

