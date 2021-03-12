// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
	char *you = "World";
	char *e = getenv("YOUVAR");
	if (e) {
		you = e;
	}
	if (argc > 1) {
		you = argv[1];
	}
	printf("Hello %s\n", you);
	fprintf(stderr, "This is on err\n");
	return 0;
}