// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
	printf("Hello");
	int i;
	for (i = 1; i < argc; i++) {
		printf(" %s", argv[i]);
	}
	printf("\n");
	return 0;
}