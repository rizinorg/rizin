// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
	int a, b, c, d;
	scanf("%d", &a);
	scanf("%d", &b);
	srand(0xcafecafe);
	c = rand();
	printf("%d\n", c);
	fflush(stdout);
	scanf("%d", &d);
	if (a + b + c == d) {
		printf("Right\n");
	} else {
		printf("Wrong\n");
	}
	return 0;
}