// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
	int a, b;
	scanf("%d", &a);
	scanf("%d", &b);
	printf("%d\n", a + b);
	return a + b;
}