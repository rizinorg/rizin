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