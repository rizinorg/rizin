#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
	char *you = "World";
	char *e = getenv ("YOUVAR");
	if (e) {
		you = e;
	}
	if (argc > 1) {
		you = argv[1];
	}
	printf("Hello %s\n", you);
	fprintf (stderr, "This is on err\n");
	return 0;
}