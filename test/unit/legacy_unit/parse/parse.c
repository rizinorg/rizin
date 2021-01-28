#include "rz_parse.h"

int main(int argc, char **argv) {
	char str[128];
	struct rz_parse_t *p;
	p = rz_parse_new();

	if (argc == 1) {
		printf("List: \n");
		rz_parse_list(p);
		printf("Using plugin: \n");
		rz_parse_use(p, "x86.pseudo");
		str[0] = '\0';
		rz_parse_assemble(p, str, strdup("eax=1;int 0x80"));
		printf("--output--\n");
		printf("%s\n", str);
		printf("\n----\n\n");
		rz_parse_use(p, "att2intel");
		rz_parse_parse(p, "movl $3, %eax", str); //, sizeof (str));
		//rz_parse_filter (p, NULL, "movl $3, %eax", str, sizeof (str));
		printf("%s\n", str);
	} else {
		char buf[128];
		rz_parse_use(p, "att2intel");
		while (!feof(stdin)) {
			buf[0] = 0;
			fgets(buf, sizeof(buf) - 1, stdin);
			if (feof(stdin))
				break;
			buf[strlen(buf) - 1] = 0;
			if (*buf) {
				rz_parse_parse(p, buf, str); //, sizeof (str));
				printf("%s\n", str);
			}
		}
	}
	return 0;
}
