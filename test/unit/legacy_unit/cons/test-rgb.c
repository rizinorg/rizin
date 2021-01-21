#include <rz_cons.h>

int main() {
	int i, j, k;
	//char *str = "\x1b[38;5;231mpop\x1b[0m";
	//char *str ="\x1b]4;%d;rgb:30/20/24pop\x1b[0m";
	char *str = "\x1b\\pop\x1b[0m";
	i = j = k = 0;

	rz_cons_new();
	//	rz_cons_rgb_init ();
	printf("3 == %d\n", rz_str_ansi_len(str));
	for (i = 0; i < 255; i += 40) {
		for (j = 0; j < 255; j += 40) {
			for (k = 0; k < 255; k += 40) {
				rz_cons_rgb(i, j, k, 0);
				rz_cons_rgb(i, j, k, 1);
				rz_cons_print("__");
				rz_cons_reset_colors();

				rz_cons_rgb(i, j, k, 0);
				//		rz_cons_rgb (155, 200, 200, 1);
				rz_cons_printf(" RGB %d %d %d", i, j, k);
				rz_cons_reset_colors();
				rz_cons_newline();
			}
		}
	}
	rz_cons_flush();

	return 0;
}
