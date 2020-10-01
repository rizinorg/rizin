/* rizin - LGPL - Copyright 2008-2020 - pancake */

#include <rz_cons.h>

static ut8 twok_buf[4][4];
static int score = 0;
static int moves = 0;

static void twok_init(void) {
	int i, j;
	score = 0;
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			twok_buf[i][j] = 0;
		}
	}
}

static void twok_add(void) {
	int i, j;
	while (true) {
		i = rz_num_rand (4);
		j = rz_num_rand (4);
		if (!twok_buf[i][j]) {
			twok_buf[i][j] = 1 + (rz_num_rand (10) == 1);
			break;
		}
	}
}

static bool twok_fin(void) {
	int i, j;
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			if (!twok_buf[i][j]) {
				return true;
			}
		}
	}
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 3; j++) {
			if (twok_buf[i][j] == twok_buf[i][j + 1]) {
				return true;
			}
		}
	}
	for (i = 0; i < 3; i++) {
		for (j = 0; j < 4; j++) {
			if (twok_buf[i][j] == twok_buf[i + 1][j]) {
				return true;
			}
		}
	}
	return false;
}

static void twok_move(int u, int v) {
	int i, j, k;
	int nKI = 0, nKJ = 0, nIK = 0, nJK = 0;
	int moved = 0;
	for (k = 0; k < 4; k++) {
		for (i = 0; i < 4; i++) {
			for (j = i + 1; j < 4 && !twok_buf[nKJ = u ? k : v ? j : 3 - j][nJK = !u ? k : v ? j : 3 - j]; j++) {
				;
			}
			if (j == 4) {
				continue;
			}
			nKI = u? k: v? i: 3 - i;
			nIK = !u? k: v? i: 3 - i;
			if (!twok_buf[nKI][nIK]) {
				twok_buf[nKI][nIK] = twok_buf[nKJ][nJK];
				twok_buf[nKJ][nJK] = 0;
				--i;
				moved = 1;
			} else if (twok_buf[nKI][nIK] == twok_buf[nKJ][nJK]) {
				score += 1 << ++twok_buf[nKI][nIK];
				twok_buf[nKJ][nJK] = 0;
				moved = 1;
			}
		}
	}
	if (moved) {
		twok_add ();
		moves++;
	}
}

static void getval(bool color, char *val0, int i, int x) {
	const char * colorarray[] = {
		Color_WHITE,
		Color_RED,
		Color_GREEN,
		Color_MAGENTA,
		Color_YELLOW,
		Color_CYAN,
		Color_BLUE,
		Color_GRAY
	};
	if (twok_buf[i][x]) {
		if (color) {
			snprintf (val0,31, "%s%4d"Color_RESET, colorarray [twok_buf [i][x] % 8 ], 1 << twok_buf[i][x]);
		} else {
			snprintf (val0,31, "%4d", 1 << twok_buf[i][x]);
		}
	} else {
		strcpy (val0, "    ");
	}
}

static void twok_print(bool color) {
	char val0[32];
	char val1[32];
	char val2[32];
	char val3[32];
	int i;
	if (color) {
		printf (Color_BBLUE"  +------+------+------+------+\n");
	} else {
		printf ("  +------+------+------+------+\n");
	}
	for (i = 0; i < 4; i++) {
		getval (color, val0, i, 0);
		getval (color, val1, i, 1);
		getval (color, val2, i, 2);
		getval (color, val3, i, 3);
		if (color) {
			printf (Color_BBLUE"  |      |      |      |      |\n");
			printf ("  |"Color_RESET" %s "Color_BBLUE"|"Color_RESET" %s "
				Color_BBLUE"|"Color_RESET" %s "Color_BBLUE"|"Color_RESET" %s "Color_BBLUE"|\n",
				val0, val1, val2, val3);
			printf ("  |      |      |      |      |\n");
			printf ("  +------+------+------+------+\n"Color_RESET);
		} else {
			printf ("  |      |      |      |      |\n");
			printf ("  | %s | %s | %s | %s |\n",
				val0, val1, val2, val3);
			printf ("  |      |      |      |      |\n");
			printf ("  +------+------+------+------+\n");
		}
	}
	printf ("Hexboard:     'hjkl' and 'q'uit\n");
	for (i = 0; i < 4; i++) {
		printf ("  %02x %02x %02x %02x\n",
			twok_buf[i][0], twok_buf[i][1],
			twok_buf[i][2], twok_buf[i][3]);
	}
}

RZ_API void rz_cons_2048(bool color) {
	int ch;
	rz_cons_set_raw (1);
	twok_init ();
	twok_add ();
	twok_add ();
	while (twok_fin ()) {
		rz_cons_clear00 ();
		if (color) {
			rz_cons_printf (Color_GREEN"[r2048]"Color_BYELLOW" score: %d   moves: %d\n"Color_RESET, score, moves);
		} else {
			rz_cons_printf ("[r2048] score: %d   moves: %d\n", score, moves);
		}
		rz_cons_flush ();
		twok_print (color);
		ch = rz_cons_readchar ();
		ch = rz_cons_arrow_to_hjkl (ch);
		switch (ch) {
		case 'h':
			twok_move (1, 1);
			break;
		case 'j':
			twok_move (0, 0);
			break;
		case 'k':
			twok_move (0, 1);
			break;
		case 'l':
			twok_move (1, 0);
			break;
		}
		if (ch < 1 || ch == 'q') {
			break;
		}
	}
	rz_cons_clear00 ();
	rz_cons_printf ("[r2048] score: %d\n", score);
	rz_cons_flush ();
	twok_print (color);

	rz_cons_printf ("\n  [r2048.score] %d\n", score);
	do {
		ch = rz_cons_any_key ("Press 'q' to quit.");
	} while (ch != 'q' && ch >= 1);
	rz_cons_set_raw (0);
}
