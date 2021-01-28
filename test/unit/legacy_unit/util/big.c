#include "../big.c"
/*
#include "../big-ssl.c"
#include "../big-gmp.c"
 */

void main() {
	int a, b;
	RNumBig n1, n2, n3, zero;

	rz_big_set_st(&n2, -2);
	rz_big_set_str(&n3, "-3");
	//rz_big_set_st (&n3, -3);
	printf("n3last = %d\n", n3.last);
	printf("%d %d\n", n3.dgts[0], n3.dgts[1]);
	rz_big_mul(&n2, &n2, &n3);
	rz_big_print(&n2);
	printf("--\n");

	rz_big_set_st(&n1, 2);
	rz_big_set_st(&n2, 3);
	rz_big_mul(&n1, &n1, &n2);
	rz_big_print(&n1);

	rz_big_set_st(&n3, 923459999);
	rz_big_mul(&n1, &n2, &n3);
	rz_big_mul(&n2, &n1, &n3);
	rz_big_mul(&n1, &n2, &n3);
	rz_big_print(&n1);

	rz_big_set_st64(&n2, 9999923459999999);
	rz_big_set_st64(&n3, 9999992345999999);
	rz_big_mul(&n1, &n2, &n3);
	rz_big_mul(&n2, &n1, &n3);
	rz_big_mul(&n1, &n2, &n3);
	rz_big_print(&n1);

	while (scanf("%d %d\n", &a, &b) != EOF) {
		printf("a = %d    b = %d\n", a, b);
		rz_big_set_st(&n1, a);
		rz_big_set_st(&n2, b);

		rz_big_add(&n3, &n1, &n2);
		printf("addition -- ");
		rz_big_print(&n3);

		printf("rz_big_cmp a ? b = %d\n", rz_big_cmp(&n1, &n2));

		rz_big_sub(&n3, &n1, &n2);
		printf("subtraction -- ");
		rz_big_print(&n3);

		rz_big_mul(&n3, &n1, &n2);
		printf("multiplication -- ");
		rz_big_print(&n3);

		rz_big_set_st(&zero, 0);
		if (rz_big_cmp(&zero, &n2) == 0)
			printf("division -- NaN \n");
		else {
			rz_big_div(&n3, &n1, &n2);
			printf("division -- ");
			rz_big_print(&n3);
		}
		printf("--------------------------\n");
	}
}
