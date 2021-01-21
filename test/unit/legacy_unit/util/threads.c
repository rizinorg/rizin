#include <rz_th.h>
#include <rz_util.h>

int looper(struct rz_th_t *th) {
	int i;
	int *ctr = th->user;
	for (i = 0; i < 9999; i++) {
		if (th->breaked)
			break;
		(*ctr)++;
		printf("%d loop %d\r", i, *ctr);
		fflush(stdout);
#if __UNIX__
		sleep(1);
#endif
	}
	return 0; // do not loop
}

int test1() {
	int ctr = 0;
	struct rz_th_t *th;

	th = rz_th_new(&looper, &ctr, 0);
	th = rz_th_new(&looper, &ctr, 0);
	//th = rz_th_new (&looper, &ctr, 0);

#if __i386__ || __x86_64__
	asm("int3");
#endif
	//rz_th_start (th, true);
	while (rz_th_wait_async(th)) {
		printf("\nwaiting...\n");
		fflush(stdout);
		rz_sys_usleep(400);
		//	rz_th_break(th);
	}
	printf("\nfinished\n");
#if 0
	rz_th_start(th, true);
	sleep(1);
#endif
	/* wait and free */
	rz_th_wait(th);
	rz_th_free(th);

	printf("\nresult %d\n", ctr);
	return 0;
}

int main() {
	return test1();
}
