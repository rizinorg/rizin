#include <rz_util.h>

const char *buf[] = { "eax", "ebx", "ecx", NULL };

int main() {
	struct rz_mem_pool_t *pool = rz_mem_pool_new(128, 0, 0);
	void *foo = rz_mem_pool_alloc(pool);
	eprintf("foo1 = %p\n", foo);
	foo = rz_mem_pool_alloc(pool);
	eprintf("foo1 = %p\n", foo);

	printf("%d\n", rz_mem_count((const ut8 **)buf));

	rz_mem_pool_free(pool);
	return 0;
}
