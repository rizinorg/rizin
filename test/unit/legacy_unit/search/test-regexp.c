#include <rz_search.h>

static const ut8 *buffer = (const ut8 *)"ELF,e,e,e,ELF--fooo";

static int hit(RzSearchKeyword *kw, void *user, ut64 addr) {
	const ut8 *buf = (const ut8 *)user;
	printf("HIT %d AT %" PFMT64d " (%s)\n", kw->count, addr, buf + addr);
	return 1;
}

int main(int argc, char **argv) {
	RzSearch *rs = rz_search_new(RZ_SEARCH_REGEXP);
	rz_search_set_callback(rs, &hit, (void *)buffer);
	rz_search_kw_add(rs, /* search for /E.F/i */
		rz_search_keyword_new_str("E.F", "i", NULL, 0));
	rz_search_begin(rs);
	printf("Searching strings in '%s'\n", buffer);
	rz_search_update_i(rs, 0LL, buffer, strlen((const char *)buffer));
	rs = rz_search_free(rs);
	return 0;
}
