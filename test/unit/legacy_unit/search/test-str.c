#include <rz_search.h>

const ut8 *buffer = (const ut8 *)"hellowor\x01\x02ldlibis\x01\x02niceandcoolib2loblubljb";

int hit(RzSearchKeyword *kw, void *user, ut64 addr) {
	const ut8 *buf = (const ut8 *)user;
	printf("HIT %d AT %" PFMT64d " (%s)\n", kw->count, addr, buf + addr);
	return 1;
}

int main(int argc, char **argv) {
	struct rz_search_t *rs;

	rs = rz_search_new(RZ_SEARCH_STRING);
	rz_search_set_callback(rs, &hit, (void *)buffer);
	rz_search_begin(rs);
	printf("Searching strings in '%s'\n", buffer);
	rz_search_update_i(rs, 0LL, buffer, strlen((const char *)buffer));
	rs = rz_search_free(rs);

	return 0;
}
