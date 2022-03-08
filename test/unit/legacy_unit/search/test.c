#include <rz_search.h>

// static char *buffer = "helloworldlibisniceandcoolib2loblubljb";
char *buffer = "helloworldlibisnlizbiceandcoolib2loblubljb";

static int hit(RzSearchKeyword *kw, void *user, ut64 addr) {
	// const ut8 *buf = (ut8*)user;
	printf("HIT %d AT %" PFMT64d " (%s)\n", kw->count, addr, buffer + addr);
	return 1;
}

int main(int argc, char **argv) {
	RzSearch *rs = rz_search_new(rz_search_params_new(RZ_SEARCH_KEYWORD));
	rz_search_params_kw_add(rs->params,
		rz_search_keyword_new_str("lib", "", NULL, 0));
	rz_search_set_callback(rs, &hit, buffer);
	rz_search_params_set_distance(rs->params, 0);
	printf("Distance: %d\n", rs->params->search_distance);
	rz_search_begin(rs);
	printf("Searching for '%s' in '%s'\n", "lib", buffer);
	rz_search_update_i(rs, 0LL, (ut8 *)buffer, strlen(buffer));

	printf("--\n");

	rz_search_params_set_distance(rs->params, 4);
	printf("Distance: %d\n", rs->params->search_distance);
	rz_search_begin(rs);
	printf("Searching for '%s' in '%s'\n", "lib", buffer);
	rz_search_update_i(rs, 0LL, (ut8 *)buffer, strlen(buffer));
	rs = rz_search_free(rs);

	printf("--\n");

	/* test binmask */
	rs = rz_search_new(rz_search_params_new(RZ_SEARCH_KEYWORD));
	{
		RzSearchKeyword *kw = rz_search_keyword_new_str("lib", "ff00ff", NULL, 0);
		printf("Keyword (%02x %02x %02x)\n", kw->bin_binmask[0],
			kw->bin_binmask[1], kw->bin_binmask[2]);
		rz_search_params_kw_add(rs->params, kw);
	}
	rz_search_set_callback(rs, &hit, buffer);
	rz_search_begin(rs);
	printf("Searching for '%s' with binmask 'ff00ff' in '%s'\n", "lib", buffer);
	rz_search_update_i(rs, 0LL, (ut8 *)buffer, strlen(buffer));
	rs = rz_search_free(rs);
	return 0;
}
