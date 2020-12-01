#include <rz_search.h>

RZ_IPI int rz_search_mybinparse_update(RzSearch *s, ut64 from, const ut8 *buf, int len);
RZ_IPI int rz_search_aes_update(RzSearch *s, ut64 from, const ut8 *buf, int len);
RZ_IPI int rz_search_privkey_update(RzSearch *s, ut64 from, const ut8 *buf, int len);
RZ_IPI int rz_search_magic_update(RzSearch *_s, ut64 from, const ut8 *buf, int len);
RZ_IPI int rz_search_deltakey_update(RzSearch *s, ut64 from, const ut8 *buf, int len);
RZ_IPI int rz_search_strings_update(RzSearch *s, ut64 from, const ut8 *buf, int len);
RZ_IPI int rz_search_regexp_update(RzSearch *s, ut64 from, const ut8 *buf, int len);

// Returns 2 if search.maxhits is reached, 0 on error, otherwise 1
RZ_IPI int rz_search_hit_new(RzSearch *s, RzSearchKeyword *kw, ut64 addr);
