#include <rz_core.h>

#undef GH
#undef GHT
#undef GHT_MAX
#undef read_le

#ifdef KHEAP64

#define GH(x)       x##_64
#define GHT         ut64
#define GHT_MAX     UT64_MAX
#define read_le(x)  rz_read_le##64(x)
#define GHFMTx      PFMT64x

#else

#define GH(x)       x##_32
#define GHT         ut32
#define GHT_MAX     UT32_MAX
#define read_le(x)  rz_read_le##32(x)
#define GHFMTx      PFMT32x

#endif

RZ_IPI RzCmdStatus GH(rz_cmd_debug_slub_dump_freelist_handler)(RzCore *core, int argc, const char **argv, RzCmdStateOutput* output_state);