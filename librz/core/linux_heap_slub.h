#include <rz_core.h>

#undef GH
#undef GH_
#undef GHT
#undef GHT_MAX
#undef read_le

#ifdef KHEAP64

#define GH_(x)      x##_64
#define GH(x)       x##64
#define GHT         ut64
#define GHT_MAX     UT64_MAX
#define read_le(x)  rz_read_le##64(x)
#define GHFMTx      PFMT64x

#else

#define GH_(x)      x##_32
#define GH(x)       x##32
#define GHT         ut32
#define GHT_MAX     UT32_MAX
#define read_le(x)  rz_read_le##32(x)
#define GHFMTx      PFMT32x

#endif

RZ_IPI RzCmdStatus GH(rz_cmd_debug_slub_dump_freelist_handler)(RzCore *core, int argc, const char **argv, RzCmdStateOutput* output_state);