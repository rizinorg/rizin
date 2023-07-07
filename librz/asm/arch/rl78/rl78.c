#include "rl78.h"

#include "maps.h"

int rl78_asm(const char *str, ut8 *buf, int buf_len)
{
        return 0;
}

int rl78_dis(struct rl78_instr *instr, const ut8 *buf, int buf_len)
{
        int byte = buf[0];
        *instr = rl78_instr_maps[byte];
        return 0;
}
