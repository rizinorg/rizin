#ifndef RL78_H
#define RL78_H

#include "instr.h"

#include <rz_util.h>

int rl78_asm(const char *str, unsigned char *buf, int buf_len);
int rl78_dis(struct rl78_instr *instr, const unsigned char *buf, int buf_len);

#endif
