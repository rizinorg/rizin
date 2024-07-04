// SPDX-FileCopyrightText: 2024 Wenlong Zhang <zhangwenlong@loongson.cn>
// SPDX-License-Identifier: LGPL-3.0-only

return strdup(
	"=PC    pc\n"
	"=SP    sp\n"
	"=BP    fp\n"
	"=A0    a0\n"
	"=A1    a1\n"
	"=A2    a2\n"
	"=A3    a3\n"
	"=A4    a4\n"
	"=A5    a5\n"
	"=A6    a6\n"
	"=A7    a7\n"
	"gpr    zero    .64     0       0\n"
	"gpr    ra      .64     8       0\n"
	"gpr    tp      .64     16      0\n"
	"gpr    sp      .64     24      0\n"
	/* args */
	"gpr    a0      .64     32      0\n"
	"gpr    a1      .64     40      0\n"
	"gpr    a2      .64     48      0\n"
	"gpr    a3      .64     56      0\n"
	"gpr    a4      .64     64      0\n"
	"gpr    a5      .64     72      0\n"
	"gpr    a6      .64     80      0\n"
	"gpr    a7      .64     88      0\n"
	/* tmp */
	"gpr    t0      .64     96      0\n"
	"gpr    t1      .64     104     0\n"
	"gpr    t2      .64     112     0\n"
	"gpr    t3      .64     120     0\n"
	"gpr    t4      .64     128     0\n"
	"gpr    t5      .64     136     0\n"
	"gpr    t6      .64     144     0\n"
	"gpr    t7      .64     152     0\n"
	"gpr    t8      .64     160     0\n"
	/* saved */
	"gpr    r21     .64     168     0\n" // Non-allocatable
	/* fp */
	"gpr    fp      .64     176     0\n"
	/* static */
	"gpr    s0      .64     184     0\n"
	"gpr    s1      .64     192     0\n"
	"gpr    s2      .64     200     0\n"
	"gpr    s3      .64     208     0\n"
	"gpr    s4      .64     216     0\n"
	"gpr    s5      .64     224     0\n"
	"gpr    s6      .64     232     0\n"
	"gpr    s7      .64     240     0\n"
	"gpr    s8      .64     248     0\n");
