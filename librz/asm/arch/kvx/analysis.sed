#!/bin/sed -f
# SPDX-FileCopyrightText: 2022 Jules Maselbas <jmaselbas@kalray.eu>
# SPDX-License-Identifier: LGPL-3.0-only

/"errop/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_TRAP |/};
/"abs/		{s/.type =/& RZ_ANALYSIS_OP_TYPE_ABS |/};
/"copy/		{s/.type =/& RZ_ANALYSIS_OP_TYPE_MOV |/};
/"xcopy/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_MOV |/};
/"not[wd]/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_NOT |/};
/"add/		{s/.type =/& RZ_ANALYSIS_OP_TYPE_ADD |/};
/"and/		{s/.type =/& RZ_ANALYSIS_OP_TYPE_AND |/};
/"mul/		{s/.type =/& RZ_ANALYSIS_OP_TYPE_MUL |/};
/"nop/		{s/.type =/& RZ_ANALYSIS_OP_TYPE_NOP |/};
/"nor/		{s/.type =/& RZ_ANALYSIS_OP_TYPE_NOR |/};
/"neg/		{s/.type =/& RZ_ANALYSIS_OP_TYPE_CPL |/};
/"or[wd]/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_OR |/};
/"xor[wd]/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_XOR |/};
/"srl[hwd]/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_SHR |/};
/"sll[hwd]/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_SHL |/};
/"rol/		{s/.type =/& RZ_ANALYSIS_OP_TYPE_ROL |/};
/"ror/		{s/.type =/& RZ_ANALYSIS_OP_TYPE_ROR |/};
/"comp/		{s/.type =/& RZ_ANALYSIS_OP_TYPE_CMP |/};
/"cmove/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_CMOV |/};
/"goto/		{s/.type =/& RZ_ANALYSIS_OP_TYPE_JMP |/};
/"igoto/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_RJMP |/};
/"cb\./		{s/.type =/& RZ_ANALYSIS_OP_TYPE_CJMP |/};
/"call/		{s/.type =/& RZ_ANALYSIS_OP_TYPE_CALL |/};
/"icall/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_RCALL |/};
/"scall/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_SWI |/};
/"ret/		{s/.type =/& RZ_ANALYSIS_OP_TYPE_RET |/};
/"rfe/		{s/.type =/& RZ_ANALYSIS_OP_TYPE_RET |/};
/"s[bhwdqov]/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_STORE |/};
/"xso/		{s/.type =/& RZ_ANALYSIS_OP_TYPE_STORE |/};
/"l[bhwdqov][^o]/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_LOAD |/};
/"xlo/		{s/.type =/& RZ_ANALYSIS_OP_TYPE_LOAD |/};
/"l[bhw][sz]/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_LOAD |/};
/"loopdo/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_REP |/};

/\.[dw]\?eqz"/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_COND |/;s/.cond =/& RZ_TYPE_COND_EQ |/};
/\.[dw]\?nez"/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_COND |/;s/.cond =/& RZ_TYPE_COND_NE |/};
/\.[dw]\?gez"/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_COND |/;s/.cond =/& RZ_TYPE_COND_GE |/};
/\.[dw]\?gtz"/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_COND |/;s/.cond =/& RZ_TYPE_COND_GT |/};
/\.[dw]\?lez"/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_COND |/;s/.cond =/& RZ_TYPE_COND_LE |/};
/\.[dw]\?ltz"/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_COND |/;s/.cond =/& RZ_TYPE_COND_LT |/};
/\.even"/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_COND |/};
/\.odd"/	{s/.type =/& RZ_ANALYSIS_OP_TYPE_COND |/};

/.*hv0/{s/"%s/&.lo/};
/.*hv1/{s/"%s/&.hi/};
/.*bv0/{s/"%s/&.x/};
/.*bv1/{s/"%s/&.y/};
/.*bv2/{s/"%s/&.z/};
/.*bv3/{s/"%s/&.t/};
