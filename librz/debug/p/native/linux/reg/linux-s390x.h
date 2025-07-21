// SPDX-FileCopyrightText: 2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#if 0

https://www.kernel.org/doc/Documentation/s390/Debugging390.txt

s/390 & z/Architecture Register usage
=====================================
r0       used by syscalls/assembly                  call-clobbered
r1	 used by syscalls/assembly                  call-clobbered
r2       argument 0 / return value 0                call-clobbered
r3       argument 1 / return value 1 (if long long) call-clobbered
r4       argument 2                                 call-clobbered
r5       argument 3                                 call-clobbered
r6	 argument 4				    saved
r7       pointer-to arguments 5 to ...              saved      
r8       this & that                                saved
r9       this & that                                saved
r10      static-chain ( if nested function )        saved
r11      frame-pointer ( if function used alloca )  saved
r12      got-pointer                                saved
r13      base-pointer                               saved
r14      return-address                             saved
r15      stack-pointer                              saved
$pc
$sp

f0       argument 0 / return value ( float/double ) call-clobbered
f2       argument 1                                 call-clobbered
f4       z/Architecture argument 2                  saved
f6       z/Architecture argument 3                  saved
The remaining floating points
f1,f3,f5 f7-f15 are call-clobbered.


The current architectures have the following registers.
 
16 General propose registers, 32 bit on s/390 and 64 bit on z/Architecture,
r0-r15 (or gpr0-gpr15), used for arithmetic and addressing.

16 Control registers, 32 bit on s/390 and 64 bit on z/Architecture, cr0-cr15,
kernel usage only, used for memory management, interrupt control, debugging
control etc.

16 Access registers (ar0-ar15), 32 bit on both s/390 and z/Architecture,
normally not used by normal programs but potentially could be used as
temporary storage. These registers have a 1:1 association with general
purpose registers and are designed to be used in the so-called access
register mode to select different address spaces.
Access register 0 (and access register 1 on z/Architecture, which needs a
64 bit pointer) is currently used by the pthread library as a pointer to
the current running threads private area.

16 64 bit floating point registers (fp0-fp15 ) IEEE & HFP floating 
point format compliant on G5 upwards & a Floating point control reg (FPC) 
4  64 bit registers (fp0,fp2,fp4 & fp6) HFP only on older machines.
Note:
Linux (currently) always uses IEEE & emulates G5 IEEE format on older machines,
( provided the kernel is configured for this ).
#endif

/* Return 32 bit s390 architecture register profile */
return rz_str_dup(
	"=PC	psw_addr\n"
	"=LR	r14\n"
	"=SP	r15\n"
	"=BP	r13\n"
	"=R0	r2\n"
	"=A0	r2\n"
	"=A1	r3\n"
	"=A2	r4\n"
	"=A3	r5\n"
	"gpr	psw .64	0	0\n"
	"gpr    psw_mask    .32 0   0\n"
	"gpr    psw_addr    .32 4   0\n"
	"gpr	r0	.32	8	0\n"
	"gpr	r1 	.32	12	0\n"
	"gpr	r2 	.32	16	0\n"
	"gpr	r3 	.32	20	0\n"
	"gpr	r4 	.32	24	0\n"
	"gpr	r5 	.32	28	0\n"
	"gpr	r6 	.32	32	0\n"
	"gpr	r7 	.32	36	0\n"
	"gpr	r8 	.32	40	0\n"
	"gpr	r9 	.32	44	0\n"
	"gpr	r10 	.32	48	0\n"
	"gpr	r11 	.32	52	0\n"
	"gpr	r12 	.32	56	0\n"
	"gpr	r13 	.32	60	0\n"
	"gpr	r14 	.32	64	0\n"
	"gpr	r15 	.32	68	0\n"
	"gpr	ar0	.32	72	0\n"
	"gpr	ar1	.32	76	0\n"
	"gpr	ar2	.32	80	0\n"
	"gpr	ar3	.32	84	0\n"
	"gpr	ar4	.32	88	0\n"
	"gpr	ar5	.32	92	0\n"
	"gpr	ar6	.32	96	0\n"
	"gpr	ar7	.32	100	0\n"
	"gpr	ar8	.32	104	0\n"
	"gpr	ar9	.32	108	0\n"
	"gpr	ar10	.32	112	0\n"
	"gpr	ar11	.32	116	0\n"
	"gpr	ar12	.32	120	0\n"
	"gpr	ar13	.32	124	0\n"
	"gpr	ar14	.32	128	0\n"
	"gpr	ar15	.32	132	0\n"
	"gpr	origgpr2	.32	136	0\n"
	"gpr	fpc	.32	144	0\n"
	"fpu	f0	.64	152	0\n"
	"fpu	f1	.64	160	0\n"
	"fpu	f2	.64	168	0\n"
	"fpu	f3	.64	176	0\n"
	"fpu	f4	.64	184	0\n"
	"fpu	f5	.64	192	0\n"
	"fpu	f6	.64	200	0\n"
	"fpu	f7	.64	208	0\n"
	"fpu	f8	.64	216	0\n"
	"fpu	f9	.64	224	0\n"
	"fpu	f10	.64	232	0\n"
	"fpu	f11	.64	240	0\n"
	"fpu	f12	.64	248	0\n"
	"fpu	f13	.64	256	0\n"
	"fpu	f14	.64	264	0\n"
	"fpu	f15	.64	272	0\n"
	/* Ptrace provides offset only for these control registers */
	"gpr	cr_9	.32	280	0\n"
	"gpr	cr_10	.32	284	0\n"
	"gpr	cr_11	.32	288	0\n"
	"gpr	ieee_ip	.32	316	0\n");