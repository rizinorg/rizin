#!/usr/bin/env python3

import re

data = """
gpr	zero	.64	0	0\n
gpr	at	.64	8	0\n
gpr	v0	.64	16	0\n
gpr	v1	.64	24	0\n
gpr	a0	.64	32	0\n
gpr	a1	.64	40	0\n
gpr	a2	.64	48	0\n
gpr	a3	.64	56	0\n
gpr	t0	.64	64	0\n
gpr	t1	.64	72	0\n
gpr	t2 	.64	80	0\n
gpr	t3 	.64	88	0\n
gpr	t4 	.64	96	0\n
gpr	t5 	.64	104	0\n
gpr	t6 	.64	112	0\n
gpr	t7 	.64	120	0\n
gpr	s0	.64	128	0\n
gpr	s1	.64	136	0\n
gpr	s2	.64	144	0\n
gpr	s3	.64	152	0\n
gpr	s4 	.64	160	0\n
gpr	s5 	.64	168	0\n
gpr	s6 	.64	176	0\n
gpr	s7 	.64	184	0\n
gpr	t8 	.64	192	0\n
gpr	t9 	.64	200	0\n
gpr	k0 	.64	208	0\n
gpr	k1 	.64	216	0\n
gpr	gp 	.64	224	0\n
gpr	sp	.64	232	0\n
gpr	fp	.64	240	0\n
gpr	ra	.64	248	0\n
gpr	pc	.64	256	0\n
gpr	hi	.64	264	0\n
gpr	lo	.64	272	0\n
gpr	t	.64	280	0\n
fpu	f0	.64	288	0\n
fpu	f1	.64	296	0\n
fpu	f2	.64	304	0\n
fpu	f3	.64	312	0\n
fpu	f4	.64	320	0\n
fpu	f5	.64	328	0\n
fpu	f6	.64	336	0\n
fpu	f7	.64	344	0\n
fpu	f8	.64	352	0\n
fpu	f9	.64	360	0\n
fpu	f10	.64	368	0\n
fpu	f11	.64	376	0\n
fpu	f12	.64	384	0\n
fpu	f13	.64	392	0\n
fpu	f14	.64	400	0\n
fpu	f15	.64	408	0\n
fpu	f16	.64	416	0\n
fpu	f17	.64	424	0\n
fpu	f18	.64	432	0\n
fpu	f19	.64	440	0\n
fpu	f20	.64	448	0\n
fpu	f21	.64	456	0\n
fpu	f22	.64	464	0\n
fpu	f23	.64	472	0\n
fpu	f24	.64	480	0\n
fpu	f25	.64	488	0\n
fpu	f26	.64	496	0\n
fpu	f27	.64	504	0\n
fpu	f28	.64	512	0\n
fpu	f29	.64	520	0\n
fpu	f30	.64	528	0\n
fpu	f31	.64	536	0\n
flg     FCC0    .1      537     0\n
flg     FCC1    .1      538     0\n
flg     FCC2    .1      539     0\n
flg     FCC3    .1      540     0\n
flg     FCC4    .1      541     0\n
flg     FCC5    .1      542     0\n
flg     FCC6    .1      543     0\n
flg     FCC7    .1      544     0\n
flg     CC0     .1      545     0\n
flg     CC1     .1      545     0\n
flg     CC2     .1      547     0\n
flg     CC3     .1      548     0\n
flg     CC4     .1      549     0\n
flg     CC5     .1      550     0\n
flg     CC6     .1      551     0\n
flg     CC7     .1      552     0\n
flg     CAUSE_EXC .8    553     0\n
flg     LLbit     .1    554     0\n
gpr	w0	.128	555	0\n
gpr	w1	.128	571	0\n
gpr	w2	.128	587	0\n
gpr	w3	.128	603	0\n
gpr	w4	.128	619	0\n
gpr	w5	.128	635	0\n
gpr	w6	.128	651	0\n
gpr	w7	.128	667	0\n
gpr	w8	.128	683	0\n
gpr	w9	.128	699	0\n
gpr	w10	.128	715	0\n
gpr	w11	.128	731	0\n
gpr	w12	.128	747	0\n
gpr	w13	.128	763	0\n
gpr	w14	.128	779	0\n
gpr	w15	.128	795	0\n
gpr	w16	.128	811	0\n
gpr	w17	.128	827	0\n
gpr	w18	.128	843	0\n
gpr	w19	.128	859	0\n
gpr	w20	.128	875	0\n
gpr	w21	.128	891	0\n
gpr	w22	.128	907	0\n
gpr	w23	.128	923	0\n
gpr	w24	.128	939	0\n
gpr	w25	.128	955	0\n
gpr	w26	.128	971	0\n
gpr	w27	.128	987	0\n
gpr	w28	.128	1003	0\n
gpr	w29	.128	1019	0\n
gpr	w30	.128	1035	0\n
gpr	w31	.128	1051	0\n
gpr	ac0	.64	1067	0\n
gpr	ac1	.64	1075	0\n
gpr	ac2	.64	1083	0\n
gpr	ac3	.64	1091	0\n
"""

lines = data.strip().split("\n")     # Split the dataset into line
fixed = ""
address = 0
for line in lines:
    columns = re.split(r"\s+", line.strip())
    if len(columns) <= 4:
        fixed += line
        fixed += "\n"
        continue
    size = int(columns[2].strip("."))
    fixed += f"{columns[0]}\t{columns[1]}\t{columns[2]}\t{address}\t0"
    address += (size + 7)//8

print(fixed)
