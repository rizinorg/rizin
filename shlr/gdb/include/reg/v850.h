return strdup(
	"=PC    pc\n"
	"=SP    sp\n"
	"gpr	r0	.32	0	0\n"
	"gpr	r1	.32	4	0\n"
	"gpr	r2	.32	8	0\n"
	"gpr	sp	.32	12	0\n" // r3
	"gpr	gp	.32	16	0\n" // r4
	"gpr	r5	.32	20	0\n"
	"gpr	r6	.32	24	0\n"
	"gpr	r7	.32	28	0\n"
	"gpr	r8	.32	32	0\n"
	"gpr	r9	.32	36	0\n"
	"gpr	r10	.32	40	0\n"
	"gpr	r11	.32	44	0\n"
	"gpr	r12	.32	48	0\n"
	"gpr	r13	.32	52	0\n"
	"gpr	r14	.32	56	0\n"
	"gpr	r15	.32	60	0\n"
	"gpr	r16	.32	64	0\n"
	"gpr	r17	.32	68	0\n"
	"gpr	r18	.32	72	0\n"
	"gpr	r19	.32	76	0\n"
	"gpr	r20	.32	80	0\n"
	"gpr	r21	.32	84	0\n"
	"gpr	r22	.32	88	0\n"
	"gpr	r23	.32	92	0\n"
	"gpr	r24	.32	96	0\n"
	"gpr	r25	.32	100	0\n"
	"gpr	r26	.32	104	0\n"
	"gpr	r27	.32	108	0\n"
	"gpr	r28	.32	112	0\n"
	"gpr	r29	.32	116	0\n"
	"gpr	ep	.32	120	0\n" // r30
	"gpr	lp	.32	124	0\n" // r31
	"gpr	eipc	.32	128	0\n"
	"gpr	eipsw	.32	132	0\n"
	"gpr	fepc	.32	136	0\n"
	"gpr	fepsw	.32	140	0\n"
	"gpr	ecr	.32	144	0\n"
	"gpr	psw	.32	148	0\n"
	// 5x reserved, sccfg, scbp, eiic, feic, dbic, ctpc, ctpsw, dbpc, dbpsw, ctbp
	// debug stuff, eiwr, fewr, dbwr, bsel
	"gpr	pc	.32	256	0\n");
