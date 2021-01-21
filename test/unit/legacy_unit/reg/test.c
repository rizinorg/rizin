#include <rz_reg.h>

void show_regs(struct rz_reg_t *reg, int bitsize) {
	RzList *reglist;
	RzListIter *iter;
	RzRegItem *ri;
	printf("%d bit registers:\n", bitsize);
	reglist = rz_reg_get_list(reg, bitsize == 1 ? RZ_REG_TYPE_FLG : RZ_REG_TYPE_GPR);
	rz_list_foreach (reglist, iter, ri) {
		if (ri->size == bitsize)
			printf(" - %s : 0x%08" PFMT64x "\n", ri->name, rz_reg_get_value(reg, ri));
	}
}

void print_eflags_bits(RzReg *reg) {
	int a;
	a = rz_reg_getv(reg, "cf");
	printf(" c:%d", a);
	printf(" 1");
	a = rz_reg_getv(reg, "pf");
	printf(" p:%d", a);
	printf(" 0");
	a = rz_reg_getv(reg, "af");
	printf(" a:%d", a);
	printf(" 0");
	a = rz_reg_getv(reg, "zf");
	printf(" z:%d", a);
	a = rz_reg_getv(reg, "sf");
	printf(" s:%d", a);
	a = rz_reg_getv(reg, "tf");
	printf(" t:%d", a);
	a = rz_reg_getv(reg, "if");
	printf(" i:%d", a);
	a = rz_reg_getv(reg, "df");
	printf(" d:%d", a);
	a = rz_reg_getv(reg, "of");
	printf(" o:%d", a);
	printf("\n");
}

int main() {
	int i;
	int foo[128];
	const char *type;
	struct rz_reg_t *reg;

	for (i = 0; i < 128; i++)
		foo[i] = i;

	reg = rz_reg_new();
	rz_reg_set_profile(reg, "./test.regs");
	rz_reg_read_regs(reg, (const ut8 *)foo, sizeof(foo));
	{
		ut64 a;
		RzRegItem *item;
		item = rz_reg_get(reg, "eflags", RZ_REG_TYPE_GPR);
		rz_reg_set_value(reg, item, 0x00000346); //0xffffffffffff);
		a = rz_reg_get_value(reg, item);
		eprintf("A32 = 0x%x\n", (int)a);
		if ((int)a != -1) {
			eprintf("1 FAIL\n");
		}

		print_eflags_bits(reg);
		item = rz_reg_get(reg, "zf", RZ_REG_TYPE_GPR);
		a = rz_reg_get_value(reg, item);
		eprintf("A = %d\n", (int)a);
		if (a != 1) {
			eprintf("2 FAIL\n");
		}

		item = rz_reg_get(reg, "zf", RZ_REG_TYPE_GPR);
		rz_reg_set_value(reg, item, 1);
		a = rz_reg_get_value(reg, item);
		eprintf("A = %d\n", (int)a);
		if (a != 1) {
			eprintf("3 FAIL\n");
		}
		rz_reg_set_value(reg, item, 0);
		a = rz_reg_get_value(reg, item);
		eprintf("A = %d\n", (int)a);
		if (a != 0) {
			eprintf("4 FAIL\n");
		}
	}
	show_regs(reg, 1); //32);

	exit(0);
	show_regs(reg, 32);
	/* --- */
	rz_reg_set_profile(reg, "../p/x86-linux.regs");
	printf("Program counter is named: %s\n", rz_reg_get_name(reg, RZ_REG_NAME_PC));
	show_regs(reg, 32);
	rz_reg_set_value(reg, rz_reg_get(reg, "eax", -1), 0x414141);
	rz_reg_set_value(reg, rz_reg_get(reg, "ecx", -1), 666);
	show_regs(reg, 32);
	rz_reg_set_value(reg, rz_reg_get(reg, "al", -1), 0x22);
	show_regs(reg, 33);

	rz_reg_set_value(reg, rz_reg_get(reg, "zero", -1), 0);
	show_regs(reg, 1);
	rz_reg_set_value(reg, rz_reg_get(reg, "zero", -1), 1);
	show_regs(reg, 1);

	for (i = 0; (type = rz_reg_get_type(i)); i++)
		printf(" - %s\n", type);

	rz_reg_arena_push(reg);
	rz_reg_arena_pop(reg);

	rz_reg_arena_push(reg);
	rz_reg_arena_push(reg);
	rz_reg_arena_push(reg);
	rz_reg_arena_pop(reg);
	rz_reg_arena_pop(reg);
	rz_reg_arena_push(reg);
	rz_reg_arena_pop(reg);
	rz_reg_arena_pop(reg);
	/*
	rz_reg_arena_pop(reg);
	rz_reg_arena_pop(reg);
	rz_reg_arena_pop(reg);
	rz_reg_arena_pop(reg);
*/
	return 0;
}
