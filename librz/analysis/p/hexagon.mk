OBJ_HEXAGON=anal_hexagon.o
OBJ_HEXAGON+=../../asm/arch/hexagon/hexagon.o
OBJ_HEXAGON+=../../asm/arch/hexagon/hexagon_disas.o
OBJ_HEXAGON+=../../analysis/arch/hexagon/hexagon_anal.o

CFLAGS +=-I../asm/arch/hexagon
CFLAGS +=-I../analysis/arch/hexagon

STATIC_OBJ+=${OBJ_HEXAGON}
TARGET_HEXAGON=anal_hexagon.${EXT_SO}

ALL_TARGETS+=${TARGET_HEXAGON}

${TARGET_HEXAGON}: ${OBJ_HEXAGON}
	${CC} $(call libname,anal_hexagon) ${LDFLAGS} ${CFLAGS} \
		-o $(TARGET_HEXAGON) $(OBJ_HEXAGON)
