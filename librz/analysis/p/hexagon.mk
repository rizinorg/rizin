OBJ_HEXAGON=analysis_hexagon.o
OBJ_HEXAGON+=../../asm/arch/hexagon/hexagon.o
OBJ_HEXAGON+=../../asm/arch/hexagon/hexagon_disas.o
OBJ_HEXAGON+=../../analysis/arch/hexagon/hexagon_analysis.o

CFLAGS +=-I../asm/arch/hexagon
CFLAGS +=-I../analysis/arch/hexagon

STATIC_OBJ+=${OBJ_HEXAGON}
TARGET_HEXAGON=analysis_hexagon.${EXT_SO}

ALL_TARGETS+=${TARGET_HEXAGON}

${TARGET_HEXAGON}: ${OBJ_HEXAGON}
	${CC} $(call libname,analysis_hexagon) ${LDFLAGS} ${CFLAGS} \
		-o $(TARGET_HEXAGON) $(OBJ_HEXAGON)
