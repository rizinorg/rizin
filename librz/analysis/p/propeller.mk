OBJ_propeller=analysis_propeller.o
CFLAGS+=-I../asm/arch/propeller/

STATIC_OBJ+=${OBJ_propeller}
OBJ_propeller+=../../asm/arch/propeller/propeller_disas.o
TARGET_propeller=analysis_propeller.${EXT_SO}

ALL_TARGETS+=${TARGET_propeller}

${TARGET_propeller}: ${OBJ_propeller} ${SHARED_OBJ}
	$(call pwd)
	${CC} $(call libname,analysis_propeller) ${CFLAGS} \
		-o ${TARGET_propeller} ${OBJ_propeller}
