# capstone

OBJ_MIPSCS=asm_mips_cs.o
OBJ_MIPSCS+=../arch/mips/mipsasm.o

include ${CURDIR}capstone.mk

STATIC_OBJ+=${OBJ_MIPSCS}
TARGET_MIPSCS=asm_mips_cs.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_MIPSCS}
${TARGET_MIPSCS}: ${OBJ_MIPSCS}
	${CC} $(call libname,asm_mips_cs) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_MIPSCS} ${OBJ_MIPSCS} ${CS_LDFLAGS}
endif
