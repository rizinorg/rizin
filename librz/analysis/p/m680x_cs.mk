OBJ_M680X_CS=analysis_m680x_cs.o

include ${CURDIR}capstone.mk

STATIC_OBJ+=$(OBJ_M680X_CS)

TARGET_M680X_CS=analysis_m680x_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_M680X_CS}

${TARGET_M680X_CS}: ${OBJ_M680X_CS}
	${CC} ${CFLAGS} $(call libname,analysis_m680x_cs) $(CS_CFLAGS) \
		-o analysis_m680x_cs.${EXT_SO} ${OBJ_M680X_CS} $(CS_LDFLAGS)
