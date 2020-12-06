OBJ_SYSTEMZ_CS=analysis_sysz.o

include p/capstone.mk

STATIC_OBJ+=${OBJ_SYSTEMZ_CS}

TARGET_SYSTEMZ_CS=analysis_sysz.${EXT_SO}

ALL_TARGETS+=${TARGET_SYSTEMZ_CS}

${TARGET_SYSTEMZ_CS}: ${OBJ_SYSTEMZ_CS}
	${CC} ${CFLAGS} $(call libname,analysis_sysz) $(CS_LDFLAGS) \
		-o analysis_sysz.${EXT_SO} ${OBJ_SYSTEMZ_CS}
