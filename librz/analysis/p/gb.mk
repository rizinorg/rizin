OBJ_GB=analysis_gb.o

STATIC_OBJ+=${OBJ_GB}
TARGET_GB=analysis_gb.${EXT_SO}

ALL_TARGETS+=${TARGET_GB}

CFLAGS += -Iarch/gb/

${TARGET_GB}: ${OBJ_GB}
	${CC} $(call libname,analysis_gb) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_GB} ${OBJ_GB}
