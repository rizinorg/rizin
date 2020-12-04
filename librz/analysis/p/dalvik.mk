OBJ_DALVIK=analysis_dalvik.o

STATIC_OBJ+=${OBJ_DALVIK}
TARGET_DALVIK=analysis_dalvik.${EXT_SO}

ALL_TARGETS+=${TARGET_DALVIK}

${TARGET_DALVIK}: ${OBJ_DALVIK}
	${CC} $(call libname,analysis_dalvik) ${LDFLAGS} ${CFLAGS} -o analysis_dalvik.${EXT_SO} ${OBJ_DALVIK}
