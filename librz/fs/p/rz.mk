OBJ_R2=fs_rz.o

STATIC_OBJ+=${OBJ_R2}
TARGET_R2=fs_rz.${EXT_SO}

ALL_TARGETS+=${TARGET_R2}

${TARGET_R2}: ${OBJ_R2}
	${CC} $(call libname,fs_rz) ${LDFLAGS} ${CFLAGS} -o ${TARGET_R2} ${OBJ_R2} ${EXTRA}
