OBJ_XAP=analysis_xap.o

STATIC_OBJ+=${OBJ_XAP}
TARGET_XAP=analysis_xap.${EXT_SO}

ALL_TARGETS+=${TARGET_XAP}

${TARGET_XAP}: ${OBJ_XAP}
	${CC} $(call libname,analysis_xap) ${CFLAGS} -o analysis_xap.${EXT_SO} ${OBJ_XAP}
