OBJ_WS=analysis_ws.o

STATIC_OBJ+=${OBJ_WS}
TARGET_WS=analysis_ws.${EXT_SO}

ALL_TARGETS+=${TARGET_WS}

${TARGET_WS}: ${OBJ_WS}
	${CC} $(call libname,analysis_ws) ${LDFLAGS} ${CFLAGS} \
		 -o analysis_ws.${EXT_SO} ${OBJ_WS}
