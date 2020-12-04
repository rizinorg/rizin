OBJ_Z80=analysis_z80.o

STATIC_OBJ+=${OBJ_Z80}
TARGET_Z80=analysis_z80.${EXT_SO}

ALL_TARGETS+=${TARGET_Z80}

${TARGET_Z80}: ${OBJ_Z80}
	${CC} $(call libname,analysis_z80) ${LDFLAGS} ${CFLAGS} \
		-o analysis_z80.${EXT_SO} ${OBJ_Z80}
