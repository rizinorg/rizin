OBJ_AVR=analysis_avr.o

STATIC_OBJ+=${OBJ_AVR}
TARGET_AVR=analysis_avr.${EXT_SO}

ALL_TARGETS+=${TARGET_AVR}

${TARGET_AVR}: ${OBJ_AVR}
	${CC} $(call libname,analysis_avr) ${CFLAGS} -o analysis_avr.${EXT_SO} ${OBJ_AVR}
