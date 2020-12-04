OBJ_AMD29K=analysis_amd29k.o ../../asm/arch/amd29k/amd29k.o

STATIC_OBJ+=${OBJ_AMD29K}
TARGET_AMD29K=analysis_amd29k.${EXT_SO}

ALL_TARGETS+=${TARGET_AMD29K}

${TARGET_AMD29K}: ${OBJ_AMD29K}
	${CC} ${CFLAGS} $(call libname,analysis_amd29k) $(CS_CFLAGS) \
		-o analysis_amd29k.${EXT_SO} ${OBJ_AMD29K} $(CS_LDFLAGS)
