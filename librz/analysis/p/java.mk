OBJ_JAVA=analysis_java.o
SHARED2_JAVA=$(addprefix ../,${SHARED_JAVA})

OBJ_JAVA+=${SHARED2_JAVA}

STATIC_OBJ+=${OBJ_JAVA}
TARGET_JAVA=analysis_java.${EXT_SO}

ALL_TARGETS+=${TARGET_JAVA}

${TARGET_JAVA}: ${OBJ_JAVA}
	${CC} $(call libname,analysis_java) ${CFLAGS} \
		-o analysis_java.${EXT_SO} \
		${OBJ_JAVA} ${SHARED2_JAVA} \
		$(SHLR)/java/librz_java.$(EXT_AR) \
		$(SHLR)/sdb/src/libsdb.$(EXT_AR)
