OBJ_PTRACE=io_ptrace.o

STATIC_OBJ+=${OBJ_PTRACE}
TARGET_PTRACE=io_ptrace.${EXT_SO}
ALL_TARGETS+=${TARGET_PTRACE}

${TARGET_PTRACE}: ${OBJ_PTRACE}
	${CC_LIB} ${CFLAGS} -o ${TARGET_PTRACE} ${LDFLAGS_LIB} \
		$(call libname,io_ptrace) $(LDFLAGS) \
		${LDFLAGS_LINKPATH}../../util -L../../util -lrz_util \
		${LDFLAGS_LINKPATH}.. -L.. -lrz_io ${OBJ_PTRACE}
