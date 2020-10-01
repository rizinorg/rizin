OBJ_NINDS=bin_ninds.o

STATIC_OBJ+=${OBJ_NINDS}
TARGET_NINDS=bin_ninds.${EXT_SO}

ALL_TARGETS+=${TARGET_NINDS}

${TARGET_NINDS}: ${OBJ_NINDS}
ifeq ($(CC),cccl)
	${CC} $(call libname,bin_ninds) ${CFLAGS} $(OBJ_NINDS) $(LINK) $(LDFLAGS) \
	-L../../magic -llibrz_magic
else
	${CC} $(call libname,bin_ninds) ${CFLAGS} $(OBJ_NINDS) $(LINK) $(LDFLAGS) \
	-L../../magic -lrz_magic
endif
