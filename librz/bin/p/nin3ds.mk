OBJ_NIN3DS=bin_nin3ds.o

STATIC_OBJ+=${OBJ_NIN3DS}
TARGET_NIN3DS=bin_nin3ds.${EXT_SO}

ALL_TARGETS+=${TARGET_NIN3DS}

${TARGET_NIN3DS}: ${OBJ_NIN3DS}
ifeq ($(CC),cccl)
	${CC} $(call libname,bin_nin3ds) ${CFLAGS} $(OBJ_NIN3DS) $(LINK) $(LDFLAGS) \
	-L../../magic -llibrz_magic
else
	${CC} $(call libname,bin_nin3ds) ${CFLAGS} $(OBJ_NIN3DS) $(LINK) $(LDFLAGS) \
	-L../../magic -lrz_magic
endif
