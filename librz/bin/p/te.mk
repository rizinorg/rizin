OBJ_TE=bin_te.o ../format/te/te.o

STATIC_OBJ+=${OBJ_TE}
TARGET_TE=bin_te.${EXT_SO}
#LINK+=-L../../util -lrz_util $(SHLR)/sdb/src/libsdb.a

ALL_TARGETS+=${TARGET_TE}

${TARGET_TE}: ${OBJ_TE}
	${CC} $(call libname,bin_te) ${CFLAGS} \
		$(OBJ_TE) $(LINK) $(LDFLAGS)
