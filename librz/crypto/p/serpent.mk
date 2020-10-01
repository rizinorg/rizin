OBJ_SERPENT=crypto_serpent.o crypto_serpent_algo.o

R2DEPS+=rz_util
DEPFLAGS=-L../../util -lrz_util -L.. -lrz_crypto

STATIC_OBJ+=${OBJ_SERPENT}
TARGET_SERPENT=crypto_serpent.${EXT_SO}

ALL_TARGETS+=${TARGET_SERPENT}

${TARGET_SERPENT}: ${OBJ_SERPENT}
	${CC} $(call libname,crypto_serpent) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_SERPENT} ${OBJ_SERPENT} $(DEPFLAGS)
