OBJ_AES=crypto_aes.o crypto_aes_algo.o

R2DEPS+=rz_util
DEPFLAGS=-L../../util -lrz_util -L.. -lrz_crypto

STATIC_OBJ+=${OBJ_AES}
TARGET_AES=crypto_aes.${EXT_SO}

ALL_TARGETS+=${TARGET_AES}

${TARGET_AES}: ${OBJ_AES}
	${CC} $(call libname,crypto_aes) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_AES} ${OBJ_AES} $(DEPFLAGS)
