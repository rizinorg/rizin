OBJ_XTENSA=analysis_xtensa.o

STATIC_OBJ+=${OBJ_XTENSA}
TARGET_XTENSA=analysis_xtensa.${EXT_SO}

ALL_TARGETS+=$(TARGET_XTENSA)

$(TARGET_XTENSA): $(OBJ_XTENSA)
	$(CC) $(call libname,analysis_xtensa) -I$(LTOP)/asm/arch/include/ \
		$(LDFLAGS) $(CFLAGS) -o analysis_xtensa.$(EXT_SO) $(OBJ_XTENSA)
