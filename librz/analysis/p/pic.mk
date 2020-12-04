OBJ_PIC=analysis_pic.o

STATIC_OBJ+=$(OBJ_PIC)
OBJ_PIC+=../../asm/arch/pic/pic_midrange.o
TARGET_PIC=analysis_pic.$(EXT_SO)

ALL_TARTGETS+=$(TARGET_PIC)

$(TARGET_PIC): $(OBJ_PIC)
	$(CC) $(call libname,analysis_pic) ${LDFLAGS} ${CFLAGS} -o analysis_pic.$(EXT_SO) $(OBJ_PIC)
