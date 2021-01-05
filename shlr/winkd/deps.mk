LINK+=$(STOP)/winkd/librz_winkd.${EXT_AR}
LDFLAGS+=-lrz_crypto -lrz_hash
include $(LIBRZ)/socket/deps.mk
