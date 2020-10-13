include ../../../global.mk
TARGET:=tags.rz

RZ_FLAGS=$(DESTDIR)$(DATADIR)/rizin/$(VERSION)/flag
FILES:=$(filter-out $(TARGET),$(filter-out Makefile,$(filter-out meson.build,$(shell ls))))

all: $(TARGET)

$(TARGET): $(FILES)
	rm -f *.rz
	for a in $(FILES) ; do b=$$(echo `cat $$a`); echo "ft $$a $$b" ; done > $(TARGET)

install: $(TARGET)
	rm -rf "${RZ_FLAGS}"
	mkdir -p "${RZ_FLAGS}"
	cp -f *.rz "${RZ_FLAGS}"

symstall install-symlink: ${TARGET}
	mkdir -p "$(RZ_FLAGS)"
	-ln -fs $(shell pwd)/tags.rz $(RZ_FLAGS)/tags.rz

uninstall:
	rm -rf "$(RZ_FLAGS)"
