include ../../../global.mk
TARGET:=tags.r2

RZ_FLAGS=$(DESTDIR)$(DATADIR)/rizin/$(VERSION)/flag
FILES:=$(filter-out $(TARGET),$(filter-out Makefile,$(filter-out meson.build,$(shell ls))))

all: $(TARGET)

$(TARGET): $(FILES)
	rm -f *.r2
	for a in $(FILES) ; do b=$$(echo `cat $$a`); echo "ft $$a $$b" ; done > $(TARGET)

install: $(TARGET)
	rm -rf "${RZ_FLAGS}"
	mkdir -p "${RZ_FLAGS}"
	cp -f *.r2 "${RZ_FLAGS}"

symstall install-symlink: ${TARGET}
	mkdir -p "$(RZ_FLAGS)"
	-ln -fs $(shell pwd)/tags.r2 $(RZ_FLAGS)/tags.r2

uninstall:
	rm -rf "$(RZ_FLAGS)"
