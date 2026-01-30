NAME=rz-svd
RZ_PLUGIN_PATH=$(shell rizin -hh | grep RZ_USER_PLUGINS | awk '{print $$2}')
CFLAGS=-g -fPIC $(shell pkg-config --cflags rz_core)
LDFLAGS=-shared $(shell pkg-config --libs rz_core)
OBJS=$(NAME).o
SO_EXT=$(shell uname | grep -q Darwin && echo dylib || echo so)
LIB=$(NAME).$(SO_EXT)

all: $(LIB)

clean:
	rm -f $(LIB) $(OBJS)

$(LIB): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $(LIB)

install:
	cp -f $(LIB) $(RZ_PLUGIN_PATH)

uninstall:
	rm -f $(RZ_PLUGIN_PATH)/$(LIB)
