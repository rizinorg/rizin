CFLAGS+=-I../../include
LDFLAGS+=-lrz_cons -L../../librz/cons
LDFLAGS+=-lrz_util -L../../librz/util

all: graph test-rgb

test-rgb: test-rgb.o
	$(CC) -o test-rgb test-rgb.o $(LDFLAGS)

graph: graph.o
	$(CC) -o graph graph.o $(LDFLAGS)
