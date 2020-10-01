include ../config.mk

NAME=rz_socket
OBJS=socket.o
OBJS+=socket_proc.o
OBJS+=socket_http.o # TODO: rename to socket_http_client.o
OBJS+=socket_http_server.o
OBJS+=socket_rap_server.o
OBJS+=socket_rap_client.o
OBJS+=run.o rzpipe.o socket_serial.o
R2DEPS=rz_util

include deps.mk
include ../rules.mk
