# RzSocket

`RzSocket` provides a portable abstraction for network sockets, process pipes, and serial communication. It is used across Rizin for IPC, remote analysis, and communication with external tools.

## Architecture

The module is divided into several components:

- **Core Socket**: Basic TCP, UDP, and Unix socket support (client and server).
- **HTTP**: Client (GET/POST) and Server implementation.
- **IPC/Process**: 
  - `RzSocketProc`: Spawning processes with redirected STDIN/STDOUT.
  - `RzPipe`: Higher-level IPC for talking to Rizin instances or libraries.
- **Serial**: Support for RS232 serial communication.

## Key Structures

- `RzSocket`: Main structure for network and serial connections. Supports SSL.
- `RzPipe`: Used for communicating with Rizin processes or linked libraries.
- `RzSocketProc`: Low-level process spawning and IO management.
- `RzRunProfile`: Configuration for spawning processes (environment, IDs, priorities).

## API Usage

### Network Client (TCP)

```c
RzSocket *s = rz_socket_new(false);
if (rz_socket_connect_tcp(s, "localhost", "9090", 0)) {
    rz_socket_printf(s, "hello\n");
    char buf[1024];
    rz_socket_read(s, (ut8 *)buf, sizeof(buf));
    rz_socket_close(s);
}
rz_socket_free(s);
```

### HTTP Client

```c
int code, rlen;
char *response = rz_socket_http_get("http://127.0.0.1:8080/index.html", &code, &rlen);
if (response) {
    printf("Status: %d, Length: %d\n", code, rlen);
    free(response);
}
```

### IPC / RzPipe (IPC)

`RzPipe` allows you to execute commands in a Rizin instance and read the results.

```c
RzPipe *p = rzpipe_open("rz-asm -a x86 -b 32 'push eax'");
char *res = rzpipe_read(p);
if (res) {
    printf("Result: %s\n", res);
    free(res);
}
rzpipe_close(p);
```

### Process Management (SocketProc)

`RzSocket` provides a way to interact with external processes using pipes.

```c
char *argv[] = { "ls", "-l", NULL };
RzSocketProc *sp = rz_socket_proc_open(argv);
if (sp) {
    char buf[1024];
    int len = rz_socket_proc_read(sp, (ut8 *)buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = 0;
        printf("Output:\n%s\n", buf);
    }
    rz_socket_proc_close(sp);
}
```

### Serial Communication

`RzSocket` can also be used to communicate with serial devices.

```c
RzSocket *s = rz_socket_new(false);
int fd = rz_socket_connect_serial(s, "/dev/ttyUSB0", 115200, 0);
if (fd != -1) {
    char buf[128];
    int len = rz_socket_read(s, (ut8 *)buf, sizeof(buf));
    if (len > 0) {
        printf("Received: %.*s\n", len, buf);
    }
    rz_socket_close(s);
}
rz_socket_free(s);
```

## RzPipe Ecosystem

The RzPipe protocol is implemented in many programming languages, allowing you to interact with Rizin from almost anywhere.

Supported languages include:
- [Python](https://github.com/rizinorg/rz-pipe/tree/master/python)
- [Rust](https://github.com/rizinorg/rz-pipe/tree/master/rust)
- [Go](https://github.com/rizinorg/rz-pipe/tree/master/go)
- [Haskell](https://github.com/rizinorg/rz-pipe/tree/master/haskell)
- [OCaml](https://github.com/rizinorg/rz-pipe/tree/master/ocaml)
- [Ruby](https://github.com/rizinorg/rz-pipe/tree/master/ruby)

For a complete list of implementations, visit the [rz-pipe](https://github.com/rizinorg/rz-pipe) repository.