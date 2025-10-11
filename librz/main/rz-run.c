// SPDX-FileCopyrightText: 2011-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_main.h>
#include <rz_socket.h>
#include <rz_util/rz_print.h>

#if __UNIX__
static void fwd(int sig) {
	/* do nothing? send kill signal to remote process */
}

static void rz_run_tty(void) {
	/* TODO: Implement in native code */
	rz_sys_xsystem("tty");
	close(1);
	dup2(2, 1);
	rz_sys_signal(SIGINT, fwd);
	for (;;) {
		sleep(1);
	}
}
#endif

static void rz_run_help(int v) {
	if (v == 0) {
		printf(Color_CYAN "Usage: ");
		printf(Color_RESET "rz-run [directives | script.rz] [-- program [args]]\n");
		const char *options[] = {
			// clang-format off
			"-h",       "",                 "Show this help",
			"-l",       "",                 "Show profile directives",
			"-t",       "",                 "Output template profile",
			"-v",       "",                 "Show version information",
			"-w",       "",                 "Wait for incoming terminal process",
			"--",       "program [args]",   "Run program",
			// clang-format on
		};
		rz_print_colored_help(options, RZ_ARRAY_SIZE(options), false);
	}
	if (v == 1) {
		// clang-format off
		printf(
			"program=/bin/ls\n"
			"arg1=/bin\n"
			"# arg2=hello\n"
			"# arg3=\"hello\\nworld\"\n"
			"# arg4=:048490184058104849\n"
			"# arg5=:!rz-gg -p n50 -d 10:0x8048123\n"
			"# arg6=@arg.txt\n"
			"# arg7=@300@ABCD # 300 chars filled with ABCD pattern\n"
			"# system=rizin -\n"
			"# daemon=false\n"
			"# aslr=no\n"
			"setenv=FOO=BAR\n"
			"# unsetenv=FOO\n"
			"# clearenv=true\n"
			"# envfile=environ.txt\n"
			"timeout=3\n"
			"# timeoutsig=SIGTERM # or 15\n"
			"# connect=localhost:8080\n"
			"# listen=8080\n"
			"# pty=false\n"
			"# fork=true\n"
			"# bits=32\n"
			"# pid=0\n"
			"# pidfile=/tmp/foo.pid\n"
			"# #sleep=0\n"
			"# #maxfd=0\n"
			"# #execve=false\n"
			"# #maxproc=0\n"
			"# #maxstack=0\n"
			"# #core=false\n"
			"# #stdio=blah.txt\n"
			"# #stderr=foo.txt\n"
			"# stdout=foo.txt\n"
			"# stdin=input.txt # or !program to redirect input from another program\n"
			"# input=input.txt\n"
			"# chdir=/\n"
			"# chroot=/mnt/chroot\n"
			"# libpath=$PWD:/tmp/lib\n"
			"# rzpreload=yes\n"
			"# preload=/lib/libfoo.so\n"
			"# setuid=2000\n"
			"# seteuid=2000\n"
			"# setgid=2001\n"
			"# setegid=2001\n"
			"# nice=5\n"
			""
		);
		// clang-format on
	}
	if (v == 2) {
		// clang-format off
		printf(Color_CYAN "Supported RzRun profile directives:\n"
			Color_RESET
			"arg[0-511]  Set value for argument N passed to the program\n"
			"aslr        Enable or disable ASLR\n"
			"bits        Set 32 or 64 bit (if the architecture supports it)\n"
			"chdir       Change directory before executing the program\n"
			"chroot      Run the program in chroot. requires some previous setup\n"
			"connect     Connect stdin/stdout/stderr to a socket\n"
			"core        Set no limit the core file size\n"
			"daemon      Set to false by default, otherwise it will run the program in background, detached from the terminal\n"
			"envfile     Set a file with lines like `var=value` to be used as env\n"
			"fork        Used with the listen option, allow to spawn a different process for each connection. Ignored when debugging.\n"
			"input       Set string to be passed to the program via stdin\n"
			"libpath     Override path where the dynamic loader will look for shared libraries\n"
			"listen      Bound stdin/stdout/stderr to a listening socket\n"
			"maxfd       Set the maximum number of file descriptors\n"
			"maxproc     Set the maximum number of processes\n"
			"maxstack    Set the maximum size for the stack\n"
			"nice        Set the niceness level of the process\n"
			"pid         Set to true to print the PID of the process to stderr\n"
			"pidfile     Print the PID of the process to the specified file\n"
			"preload     Preload a library (not supported on Windows, only linux,osx,bsd)\n"
			"program     Path to program to be executed\n"
			"pty         Use a pty for connection over socket (with connect/listen)\n"
			"runlib      Path to the library to be executed\n"
			"runlib.fcn  Function name to call from runlib library\n"
			"rzpreload   Preload with librz, kill -USR1 to get an rizin shell or -USRZ to spawn a webserver in a thread\n"
			"setegid     Set effective process group id\n"
			"setenv      Set value for given environment variable (setenv=FOO=BAR)\n"
			"seteuid     Set effective process uid\n"
			"setgid      Set process group id\n"
			"setuid      Set process uid\n"
			"sleep       Sleep for the given amount of seconds\n"
			"sterr       Select file to replace stderr file descriptor\n"
			"stdin       Select file to read data from stdin\n"
			"stdio       Select io stream to redirect data from/to\n"
			"            Redirect input/output to the process created by the specified command prefixed by '!' (stdio=!cmd)\n"
			"stdout      Select file to replace stdout file descriptor\n"
			"system      Execute the given command\n"
			"timeout     Set a timeout\n"
			"timeoutsig  Signal to use when killing the child because the timeout happens\n"
			"unsetenv    Unset one environment variable\n"
			"");
		// clang-format off
	}
}


RZ_API int rz_main_rz_run(int argc, const char **argv) {
	RzRunProfile *p;
	int i, ret;
	const char *file = argv[1];
	if (!strcmp(file, "-w")) {
#if __UNIX__
		rz_run_tty();
		return 0;
#else
		RZ_LOG_ERROR("Not supported\n");
		return 1;
#endif
	}
	if (*file && !strchr(file, '=')) {
		p = rz_run_new(file);
	} else {
		bool noMoreDirectives = false;
		int directiveIndex = 0;
		p = rz_run_new(NULL);
		if (!p) {
			RZ_LOG_ERROR("Failed to create new RzRunProfile\n");
			return 1;
		}
		for (i = *file ? 1 : 2; i < argc; i++) {
			if (!strcmp(argv[i], "--")) {
				noMoreDirectives = true;
				continue;
			}
			if (noMoreDirectives) {
				const char *word = argv[i];
				char *line = directiveIndex
					? rz_str_newf("arg%d=%s", directiveIndex, word)
					: rz_str_newf("program=%s", word);
				rz_run_parseline(p, line);
				directiveIndex++;
				free(line);
			} else {
				rz_run_parseline(p, argv[i]);
			}
		}
	}
	if (!p) {
		return 1;
	}
	if (argc == 1 || !strcmp(argv[1], "-h")) {
		rz_run_help(0);
		ret = 1;
		goto finish;
	}
	if (!strcmp(argv[1], "-v")) {
		RzPath *sys_path = rz_path_new();
		if(!sys_path){
			ret = 1;
			goto finish;
		}
		ret =  rz_main_version_print(sys_path, "rz-run");
		rz_path_free(sys_path);
		goto finish;
	}
	if (!strcmp(argv[1], "-t")) {
		rz_run_help(1);
		ret = 0;
		goto finish;
	}
	if (!strcmp(argv[1], "-l")) {
		rz_run_help(2);
		ret = 0;
		goto finish;
	}
	ret = rz_run_config_env(p);
	if (ret) {
		printf("error while configuring the environment.\n");
		rz_run_free(p);
		return 1;
	}
	ret = rz_run_start(p);
finish:
	rz_run_free(p);
	return ret;
}
