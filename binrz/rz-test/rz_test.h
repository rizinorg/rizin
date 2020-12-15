// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RIZIN_RZTEST_H
#define RIZIN_RZTEST_H

#include <rz_util.h>

#if defined (__FreeBSD__) || defined (__FreeBSD_kernel__)
#define RZ_TEST_OS "freebsd"
#elif defined(__linux__)
#define RZ_TEST_OS "linux"
#elif defined(__APPLE__)
#define RZ_TEST_OS "darwin"
#elif __WINDOWS__
#define RZ_TEST_OS "windows"
#else
#define RZ_TEST_OS "unknown"
#endif

#if __i386__
#define RZ_TEST_ARCH "x86"
#elif __x86_64__
#define RZ_TEST_ARCH "x64"
#else
#define RZ_TEST_ARCH "unknown"
#endif

#define RZ_TEST_ARCH_OS RZ_TEST_OS"-"RZ_TEST_ARCH

typedef struct rz_test_cmd_test_string_record {
	char *value;
	ut64 line_begin; // inclusive
	ut64 line_end; // exclusive
} RzCmdTestStringRecord;

typedef struct rz_test_cmd_test_bool_record {
	bool value;
	ut64 line; // bools are always oneliners (e.g. BROKEN=1)
	bool set;
} RzCmdTestBoolRecord;

typedef struct rz_test_cmd_test_num_record {
	ut64 value;
	ut64 line; // nums are always oneliners (e.g. TIMEOUT=10)
	bool set;
} RzCmdTestNumRecord;

typedef struct rz_test_cmd_test_t {
	RzCmdTestStringRecord name;
	RzCmdTestStringRecord file;
	RzCmdTestStringRecord args;
	RzCmdTestStringRecord source;
	RzCmdTestStringRecord cmds;
	RzCmdTestStringRecord expect;
	RzCmdTestStringRecord expect_err;
	RzCmdTestBoolRecord broken;
	RzCmdTestNumRecord timeout;
	ut64 run_line;
	bool load_plugins;
} RzCmdTest;

#define RZ_CMD_TEST_FOREACH_RECORD_NOP(name, field)
#define RZ_CMD_TEST_FOREACH_RECORD(macro_str, macro_bool, macro_int) \
	macro_str ("NAME", name) \
	macro_str ("FILE", file) \
	macro_str ("ARGS", args) \
	macro_int ("TIMEOUT", timeout) \
	macro_str ("SOURCE", source) \
	macro_str ("CMDS", cmds) \
	macro_str ("EXPECT", expect) \
	macro_str ("EXPECT_ERR", expect_err) \
	macro_bool ("BROKEN", broken)

typedef enum rz_test_asm_test_mode_t {
	RZ_ASM_TEST_MODE_ASSEMBLE = 1,
	RZ_ASM_TEST_MODE_DISASSEMBLE = (1 << 1),
	RZ_ASM_TEST_MODE_BIG_ENDIAN = (1 << 2),
	RZ_ASM_TEST_MODE_BROKEN = (1 << 3)
} RzAsmTestMode;

typedef struct rz_test_asm_test_t {
	ut64 line;
	const char *arch;
	const char *cpu;
	int bits;
	int mode;
	ut64 offset;
	char *disasm;
	ut8 *bytes;
	size_t bytes_size;
} RzAsmTest;

typedef struct rz_test_json_test_t {
	ut64 line;
	char *cmd;
	bool broken;
	bool load_plugins;
} RzJsonTest;

typedef struct rz_test_fuzz_test_t {
	char *file;
} RzFuzzTest;

typedef enum rz_test_test_type_t {
	RZ_TEST_TYPE_CMD,
	RZ_TEST_TYPE_ASM,
	RZ_TEST_TYPE_JSON,
	RZ_TEST_TYPE_FUZZ
} RzTestType;

typedef struct rz_test_test_t {
	const char *path;
	RzTestType type;
	union {
		RzCmdTest *cmd_test;
		RzAsmTest *asm_test;
		RzJsonTest *json_test;
		RzFuzzTest *fuzz_test;
	};
} RzTest;

typedef struct rz_test_test_database_t {
	RzPVector tests;
	RzStrConstPool strpool;
} RzTestDatabase;

typedef struct rz_test_run_config_t {
	const char *rz_cmd;
	const char *rz_asm_cmd;
	const char *json_test_file;
	ut64 timeout_ms;
} RzTestRunConfig;

typedef struct rz_test_asm_test_output_t {
	char *disasm;
	ut8 *bytes;
	size_t bytes_size;
	bool as_timeout;
	bool disas_timeout;
} RzAsmTestOutput;

typedef enum rz_test_test_result_t {
	RZ_TEST_RESULT_OK,
	RZ_TEST_RESULT_FAILED,
	RZ_TEST_RESULT_BROKEN,
	RZ_TEST_RESULT_FIXED
} RzTestResult;

typedef struct rz_test_test_result_info_t {
	RzTest *test;
	RzTestResult result;
	bool timeout;
	bool run_failed; // something went seriously wrong (e.g. rizin not found)
	ut64 time_elapsed;
	union {
		RzSubprocessOutput *proc_out; // for test->type == RZ_TEST_TYPE_CMD, RZ_TEST_TYPE_JSON or RZ_TEST_TYPE_FUZZ
		RzAsmTestOutput *asm_out;  // for test->type == RZ_TEST_TYPE_ASM
	};
} RzTestResultInfo;

RZ_API RzCmdTest *rz_test_cmd_test_new(void);
RZ_API void rz_test_cmd_test_free(RzCmdTest *test);
RZ_API RzPVector *rz_test_load_cmd_test_file(const char *file);

RZ_API RzAsmTest *rz_test_asm_test_new(void);
RZ_API void rz_test_asm_test_free(RzAsmTest *test);
RZ_API RzPVector *rz_test_load_asm_test_file(RzStrConstPool *strpool, const char *file);

RZ_API RzJsonTest *rz_test_json_test_new(void);
RZ_API void rz_test_json_test_free(RzJsonTest *test);
RZ_API RzPVector *rz_test_load_json_test_file(const char *file);

RZ_API RzTestDatabase *rz_test_test_database_new(void);
RZ_API void rz_test_test_database_free(RzTestDatabase *db);
RZ_API bool rz_test_test_database_load(RzTestDatabase *db, const char *path);
RZ_API bool rz_test_test_database_load_fuzz(RzTestDatabase *db, const char *path);

typedef RzSubprocessOutput *(*RzTestCmdRunner)(const char *file, const char *args[], size_t args_size,
	const char *envvars[], const char *envvals[], size_t env_size, ut64 timeout_ms, void *user);

RZ_API RzSubprocessOutput *rz_test_run_cmd_test(RzTestRunConfig *config, RzCmdTest *test, RzTestCmdRunner runner, void *user);
RZ_API bool rz_test_check_cmd_test(RzSubprocessOutput *out, RzCmdTest *test);
RZ_API bool rz_test_check_jq_available(void);
RZ_API RzSubprocessOutput *rz_test_run_json_test(RzTestRunConfig *config, RzJsonTest *test, RzTestCmdRunner runner, void *user);
RZ_API bool rz_test_check_json_test(RzSubprocessOutput *out, RzJsonTest *test);
RZ_API RzAsmTestOutput *rz_test_run_asm_test(RzTestRunConfig *config, RzAsmTest *test);
RZ_API bool rz_test_check_asm_test(RzAsmTestOutput *out, RzAsmTest *test);
RZ_API void rz_test_asm_test_output_free(RzAsmTestOutput *out);
RZ_API RzSubprocessOutput *rz_test_run_fuzz_test(RzTestRunConfig *config, RzFuzzTest *test, RzTestCmdRunner runner, void *user);
RZ_API bool rz_test_check_fuzz_test(RzSubprocessOutput *out);

RZ_API void rz_test_test_free(RzTest *test);
RZ_API char *rz_test_test_name(RzTest *test);
RZ_API bool rz_test_test_broken(RzTest *test);
RZ_API RzTestResultInfo *rz_test_run_test(RzTestRunConfig *config, RzTest *test);
RZ_API void rz_test_test_result_info_free(RzTestResultInfo *result);

#endif // RIZIN_RZTEST_H
