/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#ifndef RIZIN_RZTEST_H
#define RIZIN_RZTEST_H

#include <rz_util.h>

#if defined (__FreeBSD__) || defined (__FreeBSD_kernel__)
#define R2R_OS "freebsd"
#elif defined(__linux__)
#define R2R_OS "linux"
#elif defined(__APPLE__)
#define R2R_OS "darwin"
#elif __WINDOWS__
#define R2R_OS "windows"
#else
#define R2R_OS "unknown"
#endif

#if __i386__
#define R2R_ARCH "x86"
#elif __x86_64__
#define R2R_ARCH "x64"
#else
#define R2R_ARCH "unknown"
#endif

#define R2R_ARCH_OS R2R_OS"-"R2R_ARCH

typedef struct rz_test_cmd_test_string_record {
	char *value;
	ut64 line_begin; // inclusive
	ut64 line_end; // exclusive
} R2RzCmdTestStringRecord;

typedef struct rz_test_cmd_test_bool_record {
	bool value;
	ut64 line; // bools are always oneliners (e.g. BROKEN=1)
	bool set;
} R2RzCmdTestBoolRecord;

typedef struct rz_test_cmd_test_num_record {
	ut64 value;
	ut64 line; // nums are always oneliners (e.g. TIMEOUT=10)
	bool set;
} R2RzCmdTestNumRecord;

typedef struct rz_test_cmd_test_t {
	R2RzCmdTestStringRecord name;
	R2RzCmdTestStringRecord file;
	R2RzCmdTestStringRecord args;
	R2RzCmdTestStringRecord source;
	R2RzCmdTestStringRecord cmds;
	R2RzCmdTestStringRecord expect;
	R2RzCmdTestStringRecord expect_err;
	R2RzCmdTestBoolRecord broken;
	R2RzCmdTestNumRecord timeout;
	ut64 run_line;
	bool load_plugins;
} R2RzCmdTest;

#define R2R_CMD_TEST_FOREACH_RECORD_NOP(name, field)
#define R2R_CMD_TEST_FOREACH_RECORD(macro_str, macro_bool, macro_int) \
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
	R2R_ASM_TEST_MODE_ASSEMBLE = 1,
	R2R_ASM_TEST_MODE_DISASSEMBLE = (1 << 1),
	R2R_ASM_TEST_MODE_BIG_ENDIAN = (1 << 2),
	R2R_ASM_TEST_MODE_BROKEN = (1 << 3)
} R2RzAsmTestMode;

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
} R2RzAsmTest;

typedef struct rz_test_json_test_t {
	ut64 line;
	char *cmd;
	bool broken;
	bool load_plugins;
} R2RJsonTest;

typedef struct rz_test_fuzz_test_t {
	char *file;
} R2RFuzzTest;

typedef enum rz_test_test_type_t {
	R2R_TEST_TYPE_CMD,
	R2R_TEST_TYPE_ASM,
	R2R_TEST_TYPE_JSON,
	R2R_TEST_TYPE_FUZZ
} R2RTestType;

typedef struct rz_test_test_t {
	const char *path;
	R2RTestType type;
	union {
		R2RzCmdTest *cmd_test;
		R2RzAsmTest *asm_test;
		R2RJsonTest *json_test;
		R2RFuzzTest *fuzz_test;
	};
} R2RTest;

typedef struct rz_test_test_database_t {
	RPVector tests;
	RStrConstPool strpool;
} R2RTestDatabase;

typedef struct rz_test_run_config_t {
	const char *r2_cmd;
	const char *rz_asm_cmd;
	const char *json_test_file;
	ut64 timeout_ms;
} R2RRunConfig;

typedef struct rz_test_process_output_t {
	char *out; // stdout
	char *err; // stderr
	int ret; // exit code of the process
	bool timeout;
} R2RProcessOutput;

typedef struct rz_test_asm_test_output_t {
	char *disasm;
	ut8 *bytes;
	size_t bytes_size;
	bool as_timeout;
	bool disas_timeout;
} R2RzAsmTestOutput;

typedef enum rz_test_test_result_t {
	R2R_TEST_RESULT_OK,
	R2R_TEST_RESULT_FAILED,
	R2R_TEST_RESULT_BROKEN,
	R2R_TEST_RESULT_FIXED
} R2RTestResult;

typedef struct rz_test_test_result_info_t {
	R2RTest *test;
	R2RTestResult result;
	bool timeout;
	bool run_failed; // something went seriously wrong (e.g. r2 not found)
	union {
		R2RProcessOutput *proc_out; // for test->type == R2R_TEST_TYPE_CMD, R2R_TEST_TYPE_JSON or R2R_TEST_TYPE_FUZZ
		R2RzAsmTestOutput *asm_out;  // for test->type == R2R_TEST_TYPE_ASM
	};
} R2RTestResultInfo;

RZ_API R2RzCmdTest *rz_test_cmd_test_new(void);
RZ_API void rz_test_cmd_test_free(R2RzCmdTest *test);
RZ_API RPVector *rz_test_load_cmd_test_file(const char *file);

RZ_API R2RzAsmTest *rz_test_asm_test_new(void);
RZ_API void rz_test_asm_test_free(R2RzAsmTest *test);
RZ_API RPVector *rz_test_load_asm_test_file(RStrConstPool *strpool, const char *file);

RZ_API R2RJsonTest *rz_test_json_test_new(void);
RZ_API void rz_test_json_test_free(R2RJsonTest *test);
RZ_API RPVector *rz_test_load_json_test_file(const char *file);

RZ_API R2RTestDatabase *rz_test_test_database_new(void);
RZ_API void rz_test_test_database_free(R2RTestDatabase *db);
RZ_API bool rz_test_test_database_load(R2RTestDatabase *db, const char *path);
RZ_API bool rz_test_test_database_load_fuzz(R2RTestDatabase *db, const char *path);

typedef struct rz_test_subprocess_t R2RSubprocess;

RZ_API bool rz_test_subprocess_init(void);
RZ_API void rz_test_subprocess_fini(void);
RZ_API R2RSubprocess *rz_test_subprocess_start(
		const char *file, const char *args[], size_t args_size,
		const char *envvars[], const char *envvals[], size_t env_size);
RZ_API bool rz_test_subprocess_wait(R2RSubprocess *proc, ut64 timeout_ms);
RZ_API void rz_test_subprocess_free(R2RSubprocess *proc);

typedef R2RProcessOutput *(*R2RzCmdRunner)(const char *file, const char *args[], size_t args_size,
	const char *envvars[], const char *envvals[], size_t env_size, ut64 timeout_ms, void *user);

RZ_API void rz_test_process_output_free(R2RProcessOutput *out);
RZ_API R2RProcessOutput *rz_test_run_cmd_test(R2RRunConfig *config, R2RzCmdTest *test, R2RzCmdRunner runner, void *user);
RZ_API bool rz_test_check_cmd_test(R2RProcessOutput *out, R2RzCmdTest *test);
RZ_API bool rz_test_check_jq_available(void);
RZ_API R2RProcessOutput *rz_test_run_json_test(R2RRunConfig *config, R2RJsonTest *test, R2RzCmdRunner runner, void *user);
RZ_API bool rz_test_check_json_test(R2RProcessOutput *out, R2RJsonTest *test);
RZ_API R2RzAsmTestOutput *rz_test_run_asm_test(R2RRunConfig *config, R2RzAsmTest *test);
RZ_API bool rz_test_check_asm_test(R2RzAsmTestOutput *out, R2RzAsmTest *test);
RZ_API void rz_test_asm_test_output_free(R2RzAsmTestOutput *out);
RZ_API R2RProcessOutput *rz_test_run_fuzz_test(R2RRunConfig *config, R2RFuzzTest *test, R2RzCmdRunner runner, void *user);
RZ_API bool rz_test_check_fuzz_test(R2RProcessOutput *out);

RZ_API void rz_test_test_free(R2RTest *test);
RZ_API char *rz_test_test_name(R2RTest *test);
RZ_API bool rz_test_test_broken(R2RTest *test);
RZ_API R2RTestResultInfo *rz_test_run_test(R2RRunConfig *config, R2RTest *test);
RZ_API void rz_test_test_result_info_free(R2RTestResultInfo *result);

#endif //RADARE2_R2R_H
