// SPDX-FileCopyrightText: 2020 NIRMAL MANOJ C <nimmumanoj@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_vector.h>
#include <rz_core.h>
#include <rz_cons.h>
#include <rz_util/rz_annotated_code.h>

#include "minunit.h"

static RzCodeAnnotation make_code_annotation(int st, int en, RzCodeAnnotationType typec,
	ut64 offset, RSyntaxHighlightType types) {
	RzCodeAnnotation annotation = { 0 };
	annotation.start = st;
	annotation.end = en;
	annotation.type = typec;
	if (annotation.type == RZ_CODE_ANNOTATION_TYPE_OFFSET) {
		annotation.offset.offset = offset;
	}
	if (annotation.type == RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT) {
		annotation.syntax_highlight.type = types;
	}
	return annotation;
}

static RzCodeAnnotation make_variable_annotation(int st, int en, RzCodeAnnotationType typec,
	const char *name) {
	RzCodeAnnotation annotation = { 0 };
	annotation.start = st;
	annotation.end = en;
	annotation.type = typec;
	annotation.variable.name = strdup(name);
	return annotation;
}

static RzCodeAnnotation make_reference_annotation(int st, int en, RzCodeAnnotationType typec,
	ut64 offset, const char *name) {
	RzCodeAnnotation annotation = { 0 };
	annotation.start = st;
	annotation.end = en;
	annotation.type = typec;
	annotation.reference.offset = offset;
	if (annotation.type == RZ_CODE_ANNOTATION_TYPE_FUNCTION_NAME) {
		annotation.reference.name = strdup(name);
	} else {
		annotation.reference.name = NULL;
	}
	return annotation;
}

static RzVector *get_some_code_annotation_for_add(void) {
	RzVector *test_annotations = rz_vector_new(sizeof(RzCodeAnnotation), NULL, NULL);
	RzCodeAnnotation annotation;
	rz_vector_init(test_annotations, sizeof(RzCodeAnnotation), NULL, NULL);
	annotation = make_code_annotation(1, 2, RZ_CODE_ANNOTATION_TYPE_OFFSET, 123, RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	rz_vector_push(test_annotations, &annotation);
	annotation = make_code_annotation(1, 5, RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT, 123, RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	rz_vector_push(test_annotations, &annotation);
	return test_annotations;
}

static RzVector *get_some_annotations_for_in(void) {
	RzVector *test_annotations = rz_vector_new(sizeof(RzCodeAnnotation), NULL, NULL);
	RzCodeAnnotation annotation;
	annotation = make_code_annotation(1, 2, RZ_CODE_ANNOTATION_TYPE_OFFSET, 123, RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	rz_vector_push(test_annotations, &annotation);
	annotation = make_code_annotation(1, 7, RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT, 123, RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	rz_vector_push(test_annotations, &annotation);
	annotation = make_code_annotation(9, 11, RZ_CODE_ANNOTATION_TYPE_OFFSET, 123, RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	rz_vector_push(test_annotations, &annotation);

	// For offset = 11, indices expected = 3, 4, 5
	annotation = make_code_annotation(7, 13, RZ_CODE_ANNOTATION_TYPE_OFFSET, 123, RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	rz_vector_push(test_annotations, &annotation);
	annotation = make_code_annotation(11, 15, RZ_CODE_ANNOTATION_TYPE_OFFSET, 123, RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	rz_vector_push(test_annotations, &annotation);
	annotation = make_code_annotation(10, 16, RZ_CODE_ANNOTATION_TYPE_OFFSET, 123, RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	rz_vector_push(test_annotations, &annotation);
	annotation = make_code_annotation(17, 20, RZ_CODE_ANNOTATION_TYPE_OFFSET, 32, RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	rz_vector_push(test_annotations, &annotation);

	return test_annotations;
}

static RzVector *get_annotations_for_hello_world(void) {
	RzVector *test_annotations = rz_vector_new(sizeof(RzCodeAnnotation), NULL, NULL);
	RzCodeAnnotation annotation;
	// rz_vector_init (&test_annotations, sizeof (RzCodeAnnotation), NULL, NULL);
	// Code Annotations for a hello world program
	annotation = make_code_annotation(1, 5, RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT, 123, RZ_SYNTAX_HIGHLIGHT_TYPE_DATATYPE);
	rz_vector_push(test_annotations, &annotation); // 1
	annotation = make_code_annotation(6, 10, RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT, 123, RZ_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME);
	rz_vector_push(test_annotations, &annotation); // 2
	annotation = make_code_annotation(11, 15, RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT, 123, RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	rz_vector_push(test_annotations, &annotation); // 3
	annotation = make_code_annotation(23, 35, RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT, 123, RZ_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME);
	rz_vector_push(test_annotations, &annotation); // 4
	annotation = make_code_annotation(36, 51, RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT, 123, RZ_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE);
	rz_vector_push(test_annotations, &annotation); // 5
	annotation = make_code_annotation(23, 52, RZ_CODE_ANNOTATION_TYPE_OFFSET, 4440, RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	rz_vector_push(test_annotations, &annotation); // 6
	annotation = make_code_annotation(58, 64, RZ_CODE_ANNOTATION_TYPE_OFFSET, 4447, RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	rz_vector_push(test_annotations, &annotation); // 7
	annotation = make_code_annotation(58, 64, RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT, 123, RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	rz_vector_push(test_annotations, &annotation); // 8
	annotation = make_code_annotation(58, 64, RZ_CODE_ANNOTATION_TYPE_OFFSET, 4447, RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	rz_vector_push(test_annotations, &annotation); // 9

	return test_annotations;
}

static RzAnnotatedCode *get_hello_world(void) {
	char *test_string = strdup("\nvoid main(void)\n{\n    sym.imp.puts(\"Hello, World!\");\n    return;\n}\n");
	RzAnnotatedCode *code = rz_annotated_code_new(test_string);

	RzVector /*<RzCodeAnnotation>*/ *test_annotations;
	test_annotations = get_annotations_for_hello_world();
	RzCodeAnnotation *annotation;
	rz_vector_foreach (test_annotations, annotation) {
		rz_annotated_code_add_annotation(code, annotation);
	}

	rz_vector_free(test_annotations);
	return code;
}

static RzAnnotatedCode *get_all_context_annotated_code(void) {
	char *test_string = strdup("\nfunc-name\nconst-var\n   global-var(\"Hello, local-var\");\n    function-param\n}\n");
	RzAnnotatedCode *code = rz_annotated_code_new(test_string);
	RzCodeAnnotation function_name = make_reference_annotation(1, 10, RZ_CODE_ANNOTATION_TYPE_FUNCTION_NAME, 1234, "func-name");
	RzCodeAnnotation constant_variable = make_reference_annotation(10, 19, RZ_CODE_ANNOTATION_TYPE_CONSTANT_VARIABLE, 12345, NULL);
	RzCodeAnnotation global_variable = make_reference_annotation(23, 33, RZ_CODE_ANNOTATION_TYPE_GLOBAL_VARIABLE, 123456, NULL);
	RzCodeAnnotation local_variable = make_variable_annotation(42, 51, RZ_CODE_ANNOTATION_TYPE_LOCAL_VARIABLE, "local-var");
	RzCodeAnnotation function_parameter = make_variable_annotation(59, 73, RZ_CODE_ANNOTATION_TYPE_FUNCTION_PARAMETER, "function-param");
	rz_annotated_code_add_annotation(code, &function_name);
	rz_annotated_code_add_annotation(code, &constant_variable);
	rz_annotated_code_add_annotation(code, &global_variable);
	rz_annotated_code_add_annotation(code, &local_variable);
	rz_annotated_code_add_annotation(code, &function_parameter);
	return code;
}

static bool test_rz_annotated_code_new(void) {
	// Testing RAnnoatedCode->code
	char *test_string = strdup("How are you?");
	RzAnnotatedCode *code = rz_annotated_code_new(test_string);
	mu_assert_streq(code->code, test_string, "Code in RzAnnotatedCode is not set as expected");

	// Testing RAnnoatedCode->annotations
	mu_assert_eq(code->annotations.elem_size, sizeof(RzCodeAnnotation), "Code Annotations are initialized is not properly");

	rz_annotated_code_free(code);
	mu_end;
}

static bool test_rz_annotated_code_free(void) {
	char *test_string = strdup("How are you?");
	RzAnnotatedCode *code = rz_annotated_code_new(test_string);

	RzCodeAnnotation test_annotation1, test_annotation2;
	test_annotation1 = make_code_annotation(1, 2, RZ_CODE_ANNOTATION_TYPE_OFFSET, 123, RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	rz_vector_push(&code->annotations, &test_annotation1);
	test_annotation2 = make_code_annotation(1, 5, RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT, 123, RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	rz_vector_push(&code->annotations, &test_annotation2);

	// This test is only for run errors

	rz_annotated_code_free(code);
	mu_end;
}

static bool test_equal(RzCodeAnnotation *first, RzCodeAnnotation *second) { // First - Got, Second - Expected
	mu_assert_eq(first->start, second->start, "start of annotations doesn't match");
	mu_assert_eq(first->end, second->end, "end of annotations doesn't match");
	mu_assert_eq(first->type, second->type, "type of annotation doesn't match");
	if (first->type == RZ_CODE_ANNOTATION_TYPE_OFFSET) {
		mu_assert_eq(first->offset.offset, second->offset.offset, "offset of annotations doesn't match");
		return true;
	}
	if (first->type == RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT) {
		mu_assert_eq(first->syntax_highlight.type, second->syntax_highlight.type, "syntax highlight type of offset doesn't match");
		return true;
	}
	return false;
}

static bool test_rz_annotated_code_add_annotation(void) {
	char *test_string = strdup("abcdefghijklmnopqrtstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	RzAnnotatedCode *code = rz_annotated_code_new(test_string);
	RzVector /*<RzCodeAnnotation>*/ *test_annotations;
	test_annotations = get_some_code_annotation_for_add();
	RzCodeAnnotation *annotation;
	rz_vector_foreach (test_annotations, annotation) {
		rz_annotated_code_add_annotation(code, annotation);
	}

	// Comparing
	if (!test_equal(rz_vector_index_ptr(&code->annotations, 0), rz_vector_index_ptr(test_annotations, 0))) {
		return false;
	}
	if (!test_equal(rz_vector_index_ptr(&code->annotations, 1), rz_vector_index_ptr(test_annotations, 1))) {
		return false;
	}

	rz_vector_free(test_annotations);
	rz_annotated_code_free(code);
	mu_end;
}

static bool test_rz_annotated_code_annotations_in(void) {
	char *test_string = strdup("abcdefghijklmnopqrtstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	RzAnnotatedCode *code = rz_annotated_code_new(test_string);
	RzVector /*<RzCodeAnnotation>*/ *test_annotations;
	test_annotations = get_some_annotations_for_in();

	RzCodeAnnotation *annotation;
	rz_vector_foreach (test_annotations, annotation) {
		rz_annotated_code_add_annotation(code, annotation);
	}

	RzPVector *out = rz_annotated_code_annotations_in(code, 11);
	// Expecting indices = 3, 4, 5
	mu_assert_eq(out->v.len, 3, "Additional annotations found. Bad output.");
	if (!test_equal(rz_pvector_at(out, 0), rz_vector_index_ptr(test_annotations, 3))) {
		return false;
	}
	if (!test_equal(rz_pvector_at(out, 1), rz_vector_index_ptr(test_annotations, 4))) {
		return false;
	}
	if (!test_equal(rz_pvector_at(out, 2), rz_vector_index_ptr(test_annotations, 5))) {
		return false;
	}

	rz_vector_free(test_annotations);
	rz_pvector_free(out);
	rz_annotated_code_free(code);
	mu_end;
}

static bool test_rz_annotated_code_annotations_range(void) {
	char *test_string = strdup("abcdefghijklmnopqrtstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	RzAnnotatedCode *code = rz_annotated_code_new(test_string);
	RzVector /*<RzCodeAnnotation>*/ *test_annotations;
	test_annotations = get_some_annotations_for_in();
	RzCodeAnnotation *annotation;
	rz_vector_foreach (test_annotations, annotation) {
		rz_annotated_code_add_annotation(code, annotation);
	}

	RzPVector *out = rz_annotated_code_annotations_range(code, 7, 16);
	// Expecting indices = 2, 3, 4, 5
	mu_assert_eq(out->v.len, 4, "Additional annotations found. Bad output.");
	if (!test_equal(rz_pvector_at(out, 0), rz_vector_index_ptr(test_annotations, 2))) {
		return false;
	}
	if (!test_equal(rz_pvector_at(out, 1), rz_vector_index_ptr(test_annotations, 3))) {
		return false;
	}
	if (!test_equal(rz_pvector_at(out, 2), rz_vector_index_ptr(test_annotations, 4))) {
		return false;
	}
	if (!test_equal(rz_pvector_at(out, 3), rz_vector_index_ptr(test_annotations, 5))) {
		return false;
	}

	rz_vector_free(test_annotations);
	rz_pvector_free(out);
	rz_annotated_code_free(code);
	mu_end;
}

static bool test_rz_annotated_code_line_offsets(void) {

	RzAnnotatedCode *code = get_hello_world();
	RzVector *offsets = rz_annotated_code_line_offsets(code);
	mu_assert_eq(offsets->len, 6, "Number of offsets not expected");

	ut64 *off = rz_vector_index_ptr(offsets, 0);
	mu_assert_eq_fmt(*off, UT64_MAX, "Unexpected offset", "%llu");
	off = rz_vector_index_ptr(offsets, 1);
	mu_assert_eq_fmt(*off, UT64_MAX, "Unexpected offset", "%llu");
	off = rz_vector_index_ptr(offsets, 2);
	mu_assert_eq_fmt(*off, UT64_MAX, "Unexpected offset", "%llu");
	off = rz_vector_index_ptr(offsets, 3);
	mu_assert_eq_fmt(*off, (ut64)4440, "Unexpected offset", "%llu");
	off = rz_vector_index_ptr(offsets, 4);
	mu_assert_eq_fmt(*off, (ut64)4447, "Unexpected offset", "%llu");
	off = rz_vector_index_ptr(offsets, 5);
	mu_assert_eq_fmt(*off, UT64_MAX, "Unexpected offset", "%llu");

	rz_vector_free(offsets);
	rz_annotated_code_free(code);
	mu_end;
}

static bool test_rz_core_annotated_code_print_json(void) {
	RzAnnotatedCode *code = get_hello_world();
	char *actual;
	char *expected = "{\"code\":\"\\nvoid main(void)\\n{\\n    sym.imp.puts(\\\"Hello, World!\\\");\\n    return;\\n}\\n\",\"annotations\":[{\"start\":1,\"end\":5,\"type\":\"syntax_highlight\",\"syntax_highlight\":\"datatype\"},{\"start\":6,\"end\":10,\"type\":\"syntax_highlight\",\"syntax_highlight\":\"function_name\"},{\"start\":11,\"end\":15,\"type\":\"syntax_highlight\",\"syntax_highlight\":\"keyword\"},{\"start\":23,\"end\":35,\"type\":\"syntax_highlight\",\"syntax_highlight\":\"function_name\"},{\"start\":36,\"end\":51,\"type\":\"syntax_highlight\",\"syntax_highlight\":\"constant_variable\"},{\"start\":23,\"end\":52,\"type\":\"offset\",\"offset\":4440},{\"start\":58,\"end\":64,\"type\":\"offset\",\"offset\":4447},{\"start\":58,\"end\":64,\"type\":\"syntax_highlight\",\"syntax_highlight\":\"keyword\"},{\"start\":58,\"end\":64,\"type\":\"offset\",\"offset\":4447}]}\n";
	rz_cons_new();
	rz_cons_push();
	rz_core_annotated_code_print_json(code);
	actual = rz_cons_get_buffer_dup();
	rz_cons_pop();
	mu_assert_streq(actual, expected, "pdgj OUTPUT DOES NOT MATCH");

	rz_cons_free();
	free(actual);
	rz_annotated_code_free(code);
	mu_end;
}

/**
 * @brief Tests JSON output for all context related annotations
 */
static bool test_rz_core_annotated_code_print_json_context_annotations(void) {
	RzAnnotatedCode *code = get_all_context_annotated_code();
	char *expected = "{\"code\":\"\\nfunc-name\\nconst-var\\n   global-var(\\\"Hello, local-var\\\");\\n    function-param\\n}\\n\",\"annotations\":[{\"start\":1,\"end\":10,\"type\":\"function_name\",\"name\":\"func-name\",\"offset\":1234},{\"start\":10,\"end\":19,\"type\":\"constant_variable\",\"offset\":12345},{\"start\":23,\"end\":33,\"type\":\"global_variable\",\"offset\":123456},{\"start\":42,\"end\":51,\"type\":\"local_variable\",\"name\":\"local-var\"},{\"start\":59,\"end\":73,\"type\":\"function_parameter\",\"name\":\"function-param\"}]}\n";
	rz_cons_new();
	rz_cons_push();
	rz_core_annotated_code_print_json(code);
	char *actual = rz_cons_get_buffer_dup();
	rz_cons_pop();
	mu_assert_streq(actual, expected, "rz_core_annotated_code_print_json() output doesn't match with the expected output");
	free(actual);
	rz_annotated_code_free(code);
	mu_end;
}

static bool test_rz_core_annotated_code_print(void) {
	RzAnnotatedCode *code = get_hello_world();
	char *actual;
	// Checking without line offset
	char *expected_first = "\n"
			       "void main(void)\n"
			       "{\n"
			       "    sym.imp.puts(\"Hello, World!\");\n"
			       "    return;\n"
			       "}\n";
	rz_cons_new();
	rz_cons_push();
	rz_core_annotated_code_print(code, NULL);
	actual = rz_cons_get_buffer_dup();
	rz_cons_pop();
	mu_assert_streq(actual, expected_first, "pdg OUTPUT DOES NOT MATCH");
	rz_cons_pop();

	// Checking with offset - pdgo
	RzVector *offsets = rz_annotated_code_line_offsets(code);
	char *expected_second = "                  |\n"
				"                  |void main(void)\n"
				"                  |{\n"
				"    0x00001158    |    sym.imp.puts(\"Hello, World!\");\n"
				"    0x0000115f    |    return;\n"
				"                  |}\n";
	rz_core_annotated_code_print(code, offsets);
	free(actual);
	actual = rz_cons_get_buffer_dup();
	rz_cons_pop();
	mu_assert_streq(actual, expected_second, "pdgo OUTPUT DOES NOT MATCH");
	rz_cons_pop();

	rz_cons_free();
	free(actual);
	rz_vector_free(offsets);
	rz_annotated_code_free(code);
	mu_end;
}

static bool test_rz_core_annotated_code_print_comment_cmds(void) {
	RzAnnotatedCode *code = get_hello_world();
	char *actual;
	char *expected = "CCu base64:c3ltLmltcC5wdXRzKCJIZWxsbywgV29ybGQhIik= @ 0x1158\n"
			 "CCu base64:cmV0dXJu @ 0x115f\n";
	rz_cons_new();
	rz_cons_push();
	rz_core_annotated_code_print_comment_cmds(code);
	actual = rz_cons_get_buffer_dup();
	rz_cons_pop();
	mu_assert_streq(actual, expected, "pdg* OUTPUT DOES NOT MATCH");

	rz_cons_free();
	free(actual);
	rz_annotated_code_free(code);
	mu_end;
}

/**
 * @brief Tests functions rz_annotation_is_variable(), rz_annotation_is_reference(), and rz_annotation_free()
 */
static bool test_rz_annotation_free_and_is_annotation_type_functions(void) {
	// Making all types of annotations
	RzCodeAnnotation offset = make_code_annotation(58, 64, RZ_CODE_ANNOTATION_TYPE_OFFSET, 4447, RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	RzCodeAnnotation syntax_highlight = make_code_annotation(1, 5, RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT, 123, RZ_SYNTAX_HIGHLIGHT_TYPE_DATATYPE);
	RzCodeAnnotation local_variable = make_variable_annotation(1, 2, RZ_CODE_ANNOTATION_TYPE_LOCAL_VARIABLE, "RIZIN");
	RzCodeAnnotation function_parameter = make_variable_annotation(4, 10, RZ_CODE_ANNOTATION_TYPE_LOCAL_VARIABLE, "Cutter");
	RzCodeAnnotation function_name = make_reference_annotation(10, 12, RZ_CODE_ANNOTATION_TYPE_FUNCTION_NAME, 123513, "test_function");
	RzCodeAnnotation global_variable = make_reference_annotation(10, 12, RZ_CODE_ANNOTATION_TYPE_GLOBAL_VARIABLE, 1234234, NULL);
	RzCodeAnnotation constant_variable = make_reference_annotation(21, 200, RZ_CODE_ANNOTATION_TYPE_CONSTANT_VARIABLE, 12342314, NULL);
	// Test rz_annotation_is_variable()
	char *error_message = "rz_annotation_is_variable() result doesn't match with the expected output";
	mu_assert_true(rz_annotation_is_variable(&local_variable), error_message);
	mu_assert_true(rz_annotation_is_variable(&function_parameter), error_message);
	mu_assert_false(rz_annotation_is_variable(&function_name), error_message);
	mu_assert_false(rz_annotation_is_variable(&global_variable), error_message);
	mu_assert_false(rz_annotation_is_variable(&constant_variable), error_message);
	mu_assert_false(rz_annotation_is_variable(&offset), error_message);
	mu_assert_false(rz_annotation_is_variable(&syntax_highlight), error_message);
	// Test rz_annotation_is_reference()
	error_message = "rz_annotation_is_reference() result doesn't match with the expected output";
	mu_assert_true(rz_annotation_is_reference(&function_name), error_message);
	mu_assert_true(rz_annotation_is_reference(&global_variable), error_message);
	mu_assert_true(rz_annotation_is_reference(&constant_variable), error_message);
	mu_assert_false(rz_annotation_is_reference(&local_variable), error_message);
	mu_assert_false(rz_annotation_is_reference(&function_parameter), error_message);
	mu_assert_false(rz_annotation_is_reference(&offset), error_message);
	mu_assert_false(rz_annotation_is_reference(&syntax_highlight), error_message);
	// Free dynamically allocated memory for annotations.
	// This is also supposed to be a test of rz_annotation_free() for run errors.
	rz_annotation_free(&local_variable, NULL);
	rz_annotation_free(&function_parameter, NULL);
	rz_annotation_free(&function_name, NULL);
	rz_annotation_free(&global_variable, NULL);
	rz_annotation_free(&constant_variable, NULL);
	mu_end;
}

static int all_tests(void) {
	mu_run_test(test_rz_annotated_code_new);
	mu_run_test(test_rz_annotated_code_free);
	mu_run_test(test_rz_annotated_code_add_annotation);
	mu_run_test(test_rz_annotated_code_annotations_in);
	mu_run_test(test_rz_annotated_code_annotations_range);
	mu_run_test(test_rz_annotated_code_line_offsets);
	mu_run_test(test_rz_core_annotated_code_print_json);
	mu_run_test(test_rz_core_annotated_code_print_json_context_annotations);
	mu_run_test(test_rz_core_annotated_code_print);
	mu_run_test(test_rz_core_annotated_code_print_comment_cmds);
	mu_run_test(test_rz_annotation_free_and_is_annotation_type_functions);
	return tests_passed != tests_run;
}

mu_main(all_tests)
