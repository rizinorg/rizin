// SPDX-FileCopyrightText: 2020 NIRMAL MANOJ C <nimmumanoj@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_annotated_code.h>
#include <rz_core.h>
#include <rz_util.h>

RZ_API RzAnnotatedCode *rz_annotated_code_new(char *code) {
	RzAnnotatedCode *r = RZ_NEW0(RzAnnotatedCode);
	if (!r) {
		return NULL;
	}
	r->code = code;
	rz_vector_init(&r->annotations, sizeof(RzCodeAnnotation), rz_annotation_free, NULL);
	return r;
}

RZ_API void rz_annotation_free(void *e, void *user) {
	(void)user;
	RzCodeAnnotation *annotation = e;
	if (annotation->type == RZ_CODE_ANNOTATION_TYPE_FUNCTION_NAME) {
		free(annotation->reference.name);
	} else if (annotation->type == RZ_CODE_ANNOTATION_TYPE_LOCAL_VARIABLE || annotation->type == RZ_CODE_ANNOTATION_TYPE_FUNCTION_PARAMETER) {
		free(annotation->variable.name);
	}
}

RZ_API bool rz_annotation_is_reference(RzCodeAnnotation *annotation) {
	return (annotation->type == RZ_CODE_ANNOTATION_TYPE_GLOBAL_VARIABLE || annotation->type == RZ_CODE_ANNOTATION_TYPE_CONSTANT_VARIABLE || annotation->type == RZ_CODE_ANNOTATION_TYPE_FUNCTION_NAME);
}

RZ_API bool rz_annotation_is_variable(RzCodeAnnotation *annotation) {
	return (annotation->type == RZ_CODE_ANNOTATION_TYPE_LOCAL_VARIABLE || annotation->type == RZ_CODE_ANNOTATION_TYPE_FUNCTION_PARAMETER);
}

RZ_API void rz_annotated_code_free(RzAnnotatedCode *code) {
	if (!code) {
		return;
	}
	rz_vector_clear(&code->annotations);
	free(code->code);
	free(code);
}

RZ_API void rz_annotated_code_add_annotation(RzAnnotatedCode *code, RzCodeAnnotation *annotation) {
	rz_vector_push(&code->annotations, annotation);
}

RZ_API RzPVector /*<RzCodeAnnotation *>*/ *rz_annotated_code_annotations_in(RzAnnotatedCode *code, size_t offset) {
	RzPVector *r = rz_pvector_new(NULL);
	if (!r) {
		return NULL;
	}
	RzCodeAnnotation *annotation;
	rz_vector_foreach (&code->annotations, annotation) {
		if (offset >= annotation->start && offset < annotation->end) {
			rz_pvector_push(r, annotation);
		}
	}
	return r;
}

RZ_API RzPVector /*<RzCodeAnnotation *>*/ *rz_annotated_code_annotations_range(RzAnnotatedCode *code, size_t start, size_t end) {
	RzPVector *r = rz_pvector_new(NULL);
	if (!r) {
		return NULL;
	}
	RzCodeAnnotation *annotation;
	rz_vector_foreach (&code->annotations, annotation) {
		if (start >= annotation->end || end < annotation->start) {
			continue;
		}
		rz_pvector_push(r, annotation);
	}
	return r;
}

RZ_API RzVector /*<ut64>*/ *rz_annotated_code_line_offsets(RzAnnotatedCode *code) {
	RzVector *r = rz_vector_new(sizeof(ut64), NULL, NULL);
	if (!r) {
		return NULL;
	}
	size_t cur = 0;
	size_t len = strlen(code->code);
	do {
		char *next = strchr(code->code + cur, '\n');
		size_t next_i = next ? (next - code->code) + 1 : len;
		RzPVector *annotations = rz_annotated_code_annotations_range(code, cur, next_i);
		ut64 offset = UT64_MAX;
		void **it;
		rz_pvector_foreach (annotations, it) {
			RzCodeAnnotation *annotation = *it;
			if (annotation->type != RZ_CODE_ANNOTATION_TYPE_OFFSET) {
				continue;
			}
			offset = annotation->offset.offset;
			break;
		}
		rz_vector_push(r, &offset);
		cur = next_i;
		rz_pvector_free(annotations);
	} while (cur < len);
	return r;
}
