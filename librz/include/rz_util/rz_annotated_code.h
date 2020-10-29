
#ifndef RZ_ANNOTATEDCODE_H
#define RZ_ANNOTATEDCODE_H

// #include <rz_core.h>
#include <rz_types.h>
#include <rz_vector.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum rz_syntax_highlight_type_t {
	RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD,
	RZ_SYNTAX_HIGHLIGHT_TYPE_COMMENT,
	RZ_SYNTAX_HIGHLIGHT_TYPE_DATATYPE,
	RZ_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME,
	RZ_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_PARAMETER,
	RZ_SYNTAX_HIGHLIGHT_TYPE_LOCAL_VARIABLE,
	RZ_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE,
	RZ_SYNTAX_HIGHLIGHT_TYPE_GLOBAL_VARIABLE,
} RSyntaxHighlightType;

/** Represents the type of annnotation. */
typedef enum rz_code_annotation_type_t {
	RZ_CODE_ANNOTATION_TYPE_OFFSET, /*!< Gives the offset of the specified range in annotation. */
	RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT, /*!< Represents the kind of data the specified range represents for highlighting purposes. */
	RZ_CODE_ANNOTATION_TYPE_FUNCTION_NAME, /*!< Specified range in annotation represents a function name. */
	RZ_CODE_ANNOTATION_TYPE_GLOBAL_VARIABLE, /*!< Specified range in annotation represents a global variable. */
	RZ_CODE_ANNOTATION_TYPE_CONSTANT_VARIABLE, /*!< Specified range in annotation represents a constant variable with an address. */
	RZ_CODE_ANNOTATION_TYPE_LOCAL_VARIABLE, /*!< Specified range in annotation represents a local variable. */
	RZ_CODE_ANNOTATION_TYPE_FUNCTION_PARAMETER, /*!< Specified range in annotation represents a function parameter. */
	// ...
} RzCodeAnnotationType;

/**
 * \brief Annotations for the decompiled code are represented using this structure.
 */
typedef struct rz_code_annotation_t {
	size_t start; /**< Start of the range in the annotation(inclusive). */
	size_t end; /**< End of the range in the annotation(exclusive). */
	RzCodeAnnotationType type;
	union {
		/** If the annotation is of type RZ_CODE_ANNOTATION_TYPE_OFFSET,
		 * offset should be stored in the struct named offset in this union.
		 */
		struct {
			ut64 offset;
		} offset;
		/** If the annotation is of type RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT,
		 * type of the syntax highlight will be stored in the struct named syntax_highlight
		 * in this union.
		 */
		struct {
			RSyntaxHighlightType type;
		} syntax_highlight;

		/** Information in annotations of type RZ_CODE_ANNOTATION_TYPE_FUNCTION_NAME,
		 * RZ_CODE_ANNOTATION_TYPE_GLOBAL_VARIABLE, and RZ_CODE_ANNOTATION_TYPE_CONSTANT_VARIABLE
		 * will be stored in the struct named reference in this union.
		 */
		struct {
			char *name;
			ut64 offset;
		} reference;

		/** Information in annotations of type RZ_CODE_ANNOTATION_TYPE_LOCAL_VARIABLE
		 * and RZ_CODE_ANNOTATION_TYPE_FUNCTION_PARAMETER will be stored in the 
		 * struct named variable in this union.
		 */
		struct {
			char *name;
		} variable;
	};
} RzCodeAnnotation;
/**
 * \brief This structure contains the decompiled code and all the annotations for the decompiled code.
 */
typedef struct rz_annotated_code_t {
	char *code; /**< Decompiled code. RzAnnotatedCode owns this string and it must free it. */
	RzVector annotations; /**< @ref RzVector <RzCodeAnnotation> contains the list of annotations for the decompiled code. */
} RzAnnotatedCode;

/**
 * @brief Create and initialize a RzAnnotatedCode structure and returns its pointer.
 * 
 * This function creates and initializes a new RzAnnotatedCode
 * structure with the specified decompiled code that's passed
 * as an argument. Here, the argument code must be a string that can be deallocated.
 * This will initialize @ref RzVector <RzCodeAnnotation> annotations as well.
 * 
 * @param code A deallocatable character array.
 * @return Pointer to the new RzAnnotatedCode structure created.
 */
RZ_API RzAnnotatedCode *rz_annotated_code_new(char *code);
/**
 * @brief Deallocates the dynamically allocated memory for the specified RzAnnotatedCode.
 * 
 * @param code Pointer to a RzAnnotatedCode.
 */
RZ_API void rz_annotated_code_free(RzAnnotatedCode *code);
/**
 * @brief Deallocates dynamically allocated memory for the specified annotation.
 * 
 * This function recognizes the type of the specified annotation and
 * frees memory that is dynamically allocated for it.
 * 
 * @param e Pointer to the annotation.
 * @param user Always NULL for this function. Present here for this function to be of the type @ref RzVectorFree.
 */
RZ_API void rz_annotation_free(void *e, void *user);
/**
 * @brief Checks if the specified annotation is a reference.
 * 
 * This function recognizes the type of the specified annotation and returns true if its
 * type is any of the following three: RZ_CODE_ANNOTATION_TYPE_GLOBAL_VARIABLE,
 * RZ_CODE_ANNOTATION_TYPE_CONSTANT_VARIABLE, RZ_CODE_ANNOTATION_TYPE_FUNCTION_NAME
 * 
 * @param annotation Pointer to an annotation.
 * @return Returns true if the specified annotation is a reference.
 */
RZ_API bool rz_annotation_is_reference(RzCodeAnnotation *annotation);
/**
 * @brief Checks if the specified annotation is a function variable.
 * 
 * This function recognizes the type of the specified annotation and returns true if its
 * type is any of the following two: RZ_CODE_ANNOTATION_TYPE_LOCAL_VARIABLE,
 * RZ_CODE_ANNOTATION_TYPE_FUNCTION_PARAMETER
 * 
 * @param annotation Pointer to an annotation.
 * @return Returns true if the specified annotation is a function variable.
 */
RZ_API bool rz_annotation_is_variable(RzCodeAnnotation *annotation);
/**
 * @brief Inserts the specified annotation into the list of annotations in the specified RzAnnotatedCode.
 * 
 * @param code Pointer to a RzAnnotatedCode.
 * @param annotation Pointer to an annotation.
 */
RZ_API void rz_annotated_code_add_annotation(RzAnnotatedCode *code, RzCodeAnnotation *annotation);
/**
 * @brief Returns all annotations with range that contains the given offset.
 * 
 * Creates a @ref RzPVector <RzCodeAnnotation> and inserts the pointers to all annotations in which 
 * annotation->start <= offset < annotation->end.
 * 
 * @param code Pointer to a RzAnnotatedCode.
 * @param offset Offset.
 * @return Pointer to the @ref RzPVector created.
 */
RZ_API RzPVector *rz_annotated_code_annotations_in(RzAnnotatedCode *code, size_t offset);
/**
 * @brief Returns all annotations with range that overlap with the specified range.
 * 
 * Creates an @ref RzPVector <RzCodeAnnotation> and inserts the pointers to all annotations whose 
 * range overlap with range specified.
 * 
 * @param code Pointer to a RzAnnotatedCode.
 * @param start Start of the range(inclusive).
 * @param end End of the range(exclusive).
 * @return Pointer to the @ref RzPVector created.
 */
RZ_API RzPVector *rz_annotated_code_annotations_range(RzAnnotatedCode *code, size_t start, size_t end);
/**
 * @brief Returns the offset for every line of decompiled code in the specified RzAnnotatedCode.
 * 
 * Creates an @ref RzVector <ut64> and inserts the offsets for every seperate line of decompiled code in
 * the specified RzAnnotatedCode.
 * If a line of decompiled code doesn't have a unique offset, UT64_MAX is inserted as its offset.
 * 
 * @param code Pointer to a RzAnnotatedCode.
 * @return Pointer to the @ref RzVector created.
 */
RZ_API RzVector *rz_annotated_code_line_offsets(RzAnnotatedCode *code);

#ifdef __cplusplus
}
#endif

#endif //RZ_ANNOTATEDCODE_H
