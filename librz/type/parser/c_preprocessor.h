// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// Internal definitions

typedef struct CString {
	int size; /* size in bytes */
	void *data; /* either 'char *' or 'nwchar_t *' */
	int size_allocated;
	void *data_allocated; /* if non NULL, data has been malloced */
} CString;

/* constant value */
typedef union CValue {
	long double ld;
	double d;
	float f;
	int i;
	unsigned int ui;
	unsigned int ul; /* address (should be unsigned long on 64 bit cpu) */
	long long ll;
	unsigned long long ull;
	struct CString *cstr;
	void *ptr;
	int tab[4];
} CValue;

/* used to record tokens */
typedef struct TokenString {
	int *str;
	int len;
	int allocated_len;
	int last_line_num;
} TokenString;

/* symbol management */
typedef struct Sym {
	int v; /* symbol token */
	int t; /* type of the symbol */
	unsigned int label_flags; /* label flags */
	union {
		long long c; /* associated number */
		int *d; /* define token stream */
	};
	union {
		struct Sym *next; /* next related symbol */
		long jnext; /* next jump label */
	};
	struct Sym *prev; /* prev symbol in stack */
	struct Sym *prev_tok; /* previous symbol for this token */
} Sym;

/* token symbol management */
typedef struct TokenSym {
	struct TokenSym *hash_next;
	struct Sym *sym_define; /* direct pointer to define */
	struct Sym *sym_label; /* direct pointer to label */
	struct Sym *sym_struct; /* direct pointer to structure */
	struct Sym *sym_identifier; /* direct pointer to identifier */
	int tok; /* token number */
	int len;
	char str[1];
} TokenSym;

struct macro_level {
	struct macro_level *prev;
	const int *p;
};

/* include file cache, used to find files faster and also to eliminate
   inclusion if the include file is protected by #ifndef ... #endif */
typedef struct CachedInclude {
	int ifndef_macro;
	int hash_next; /* -1 if none */
	char filename[1]; /* path specified in #include */
} CachedInclude;

#define IO_BUF_SIZE 8192

typedef struct BufferedFile {
	uint8_t *buf_ptr;
	uint8_t *buf_end;
	int fd;
	struct BufferedFile *prev;
	int line_num; /* current line number - here to simplify code */
	int ifndef_macro; /* #ifndef macro / #endif search */
	int ifndef_macro_saved; /* saved ifndef_macro */
	int *ifdef_stack_ptr; /* ifdef_stack value at the start of the file */
	char filename[1024]; /* filename */
	char *dirname; /* file directory */
	unsigned char buffer[IO_BUF_SIZE + 1]; /* extra size for CH_EOB char */
} BufferedFile;

// The C preprocessor state

#define INCLUDE_STACK_SIZE 32
#define IFDEF_STACK_SIZE   64
#define VSTACK_SIZE        1024
#define STRING_MAX_SIZE    1024
#define PACK_STACK_SIZE    8

typedef struct {
	int ch;
	int tok;
	int tok_flags; //<< token flags - EOL, EOF, etc
	int parse_flags; //<< parser flags
	CValue tokc;
	CString tokcstr; //<< current parsed string
} CPreprocessorCursorState;

typedef struct {
	bool gnu_ext; // GNU extensions
	bool tcc_ext; // TinyCC extensions
	size_t ifdef_stack_size; // Depth of the `ifdef` nesting
} CPreprocessorOptions;

typedef struct {
	bool verbose;
	Sym *define_stack;

	// TODO: Simplify to use vectors
	// TODO: Get rid of some unnecessary variables
	Sym *global_label_stack;
	Sym *sym_free_first;

	/* #ifdef stack */
	int ifdef_stack[IFDEF_STACK_SIZE];
	int *ifdef_stack_ptr;
	/* #pragma pack stack */
	int pack_stack[PACK_STACK_SIZE];
	int *pack_stack_ptr;
	/* #include stack */
	BufferedFile *include_stack[INCLUDE_STACK_SIZE];
	BufferedFile **include_stack_ptr;

	RzPVector *include_paths; //<< local include paths
	RzPVector *sysinclude_paths; //<< system include paths

	HtPP *includes; //<< cached includes
	RzStrBuf *errors;
	RzStrBuf *warnings;
	RzStrBuf *debug;
	size_t nb_errors;
	CPreprocessorCursorState *cur;
	CPreprocessorOptions *opts;
} CPreprocessorState;

CPreprocessorState *c_preprocessor_state_new();
void c_preprocessor_state_free(CPreprocessorState *state);
