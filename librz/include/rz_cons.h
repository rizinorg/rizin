#ifndef RZ_CONS_H
#define RZ_CONS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <rz_types.h>
#include <rz_util/rz_graph.h>
#include <rz_util/rz_hex.h>
#include <rz_util/rz_log.h>
#include <rz_util/rz_num.h>
#include <rz_util/rz_panels.h>
#include <rz_util/rz_pj.h>
#include <rz_util/rz_signal.h>
#include <rz_util/rz_stack.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_str_constpool.h>
#include <rz_util/rz_sys.h>
#include <rz_util/rz_utf8.h>
#include <rz_util/rz_file.h>
#include <rz_vector.h>
#include <sdb.h>
#include <rz_util/ht_up.h>
#include <rz_util/ht_pp.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if __UNIX__
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#endif
#if !__WINDOWS__
#include <unistd.h>
#endif

/* constants */
#define CONS_MAX_USER  102400
#define CONS_BUFSZ     0x4f00
#define STR_IS_NULL(x) (!x || !x[0])

/* palette */
#define CONS_PALETTE_SIZE 22
#define CONS_COLORS_SIZE  21

#define RZ_CONS_GREP_WORDS     10
#define RZ_CONS_GREP_WORD_SIZE 64
#define RZ_CONS_GREP_TOKENS    64

RZ_LIB_VERSION_HEADER(rz_cons);

#define RZ_CONS_CMD_DEPTH 100

typedef int (*RzConsGetSize)(int *rows);
typedef int (*RzConsGetCursor)(RZ_NONNULL int *rows);
typedef bool (*RzConsIsBreaked)(void);
typedef void (*RzConsFlush)(void);
typedef void (*RzConsGrepCallback)(const char *grep);

typedef struct rz_cons_bind_t {
	RzConsGetSize get_size;
	RzConsGetCursor get_cursor;
	PrintfCallback cb_printf;
	RzConsIsBreaked is_breaked;
	RzConsFlush cb_flush;
	RzConsGrepCallback cb_grep;
} RzConsBind;

typedef struct rz_cons_grep_t {
	char strings[RZ_CONS_GREP_WORDS][RZ_CONS_GREP_WORD_SIZE];
	int nstrings;
	char *str;
	int counter;
	bool charCounter;
	int less;
	bool hud;
	bool human;
	int json;
	char *json_path;
	int range_line;
	int line;
	int sort;
	int sort_row;
	bool sort_invert;
	int f_line; // first line
	int l_line; // last line
	int tokens[RZ_CONS_GREP_TOKENS];
	int tokens_used;
	int amp;
	int zoom;
	int zoomy; // if set then its scaled unproportionally
	int neg;
	int begin;
	int end;
	int icase;
	int sorted_column;
	RzList /*<char *>*/ *sorted_lines;
	RzList /*<char *>*/ *unsorted_lines;
} RzConsGrep;

#if 0
// TODO Might be better than using rz_cons_pal_get_i
// And have smaller RzConsPrintablePalette and RzConsPalette
enum {
	RZ_CONS_PAL_0x00 = 0,
	RZ_CONS_PAL_0x7f,
	RZ_CONS_PAL_0xff,
	RZ_CONS_PAL_ARGS,
	RZ_CONS_PAL_BIN,
	RZ_CONS_PAL_BTEXT,
	RZ_CONS_PAL_CALL,
	RZ_CONS_PAL_CJMP,
	RZ_CONS_PAL_CMP,
	RZ_CONS_PAL_COMMENT,
	RZ_CONS_PAL_CREG,
	RZ_CONS_PAL_FLAG,
	RZ_CONS_PAL_FLINE,
	RZ_CONS_PAL_FLOC,
	RZ_CONS_PAL_FLOW,
	RZ_CONS_PAL_FLOW2,
	RZ_CONS_PAL_FNAME,
	RZ_CONS_PAL_HELP,
	RZ_CONS_PAL_INPUT,
	RZ_CONS_PAL_INVALID,
	RZ_CONS_PAL_JMP,
	RZ_CONS_PAL_LABEL,
	RZ_CONS_PAL_MATH,
	RZ_CONS_PAL_MOV,
	RZ_CONS_PAL_NOP,
	RZ_CONS_PAL_NUM,
	RZ_CONS_PAL_OFFSET,
	RZ_CONS_PAL_OTHER,
	RZ_CONS_PAL_POP,
	RZ_CONS_PAL_PROMPT,
	RZ_CONS_PAL_PUSH,
	RZ_CONS_PAL_CRYPTO,
	RZ_CONS_PAL_REG,
	RZ_CONS_PAL_RESET,
	RZ_CONS_PAL_RET,
	RZ_CONS_PAL_SWI,
	RZ_CONS_PAL_TRAP,
	RZ_CONS_PAL_AI_READ,
	RZ_CONS_PAL_AI_WRITE,
	RZ_CONS_PAL_AI_EXEC,
	RZ_CONS_PAL_AI_SEQ,
	RZ_CONS_PAL_AI_ASCII,
	RZ_CONS_PAL_AI_UNMAP,
	RZ_CONS_PAL_GUI_CFLOW,
	RZ_CONS_PAL_GUI_DATAOFFSET,
	RZ_CONS_PAL_GUI_BACKGROUND,
	RZ_CONS_PAL_GUI_ALT_BACKGROUND,
	RZ_CONS_PAL_GUI_BORDER,
	RZ_CONS_PAL_LINEHL,
	RZ_CONS_PAL_GRAPH_BOX,
	RZ_CONS_PAL_GRAPH_BOX2,
	RZ_CONS_PAL_GRAPH_BOX3,
	RZ_CONS_PAL_GRAPH_BOX4,
	RZ_CONS_PAL_GRAPH_TRUE,
	RZ_CONS_PAL_GRAPH_FALSE,
	RZ_CONS_PAL_GRAPH_TRUFAE,
	RZ_CONS_PAL_GRAPH_TRACED,
	RZ_CONS_PAL_GRAPH_CURRENT,
	RZ_CONS_PAL_LAST
};
#endif

enum { ALPHA_RESET = 0x00,
	ALPHA_FG = 0x01,
	ALPHA_BG = 0x02,
	ALPHA_FGBG = 0x03 };
enum { RZ_CONS_ATTR_BOLD = 1u << 1,
	RZ_CONS_ATTR_DIM = 1u << 2,
	RZ_CONS_ATTR_ITALIC = 1u << 3,
	RZ_CONS_ATTR_UNDERLINE = 1u << 4,
	RZ_CONS_ATTR_BLINK = 1u << 5
};

typedef struct rcolor_t {
	// bold, italic, underline, ...
	ut8 attr;
	ut8 a;
	ut8 r;
	ut8 g;
	ut8 b;
	ut8 r2; // Background color
	ut8 g2; // Only used when a &= ALPHA_FGBG
	ut8 b2;
	st8 id16; // Mapping to 16-color table
} RzColor;

typedef struct rz_cons_palette_t {
	RzColor b0x00;
	RzColor b0x7f;
	RzColor b0xff;
	RzColor args;
	RzColor bin;
	RzColor btext;
	RzColor call;
	RzColor cjmp;
	RzColor cmp;
	RzColor comment;
	RzColor usercomment;
	RzColor creg;
	RzColor flag;
	RzColor fline;
	RzColor floc;
	RzColor flow;
	RzColor flow2;
	RzColor fname;
	RzColor help;
	RzColor input;
	RzColor invalid;
	RzColor jmp;
	RzColor label;
	RzColor math;
	RzColor mov;
	RzColor nop;
	RzColor num;
	RzColor offset;
	RzColor other;
	RzColor pop;
	RzColor prompt;
	RzColor push;
	RzColor crypto;
	RzColor reg;
	RzColor reset;
	RzColor ret;
	RzColor swi;
	RzColor trap;
	RzColor ucall;
	RzColor ujmp;
	RzColor ai_read;
	RzColor ai_write;
	RzColor ai_exec;
	RzColor ai_seq;
	RzColor ai_ascii;
	RzColor gui_cflow;
	RzColor gui_dataoffset;
	RzColor gui_background;
	RzColor gui_alt_background;
	RzColor gui_border;
	RzColor wordhl;
	RzColor linehl;
	RzColor func_var;
	RzColor func_var_type;
	RzColor func_var_addr;
	RzColor widget_bg;
	RzColor widget_sel;
	RzColor meta;

	/* Graph colors */
	RzColor graph_box;
	RzColor graph_box2;
	RzColor graph_box3;
	RzColor graph_box4;
	RzColor graph_true;
	RzColor graph_false;
	RzColor graph_ujump;
	RzColor graph_traced;
	RzColor graph_current;
	RzColor diff_match;
	RzColor diff_unmatch;
	RzColor diff_unknown;
	RzColor diff_new;
} RzConsPalette;

typedef struct rz_cons_printable_palette_t {
	char *b0x00;
	char *b0x7f;
	char *b0xff;
	char *args;
	char *bin;
	char *btext;
	char *call;
	char *cjmp;
	char *cmp;
	char *comment;
	char *usercomment;
	char *creg;
	char *flag;
	char *fline;
	char *floc;
	char *flow;
	char *flow2;
	char *fname;
	char *help;
	char *input;
	char *invalid;
	char *jmp;
	char *label;
	char *math;
	char *mov;
	char *nop;
	char *num;
	char *offset;
	char *other;
	char *pop;
	char *prompt;
	char *push;
	char *crypto;
	char *reg;
	char *reset;
	char *ret;
	char *swi;
	char *trap;
	char *ucall;
	char *ujmp;
	char *ai_read;
	char *ai_write;
	char *ai_exec;
	char *ai_seq;
	char *ai_ascii;
	char *ai_unmap;
	char *gui_cflow;
	char *gui_dataoffset;
	char *gui_background;
	char *gui_alt_background;
	char *gui_border;
	char *wordhl;
	char *linehl;
	char *func_var;
	char *func_var_type;
	char *func_var_addr;
	char *widget_bg;
	char *widget_sel;
	char *meta;

	/* graph colors */
	char *graph_box;
	char *graph_box2;
	char *graph_box3;
	char *graph_box4;
	char *diff_match;
	char *diff_unmatch;
	char *diff_unknown;
	char *diff_new;
	char *graph_true;
	char *graph_false;
	char *graph_ujump;
	char *graph_traced;
	char *graph_current;
	char **rainbow; // rainbow
	int rainbow_sz; // size of rainbow
} RzConsPrintablePalette;

typedef void (*RzConsEvent)(void *);

#define CONS_MAX_ATTR_SZ 16

typedef struct rz_cons_canvas_t {
	int w;
	int h;
	int x;
	int y;
	char **b;
	int *blen;
	int *bsize;
	const char *attr; // The current attr (inserted on each write)
	HtUP *attrs; // all the different attributes <key: unsigned int loc, const char *attr>
	RzStrConstPool constpool; // Pool for non-compile-time attrs
	int sx; // scrollx
	int sy; // scrolly
	int color;
	int linemode; // 0 = diagonal , 1 = square
} RzConsCanvas;

#define RUNECODE_MIN             0xc8 // 200
#define RUNECODE_LINE_VERT       0xc8
#define RUNECODE_LINE_CROSS      0xc9
#define RUNECODE_CORNER_BR       0xca
#define RUNECODE_CORNER_BL       0xcb
#define RUNECODE_ARROW_RIGHT     0xcc
#define RUNECODE_ARROW_LEFT      0xcd
#define RUNECODE_LINE_HORIZ      0xce
#define RUNECODE_CORNER_TL       0xcf
#define RUNECODE_CORNER_TR       0xd0
#define RUNECODE_LINE_UP         0xd1
#define RUNECODE_CURVE_CORNER_TL 0xd2
#define RUNECODE_CURVE_CORNER_TR 0xd3
#define RUNECODE_CURVE_CORNER_BR 0xd4
#define RUNECODE_CURVE_CORNER_BL 0xd5
#define RUNECODE_MAX             0xd6

#define RUNECODESTR_MIN             0xc8 // 200
#define RUNECODESTR_LINE_VERT       "\xc8"
#define RUNECODESTR_LINE_CROSS      "\xc9"
#define RUNECODESTR_CORNER_BR       "\xca"
#define RUNECODESTR_CORNER_BL       "\xcb"
#define RUNECODESTR_ARROW_RIGHT     "\xcc"
#define RUNECODESTR_ARROW_LEFT      "\xcd"
#define RUNECODESTR_LINE_HORIZ      "\xce"
#define RUNECODESTR_CORNER_TL       "\xcf"
#define RUNECODESTR_CORNER_TR       "\xd0"
#define RUNECODESTR_LINE_UP         "\xd1"
#define RUNECODESTR_CURVE_CORNER_TL "\xd2"
#define RUNECODESTR_CURVE_CORNER_TR "\xd3"
#define RUNECODESTR_CURVE_CORNER_BR "\xd4"
#define RUNECODESTR_CURVE_CORNER_BL "\xd5"
#define RUNECODESTR_MAX             0xd5

#define RUNE_LINE_VERT       "│"
#define RUNE_LINE_CROSS      "┼" /* ├ */
#define RUNE_LINE_HORIZ      "─"
#define RUNE_LINE_UP         "↑"
#define RUNE_CORNER_BR       "┘"
#define RUNE_CORNER_BL       "└"
#define RUNE_CORNER_TL       "┌"
#define RUNE_CORNER_TR       "┐"
#define RUNE_ARROW_RIGHT     "ᐳ"
#define RUNE_ARROW_LEFT      "ᐸ"
#define RUNE_ARROW_UP        "ᐱ"
#define RUNE_ARROW_DOWN      "ᐯ"
#define RUNE_CURVE_CORNER_TL "╭"
#define RUNE_CURVE_CORNER_TR "╮"
#define RUNE_CURVE_CORNER_BR "╯"
#define RUNE_CURVE_CORNER_BL "╰"
#define RUNE_LONG_LINE_HORIZ "―"
#define UTF_CIRCLE           "\u25EF"
#define UTF_BLOCK            "\u2588"

// Emoji
#define UTF8_POLICE_CARS_REVOLVING_LIGHT    "🚨"
#define UTF8_WHITE_HEAVY_CHECK_MARK         "✅"
#define UTF8_SEE_NO_EVIL_MONKEY             "🙈"
#define UTF8_SKULL_AND_CROSSBONES           "☠"
#define UTF8_KEYBOARD                       "⌨"
#define UTF8_LEFT_POINTING_MAGNIFYING_GLASS "🔍"
#define UTF8_DOOR                           "🚪"

// Variation Selectors
#define UTF8_VS16 "\xef\xb8\x8f"

typedef char *(*RzConsEditorCallback)(void *core, const char *file, const char *str);
typedef int (*RzConsClickCallback)(void *core, int x, int y);
typedef void (*RzConsBreakCallback)(void *core);
typedef void *(*RzConsSleepBeginCallback)(void *core);
typedef void (*RzConsSleepEndCallback)(void *core, void *user);
typedef void (*RzConsQueueTaskOneshot)(void *core, void *task, void *user);
typedef void (*RzConsFunctionKey)(void *core, int fkey);

typedef enum {
	COLOR_MODE_DISABLED = 0,
	COLOR_MODE_16,
	COLOR_MODE_256,
	COLOR_MODE_16M
} RzConsColorMode;

typedef enum {
	RZ_VIRT_TERM_MODE_DISABLE = 0, ///< Windows only: Use console c api for everything (Windows <= 8)
	RZ_VIRT_TERM_MODE_OUTPUT_ONLY, ///< Windows only: Use console c api for input, but output on VT (Windows >= 10)
	RZ_VIRT_TERM_MODE_COMPLETE, ///< All the sequences goes through VT (Windows Terminal, mintty, all OSs)
} RzVirtTermMode;

typedef struct rz_cons_input_context_t {
	size_t readbuffer_length;
	char *readbuffer;
	bool bufactive;
} RzConsInputContext;

typedef enum {
	RZ_CONS_PAL_SEEK_PREVIOUS,
	RZ_CONS_PAL_SEEK_NEXT,
} RzConsPalSeekMode;

typedef struct rz_cons_context_t {
	RzConsGrep grep;
	RzStack *cons_stack;
	char *buffer;
	size_t buffer_len;
	size_t buffer_sz;

	bool breaked;
	RzStack *break_stack;
	RzConsEvent event_interrupt;
	void *event_interrupt_data;
	int cmd_depth;

	// Used for per-task logging redirection
	RzLogCallback log_callback; // TODO: RzList of callbacks

	char *lastOutput;
	int lastLength;
	bool lastMode;
	bool lastEnabled;
	bool is_interactive;
	bool pageable;
	bool noflush;

	int color_mode;
	RzConsPalette cpal;
	RzConsPrintablePalette pal;

	// Memoized last calculated row/column inside buffer
	int row;
	int col;
	int rowcol_calc_start;
} RzConsContext;

#define HUD_BUF_SIZE 512

typedef enum {
	MOUSE_NONE = 0,
	MOUSE_DEFAULT, // indicate an event with no consideration of specific type
	LEFT_PRESS,
	LEFT_RELEASE,
	WHEEL_PRESS,
	WHEEL_RELEASE,
	RIGHT_PRESS,
	RIGHT_RELEASE,
	WHEEL_UP,
	WHEEL_DOWN,
} MouseEvent;

typedef struct rz_cons_t {
	RzConsContext *context;
	RzConsInputContext *input;
	bool is_html;
	bool was_html;
	int lines;
	int rows;
	int echo; // dump to stdout in realtime
	int columns;
	int force_rows;
	int force_columns;
	int fix_rows;
	int fix_columns;
	bool break_lines;
	bool show_autocomplete_widget;
	FILE *fdin; // FILE? and then int ??
	int fdout; // only used in pipe.c :?? remove?
	const char *teefile;
	int (*user_fgets)(char *buf, int len, void *user);
	void *user_fgets_user;
	RzConsEvent event_resize;
	void *event_data;
	MouseEvent mouse_event;

	RzConsEditorCallback cb_editor;
	RzConsBreakCallback cb_break;
	RzConsSleepBeginCallback cb_sleep_begin;
	RzConsSleepEndCallback cb_sleep_end;
	RzConsClickCallback cb_click;
	RzConsQueueTaskOneshot cb_task_oneshot;
	RzConsFunctionKey cb_fkey;

	void *user; // Used by <RzCore*>
#if __UNIX__
	struct termios term_raw, term_buf;
#elif __WINDOWS__
	unsigned long term_raw, term_buf, term_pty;
	unsigned long old_input_mode, old_output_mode;
	ut32 old_cp;
	ut32 old_ocp;
#endif
	RzNum *num;
	/* Pager (like more or less) to use if the output doesn't fit on the
	 * current window. If NULL or "" no pager is used. */
	char *pager;
	int blankline;
	char *highlight;
	bool enable_highlight;
	int null; // if set, does not show anything
	int mouse;
	int is_wine;
	struct rz_line_t *line;
	const char **vline;
	int refcnt;
	RZ_DEPRECATE bool newline;
	RzVirtTermMode vtmode;
	bool flush;
	bool use_utf8; // use utf8 features
	bool use_utf8_curvy; // use utf8 curved corners
	bool dotted_lines;
	int linesleep;
	int pagesize;
	char *break_word;
	int break_word_len;
	ut64 timeout; // must come from rz_time_now_mono()
	bool grep_color;
	bool grep_highlight;
	int grep_icase;
	bool filter;
	char *(*rgbstr)(char *str, size_t sz, ut64 addr);
	bool click_set;
	int click_x;
	int click_y;
	bool show_vals; // show which section in Vv
	// TODO: move into instance? + avoid unnecessary copies
} RzCons;

#define RZ_CONS_SEARCH_CASE_SENSITIVE   0
#define RZ_CONS_SEARCH_CASE_INSENSITIVE 1
#define RZ_CONS_SEARCH_CASE_SMART       2

#define RZ_CONS_KEY_F1  0xf1
#define RZ_CONS_KEY_F2  0xf2
#define RZ_CONS_KEY_F3  0xf3
#define RZ_CONS_KEY_F4  0xf4
#define RZ_CONS_KEY_F5  0xf5
#define RZ_CONS_KEY_F6  0xf6
#define RZ_CONS_KEY_F7  0xf7
#define RZ_CONS_KEY_F8  0xf8
#define RZ_CONS_KEY_F9  0xf9
#define RZ_CONS_KEY_F10 0xfa
#define RZ_CONS_KEY_F11 0xfb
#define RZ_CONS_KEY_F12 0xfc

#define RZ_CONS_KEY_ESC 0x1b

#define RZ_CONS_CLEAR_LINE               "\x1b[2K\r"
#define RZ_CONS_CLEAR_SCREEN             "\x1b[2J\r"
#define RZ_CONS_CLEAR_FROM_CURSOR_TO_END "\x1b[0J\r"

#define RZ_CONS_CURSOR_SAVE         "\x1b[s"
#define RZ_CONS_CURSOR_RESTORE      "\x1b[u"
#define RZ_CONS_GET_CURSOR_POSITION "\x1b[6n"
#define RZ_CONS_CURSOR_UP           "\x1b[A"
#define RZ_CONS_CURSOR_DOWN         "\x1b[B"
#define RZ_CONS_CURSOR_RIGHT        "\x1b[C"
#define RZ_CONS_CURSOR_LEFT         "\x1b[D"

#define Color_BLINK        "\x1b[5m"
#define Color_INVERT       "\x1b[7m"
#define Color_INVERT_RESET "\x1b[27m"
/* See 'man 4 console_codes' for details:
 * "ESC c"        -- Reset
 * "ESC ( K"      -- Select user mapping
 * "ESC [ 0 m"    -- Reset all display attributes
 * "ESC [ J"      -- Erase to the end of screen
 * "ESC [ ? 25 h" -- Make cursor visible
 */
#define Color_RESET_TERMINAL "\x1b" \
			     "c\x1b(K\x1b[0m\x1b[J\x1b[?25h"
#define Color_RESET      "\x1b[0m" /* reset all */
#define Color_RESET_NOBG "\x1b[27;22;24;25;28;39m" /* Reset everything except background (order is important) */
#define Color_RESET_BG   "\x1b[49m"
#define Color_RESET_ALL  "\x1b[0m\x1b[49m"
#define Color_BLACK      "\x1b[30m"
#define Color_BGBLACK    "\x1b[40m"
#define Color_RED        "\x1b[31m"
#define Color_BGRED      "\x1b[41m"
#define Color_WHITE      "\x1b[37m"
#define Color_BGWHITE    "\x1b[47m"
#define Color_GREEN      "\x1b[32m"
#define Color_BGGREEN    "\x1b[42m"
#define Color_MAGENTA    "\x1b[35m"
#define Color_BGMAGENTA  "\x1b[45m"
#define Color_YELLOW     "\x1b[33m"
#define Color_BGYELLOW   "\x1b[43m"
#define Color_CYAN       "\x1b[36m"
#define Color_BGCYAN     "\x1b[46m"
#define Color_BLUE       "\x1b[34m"
#define Color_BGBLUE     "\x1b[44m"
#define Color_GRAY       "\x1b[90m"
#define Color_BGGRAY     "\x1b[100m"
/* bright colors */
#define Color_BBLACK     Color_GRAY
#define Color_BBGBLACK   Color_BGGRAY
#define Color_BRED       "\x1b[91m"
#define Color_BBGRED     "\x1b[101m"
#define Color_BWHITE     "\x1b[97m"
#define Color_BBGWHITE   "\x1b[107m"
#define Color_BGREEN     "\x1b[92m"
#define Color_BBGGREEN   "\x1b[102m"
#define Color_BMAGENTA   "\x1b[95m"
#define Color_BBGMAGENTA "\x1b[105m"
#define Color_BYELLOW    "\x1b[93m"
#define Color_BBGYELLOW  "\x1b[103m"
#define Color_BCYAN      "\x1b[96m"
#define Color_BBGCYAN    "\x1b[106m"
#define Color_BBLUE      "\x1b[94m"
#define Color_BBGBLUE    "\x1b[104m"

#if defined(_MSC_VER) || (defined(__GNUC__) && __GNUC__ < 5)
#define RZCOLOR(a, r, g, b, bgr, bgg, bgb, id16) \
	{ 0, a, r, g, b, bgr, bgg, bgb, id16 }
#else
#define RZCOLOR(a, r, g, b, bgr, bgg, bgb, id16) \
	(RzColor) { \
		0, a, r, g, b, bgr, bgg, bgb, id16 \
	}
#endif
#define RzColor_NULL RZCOLOR(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, -1)
#if __WINDOWS__
#define RzColor_BLACK      RZCOLOR(ALPHA_FG, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0)
#define RzColor_BGBLACK    RZCOLOR(ALPHA_BG, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0)
#define RzColor_RED        RZCOLOR(ALPHA_FG, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 1)
#define RzColor_BGRED      RZCOLOR(ALPHA_BG, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 1)
#define RzColor_WHITE      RZCOLOR(ALPHA_FG, 0xc0, 0xc0, 0xc0, 0x00, 0x00, 0x00, 7)
#define RzColor_BGWHITE    RZCOLOR(ALPHA_BG, 0xc0, 0xc0, 0xc0, 0x00, 0x00, 0x00, 7)
#define RzColor_GREEN      RZCOLOR(ALPHA_FG, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 2)
#define RzColor_BGGREEN    RZCOLOR(ALPHA_BG, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 2)
#define RzColor_MAGENTA    RZCOLOR(ALPHA_FG, 0x80, 0x00, 0x80, 0x00, 0x00, 0x00, 5)
#define RzColor_BGMAGENTA  RZCOLOR(ALPHA_BG, 0x80, 0x00, 0x80, 0x00, 0x00, 0x00, 5)
#define RzColor_YELLOW     RZCOLOR(ALPHA_FG, 0x80, 0x80, 0x00, 0x00, 0x00, 0x00, 3)
#define RzColor_BGYELLOW   RZCOLOR(ALPHA_BG, 0x80, 0x80, 0x00, 0x00, 0x00, 0x00, 3)
#define RzColor_CYAN       RZCOLOR(ALPHA_FG, 0x00, 0x80, 0x80, 0x00, 0x00, 0x00, 6)
#define RzColor_BGCYAN     RZCOLOR(ALPHA_BG, 0x00, 0x80, 0x80, 0x00, 0x00, 0x00, 6)
#define RzColor_BLUE       RZCOLOR(ALPHA_FG, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 4)
#define RzColor_BGBLUE     RZCOLOR(ALPHA_BG, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 4)
#define RzColor_BBLACK     RZCOLOR(ALPHA_FG, 0x80, 0x80, 0x80, 0x00, 0x00, 0x00, 8)
#define RzColor_BBGBLACK   RZCOLOR(ALPHA_BG, 0x80, 0x80, 0x80, 0x00, 0x00, 0x00, 8)
#define RzColor_BRED       RZCOLOR(ALPHA_FG, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 9)
#define RzColor_BBGRED     RZCOLOR(ALPHA_BG, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 9)
#define RzColor_BWHITE     RZCOLOR(ALPHA_FG, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 15)
#define RzColor_BBGWHITE   RZCOLOR(ALPHA_BG, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 15)
#define RzColor_BGREEN     RZCOLOR(ALPHA_FG, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 10)
#define RzColor_BBGGREEN   RZCOLOR(ALPHA_BG, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 10)
#define RzColor_BMAGENTA   RZCOLOR(ALPHA_FG, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 13)
#define RzColor_BBGMAGENTA RZCOLOR(ALPHA_BG, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 13)
#define RzColor_BYELLOW    RZCOLOR(ALPHA_FG, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 11)
#define RzColor_BBGYELLOW  RZCOLOR(ALPHA_BG, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 11)
#define RzColor_BCYAN      RZCOLOR(ALPHA_FG, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 14)
#define RzColor_BBGCYAN    RZCOLOR(ALPHA_BG, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 14)
#define RzColor_BBLUE      RZCOLOR(ALPHA_FG, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 12)
#define RzColor_BBGBLUE    RZCOLOR(ALPHA_BG, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 12)
#else
// Campbell (https://devblogs.microsoft.com/commandline/updating-the-windows-console-colors/).
// Not used on Windows since cmd.exe doesn't support bold (needed for easier
// differentiation between normal and bright color text for some colors).
#define RzColor_BLACK      RZCOLOR(ALPHA_FG, 12, 12, 12, 0x00, 0x00, 0x00, 0)
#define RzColor_BGBLACK    RZCOLOR(ALPHA_BG, 12, 12, 12, 0x00, 0x00, 0x00, 0)
#define RzColor_RED        RZCOLOR(ALPHA_FG, 197, 15, 31, 0x00, 0x00, 0x00, 1)
#define RzColor_BGRED      RZCOLOR(ALPHA_BG, 197, 15, 31, 0x00, 0x00, 0x00, 1)
#define RzColor_WHITE      RZCOLOR(ALPHA_FG, 204, 204, 204, 0x00, 0x00, 0x00, 7)
#define RzColor_BGWHITE    RZCOLOR(ALPHA_BG, 204, 204, 204, 0x00, 0x00, 0x00, 7)
#define RzColor_GREEN      RZCOLOR(ALPHA_FG, 19, 161, 14, 0x00, 0x00, 0x00, 2)
#define RzColor_BGGREEN    RZCOLOR(ALPHA_BG, 19, 161, 14, 0x00, 0x00, 0x00, 2)
#define RzColor_MAGENTA    RZCOLOR(ALPHA_FG, 136, 23, 152, 0x00, 0x00, 0x00, 5)
#define RzColor_BGMAGENTA  RZCOLOR(ALPHA_BG, 136, 23, 152, 0x00, 0x00, 0x00, 5)
#define RzColor_YELLOW     RZCOLOR(ALPHA_FG, 193, 156, 0, 0x00, 0x00, 0x00, 3)
#define RzColor_BGYELLOW   RZCOLOR(ALPHA_BG, 193, 156, 0, 0x00, 0x00, 0x00, 3)
#define RzColor_CYAN       RZCOLOR(ALPHA_FG, 58, 150, 221, 0x00, 0x00, 0x00, 6)
#define RzColor_BGCYAN     RZCOLOR(ALPHA_BG, 58, 150, 221, 0x00, 0x00, 0x00, 6)
#define RzColor_BLUE       RZCOLOR(ALPHA_FG, 0, 55, 218, 0x00, 0x00, 0x00, 4)
#define RzColor_BGBLUE     RZCOLOR(ALPHA_BG, 0, 55, 218, 0x00, 0x00, 0x00, 4)
#define RzColor_BBLACK     RZCOLOR(ALPHA_FG, 118, 118, 118, 0x00, 0x00, 0x00, 8)
#define RzColor_BBGBLACK   RZCOLOR(ALPHA_BG, 118, 118, 118, 0x00, 0x00, 0x00, 8)
#define RzColor_BRED       RZCOLOR(ALPHA_FG, 231, 72, 86, 0x00, 0x00, 0x00, 9)
#define RzColor_BBGRED     RZCOLOR(ALPHA_BG, 231, 72, 86, 0x00, 0x00, 0x00, 9)
#define RzColor_BWHITE     RZCOLOR(ALPHA_FG, 242, 242, 242, 0x00, 0x00, 0x00, 15)
#define RzColor_BBGWHITE   RZCOLOR(ALPHA_BG, 242, 242, 242, 0x00, 0x00, 0x00, 15)
#define RzColor_BGREEN     RZCOLOR(ALPHA_FG, 22, 198, 12, 0x00, 0x00, 0x00, 10)
#define RzColor_BBGGREEN   RZCOLOR(ALPHA_BG, 22, 198, 12, 0x00, 0x00, 0x00, 10)
#define RzColor_BMAGENTA   RZCOLOR(ALPHA_FG, 180, 0, 158, 0x00, 0x00, 0x00, 13)
#define RzColor_BBGMAGENTA RZCOLOR(ALPHA_BG, 180, 0, 158, 0x00, 0x00, 0x00, 13)
#define RzColor_BYELLOW    RZCOLOR(ALPHA_FG, 249, 241, 165, 0x00, 0x00, 0x00, 11)
#define RzColor_BBGYELLOW  RZCOLOR(ALPHA_BG, 249, 241, 165, 0x00, 0x00, 0x00, 11)
#define RzColor_BCYAN      RZCOLOR(ALPHA_FG, 97, 214, 214, 0x00, 0x00, 0x00, 14)
#define RzColor_BBGCYAN    RZCOLOR(ALPHA_BG, 97, 214, 214, 0x00, 0x00, 0x00, 14)
#define RzColor_BBLUE      RZCOLOR(ALPHA_FG, 59, 120, 255, 0x00, 0x00, 0x00, 12)
#define RzColor_BBGBLUE    RZCOLOR(ALPHA_BG, 59, 120, 255, 0x00, 0x00, 0x00, 12)
#endif
#define RzColor_GRAY   RzColor_BBLACK
#define RzColor_BGGRAY RzColor_BBGBLACK

#define Colors_PLAIN \
	{ \
		Color_BLACK, Color_RED, Color_WHITE, \
		Color_GREEN, Color_MAGENTA, Color_YELLOW, \
		Color_CYAN, Color_BLUE, Color_GRAY \
	}

enum {
	PAL_PROMPT = 0,
	PAL_ADDRESS,
	PAL_DEFAULT,
	PAL_CHANGED,
	PAL_JUMP,
	PAL_CALL,
	PAL_PUSH,
	PAL_TRAP,
	PAL_CMP,
	PAL_RET,
	PAL_NOP,
	PAL_METADATA,
	PAL_HEADER,
	PAL_PRINTABLE,
	PAL_LINES0,
	PAL_LINES1,
	PAL_LINES2,
	PAL_00,
	PAL_7F,
	PAL_FF
};

/* canvas line colors */
enum {
	LINE_NONE = 0,
	LINE_TRUE,
	LINE_FALSE,
	LINE_UNCJMP,
	LINE_NOSYM_VERT,
	LINE_NOSYM_HORIZ
};

typedef enum {
	INSERT_MODE = 'i',
	CONTROL_MODE = 'c'
} RViMode;

#define DOT_STYLE_NORMAL      0
#define DOT_STYLE_CONDITIONAL 1
#define DOT_STYLE_BACKEDGE    2

typedef struct rz_cons_canvas_line_style_t {
	int color;
	int symbol;
	int dot_style;
} RzCanvasLineStyle;

// UTF-8 symbols indexes
#define LINE_VERT   0
#define LINE_CROSS  1
#define LINE_HORIZ  2
#define LINE_UP     3
#define CORNER_TL   6
#define CORNER_BR   4
#define CORNER_BL   5
#define CORNER_TR   6
#define ARROW_RIGHT 8
#define ARROW_LEFT  9
#define SELF_LOOP   10

typedef struct rz_histogram_options_t {
	bool unicode; //<< Use Unicode characters instead of ASCII
	bool thinline; //<< Use thin lines instead of block lines
	bool legend; //<< Show axes and legend
	bool offset; //<< Show offsets
	ut64 offpos; //<< Starting offset value
	bool cursor; //<< Show cursor position
	ut64 curpos; //<< Cursor position
	bool color; //<< Use colors
	RzConsPrintablePalette *pal; //<< Colors palette if color is enabled
} RzHistogramOptions;

typedef struct rz_bar_options_t {
	bool unicode; //<< Use Unicode characters instead of ASCII
	bool thinline; //<< Use thin lines instead of block lines
	bool legend; //<< Show axes and legend
	bool offset; //<< Show offsets
	ut64 offpos; //<< Starting offset value
	bool cursor; //<< Show cursor position
	ut64 curpos; //<< Cursor position
	bool color; //<< Use colors
} RzBarOptions;

typedef struct rz_histogram_interactive_t {
	RzConsCanvas *can;

	int barnumber;
	int size;
	int zoom;
	int movspeed;

	int x, y;
	int w, h;

	RzHistogramOptions *opts;
} RzHistogramInteractive;

#ifdef RZ_API
RZ_API RzConsCanvas *rz_cons_canvas_new(int w, int h);
RZ_API void rz_cons_canvas_free(RzConsCanvas *c);
RZ_API void rz_cons_canvas_clear(RzConsCanvas *c);
RZ_API void rz_cons_canvas_print(RzConsCanvas *c);
RZ_API void rz_cons_canvas_print_region(RzConsCanvas *c);
RZ_API RZ_OWN char *rz_cons_canvas_to_string(RzConsCanvas *c);
RZ_API void rz_cons_canvas_write(RzConsCanvas *c, const char *_s);
RZ_API bool rz_cons_canvas_gotoxy(RzConsCanvas *c, int x, int y);
RZ_API void rz_cons_canvas_box(RzConsCanvas *c, int x, int y, int w, int h, const char *color);
RZ_API void rz_cons_canvas_line(RzConsCanvas *c, int x, int y, int x2, int y2, RzCanvasLineStyle *style);
RZ_API void rz_cons_canvas_line_diagonal(RzConsCanvas *c, int x, int y, int x2, int y2, RzCanvasLineStyle *style);
RZ_API void rz_cons_canvas_line_square(RzConsCanvas *c, int x, int y, int x2, int y2, RzCanvasLineStyle *style);
RZ_API int rz_cons_canvas_resize(RzConsCanvas *c, int w, int h);
RZ_API void rz_cons_canvas_fill(RzConsCanvas *c, int x, int y, int w, int h, char ch);
RZ_API void rz_cons_canvas_line_square_defined(RzConsCanvas *c, int x, int y, int x2, int y2, RzCanvasLineStyle *style, int bendpoint, int isvert);
RZ_API void rz_cons_canvas_line_back_edge(RzConsCanvas *c, int x, int y, int x2, int y2, RzCanvasLineStyle *style, int ybendpoint1, int xbendpoint, int ybendpoint2, int isvert);
RZ_API RzCons *rz_cons_new(void);
RZ_API RzCons *rz_cons_singleton(void);
RZ_API RzCons *rz_cons_free(void);
RZ_API char *rz_cons_lastline(int *size);
RZ_API char *rz_cons_lastline_utf8_ansi_len(int *len);
RZ_API void rz_cons_set_click(int x, int y, MouseEvent event);
RZ_API bool rz_cons_get_click(int *x, int *y);

typedef void (*RzConsBreak)(void *);
RZ_API bool rz_cons_is_breaked(void);
RZ_API bool rz_cons_is_interactive(void);
RZ_API bool rz_cons_default_context_is_interactive(void);
RZ_API void *rz_cons_sleep_begin(void);
RZ_API void rz_cons_sleep_end(void *user);

/* ^C */
RZ_API void rz_cons_break_push(RzConsBreak cb, void *user);
RZ_API void rz_cons_break_pop(void);
RZ_API void rz_cons_break_clear(void);
RZ_API void rz_cons_breakword(RZ_NULLABLE const char *s);
RZ_API void rz_cons_break_end(void);
RZ_API void rz_cons_break_timeout(int timeout);

/* pipe */
typedef struct rz_cons_pipe_t RzConsPipe;
RZ_API RZ_OWN RzConsPipe *rz_cons_pipe_open(RZ_NONNULL const char *file, int old_fd, bool append);
RZ_API void rz_cons_pipe_close(RZ_NULLABLE RzConsPipe *cpipe);

#if __WINDOWS__
RZ_API RzVirtTermMode rz_cons_detect_vt_mode(void);
RZ_API void rz_cons_w32_clear(void);
RZ_API void rz_cons_w32_gotoxy(int fd, int x, int y);
RZ_API int rz_cons_w32_print(const char *ptr, int len, bool vmode);
RZ_API int rz_cons_win_printf(bool vmode, const char *fmt, ...) RZ_PRINTF_CHECK(2, 3);
RZ_API int rz_cons_win_eprintf(bool vmode, const char *fmt, ...) RZ_PRINTF_CHECK(2, 3);
RZ_API int rz_cons_win_vhprintf(unsigned long hdl, bool vmode, const char *fmt, va_list ap);
#endif

RZ_API void rz_cons_push(void);
RZ_API void rz_cons_pop(void);
RZ_API RzConsContext *rz_cons_context_new(RZ_NULLABLE RzConsContext *parent);
RZ_API void rz_cons_context_free(RzConsContext *context);
RZ_API void rz_cons_context_load(RzConsContext *context);
RZ_API void rz_cons_context_reset(void);
RZ_API bool rz_cons_context_is_main(void);
RZ_API void rz_cons_context_break(RzConsContext *context);
RZ_API void rz_cons_context_break_push(RzConsContext *context, RzConsBreak cb, void *user, bool sig);
RZ_API void rz_cons_context_break_pop(RzConsContext *context, bool sig);

/* control */
RZ_API void rz_cons_reset(void);
RZ_API void rz_cons_reset_colors(void);
RZ_API void rz_cons_goto_origin_reset(void);
RZ_API void rz_cons_echo(const char *msg);
RZ_API void rz_cons_zero(void);
RZ_API void rz_cons_highlight(const char *word);
RZ_API void rz_cons_clear(void);
RZ_API void rz_cons_clear_buffer(void);
RZ_API void rz_cons_clear00(void);
RZ_API void rz_cons_clear_line(int err);
RZ_API void rz_cons_fill_line(void);
RZ_API void rz_cons_gotoxy(int x, int y);
RZ_API int rz_cons_get_cur_line(void);
RZ_API void rz_cons_show_cursor(int cursor);
RZ_API char *rz_cons_swap_ground(const char *col);
RZ_API bool rz_cons_drop(int n);
RZ_API void rz_cons_chop(void);
RZ_API void rz_cons_set_raw(bool b);
RZ_API void rz_cons_set_interactive(bool b);
RZ_API void rz_cons_set_last_interactive(void);
RZ_API void rz_cons_set_utf8(bool b);
RZ_API void rz_cons_grep(const char *grep);

/* output */
RZ_API int rz_cons_printf(const char *format, ...) RZ_PRINTF_CHECK(1, 2);
RZ_API void rz_cons_printf_list(const char *format, va_list ap);
RZ_API void rz_cons_strcat(const char *str);
RZ_API void rz_cons_strcat_at(const char *str, int x, char y, int w, int h);
#define rz_cons_print(x) rz_cons_strcat(x)
RZ_API void rz_cons_println(const char *str);

RZ_API void rz_cons_strcat_justify(const char *str, int j, char c);
RZ_API int rz_cons_memcat(const char *str, int len);
RZ_API void rz_cons_newline(void);
RZ_API void rz_cons_filter(void);
RZ_API void rz_cons_flush(void);
RZ_API void rz_cons_set_flush(bool flush);
RZ_API void rz_cons_last(void);
RZ_API int rz_cons_less_str(const char *str, const char *exitkeys);
RZ_API void rz_cons_less(void);
RZ_API void rz_cons_memset(char ch, int len);
RZ_API void rz_cons_visual_flush(void);
RZ_API void rz_cons_visual_write(char *buffer);
RZ_API bool rz_cons_is_utf8(void);
RZ_API void rz_cons_cmd_help(const char *help[], bool use_color);

/* input */
RZ_API int rz_cons_controlz(int ch);
RZ_API int rz_cons_readchar(void);
RZ_API bool rz_cons_readbuffer_readchar(char *ch);
RZ_API bool rz_cons_readpush(const char *str, int len);
RZ_API void rz_cons_readflush(void);
RZ_API void rz_cons_switchbuf(bool active);
RZ_API int rz_cons_readchar_timeout(ut32 usec);
RZ_API int rz_cons_any_key(const char *msg);
RZ_API int rz_cons_eof(void);

RZ_API int rz_cons_pal_set(const char *key, const char *val);
RZ_API void rz_cons_pal_update_event(void);
RZ_API void rz_cons_pal_free(RzConsContext *ctx);
RZ_API void rz_cons_pal_init(RzConsContext *ctx);
RZ_API void rz_cons_pal_copy(RzConsContext *dst, RzConsContext *src);
RZ_API char *rz_cons_pal_parse(const char *str, RzColor *outcol);
RZ_API void rz_cons_pal_random(void);
RZ_API RzColor rz_cons_pal_get(const char *key);
RZ_API RzColor rz_cons_pal_get_i(int index);
RZ_API const char *rz_cons_pal_get_name(int index);
RZ_API int rz_cons_pal_len(void);
RZ_API int rz_cons_rgb_parse(const char *p, ut8 *r, ut8 *g, ut8 *b, ut8 *a);
RZ_API char *rz_cons_rgb_tostring(ut8 r, ut8 g, ut8 b);
RZ_API void rz_cons_pal_list(int rad, const char *arg);
RZ_API void rz_cons_pal_show(void);
RZ_API int rz_cons_get_size(int *rows);
RZ_API bool rz_cons_isatty(void);
RZ_API int rz_cons_get_cursor(RZ_NONNULL int *rows);
RZ_API int rz_cons_arrow_to_hjkl(int ch);
RZ_API char *rz_cons_html_filter(const char *ptr, int *newlen);
RZ_API char *rz_cons_rainbow_get(int idx, int last, bool bg);
RZ_API void rz_cons_rainbow_free(RzConsContext *ctx);
RZ_API void rz_cons_rainbow_new(RzConsContext *ctx, int sz);

RZ_API int rz_cons_fgets(char *buf, int len, int argc, const char **argv);
RZ_API char *rz_cons_hud(RzList /*<char *>*/ *list, const char *prompt);
RZ_API char *rz_cons_hud_path(const char *path, int dir);
RZ_API char *rz_cons_hud_string(const char *s);
RZ_API char *rz_cons_hud_file(const char *f);

RZ_API const char *rz_cons_get_buffer(void);
RZ_API RZ_OWN char *rz_cons_get_buffer_dup(void);
RZ_API int rz_cons_get_buffer_len(void);
RZ_API void rz_cons_grep_help(void);
RZ_API void rz_cons_grep_parsecmd(char *cmd, const char *quotestr);
RZ_API char *rz_cons_grep_strip(char *cmd, const char *quotestr);
RZ_API void rz_cons_grep_process(RZ_OWN char *grep);
RZ_API int rz_cons_grep_line(char *buf, int len); // must be static
RZ_API void rz_cons_grepbuf(void);

RZ_API void rz_cons_rgb_init(void);
RZ_API char *rz_cons_rgb_str_mode(RzConsColorMode mode, char *outstr, size_t sz, const RzColor *rcolor);
RZ_API char *rz_cons_rgb_str(char *outstr, size_t sz, const RzColor *rcolor);
RZ_API char *rz_cons_rgb_str_off(char *outstr, size_t sz, ut64 off);
RZ_API void rz_cons_color(int fg, int r, int g, int b);

RZ_API RzColor rz_cons_color_random(ut8 alpha);
RZ_API void rz_cons_invert(int set, int color);
RZ_API bool rz_cons_yesno(int def, const char *fmt, ...) RZ_PRINTF_CHECK(2, 3);
RZ_API char *rz_cons_input(const char *msg);
RZ_API bool rz_cons_set_cup(bool enable);
RZ_API void rz_cons_column(int c);
RZ_API int rz_cons_get_column(void);
RZ_API void rz_cons_message(RZ_NONNULL const char *msg);
RZ_API void rz_cons_set_title(const char *str);
RZ_API bool rz_cons_enable_mouse(const bool enable);
RZ_API void rz_cons_enable_highlight(const bool enable);
RZ_API void rz_cons_bind(RzConsBind *bind);
RZ_API const char *rz_cons_get_rune(const ut8 ch);

/* Histograms */
RZ_API RZ_OWN RzStrBuf *rz_histogram_horizontal(RZ_NONNULL RzHistogramOptions *opts, RZ_NONNULL const ut8 *data, ut32 width, ut32 height);
RZ_API RZ_OWN RzStrBuf *rz_histogram_vertical(RZ_NONNULL RzHistogramOptions *opts, RZ_NONNULL const ut8 *data, int width, int step);
RZ_API RZ_OWN RzStrBuf *rz_histogram_interactive_horizontal(RZ_NONNULL RzHistogramInteractive *hist, const unsigned char *data);
RZ_API RzHistogramOptions *rz_histogram_options_new();
RZ_API void rz_histogram_options_free(RzHistogramOptions *histops);
RZ_API RzHistogramInteractive *rz_histogram_interactive_new(RzConsCanvas *can, RzHistogramOptions *opts);
RZ_API void rz_histogram_interactive_free(RzHistogramInteractive *hist);
RZ_API void rz_histogram_interactive_zoom_in(RzHistogramInteractive *hist);
RZ_API void rz_histogram_interactive_zoom_out(RzHistogramInteractive *hist);
#endif

/* Bars */
RZ_API RZ_OWN RzStrBuf *rz_progressbar(RZ_NONNULL RzBarOptions *opts, int pc, int width);
RZ_API RZ_OWN RzStrBuf *rz_rangebar(RZ_NONNULL RzBarOptions *opts, ut64 startA, ut64 endA, ut64 min,
	ut64 max, int width);

/* rz_line */
#define RZ_LINE_BUFSIZE  4096
#define RZ_LINE_HISTSIZE 256
#define RZ_LINE_UNDOSIZE 512

#define RZ_EDGES_X_INC 4

#define RZ_SELWIDGET_MAXH     15
#define RZ_SELWIDGET_MAXW     30
#define RZ_SELWIDGET_DIR_UP   0
#define RZ_SELWIDGET_DIR_DOWN 1

typedef struct rz_selection_widget_t {
	const char **options;
	int options_len;
	int selection;
	int w, h;
	int scroll;
	bool complete_common;
	bool direction;
} RzSelWidget;

typedef struct rz_line_hist_t {
	char **data;
	char *match;
	int size;
	int index;
	int top;
	int autosave;
	bool do_setup_match;
} RzLineHistory;

typedef struct rz_line_buffer_t {
	char data[RZ_LINE_BUFSIZE];
	int index;
	int length;
} RzLineBuffer;

typedef struct rz_hud_t {
	int current_entry_n;
	int top_entry_n;
	char activate;
	int vi;
} RzLineHud;

typedef struct rz_line_t RzLine; // forward declaration
typedef struct rz_line_comp_t RzLineCompletion;

typedef enum { RZ_LINE_PROMPT_DEFAULT,
	RZ_LINE_PROMPT_OFFSET,
	RZ_LINE_PROMPT_FILE } RzLinePromptType;

typedef int (*RzLineCompletionCb)(RzLineCompletion *completion, RzLineBuffer *buf, RzLinePromptType prompt_type, void *user);

struct rz_line_comp_t {
	bool opt;
	size_t args_limit;
	bool quit;
	RzPVector /*<char *>*/ args;
	RzLineCompletionCb run;
	void *run_user;
};

typedef struct rz_line_ns_completion_t RzLineNSCompletion;

/**
 * Result returned by a completion callback function. It includes all the
 * information required to provide meaningful autocompletion suggestion to the
 * user.
 */
typedef struct rz_line_ns_completion_result_t {
	RzPVector /*<char *>*/ options; ///< Vector of options that can be used for autocompletion
	HtPP *options_ht; ///< Hash table to keep track of duplicated autocompletion suggestions
	size_t start; ///< First byte that was considered for autocompletion. Everything before this will be left intact.
	size_t end; ///< Last byte that was considered for autocompletion. Everything after this will be left intact.
	const char *end_string; ///< String to place after the only option available is autocompleted. By default a space is used.
} RzLineNSCompletionResult;

/**
 * Callback that analyze the current user input and provides options for autocompletion.
 *
 * \param buf RLineBuffer pointer, containing all the info about the current user input
 * \param prompt_type Type of prompt used
 * \param user User data that was previously setup in \p RzLineNSCompletion
 */
typedef RzLineNSCompletionResult *(*RzLineNSCompletionCb)(RzLineBuffer *buf, RzLinePromptType prompt_type, void *user);

/**
 * Autocompletion callback data.
 */
struct rz_line_ns_completion_t {
	RzLineNSCompletionCb run; ///< Callback function that is called when autocompletion is required. (e.g. TAB is pressed)
	void *run_user; ///< User data that can be passed to the callback
};

typedef char *(*RzLineEditorCb)(void *core, const char *str);
typedef int (*RzLineHistoryUpCb)(RzLine *line);
typedef int (*RzLineHistoryDownCb)(RzLine *line);

typedef struct rz_line_undo_entry_t RzLineUndoEntry;

struct rz_line_t {
	RzLineCompletion completion;
	RzLineNSCompletion ns_completion;
	RzLineBuffer buffer;
	RzLineHistory history;
	RzVector /*<RzLineUndoEntry>*/ *undo_vec;
	RzSelWidget *sel_widget;
	/* callbacks */
	RzLineHistoryUpCb cb_history_up;
	RzLineHistoryDownCb cb_history_down;
	RzLineEditorCb cb_editor;
	// RzLineFunctionKeyCb cb_fkey;
	RzConsFunctionKey cb_fkey;
	/* state , TODO: use more bool */
	int gcomp;
	int gcomp_idx;
	int echo;
	int has_echo;
	char *prompt;
	RzList /*<char *>*/ *kill_ring;
	int kill_ring_ptr;
	bool yank_flag;
	int undo_cursor;
	bool undo_continue;
	char *clipboard;
	int disable;
	void *user;
	int (*hist_up)(void *user);
	int (*hist_down)(void *user);
	char *contents;
	bool zerosep;
	bool enable_vi_mode;
	int vi_mode;
	bool prompt_mode;
	RzLinePromptType prompt_type;
	int offset_hist_index;
	int file_hist_index;
	RzLineHud *hud;
	RzList /*<char *>*/ *sdbshell_hist;
	RzListIter /*<char *>*/ *sdbshell_hist_iter;
	RzVirtTermMode vtmode;
}; /* RzLine */

#ifdef RZ_API

RZ_API RZ_OWN RzLine *rz_line_new(void);
RZ_API void rz_line_free(RZ_NULLABLE RzLine *line);
RZ_API RZ_OWN char *rz_line_get_prompt(RZ_NONNULL RzLine *line);
RZ_API void rz_line_set_prompt(RZ_NONNULL RzLine *line, RZ_NONNULL const char *prompt);
RZ_API bool rz_line_dietline_init(RZ_NONNULL RzLine *line);
RZ_API void rz_line_clipboard_push(RZ_NONNULL RzLine *line, RZ_NONNULL const char *str);
RZ_API void rz_line_hist_free(RZ_NULLABLE RzLine *line);
RZ_API void rz_line_autocomplete(RZ_NONNULL RzLine *line);

typedef int(RzLineReadCallback)(void *user, const char *line);
RZ_API const char *rz_line_readline(RZ_NONNULL RzLine *line);
RZ_API const char *rz_line_readline_cb(RZ_NONNULL RzLine *line, RzLineReadCallback cb, void *user);

RZ_API bool rz_line_hist_load(RZ_NONNULL RzLine *line, RZ_NONNULL const char *file);
RZ_API bool rz_line_hist_add(RZ_NONNULL RzLine *line, RZ_NONNULL const char *str);
RZ_API bool rz_line_hist_save(RZ_NONNULL RzLine *line, const char *file);
RZ_API int rz_line_hist_list(RZ_NONNULL RzLine *line);
RZ_API const char *rz_line_hist_get(RZ_NONNULL RzLine *line, int n);

RZ_API int rz_line_set_hist_callback(RZ_NONNULL RzLine *line, RzLineHistoryUpCb cb_up, RzLineHistoryDownCb cb_down);
RZ_API int rz_line_hist_cmd_up(RZ_NONNULL RzLine *line);
RZ_API int rz_line_hist_cmd_down(RZ_NONNULL RzLine *line);

RZ_API void rz_line_completion_init(RzLineCompletion *completion, size_t args_limit);
RZ_API void rz_line_completion_fini(RzLineCompletion *completion);
RZ_API void rz_line_completion_push(RzLineCompletion *completion, const char *str);
RZ_API void rz_line_completion_set(RzLineCompletion *completion, int argc, const char **argv);
RZ_API void rz_line_completion_clear(RzLineCompletion *completion);

RZ_API RzLineNSCompletionResult *rz_line_ns_completion_result_new(size_t start, size_t end, const char *end_string);
RZ_API void rz_line_ns_completion_result_free(RzLineNSCompletionResult *res);
RZ_API void rz_line_ns_completion_result_add(RzLineNSCompletionResult *res, const char *option);
RZ_API void rz_line_ns_completion_result_propose(RzLineNSCompletionResult *res, const char *option, const char *cur, size_t cur_len);

RZ_API RZ_OWN char *rz_cons_prompt(RZ_NONNULL const char *str, RZ_NULLABLE const char *txt);

#define RZ_CONS_INVERT(x, y) (y ? (x ? Color_INVERT : Color_INVERT_RESET) : (x ? "[" : "]"))

#endif

#ifdef __sun
static inline void cfmakeraw(struct termios *tm) {
	tm->c_cflag &= ~(CSIZE | PARENB);
	tm->c_cflag |= CS8;
	tm->c_iflag &= ~(IMAXBEL | IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
	tm->c_oflag &= ~OPOST;
	tm->c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
}
#endif

#ifdef __cplusplus
}
#endif
#endif
