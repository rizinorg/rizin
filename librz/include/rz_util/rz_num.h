#ifndef RZ_NUM_H
#define RZ_NUM_H

#define RZ_NUMCALC_STRSZ 1024

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	double d;
	ut64 n;
} RzNumCalcValue;

typedef enum {
	RNCNAME,
	RNCNUMBER,
	RNCEND,
	RNCINC,
	RNCDEC,
	RNCLT, // comparison operator <
	RNCGT, // comparison operator >
	RNCPLUS = '+',
	RNCMINUS = '-',
	RNCMUL = '*',
	RNCDIV = '/',
	RNCMOD = '%',
	//RNCXOR='^', RNCOR='|', RNCAND='&',
	RNCNEG = '~',
	RNCAND = '&',
	RNCORR = '|',
	RNCXOR = '^',
	RNCPRINT = ';',
	RNCASSIGN = '=',
	RNCLEFTP = '(',
	RNCRIGHTP = ')',
	RNCSHL = '<',
	RNCSHR = '>',
	RNCROL = '#',
	RNCROR = '$'
} RzNumCalcToken;

typedef struct rz_num_calc_t {
	RzNumCalcToken curr_tok;
	RzNumCalcValue number_value;
	char string_value[RZ_NUMCALC_STRSZ];
	int errors;
	char oc;
	const char *calc_err;
	int calc_i;
	const char *calc_buf;
	int calc_len;
	bool under_calc;
} RzNumCalc;

typedef struct rz_num_t {
	ut64 (*callback)(struct rz_num_t *userptr, const char *str, int *ok);
	const char *(*cb_from_value)(struct rz_num_t *userptr, ut64 value, int *ok);
	//	RzNumCallback callback;
	ut64 value;
	double fvalue;
	void *userptr;
	int dbz; /// division by zero happened
	RzNumCalc nc;
} RzNum;

typedef ut64 (*RzNumCallback)(struct rz_num_t *self, const char *str, int *ok);
typedef const char *(*RzNumCallback2)(struct rz_num_t *self, ut64, int *ok);

RZ_API RzNum *rz_num_new(RzNumCallback cb, RzNumCallback2 cb2, void *ptr);
RZ_API void rz_num_free(RzNum *num);
RZ_API char *rz_num_units(char *buf, size_t len, ut64 number);
RZ_API int rz_num_conditional(RzNum *num, const char *str);
RZ_API ut64 rz_num_calc(RzNum *num, const char *str, const char **err);
RZ_API const char *rz_num_calc_index(RzNum *num, const char *p);
RZ_API ut64 rz_num_chs(int cylinder, int head, int sector, int sectorsize);
RZ_API int rz_num_is_valid_input(RzNum *num, const char *input_value);
RZ_API ut64 rz_num_get_input_value(RzNum *num, const char *input_value);
RZ_API const char *rz_num_get_name(RzNum *num, ut64 n);
RZ_API char *rz_num_as_string(RzNum *___, ut64 n, bool printable_only);
RZ_API ut64 rz_num_tail(RzNum *num, ut64 addr, const char *hex);
RZ_API ut64 rz_num_tail_base(RzNum *num, ut64 addr, ut64 off);
RZ_API void rz_num_minmax_swap(ut64 *a, ut64 *b);
RZ_API void rz_num_minmax_swap_i(int *a, int *b); // XXX this can be a cpp macro :??
RZ_API ut64 rz_num_math(RzNum *num, const char *str);
RZ_API ut64 rz_num_get(RzNum *num, const char *str);
RZ_API int rz_num_to_bits(char *out, ut64 num);
RZ_API int rz_num_to_trits(char *out, ut64 num); //Rename this please
RZ_API int rz_num_rand(int max);
RZ_API void rz_num_irand(void);
RZ_API ut16 rz_num_ntohs(ut16 foo);
RZ_API ut64 rz_get_input_num_value(RzNum *num, const char *input_value);
RZ_API bool rz_is_valid_input_num_value(RzNum *num, const char *input_value);
RZ_API int rz_num_between(RzNum *num, const char *input_value);
RZ_API bool rz_num_is_op(const char c);
RZ_API int rz_num_str_len(const char *str);
RZ_API int rz_num_str_split(char *str);
RZ_API RzList *rz_num_str_split_list(char *str);
RZ_API void *rz_num_dup(ut64 n);
RZ_API size_t rz_num_base_of_string(RzNum *num, RZ_NONNULL const char *str);
RZ_API double rz_num_cos(double a);
RZ_API double rz_num_sin(double a);
RZ_API double rz_num_get_float(RzNum *num, const char *str);

static inline st64 rz_num_abs(st64 num) {
	return num < 0 ? -num : num;
}

/**
 * \brief Padding to align v to the next alignment-boundary.
 * \return the least `d` such that `(v + d) % alignment == 0`.
 */
static inline ut64 rz_num_align_delta(ut64 v, ut64 alignment) {
	if (!alignment) {
		return 0;
	}
	ut64 excess = v % alignment;
	if (!excess) {
		return 0;
	}
	return alignment - excess;
}

#define CONVERT_TO_TWO_COMPLEMENT(x) \
	static inline st##x convert_to_two_complement_##x(ut##x value) { \
		if (value <= ST##x##_MAX) { \
			return (st##x)value; \
		} \
\
		value = ~value + 1; \
		return -(st##x)value; \
	}

CONVERT_TO_TWO_COMPLEMENT(8)
CONVERT_TO_TWO_COMPLEMENT(16)
CONVERT_TO_TWO_COMPLEMENT(32)
CONVERT_TO_TWO_COMPLEMENT(64)

/// Typical comparison (1/0/-1) for two numbers of arbitrary types, including unsigned
#define RZ_NUM_CMP(a, b) ((a) > (b) ? 1 : ((b) > (a) ? -1 : 0))

#ifdef __cplusplus
}
#endif

#endif //  RZ_NUM_H
