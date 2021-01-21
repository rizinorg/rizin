#ifndef RZ_NUM_H
#define RZ_NUM_H

#define RZ_NUMCALC_STRSZ 1024

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	double d;
	ut64 n;
} RNumCalcValue;

typedef enum {
	RNCNAME,
	RNCNUMBER,
	RNCEND,
	RNCINC,
	RNCDEC,
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
} RNumCalcToken;

typedef struct rz_num_calc_t {
	RNumCalcToken curr_tok;
	RNumCalcValue number_value;
	char string_value[RZ_NUMCALC_STRSZ];
	int errors;
	char oc;
	const char *calc_err;
	int calc_i;
	const char *calc_buf;
	int calc_len;
	bool under_calc;
} RNumCalc;

typedef struct rz_num_t {
	ut64 (*callback)(struct rz_num_t *userptr, const char *str, int *ok);
	const char *(*cb_from_value)(struct rz_num_t *userptr, ut64 value, int *ok);
	//	RNumCallback callback;
	ut64 value;
	double fvalue;
	void *userptr;
	int dbz; /// division by zero happened
	RNumCalc nc;
} RNum;

typedef ut64 (*RNumCallback)(struct rz_num_t *self, const char *str, int *ok);
typedef const char *(*RNumCallback2)(struct rz_num_t *self, ut64, int *ok);

RZ_API RNum *rz_num_new(RNumCallback cb, RNumCallback2 cb2, void *ptr);
RZ_API void rz_num_free(RNum *num);
RZ_API char *rz_num_units(char *buf, size_t len, ut64 number);
RZ_API int rz_num_conditional(RNum *num, const char *str);
RZ_API ut64 rz_num_calc(RNum *num, const char *str, const char **err);
RZ_API const char *rz_num_calc_index(RNum *num, const char *p);
RZ_API ut64 rz_num_chs(int cylinder, int head, int sector, int sectorsize);
RZ_API int rz_num_is_valid_input(RNum *num, const char *input_value);
RZ_API ut64 rz_num_get_input_value(RNum *num, const char *input_value);
RZ_API const char *rz_num_get_name(RNum *num, ut64 n);
RZ_API char *rz_num_as_string(RNum *___, ut64 n, bool printable_only);
RZ_API ut64 rz_num_tail(RNum *num, ut64 addr, const char *hex);
RZ_API ut64 rz_num_tail_base(RNum *num, ut64 addr, ut64 off);
RZ_API void rz_num_minmax_swap(ut64 *a, ut64 *b);
RZ_API void rz_num_minmax_swap_i(int *a, int *b); // XXX this can be a cpp macro :??
RZ_API ut64 rz_num_math(RNum *num, const char *str);
RZ_API ut64 rz_num_get(RNum *num, const char *str);
RZ_API int rz_num_to_bits(char *out, ut64 num);
RZ_API int rz_num_to_trits(char *out, ut64 num); //Rename this please
RZ_API int rz_num_rand(int max);
RZ_API void rz_num_irand(void);
RZ_API ut16 rz_num_ntohs(ut16 foo);
RZ_API ut64 rz_get_input_num_value(RNum *num, const char *input_value);
RZ_API bool rz_is_valid_input_num_value(RNum *num, const char *input_value);
RZ_API int rz_num_between(RNum *num, const char *input_value);
RZ_API bool rz_num_is_op(const char c);
RZ_API int rz_num_str_len(const char *str);
RZ_API int rz_num_str_split(char *str);
RZ_API RzList *rz_num_str_split_list(char *str);
RZ_API void *rz_num_dup(ut64 n);
RZ_API double rz_num_cos(double a);
RZ_API double rz_num_sin(double a);
RZ_API double rz_num_get_float(RNum *num, const char *str);

static inline st64 rz_num_abs(st64 num) {
	return num < 0 ? -num : num;
}

#ifdef __cplusplus
}
#endif

#endif //  RZ_NUM_H
