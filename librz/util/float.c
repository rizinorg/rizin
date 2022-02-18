#include "float_internal.c"

static inline ut32 rz_float_info_bin32(RzFloatInfo which_info) {
    switch (which_info) {
        case RZ_FLOAT_INFO_BASE:
            return 2;
        case RZ_FLOAT_INFO_EXP_LEN:
            return 8;
        case RZ_FLOAT_INFO_MAN_LEN:
            return 23;
        default:
            return 0;
    }
}

static inline ut32 rz_float_info_bin64(RzFloatInfo which_info) {
    switch (which_info) {
        case RZ_FLOAT_INFO_BASE:
            return 2;
        case RZ_FLOAT_INFO_EXP_LEN:
            return 11;
        case RZ_FLOAT_INFO_MAN_LEN:
            return 52;
        default:
            return 0;
    }
}

static inline ut32 rz_float_info_bin128(RzFloatInfo which_info) {
    switch (which_info) {
        case RZ_FLOAT_INFO_BASE:
            return 2;
        case RZ_FLOAT_INFO_EXP_LEN:
            return 15;
        case RZ_FLOAT_INFO_MAN_LEN:
            return 112;
        default:
            return 0;
    }
}

/// Be used in RzFloat
RZ_API ut32 rz_float_get_format_info(RzFloatFormat format, RzFloatInfo which_info) {
    switch (format) {
        case RZ_FLOAT_IEEE754_BIN_32:
            return rz_float_info_bin32(which_info);
        case RZ_FLOAT_IEEE754_BIN_64:
            return rz_float_info_bin64(which_info);
        case RZ_FLOAT_IEEE754_BIN_128:
            return rz_float_info_bin128(which_info);
        case RZ_FLOAT_IEEE754_DEC_64:
        case RZ_FLOAT_IEEE754_DEC_128:
        default:
            RZ_LOG_ERROR("TODO");
            return 0;
    }
}