// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_OPTION_H_
#define RZ_OPTION_H_

#include <rz_util.h>

#define RZ_OPTION(type) type##Option

#define RZ_OPTION_NEW(type)       rz_option_##type##_new
#define RZ_OPTION_NONE(type)      rz_option_##type##_none
#define RZ_OPTION_IS_NONE(type)   rz_option_##type##_is_none
#define RZ_OPTION_GET_VALUE(type) rz_option_##type##_get_value

#define DEFINE_RZ_OPTION(type) typedef struct rz_option_##type##_t type##Option

#define DEFINE_RZ_OPTION_NEW(type)       type##Option rz_option_##type##_new(type value)
#define DEFINE_RZ_OPTION_NONE(type)      type##Option rz_option_##type##_none(void)
#define DEFINE_RZ_OPTION_IS_NONE(type)   bool rz_option_##type##_is_none(type##Option option)
#define DEFINE_RZ_OPTION_GET_VALUE(type) type rz_option_##type##_get_value(type##Option option)

#define IMPLEMENT_RZ_OPTION(type) \
	typedef struct rz_option_##type##_t { \
		bool is_none; \
		type value; \
	} type##Option

#define IMPLEMENT_RZ_OPTION_NEW(type) \
	type##Option rz_option_##type##_new(type value) { \
		return (type##Option){ .is_none = false, .value = value }; \
	}

#define IMPLEMENT_RZ_OPTION_NONE(type) \
	type##Option rz_option_##type##_none(void) { \
		return (type##Option){ .is_none = true }; \
	}

#define IMPLEMENT_RZ_OPTION_IS_NONE(type) \
	bool rz_option_##type##_is_none(type##Option option) { \
		return option.is_none; \
	}

#define IMPLEMENT_RZ_OPTION_GET_VALUE(type) \
	type rz_option_##type##_get_value(type##Option option) { \
		rz_warn_if_fail(rz_option_##type##_is_none(option)); \
		return option.value; \
	}

#endif // !RZ_OPTION_H_
