// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-FileCopyrightText: 2020 Riccardo Schirone <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2017 SchumBlubBlub <6bx0lm+7siazd414punk@sharklasers.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_STR_UTIL_H
#define RZ_STR_UTIL_H

#define IS_NULLSTR(x)   (!(x) || !*(x))
#define IS_WHITECHAR(x) ((x) == ' ' || (x) == '\t' || (x) == '\n' || (x) == '\r')
#define IS_SEPARATOR(x) ((x) == ' ' || (x) == '\t' || (x) == '\n' || (x) == '\r' || (x) == ' ' || \
	(x) == ',' || (x) == ';' || (x) == ':' || (x) == '[' || (x) == ']' || \
	(x) == '(' || (x) == ')' || (x) == '{' || (x) == '}')
#define IS_HEXCHAR(x)    (((x) >= '0' && (x) <= '9') || ((x) >= 'a' && (x) <= 'f') || ((x) >= 'A' && (x) <= 'F'))
#define IS_PRINTABLE(x)  ((x) >= ' ' && (x) <= '~')
#define IS_DIGIT(x)      ((x) >= '0' && (x) <= '9')
#define IS_OCTAL(x)      ((x) >= '0' && (x) <= '7')
#define IS_WHITESPACE(x) ((x) == ' ' || (x) == '\t')
#define IS_UPPER(c)      ((c) >= 'A' && (c) <= 'Z')
#define IS_LOWER(c)      ((c) >= 'a' && (c) <= 'z')
#define IS_ALPHANUM(c)   (IS_DIGIT(c) || IS_UPPER(c) || IS_LOWER(c))

#endif //  RZ_STR_UTIL_H
