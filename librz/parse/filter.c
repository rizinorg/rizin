// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2019 maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>

#include <rz_types.h>
#include <rz_parse.h>
#include <config.h>

#define isx86separator(x) ( \
	(x) == ' ' || (x) == '\t' || (x) == '\n' || (x) == '\r' || (x) == ' ' || \
	(x) == ',' || (x) == ';' || (x) == '[' || (x) == ']' || \
	(x) == '(' || (x) == ')' || (x) == '{' || (x) == '}' || (x) == '\x1b')

static bool isvalidflag(RzFlagItem *flag) {
	if (flag) {
		if (strstr(flag->name, "main") || strstr(flag->name, "entry")) {
			return true;
		}
		if (strchr(flag->name, '.')) {
			return true;
		}
	}
	return false;
}

static char *findEnd(const char *s) {
	while (*s == 'x' || IS_HEXCHAR(*s)) {
		s++;
		// also skip ansi escape codes here :?
	}
	return strdup(s);
}

static void insert(char *dst, const char *src) {
	char *endNum = findEnd(dst);
	strcpy(dst, src);
	strcpy(dst + strlen(src), endNum);
	free(endNum);
}

// TODO: move into rz_util/rz_str
static void replaceWords(char *s, const char *k, const char *v) {
	for (;;) {
		char *p = strstr(s, k);
		if (!p) {
			break;
		}
		char *s = p + strlen(k);
		char *d = p + strlen(v);
		memmove(d, s, strlen(s) + 1);
		memmove(p, v, strlen(v));
	}
}

static char *findNextNumber(char *op) {
	if (!op) {
		return NULL;
	}
	bool ansi_found = false;
	char *p = op;
	const char *o = NULL;
	while (*p) {
		if (p[0] == 0x1b && p[1] == '[') {
			ansi_found = true;
			p += 2;
			for (; *p && *p != 'J' && *p != 'm' && *p != 'H'; p++) {
				;
			}
			if (*p) {
				p++;
				if (!*p) {
					break;
				}
			}
			o = p - 1;
		} else {
			bool isSpace = ansi_found;
			ansi_found = false;
			if (!isSpace) {
				isSpace = p == op;
				if (!isSpace && o) {
					isSpace = (*o == ' ' || *o == ',' || *o == '[');
				}
			}
			if (*p == '[') {
				p++;
				if (!*p) {
					break;
				}
				if (!IS_DIGIT(*p)) {
					char *t = p;
					for (; *t && *t != ']'; t++) {
						;
					}
					if (*t == ']') {
						continue;
					}
					p = t;
					if (!*p) {
						break;
					}
				}
			}
			if (isSpace) {
				if (IS_DIGIT(*p)) {
					return p;
				}
				if ((*p == '-') && IS_DIGIT(p[1])) {
					return p + 1;
				}
			}
			o = p++;
		}
	}
	return NULL;
}

static void __replaceRegisters(RzReg *reg, char *s, bool x86) {
	int i;
	for (i = 0; i < 64; i++) {
		const char *k = rz_reg_get_name(reg, i);
		if (!k || i == RZ_REG_NAME_PC) {
			continue;
		}
		const char *v = rz_reg_get_role(i);
		if (!v) {
			break;
		}
		if (x86 && *k == 'r') {
			replaceWords(s, k, v);
			char *reg32 = strdup(k);
			*reg32 = 'e';
			replaceWords(s, reg32, v);
		} else {
			replaceWords(s, k, v);
		}
	}
}

static bool filter(RzParse *p, ut64 addr, RzFlag *f, RzAnalysisHint *hint, char *data, char *str, int len, bool big_endian) {
	char *ptr = data, *ptr2, *ptr_backup;
	RzAnalysisFunction *fcn;
	RzFlagItem *flag;
	ut64 off;
	bool x86 = false;
	bool arm = false;
	if (p && p->cur && p->cur->name) {
		if (strstr(p->cur->name, "x86")) {
			x86 = true;
		}
		if (strstr(p->cur->name, "m68k")) {
			x86 = true;
		}
		if (strstr(p->cur->name, "arm")) {
			arm = true;
		}
	}
	if (!data || !p) {
		return 0;
	}
#if FILTER_DWORD
	replaceWords(ptr, "dword ", src);
	replaceWords(ptr, "qword ", src);
#endif
	if (p->subreg) {
		__replaceRegisters(p->analb.analysis->reg, ptr, false);
		if (x86) {
			__replaceRegisters(p->analb.analysis->reg, ptr, true);
		}
	}
	ptr2 = NULL;
	// remove "dword" 2
	char *nptr;
	int count = 0;
	for (count = 0; (nptr = findNextNumber(ptr)); count++) {
		ptr = nptr;
		if (x86) {
			for (ptr2 = ptr; *ptr2 && !isx86separator(*ptr2); ptr2++) {
				;
			}
		} else {
			for (ptr2 = ptr; *ptr2 && (*ptr2 != ']' && (*ptr2 != '\x1b') && !IS_SEPARATOR(*ptr2)); ptr2++) {
				;
			}
		}
		off = rz_num_math(NULL, ptr);
		if (off >= p->minval) {
			fcn = p->analb.get_fcn_in(p->analb.analysis, off, 0);
			if (fcn && fcn->addr == off) {
				*ptr = 0;
				// hack to realign pointer for colours
				ptr2--;
				if (*ptr2 != 0x1b) {
					ptr2++;
				}
				const char *name = fcn->name;
				// TODO: implement realname with flags, because functions dont hold this yet
				if (f->realnames) {
					flag = p->flag_get(f, off);
					if (flag && flag->realname) {
						name = flag->realname;
					}
				}
				snprintf(str, len, "%s%s%s", data, name,
					(ptr != ptr2) ? ptr2 : "");
				return true;
			}
			if (f) {
				RzFlagItem *flag2;
				bool lea = x86 && rz_str_startswith(data, "lea") && (data[3] == ' ' || data[3] == 0x1b);
				bool remove_brackets = false;
				flag = p->flag_get(f, off);
				if ((!flag || arm) && p->subrel_addr) {
					remove_brackets = lea || (arm && p->subrel_addr);
					flag2 = p->flag_get(f, p->subrel_addr);
					if (!flag || arm) {
						flag = flag2;
					}
				}
				if (flag && !strncmp(flag->name, "section.", 8)) {
					flag = rz_flag_get_i(f, off);
				}
				const char *label = fcn ? p->label_get(fcn, off) : NULL;
				if (label || isvalidflag(flag)) {
					if (p->notin_flagspace) {
						if (p->flagspace == flag->space) {
							continue;
						}
					} else if (p->flagspace && (p->flagspace != flag->space)) {
						ptr = ptr2;
						continue;
					}
					// hack to realign pointer for colours
					ptr2--;
					if (*ptr2 != 0x1b) {
						ptr2++;
					}
					ptr_backup = ptr;
					if (remove_brackets && ptr != ptr2 && *ptr) {
						if (*ptr2 == ']') {
							ptr2++;
							for (ptr--; ptr > data && *ptr != '['; ptr--) {
								;
							}
							if (ptr == data) {
								ptr = ptr_backup;
							}
						}
					}
					*ptr = 0;
					char *flagname;
					if (label) {
						flagname = rz_str_newf(".%s", label);
					} else {
						flagname = strdup(f->realnames ? flag->realname : flag->name);
					}
					int maxflagname = p->maxflagnamelen;
					if (maxflagname > 0 && strlen(flagname) > maxflagname) {
						char *doublelower = (char *)rz_str_rstr(flagname, "__");
						char *doublecolon = (char *)rz_str_rstr(flagname, "::");
						char *token = NULL;
						if (doublelower && doublecolon) {
							token = RZ_MAX(doublelower, doublecolon);
						} else {
							token = doublelower ? doublelower : doublecolon;
						}
						if (token) {
							const char *mod = doublecolon ? "(cxx)" : "(...)";
							char *newstr = rz_str_newf("%s%s", mod, token);
							free(flagname);
							flagname = newstr;
						} else {
							const char *lower = rz_str_rstr(flagname, "_");
							char *newstr;
							if (lower) {
								newstr = rz_str_newf("..%s", lower + 1);
							} else {
								newstr = rz_str_newf("..%s", flagname + (strlen(flagname) - maxflagname));
							}
							free(flagname);
							flagname = newstr;
						}
					}
					snprintf(str, len, "%s%s%s", data, flagname, (ptr != ptr2) ? ptr2 : "");
					free(flagname);
					bool banned = false;
					{
						const char *p = strchr(str, '[');
						const char *a = strchr(str, '+');
						const char *m = strchr(str, '*');
						if (p && (a || m)) {
							banned = true;
						}
					}
					if (p->subrel_addr && !banned && lea) { // TODO: use remove_brackets
						int flag_len = strlen(flag->name);
						char *ptr_end = str + strlen(data) + flag_len - 1;
						char *ptr_right = ptr_end + 1, *ptr_left, *ptr_esc;
						bool ansi_found = false;
						if (!*ptr_end) {
							return true;
						}
						while (*ptr_right) {
							if (*ptr_right == 0x1b) {
								while (*ptr_right && *ptr_right != 'm') {
									ptr_right++;
								}
								if (*ptr_right) {
									ptr_right++;
								}
								ansi_found = true;
								continue;
							}
							if (*ptr_right == ']') {
								ptr_left = ptr_esc = ptr_end - flag_len;
								while (ptr_left >= str) {
									if (*ptr_left == '[' &&
										(ptr_left == str || *(ptr_left - 1) != 0x1b)) {
										break;
									}
									ptr_left--;
								}
								if (ptr_left < str) {
									break;
								}
								for (; ptr_esc >= str && *ptr_esc != 0x1b; ptr_esc--) {
									;
								}
								if (ptr_esc < str) {
									ptr_esc = ptr_end - flag_len + 1;
								}
								int copied_len = ptr_end - ptr_esc + 1;
								if (copied_len < 1) {
									break;
								}
								memmove(ptr_left, ptr_esc, copied_len);
								char *dptr_left = strcpy(ptr_left + copied_len,
									(ansi_found && ptr_right - ptr_end + 1 >= 4) ? Color_RESET : "");
								int dlen = strlen(dptr_left);
								dptr_left += dlen;
								char *dptr_end = ptr_right + 1;
								while (*dptr_end) {
									dptr_end++;
								}
								int llen = dptr_end - (ptr_right + 1);
								memmove(dptr_left, ptr_right + 1, llen);
								dptr_left[llen] = 0;
							}
							break;
						}
					}
					return true;
				}
				if (p->subtail) { //  && off > UT32_MAX && addr > UT32_MAX)
					if (off != UT64_MAX) {
						if (off == addr) {
							insert(ptr, "$$");
						} else {
							ut64 tail = rz_num_tail_base(NULL, addr, off);
							if (tail != UT64_MAX) {
								char str[128];
								snprintf(str, sizeof(str), "..%" PFMT64x, tail);
								insert(ptr, str);
							}
						}
					}
				}
			}
		}
		if (hint) {
			const int nw = hint->nword;
			if (count != nw) {
				ptr = ptr2;
				continue;
			}
			int pnumleft, immbase = hint->immbase;
			char num[256] = { 0 }, *pnum, *tmp;
			bool is_hex = false;
			int tmp_count;
			if (hint->offset) {
				*ptr = 0;
				snprintf(str, len, "%s%s%s", data, hint->offset, (ptr != ptr2) ? ptr2 : "");
				return true;
			}
			strncpy(num, ptr, sizeof(num) - 2);
			pnum = num;
			if (!strncmp(pnum, "0x", 2)) {
				is_hex = true;
				pnum += 2;
			}
			for (; *pnum; pnum++) {
				if ((is_hex && IS_HEXCHAR(*pnum)) || IS_DIGIT(*pnum)) {
					continue;
				}
				break;
			}
			*pnum = 0;
			switch (immbase) {
			case 0:
				// do nothing
				break;
			case 1: // hack for ascii
				tmp_count = 0;
				for (tmp = data; tmp < ptr; tmp++) {
					if (*tmp == 0x1b) {
						while (tmp < ptr - 1 && *tmp != 'm') {
							tmp++;
						}
						continue;
					} else if (*tmp == '[') {
						tmp_count++;
					} else if (*tmp == ']') {
						tmp_count--;
					}
				}
				if (tmp_count > 0) {
					ptr = ptr2;
					continue;
				}
				memset(num, 0, sizeof(num));
				pnum = num;
				*pnum++ = '\'';
				pnumleft = sizeof(num) - 2;
				// Convert *off* to ascii string, byte by byte.
				// Since *num* is 256 bytes long, we can omit
				// overflow checks.
				while (off) {
					ut8 ch;
					if (big_endian) {
						ch = off & 0xff;
						off >>= 8;
					} else {
						ch = off >> (8 * (sizeof(off) - 1));
						off <<= 8;
					}

					//Skip first '\x00' bytes
					if (num[1] == '\0' && ch == '\0') {
						continue;
					}
					if (IS_PRINTABLE(ch)) {
						*pnum++ = ch;
						pnumleft--;
					} else {
						int sz = snprintf(pnum, pnumleft, "\\x%2.2x", ch);
						if (sz < 0) {
							break;
						}
						pnum += sz;
						pnumleft -= sz;
					}
				}
				*pnum++ = '\'';
				*pnum = '\0';
				break;
			case 2:
				rz_num_to_bits(num, off);
				strcat(num, "b");
				break;
			case 3: {
				ut64 swap = 0;
				if (big_endian) {
					swap = off & 0xffff;
				} else {
					if (off >> 32) {
						rz_mem_swapendian((ut8 *)&swap, (const ut8 *)&off, sizeof(off));
					} else if (off >> 16) {
						ut32 port = 0;
						rz_mem_swapendian((ut8 *)&port, (const ut8 *)&off, sizeof(port));
						swap = port;
					} else {
						ut16 port = 0;
						rz_mem_swapendian((ut8 *)&port, (const ut8 *)&off, sizeof(port));
						swap = port;
					}
				}
				snprintf(num, sizeof(num), "htons (%d)", (int)(swap & 0xFFFF));
			} break;
			case 8:
				snprintf(num, sizeof(num), "0%o", (int)off);
				break;
			case 10: {
				const RzList *regs = rz_reg_get_list(p->analb.analysis->reg, RZ_REG_TYPE_GPR);
				RzRegItem *reg;
				RzListIter *iter;
				bool imm32 = false;
				rz_list_foreach (regs, iter, reg) {
					if (reg->size == 32 && rz_str_casestr(data, reg->name)) {
						imm32 = true;
						break;
					}
				}
				if (imm32) {
					snprintf(num, sizeof(num), "%" PFMT32d, (st32)off);
					break;
				}
				snprintf(num, sizeof(num), "%" PFMT64d, (st64)off);
			} break;
			case 11:
				snprintf(num, sizeof(num), "%" PFMT64u, off);
				break;
			case 32: {
				ut32 ip32 = off;
				ut8 *ip = (ut8 *)&ip32;
				snprintf(num, sizeof(num), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
			} break;
			case 80:
				if (p && p->analb.analysis && p->analb.analysis->syscall) {
					RzSyscallItem *si;
					si = rz_syscall_get(p->analb.analysis->syscall, off, -1);
					if (si) {
						snprintf(num, sizeof(num), "%s()", si->name);
						rz_syscall_item_free(si);
					} else {
						snprintf(num, sizeof(num), "unknown()");
					}
				}
				break;
			case 16:
				/* do nothing */
			default:
				snprintf(num, sizeof(num), "0x%" PFMT64x, (ut64)off);
				break;
			}
			*ptr = 0;
			snprintf(str, len, "%s%s%s", data, num, (ptr != ptr2) ? ptr2 : "");
			return true;
		}
		ptr = ptr2;
	}
	if (data != str) {
		strncpy(str, data, len);
	} else {
		eprintf("Invalid str/data inputs\n");
	}
	return false;
}

/// filter the opcode in data into str by following the flags and hints information
// XXX this function have too many parameters, we need to simplify this
// XXX too many arguments here
// TODO we shouhld use RzCoreBind and use the hintGet/flagGet methods, but we can also have rflagbind+ranalbind, but kiss pls
// TODO: NEW SIGNATURE: RZ_API char *rz_parse_filter(RzParse *p, ut64 addr, const char *str)
// DEPRECATE
RZ_API bool rz_parse_filter(RzParse *p, ut64 addr, RzFlag *f, RzAnalysisHint *hint, char *data, char *str, int len, bool big_endian) {
	filter(p, addr, f, hint, data, str, len, big_endian);
	if (p->cur && p->cur->filter) {
		return p->cur->filter(p, addr, f, data, str, len, big_endian);
	}
	return false;
}

// easier to use, should replace rz_parse_filter(), but its not using rflag, analhint, endian, etc
RZ_API char *rz_parse_filter_dup(RzParse *p, ut64 addr, const char *opstr) {
	const size_t out_len = 256;
	char *in = strdup(opstr);
	char *out = calloc(out_len, 1);
	if (!rz_parse_filter(p, addr, NULL, NULL, in, out, out_len, false)) {
		free(out);
		return NULL;
	}
	return out;
}
