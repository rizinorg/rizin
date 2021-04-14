Z_API RzAsmCode *rz_asm_massemble(RzAsm *a, const char *assembly) {
	int num, stage, ret, idx, ctr, i, linenum = 0;
	char *lbuf = NULL, *ptr2, *ptr = NULL, *ptr_start = NULL;
	const char *asmcpu = NULL;
	RzAsmCode *acode = NULL;
	RzAsmOp op = { 0 };
	ut64 off, pc;
//static void *__dup_val(const void *v) {
//	return (void *)strdup((char *)v);
//}

	char *buf_token = NULL;
	size_t tokens_size = 32;
	char **tokens = calloc(sizeof(char *), tokens_size);
	if (!tokens) {
		return NULL;
	}
	if (!assembly) {
		free(tokens);
		return NULL;
	}
	ht_pp_free(a->flags);
	if (!(a->flags = ht_pp_new(__dup_val, __flag_free_kv, NULL))) {
		free(tokens);
		return NULL;
	}
	if (!(acode = rz_asm_code_new())) {
		free(tokens);
		return NULL;
	}
	if (!(acode->assembly = malloc(strlen(assembly) + 16))) {
		free(tokens);
		return rz_asm_code_free(acode);
	}
	rz_str_ncpy(acode->assembly, assembly, sizeof(acode->assembly) - 1);
	if (!(acode->bytes = calloc(1, 64))) {
		free(tokens);
		return rz_asm_code_free(acode);
	}
	lbuf = strdup(assembly);
	acode->code_align = 0;

	/* consider ,, an alias for a newline */
	lbuf = rz_str_replace(lbuf, ",,", "\n", true);
	/* accept ';' as comments when input is multiline */
	{
		char *nl = strchr(lbuf, '\n');
		if (nl) {
			if (strchr(nl + 1, '\n')) {
				rz_str_replace_char(lbuf, ';', '#');
			}
		}
	}
	// XXX: ops like mov eax, $pc+33 fail coz '+' is not a valid number!!!
	// XXX: must be handled here to be global.. and not arch-specific
	{
		char val[32];
		snprintf(val, sizeof(val), "0x%" PFMT64x, a->pc);
		lbuf = rz_str_replace(lbuf, "$$", val, 1);
	}
	if (a->syscall) {
		char val[32];
		char *aa, *p = strstr(lbuf, "$sys.");
		while (p) {
			char *sp = (char *)rz_str_closer_chr(p, " \n\r#");
			if (sp) {
				char osp = *sp;
				*sp = 0;
				aa = strdup(p);
				*sp = osp;
				num = rz_syscall_get_num(a->syscall, aa + 5);
				snprintf(val, sizeof(val), "%d", num);
				lbuf = rz_str_replace(lbuf, aa, val, 1);
				free(aa);
			}
			p = strstr(p + 5, "$sys.");
		}
	}
	bool labels = !!strchr(lbuf, ':');

	/* Tokenize */
	for (tokens[0] = lbuf, ctr = 0;
		((ptr = strchr(tokens[ctr], ';')) ||
			(ptr = strchr(tokens[ctr], '\n')) ||
			(ptr = strchr(tokens[ctr], '\r')));) {
		if (ctr + 1 >= tokens_size) {
			const size_t new_tokens_size = tokens_size * 2;
			if (sizeof(char *) * new_tokens_size <= sizeof(char *) * tokens_size) {
				// overflow
				eprintf("Too many tokens\n");
				goto fail;
			}
			char **new_tokens = realloc(tokens, sizeof(char *) * new_tokens_size);
			if (!new_tokens) {
				eprintf("Too many tokens\n");
				goto fail;
			}
			tokens_size = new_tokens_size;
			tokens = new_tokens;
		}
		ctr++;
		*ptr = '\0';
		tokens[ctr] = ptr + 1;
	}

#define isavrseparator(x) ((x) == ' ' || (x) == '\t' || (x) == '\n' || (x) == '\r' || (x) == ' ' || \
	(x) == ',' || (x) == ';' || (x) == '[' || (x) == ']' || \
	(x) == '(' || (x) == ')' || (x) == '{' || (x) == '}')

	/* Stage 0-2: Parse labels*/
	/* Stage 3: Assemble */
// XXX: stages must be dynamic. until all equs have been resolved
#define STAGES 5
	pc = a->pc;
	bool inComment = false;
	for (stage = 0; stage < STAGES; stage++) {
		if (stage < 2 && !labels) {
			continue;
		}
		inComment = false;
		rz_asm_set_pc(a, pc);
		for (idx = ret = i = 0; i <= ctr; i++, idx += ret) {
			buf_token = tokens[i];
			if (!buf_token) {
				continue;
			}
			if (inComment) {
				if (!strncmp(ptr_start, "*/", 2)) {
					inComment = false;
				}
				continue;
			}
			// XXX TODO remove arch-specific hacks
			if (!strncmp(a->cur->arch, "avr", 3)) {
				for (ptr_start = buf_token; *ptr_start && isavrseparator(*ptr_start); ptr_start++)
					;
			} else {
				for (ptr_start = buf_token; *ptr_start && IS_SEPARATOR(*ptr_start); ptr_start++)
					;
			}
			if (!strncmp(ptr_start, "/*", 2)) {
				if (!strstr(ptr_start + 2, "*/")) {
					inComment = true;
				}
				continue;
			}
			/* Comments */ {
				bool likely_comment = true;
				char *cptr = strchr(ptr_start, ',');
				ptr = strchr(ptr_start, '#');
				// a comma is probably not followed by a comment
				// 8051 often uses #symbol notation as 2nd arg
				if (cptr && ptr && cptr < ptr) {
					likely_comment = false;
					for (cptr += 1; cptr < ptr; cptr += 1) {
						if (!isspace(*cptr)) {
							likely_comment = true;
							break;
						}
					}
				}
				// # followed by number literal also
				// isn't likely to be a comment
				likely_comment = likely_comment && ptr && !RZ_BETWEEN('0', ptr[1], '9') && ptr[1] != '-';
				if (likely_comment) {
					*ptr = '\0';
				}
			}
			rz_asm_set_pc(a, a->pc + ret);
			off = a->pc;
			ret = 0;
			if (!*ptr_start) {
				continue;
			}
			linenum++;
			/* labels */
			if (labels && (ptr = strchr(ptr_start, ':'))) {
				bool is_a_label = true;
				char *q = ptr_start;
				while (*q) {
					if (*q == ' ') {
						is_a_label = false;
						break;
					}
					q++;
				}
				if (is_a_label) {
					//if (stage != 2) {
					if (ptr_start[1] && ptr_start[1] != ' ') {
						*ptr = 0;
						char *p = strdup(ptr_start);
						*ptr = ':';
						if (acode->code_align) {
							off += (acode->code_align - (off % acode->code_align));
						}
						char *food = rz_str_newf("0x%" PFMT64x, off);
						ht_pp_insert(a->flags, ptr_start, food);
						rz_asm_code_set_equ(acode, p, food);
						free(p);
						free(food);
					}
					//}
					ptr_start = ptr + 1;
				}
			}
			if (!*ptr_start) {
				ret = 0;
				continue;
			}
			if (*ptr_start == '.') { /* pseudo */
				/* TODO: move into a separate function */
				ptr = ptr_start;
				rz_str_trim(ptr);
				if (!strncmp(ptr, ".intel_syntax", 13)) {
					a->syntax = RZ_ASM_SYNTAX_INTEL;
				} else if (!strncmp(ptr, ".att_syntax", 11)) {
					a->syntax = RZ_ASM_SYNTAX_ATT;
				} else if (!strncmp(ptr, ".endian", 7)) {
					rz_asm_set_big_endian(a, atoi(ptr + 7));
				} else if (!strncmp(ptr, ".big_endian", 7 + 4)) {
					rz_asm_set_big_endian(a, true);
				} else if (!strncmp(ptr, ".lil_endian", 7 + 4) || !strncmp(ptr, "little_endian", 7 + 6)) {
					rz_asm_set_big_endian(a, false);
				} else if (!strncmp(ptr, ".asciz", 6)) {
					rz_str_trim(ptr + 8);
					ret = rz_asm_pseudo_string(&op, ptr + 8, 1);
				} else if (!strncmp(ptr, ".string ", 8)) {
					rz_str_trim(ptr + 8);
					char *str = strdup(ptr + 8);
					ret = rz_asm_pseudo_string(&op, str, 1);
					free(str);
				} else if (!strncmp(ptr, ".ascii", 6)) {
					ret = rz_asm_pseudo_string(&op, ptr + 7, 0);
				} else if (!strncmp(ptr, ".align", 6)) {
					ret = rz_asm_pseudo_align(acode, &op, ptr + 7);
				} else if (!strncmp(ptr, ".arm", 4)) {
					rz_asm_use(a, "arm");
					rz_asm_set_bits(a, 32);
					ret = 0;
				} else if (!strncmp(ptr, ".thumb", 6)) {
					rz_asm_use(a, "arm");
					rz_asm_set_bits(a, 16);
					ret = 0;
				} else if (!strncmp(ptr, ".arch ", 6)) {
					ret = rz_asm_pseudo_arch(a, ptr + 6);
				} else if (!strncmp(ptr, ".bits ", 6)) {
					ret = rz_asm_pseudo_bits(a, ptr + 6);
				} else if (!strncmp(ptr, ".fill ", 6)) {
					ret = rz_asm_pseudo_fill(&op, ptr + 6);
				} else if (!strncmp(ptr, ".kernel ", 8)) {
					rz_syscall_setup(a->syscall, a->cur->arch, a->bits, asmcpu, ptr + 8);
				} else if (!strncmp(ptr, ".cpu ", 5)) {
					rz_asm_set_cpu(a, ptr + 5);
				} else if (!strncmp(ptr, ".os ", 4)) {
					rz_syscall_setup(a->syscall, a->cur->arch, a->bits, asmcpu, ptr + 4);
				} else if (!strncmp(ptr, ".hex ", 5)) {
					ret = rz_asm_op_set_hex(&op, ptr + 5);
				} else if ((!strncmp(ptr, ".int16 ", 7)) || !strncmp(ptr, ".short ", 7)) {
					ret = rz_asm_pseudo_int16(a, &op, ptr + 7);
				} else if (!strncmp(ptr, ".int32 ", 7)) {
					ret = rz_asm_pseudo_int32(a, &op, ptr + 7);
				} else if (!strncmp(ptr, ".int64 ", 7)) {
					ret = rz_asm_pseudo_int64(a, &op, ptr + 7);
				} else if (!strncmp(ptr, ".size", 5)) {
					ret = true; // do nothing, ignored
				} else if (!strncmp(ptr, ".section", 8)) {
					ret = true; // do nothing, ignored
				} else if ((!strncmp(ptr, ".byte ", 6)) || (!strncmp(ptr, ".int8 ", 6))) {
					ret = rz_asm_pseudo_byte(&op, ptr + 6);
				} else if (!strncmp(ptr, ".glob", 5)) { // .global .globl
					//	eprintf (".global directive not yet implemented\n");
					ret = 0;
					continue;
				} else if (!strncmp(ptr, ".equ ", 5)) {
					ptr2 = strchr(ptr + 5, ',');
					if (!ptr2) {
						ptr2 = strchr(ptr + 5, '=');
					}
					if (!ptr2) {
						ptr2 = strchr(ptr + 5, ' ');
					}
					if (ptr2) {
						*ptr2 = '\0';
						rz_asm_code_set_equ(acode, ptr + 5, ptr2 + 1);
					} else {
						eprintf("Invalid syntax for '.equ': Use '.equ <word> <word>'\n");
					}
				} else if (!strncmp(ptr, ".org ", 5)) {
					ret = rz_asm_pseudo_org(a, ptr + 5);
				} else if (rz_str_startswith(ptr, ".offset ")) {
					eprintf("Invalid use of the .offset directory. This directive is only supported in rizin -c 'waf'.\n");
				} else if (!strncmp(ptr, ".text", 5)) {
					acode->code_offset = a->pc;
				} else if (!strncmp(ptr, ".data", 5)) {
					acode->data_offset = a->pc;
				} else if (!strncmp(ptr, ".incbin", 7)) {
					if (ptr[7] != ' ') {
						eprintf("incbin missing filename\n");
						continue;
					}
					ret = rz_asm_pseudo_incbin(&op, ptr + 8);
				} else {
					eprintf("Unknown directive (%s)\n", ptr);
					goto fail;
				}
				if (!ret) {
					continue;
				}
				if (ret < 0) {
					eprintf("!!! Oops (%s)\n", ptr);
					goto fail;
				}
			} else { /* Instruction */
				char *str = ptr_start;
				rz_str_trim(str);
				if (a->ifilter) {
					rz_parse_parse(a->ifilter, ptr_start, ptr_start);
				}
				if (acode->equs) {
					if (!*ptr_start) {
						continue;
					}
					str = rz_asm_code_equ_replace(acode, strdup(ptr_start));
					ret = rz_asm_assemble(a, &op, str);
					free(str);
				} else {
					if (!*ptr_start) {
						continue;
					}
					ret = rz_asm_assemble(a, &op, ptr_start);
				}
			}
			if (stage == STAGES - 1) {
				if (ret < 1) {
					eprintf("Cannot assemble '%s' at line %d\n", ptr_start, linenum);
					goto fail;
				}
				acode->len = idx + ret;
				char *newbuf = realloc(acode->bytes, (idx + ret) * 2);
				if (!newbuf) {
					goto fail;
				}
				acode->bytes = (ut8 *)newbuf;
				memcpy(acode->bytes + idx, rz_strbuf_get(&op.buf), rz_strbuf_length(&op.buf));
				memset(acode->bytes + idx + ret, 0, idx + ret);
				if (op.buf_inc && rz_buf_size(op.buf_inc) > 1) {
					char *inc = rz_buf_to_string(op.buf_inc);
					rz_buf_free(op.buf_inc);
					if (inc) {
						ret += rz_hex_str2bin(inc, acode->bytes + idx + ret);
						free(inc);
					}
				}
			}
		}
	}
	free(lbuf);
	free(tokens);
	return acode;
fail:
	free(lbuf);
	free(tokens);
	return rz_asm_code_free(acode);
}