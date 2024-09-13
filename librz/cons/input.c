// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include <string.h>
#if __UNIX__
#include <errno.h>
#elif __WINDOWS__
#include <rz_windows.h>
#endif

#define I rz_cons_singleton()

RZ_API int rz_cons_controlz(int ch) {
#if __UNIX__
	if (ch == 0x1a) {
		rz_cons_show_cursor(true);
		rz_cons_enable_mouse(false);
		rz_sys_stop();
		return 0;
	}
#endif
	return ch;
}

// 96 - wheel up
// 97 - wheel down
// 95 - mouse up
// 92 - mouse down
static int __parseMouseEvent(void) {
	char xpos[32];
	char ypos[32];
	(void)rz_cons_readchar(); // skip first char
	int ch2 = rz_cons_readchar();

	// [32M - mousedown
	// [35M - mouseup
	if (ch2 == ';') {
		int i;
		// read until next ;
		for (i = 0; i < sizeof(xpos) - 1; i++) {
			char ch = rz_cons_readchar();
			if (ch == ';' || ch == 'M') {
				break;
			}
			xpos[i] = ch;
		}
		xpos[i] = 0;
		for (i = 0; i < sizeof(ypos) - 1; i++) {
			char ch = rz_cons_readchar();
			if (ch == ';' || ch == 'M') {
				break;
			}
			ypos[i] = ch;
		}
		ypos[i] = 0;
		rz_cons_set_click(atoi(xpos), atoi(ypos), MOUSE_DEFAULT);
		(void)rz_cons_readchar();
		// ignored
		int ch = rz_cons_readchar();
		if (ch == 27) {
			ch = rz_cons_readchar(); // '['
		}
		if (ch == '[') {
			do {
				ch = rz_cons_readchar(); // '3'
			} while (ch != 'M');
		}
	}
	return 0;
}

RZ_API int rz_cons_arrow_to_hjkl(int ch) {
	I->mouse_event = MOUSE_NONE;
	/* emacs */
	switch ((ut8)ch) {
	case 0xc3:
		rz_cons_readchar();
		ch = 'K';
		break; // emacs repag (alt + v)
	case 0x16: ch = 'J'; break; // emacs avpag (ctrl + v)
	case 0x10: ch = 'k'; break; // emacs up (ctrl + p)
	case 0x0e: ch = 'j'; break; // emacs down (ctrl + n)
	case 0x06: ch = 'l'; break; // emacs right (ctrl + f)
	case 0x02: ch = 'h'; break; // emacs left (ctrl + b)
	}
	if (ch != 0x1b) {
		return ch;
	}
	ch = rz_cons_readchar();
	if (!ch) {
		return 0;
	}
	switch (ch) {
	case 0x1b:
		ch = 'q'; // XXX: must be 0x1b (RZ_CONS_KEY_ESC)
		break;
	case 0x4f: // function keys from f1 to f4
		ch = rz_cons_readchar();
#if defined(__HAIKU__)
		/* Haiku't don use the '[' char for function keys */
		if (ch > 'O') { /* only in f1..f12 function keys */
			ch = 0xf1 + (ch & 0xf);
			break;
		}
	case '[': // 0x5b function keys (2)
		/* Haiku need ESC + [ for PageUp and PageDown  */
		if (ch < 'A' || ch == '[') {
			ch = rz_cons_readchar();
		}
#else
		switch (ch) { // Arrow keys
		case 'A': ch = 'k'; break;
		case 'B': ch = 'j'; break;
		case 'C': ch = 'l'; break;
		case 'D': ch = 'h'; break;
		default: ch = 0xf1 + (ch & 0xf); break;
		}
		break;
	case '[': // function keys (2)
		ch = rz_cons_readchar();
#endif
		switch (ch) {
		case '<': {
			// https://tintin.mudhalla.net/info/xterm/ CSI < flag ; x ; y M/m
			char pos[8] = { 0 };
			int p = 0;
			int x = 0;
			int y = 0;
			int sc = 0;

			char vel[8] = { 0 };
			int vn = 0;
			do {
				ch = rz_cons_readchar();
				if (sc > 0) {
					if (ch >= '0' && ch <= '9') {
						pos[p++] = ch;
					}
				}
				if (sc < 1) {
					vel[vn++] = ch;
				}
				if (ch == ';') {
					if (sc == 1) {
						pos[p++] = 0;
						x = atoi(pos);
					}
					sc++;
					p = 0;
				}
			} while (ch != 'M' && ch != 'm');
			int nvel = atoi(vel);
			MouseEvent event = MOUSE_DEFAULT;
			switch (nvel) {
			case 0:
				event = ch == 'M' ? LEFT_PRESS : LEFT_RELEASE;
				break;
			case 2: // right click
				if (ch == 'M') {
					return INT8_MAX;
				}
				return -INT8_MAX;
			case 64: // wheel up
				return 'k';
			case 65: // wheel down
				return 'j';
			}
			// setup click
			pos[p++] = 0;
			y = atoi(pos);
			rz_cons_set_click(x, y, event);
		}
			return 0;
		case '[':
			ch = rz_cons_readchar();
			switch (ch) {
			case '2': ch = RZ_CONS_KEY_F11; break;
			case 'A': ch = RZ_CONS_KEY_F1; break;
			case 'B': ch = RZ_CONS_KEY_F2; break;
			case 'C': ch = RZ_CONS_KEY_F3; break;
			case 'D': ch = RZ_CONS_KEY_F4; break;
			}
			break;
		case '9':
			// handle mouse wheel
			//		__parseWheelEvent();
			ch = rz_cons_readchar();
			// 6 is up
			// 7 is down
			I->mouse_event = MOUSE_DEFAULT;
			if (ch == '6') {
				ch = 'k';
			} else if (ch == '7') {
				ch = 'j';
			} else {
				// unhandled case
				ch = 0;
			}
			int ch2;
			do {
				ch2 = rz_cons_readchar();
			} while (ch2 != 'M');
			break;
		case '3':
			// handle mouse down /up events (35 vs 32)
			__parseMouseEvent();
			return 0;
			break;
		case '2':
			ch = rz_cons_readchar();
			switch (ch) {
			case 0x7e:
				ch = RZ_CONS_KEY_F12;
				break;
			default:
				rz_cons_readchar();
				switch (ch) {
				case '0': ch = RZ_CONS_KEY_F9; break;
				case '1': ch = RZ_CONS_KEY_F10; break;
				case '3': ch = RZ_CONS_KEY_F11; break;
				}
				break;
			}
			break;
		case '1':
			ch = rz_cons_readchar();
			switch (ch) {
			case '1': ch = RZ_CONS_KEY_F1; break;
			case '2': ch = RZ_CONS_KEY_F2; break;
			case '3': ch = RZ_CONS_KEY_F3; break;
			case '4': ch = RZ_CONS_KEY_F4; break;
			case '5': ch = RZ_CONS_KEY_F5; break;
			// case '6': ch = RZ_CONS_KEY_F5; break;
			case '7': ch = RZ_CONS_KEY_F6; break;
			case '8': ch = RZ_CONS_KEY_F7; break;
			case '9': ch = RZ_CONS_KEY_F8; break;
#if 0
			case '5':
				rz_cons_readchar ();
				ch = 0xf5;
				break;
			case '6':
				rz_cons_readchar ();
				ch = 0xf7;
				break;
			case '7':
				rz_cons_readchar ();
				ch = 0xf6;
				break;
			case '8':
				rz_cons_readchar ();
				ch = 0xf7;
				break;
			case '9':
				rz_cons_readchar ();
				ch = 0xf8;
				break;
#endif
			// Support st/st-256color term and others
			// for shift+arrows
			case ';': // arrow+mod
				ch = rz_cons_readchar();
				switch (ch) {
				case '2': // arrow+shift
					ch = rz_cons_readchar();
					switch (ch) {
					case 'A': ch = 'K'; break;
					case 'B': ch = 'J'; break;
					case 'C': ch = 'L'; break;
					case 'D': ch = 'H'; break;
					}
					break;
					// add other modifiers
				}
				break;
			case ':': // arrow+shift
				rz_cons_readchar();
				ch = rz_cons_readchar();
				switch (ch) {
				case 'A': ch = 'K'; break;
				case 'B': ch = 'J'; break;
				case 'C': ch = 'L'; break;
				case 'D': ch = 'H'; break;
				}
				break;
			} // F9-F12 not yet supported!!
			break;
		case '5':
			ch = 'K';
			rz_cons_readchar();
			break; // repag
		case '6':
			ch = 'J';
			rz_cons_readchar();
			break; // avpag
		/* arrow keys */
		case 'A': ch = 'k'; break; // up
		case 'B': ch = 'j'; break; // down
		case 'C': ch = 'l'; break; // right
		case 'D':
			ch = 'h';
			break; // left
		// Support rxvt-unicode term for shift+arrows
		case 'a': ch = 'K'; break; // shift+up
		case 'b': ch = 'J'; break; // shift+down
		case 'c': ch = 'L'; break; // shift+right
		case 'd': ch = 'H'; break; // shift+left
		case 'M': ch = __parseMouseEvent(); break;
		}
		break;
	}
	return ch;
}

// XXX no control for max length here?!?!
RZ_API int rz_cons_fgets(char *buf, int len, int argc, const char **argv) {
#define RETURN(x) \
	{ \
		ret = x; \
		goto beach; \
	}
	RzCons *cons = rz_cons_singleton();
	int ret = 0, color = cons->context->pal.input && *cons->context->pal.input;
	if (cons->echo) {
		rz_cons_set_raw(false);
		rz_cons_show_cursor(true);
	}
#if 0
	int mouse = rz_cons_enable_mouse (false);
	rz_cons_enable_mouse (false);
	rz_cons_flush ();
#endif
	errno = 0;
	if (cons->user_fgets) {
		RETURN(cons->user_fgets(buf, len, cons->user_fgets_user));
	}
	printf("%s", cons->line->prompt);
	fflush(stdout);
	*buf = '\0';
	if (color) {
		const char *p = cons->context->pal.input;
		if (RZ_STR_ISNOTEMPTY(p)) {
			fwrite(p, strlen(p), 1, stdout);
			fflush(stdout);
		}
	}
	if (!fgets(buf, len, cons->fdin)) {
		if (color) {
			printf(Color_RESET);
			fflush(stdout);
		}
		RETURN(-1);
	}
	if (feof(cons->fdin)) {
		if (color) {
			printf(Color_RESET);
		}
		RETURN(-2);
	}
	rz_str_trim_tail(buf);
	if (color) {
		printf(Color_RESET);
	}
	ret = strlen(buf);
beach:
	// rz_cons_enable_mouse (mouse);
	return ret;
}

RZ_API int rz_cons_any_key(const char *msg) {
	if (msg && *msg) {
		rz_cons_printf("\n-- %s --\n", msg);
	} else {
		rz_cons_print("\n--press any key--\n");
	}
	rz_cons_flush();
	return rz_cons_readchar();
	// rz_cons_strcat ("\x1b[2J\x1b[0;0H");
}

extern void resizeWin(void);

#if __WINDOWS__
static int __cons_readchar_w32(ut32 usec) {
	int ch = 0;
	BOOL ret;
	DWORD mode, out;
	HANDLE h;
	INPUT_RECORD irInBuf = { 0 };
	CONSOLE_SCREEN_BUFFER_INFO info = { 0 };
	wchar_t surrogate[3] = { 0 };
	const bool mouse_enabled = I->mouse;
	bool click_n_drag = false;
	bool shift = false;
	bool alt = false;
	bool ctrl = false;
	bool do_break = false;
	const bool is_console = rz_cons_isatty();
	void *bed;
	I->mouse_event = MOUSE_NONE;
	h = GetStdHandle(STD_INPUT_HANDLE);
	GetConsoleMode(h, &mode);
	DWORD newmode = ENABLE_WINDOW_INPUT;
	if (I->vtmode == RZ_VIRT_TERM_MODE_COMPLETE) {
		newmode |= ENABLE_VIRTUAL_TERMINAL_INPUT;
	}
	newmode |= mode;
	SetConsoleMode(h, newmode);
	do {
		bed = rz_cons_sleep_begin();
		if (usec) {
			if (WaitForSingleObject(h, usec) == WAIT_TIMEOUT) {
				rz_cons_sleep_end(bed);
				return -1;
			}
		}
		if (I->term_pty || !is_console) {
			if (I->term_pty) {
				rz_cons_enable_mouse(I->mouse);
			}
			ret = ReadFile(h, &ch, 1, &out, NULL);
		} else {
			ret = ReadConsoleInputW(h, &irInBuf, 1, &out);
		}
		rz_cons_sleep_end(bed);
		if (!ret) {
			ch = -1;
			break;
		}
		if (irInBuf.EventType == MENU_EVENT || irInBuf.EventType == FOCUS_EVENT) {
			continue;
		}
		if (mouse_enabled) {
			rz_cons_enable_mouse(true);
		}
		if (irInBuf.EventType == MOUSE_EVENT && I->vtmode != RZ_VIRT_TERM_MODE_COMPLETE) {
			if (irInBuf.Event.MouseEvent.dwEventFlags == MOUSE_MOVED) {
				if (irInBuf.Event.MouseEvent.dwButtonState == FROM_LEFT_1ST_BUTTON_PRESSED) {
					click_n_drag = true;
				}
				continue;
			}
			if (irInBuf.Event.MouseEvent.dwEventFlags == MOUSE_WHEELED) {
				if (irInBuf.Event.MouseEvent.dwButtonState & 0xFF000000) {
					ch = ctrl ? 'J' : 'j';
				} else {
					ch = ctrl ? 'K' : 'k';
				}
				I->mouse_event = MOUSE_DEFAULT;
			}
			switch (irInBuf.Event.MouseEvent.dwButtonState) {
			case FROM_LEFT_1ST_BUTTON_PRESSED:
				GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info);
				int rel_y = irInBuf.Event.MouseEvent.dwMousePosition.Y - info.srWindow.Top;
				rz_cons_set_click(irInBuf.Event.MouseEvent.dwMousePosition.X + 1, rel_y + 1, LEFT_PRESS);
				do_break = true;
				break;
			} // TODO: Handle more buttons?
		}

		if (click_n_drag) {
			rz_cons_set_click(irInBuf.Event.MouseEvent.dwMousePosition.X + 1, irInBuf.Event.MouseEvent.dwMousePosition.Y + 1, MOUSE_DEFAULT);
			do_break = true;
		}

		if (irInBuf.EventType == KEY_EVENT) {
			shift = irInBuf.Event.KeyEvent.dwControlKeyState & SHIFT_PRESSED;
			alt = irInBuf.Event.KeyEvent.dwControlKeyState & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED);
			ctrl = irInBuf.Event.KeyEvent.dwControlKeyState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED);
			int state = 1;
			state += shift ? 1 : 0;
			state += alt ? 2 : 0;
			state += ctrl ? 4 : 0;
			if (irInBuf.Event.KeyEvent.bKeyDown) {
				if (irInBuf.Event.KeyEvent.uChar.UnicodeChar) {
					if (IS_LOW_SURROGATE(irInBuf.Event.KeyEvent.uChar.UnicodeChar)) {
						surrogate[1] = irInBuf.Event.KeyEvent.uChar.UnicodeChar;
					} else {
						surrogate[0] = irInBuf.Event.KeyEvent.uChar.UnicodeChar;
						if (IS_HIGH_SURROGATE(irInBuf.Event.KeyEvent.uChar.UnicodeChar)) {
							continue;
						}
					}
					ut8 *tmp = rz_utf16_to_utf8(surrogate);
					memset(surrogate, 0, sizeof(surrogate));
					if (tmp) {
						if (alt) {
							ch = '\x1b';
							rz_cons_readpush(tmp, strlen(tmp));
						} else {
							ch = *tmp;
							if (tmp[1]) {
								rz_cons_readpush(&tmp[1], strlen(&tmp[1]));
							}
						}
						free(tmp);
					}
				} else if (I->vtmode != RZ_VIRT_TERM_MODE_COMPLETE) {
					char *c;
					char mod[2];
					sprintf(mod, "%d", state);
					switch (irInBuf.Event.KeyEvent.wVirtualKeyCode) {
					case VK_UP: c = "A"; break;
					case VK_DOWN: c = "B"; break;
					case VK_RIGHT: c = "C"; break;
					case VK_LEFT: c = "D"; break;
					case VK_HOME: c = "1"; break;
					case VK_INSERT: c = "2"; break;
					case VK_DELETE: c = "3"; break;
					case VK_END: c = "4"; break;
					case VK_PRIOR: c = "5"; break;
					case VK_NEXT: c = "6"; break;
					case VK_F1: c = "11"; break;
					case VK_F2: c = "12"; break;
					case VK_F3: c = "13"; break;
					case VK_F4: c = "14"; break;
					case VK_F5: c = "15"; break;
					case VK_F6: c = "17"; break;
					case VK_F7: c = "18"; break;
					case VK_F8: c = "19"; break;
					case VK_F9: c = "20"; break;
					case VK_F10: c = "21"; break;
					case VK_F11: c = "23"; break;
					case VK_F12: c = "24"; break;
					default: c = NULL; break;
					}
					if (c) {
						ch = '\x1b';
						rz_cons_readpush("[[", 1);
						if (state != 1 && isalpha((int)*c)) {
							rz_cons_readpush("1;", 2);
							rz_cons_readpush(mod, 1);
						}
						rz_cons_readpush(c, strlen(c));
						if (!isalpha((int)*c)) {
							if (state != 1) {
								rz_cons_readpush(";", 1);
								rz_cons_readpush(mod, 1);
							}
							rz_cons_readpush("~", 1);
						}
					}
				}
			}
		}
		if (irInBuf.EventType == WINDOW_BUFFER_SIZE_EVENT) {
			resizeWin();
		}
	} while (ch == 0 && !do_break);
	SetConsoleMode(h, mode);
	return ch;
}
#endif

RZ_API int rz_cons_readchar_timeout(ut32 usec) {
	char ch;
	if (rz_cons_readbuffer_readchar(&ch)) {
		return ch;
	}
#if __UNIX__
	struct timeval tv;
	fd_set fdset, errset;
	FD_ZERO(&fdset);
	FD_ZERO(&errset);
	FD_SET(0, &fdset);
	tv.tv_sec = 0; // usec / 1000;
	tv.tv_usec = 1000 * usec;
	rz_cons_set_raw(1);
	if (select(1, &fdset, NULL, &errset, &tv) == 1) {
		return rz_cons_readchar();
	}
	rz_cons_set_raw(0);
	// timeout
	return -1;
#else
	return __cons_readchar_w32(usec);
#endif
}

RZ_API bool rz_cons_readpush(const char *str, int len) {
	char *res = (len + I->input->readbuffer_length > 0) ? realloc(I->input->readbuffer, len + I->input->readbuffer_length) : NULL;
	if (res) {
		I->input->readbuffer = res;
		memmove(I->input->readbuffer + I->input->readbuffer_length, str, len);
		I->input->readbuffer_length += len;
		return true;
	}
	return false;
}

RZ_API void rz_cons_readflush(void) {
	RZ_FREE(I->input->readbuffer);
	I->input->readbuffer_length = 0;
}

RZ_API void rz_cons_switchbuf(bool active) {
	I->input->bufactive = active;
}

#if !__WINDOWS__
extern volatile sig_atomic_t sigwinchFlag;
#endif

RZ_API bool rz_cons_readbuffer_readchar(char *ch) {
	if (I->input->readbuffer_length <= 0) {
		return false;
	}
	*ch = *I->input->readbuffer;
	I->input->readbuffer_length--;
	memmove(I->input->readbuffer, I->input->readbuffer + 1, I->input->readbuffer_length);
	return true;
}

RZ_API int rz_cons_readchar(void) {
	char buf[2], ch;
	buf[0] = -1;
	if (rz_cons_readbuffer_readchar(&ch)) {
		return ch;
	}
	rz_cons_set_raw(1);
#if __WINDOWS__
	return __cons_readchar_w32(0);
#else
	void *bed = rz_cons_sleep_begin();

	// Blocks until either stdin has something to read or a signal happens.
	// This serves to check if the terminal window was resized. It avoids the race
	// condition that could happen if we did not use pselect or select in case SIGWINCH
	// was handled immediately before the blocking call (select or read). The race is
	// prevented from happening by having SIGWINCH blocked process-wide except for in
	// pselect (that is what pselect is for).
	fd_set readfds;
	sigset_t sigmask;
	FD_ZERO(&readfds);
	FD_SET(STDIN_FILENO, &readfds);
	rz_signal_sigmask(0, NULL, &sigmask);
	sigdelset(&sigmask, SIGWINCH);
	while (pselect(STDIN_FILENO + 1, &readfds, NULL, NULL, NULL, &sigmask) == -1) {
		if (errno == EBADF) {
			eprintf("rz_cons_readchar (): EBADF\n");
			return -1;
		}
		if (sigwinchFlag) {
			sigwinchFlag = 0;
			resizeWin();
		}
	}

	ssize_t ret = read(STDIN_FILENO, buf, 1);
	rz_cons_sleep_end(bed);
	if (ret != 1) {
		return -1;
	}
	if (I->input->bufactive) {
		rz_cons_set_raw(0);
	}
	return rz_cons_controlz(buf[0]);
#endif
}

RZ_API bool rz_cons_yesno(int def, const char *fmt, ...) {
	va_list ap;
	ut8 key = (ut8)def;
	va_start(ap, fmt);

	if (!rz_cons_is_interactive()) {
		va_end(ap);
		return def == 'y';
	}
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fflush(stderr);
	rz_cons_set_raw(true);
	char buf[] = " ?\n";
	if (read(0, buf + 1, 1) == 1) {
		key = (ut8)buf[1];
		if (write(2, buf, 3) == 3) {
			if (key == 'Y') {
				key = 'y';
			}
			rz_cons_set_raw(false);
			if (key == '\n' || key == '\r') {
				key = def;
			}
			return key == 'y';
		}
	}
	return false;
}

RZ_API char *rz_cons_input(const char *msg) {
	char *oprompt = rz_line_get_prompt(I->line);
	if (!oprompt) {
		return NULL;
	}
	char buf[1024];
	if (msg) {
		rz_line_set_prompt(I->line, msg);
	} else {
		rz_line_set_prompt(I->line, "");
	}
	buf[0] = 0;
	rz_cons_fgets(buf, sizeof(buf), 0, NULL);
	rz_line_set_prompt(I->line, oprompt);
	free(oprompt);
	return rz_str_dup(buf);
}
