# SPDX-FileCopyrightText: 2022 Jules Maselbas <jmaselbas@kalray.eu>
# SPDX-License-Identifier: LGPL-3.0-only

SRC=https://raw.githubusercontent.com/kalray/gdb-binutils/binutils-2_35_2/coolidge/opcodes/kv3-opc.c
kv3.opc: kv3-opc.c Makefile opc.sed analysis.sed arg.sed
	echo "// SPDX-FileCopyrightText: 2010-2018 Kalray SA." > $@
	echo "// SPDX-License-Identifier: GPL-2.0-or-later" >> $@
	echo "// derived from $(SRC)" >> $@
	./opc.sed $< | ./analysis.sed | ./arg.sed >> $@
kv3-opc.c:
	curl $(SRC) > $@
