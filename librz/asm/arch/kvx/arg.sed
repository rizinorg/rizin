#!/bin/sed -f
# SPDX-FileCopyrightText: 2022 Jules Maselbas <jmaselbas@kalray.eu>
# SPDX-License-Identifier: LGPL-3.0-only

s/&kv3_/kv3_decode/g;
s/registera[0123]/registerap/g;

s/register\(.[pq]\?\)[hlxyzt]\?_opnd/_r\1/g;
s/register\([bc]\)o_opnd/_r\1_odd/g;
s/register\([bc]\)e_opnd/_r\1_even/g;
s/system[^_]*_opnd/_rs/g;
s/extend27_offset27_opnd/_off54/;
s/offset27_opnd/_off27/;

s/extend27_upper27_lower10_opnd/_imm64/;
s/extend6_upper27_lower10_opnd/_imm43/;
s/upper27_lower10_opnd/_imm37/;
s/upper27_lower5_opnd/_imm32/;
s/stopbit2_stopbit4_opnd/_stop_bit/;
s/startbit_opnd/_start_bit/;
s/sysnumber_opnd/_sys/;

s/signed10_opnd/_s10/;
s/signed16_opnd/_s16/;
s/unsigned6_opnd/_u6/;

s/pcrel17_opnd/_pcrel17/;
s/pcrel27_opnd/_pcrel27/;
s/byteshift_opnd/_shift/;
