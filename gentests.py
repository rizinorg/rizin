#!/usr/bin/env python3
######################################################################
# Dear reviewer, please ignore this file. I will delete it later :-) #
######################################################################

import itertools
import subprocess

bitness = ["", "w", "b", "h"]
acc = ["", "a", "al", "l"]

def make_test(disasm):
    b = subprocess.run(["rz-asm", "-a", "arm.llvm", "-b", "64", disasm], capture_output=True).stdout
    b = b.decode("utf-8").strip()
    print(f"d \"{disasm}\" {b} 0x0 fixme")

def gen_tests(op):
    for (b, a) in itertools.product(bitness, acc):
        reg = "w"
        if b == "w":
            b = ""
        elif b == "":
            reg = "x"
        make_test(f"ld{op}{a}{b} {reg}0, {reg}1, [x2]")
        if a == "" or a == "l":
            make_test(f"st{op}{a}{b} {reg}0, [x1]")

gen_tests("smax")
gen_tests("smin")
gen_tests("umax")
gen_tests("umin")
