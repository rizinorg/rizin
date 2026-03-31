import sys
import rzpipe

rzp = rzpipe.open("bins/elf/analysis/calls_x64", flags=["-a", "x86", "-d", "-1"])
expected = "child received signal 9"
sys.stdout.write(rzp.cmd(""))  # should print nothing
actual = rzp.cmd("wx ebfe; dk 9; dc")  # ebfe is infinite loop
actual += rzp.cmd("")
if expected in actual or "Process exited with status=0x9" in actual:
    sys.stderr.write(expected + "\n")
else:
    sys.stderr.write(actual)
