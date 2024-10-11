import rzpipe
import sys

rzp = rzpipe.open("bins/elf/analysis/calls_x64", flags=["-a", "x86", "-d", "-1"])
rzp.cmd("")  # Eat "PID ?? started" banner
expected = "child received signal 9"
# ebfe is infinite loop
actual = rzp.cmd("wx ebfe; dk 9; dc")
if expected in actual or "Process exited with status=0x9" in actual:
    sys.stderr.write(expected + "\n")
else:
    sys.stderr.write(actual)
