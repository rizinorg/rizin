import json

import rzpipe


def chk(x):
    if x[1]["opcode"] == "svc 0x80":
        name = x[0]["flags"][0][8:]
        sysnum = int(x[0]["opcode"].split(" ")[2], 16)
        print("%d\t%s" % (sysnum, name))


dev_pid = "23f88587e12c30376f8ab0b05236798fdfa4e853/4903"

rz = rzpipe.open("frida://" + dev_pid)
print("Importing symbols from libSystem...")
rz.cmd(".=!i*")
rz.cmd(".=!ie* libSystem.B.dylib")
print("Finding syscalls...")
funcs = rz.cmd("pdj 2 @@f:sym.fun.*")

for doc in funcs.split("\n"):
    if len(doc) > 1:
        chk(json.loads(doc))
rz.quit()
print("Thanks for waiting")
