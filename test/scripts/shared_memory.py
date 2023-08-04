#!/usr/bin/env python3

from multiprocessing import shared_memory

import rzpipe

FILENAMES = ["bins/elf/_Exit (42)", "bins/pe/winver.exe", "bins/mach0/mach0_2-x86_64"]

for fname in FILENAMES:
    with open(fname, "rb") as f:
        data = f.read()
        data_size = len(data)
        shm = shared_memory.SharedMemory(create=True, size=data_size)
        print("Copying %s..." % fname)
        shm.buf[:data_size] = data[:]
        print("Copied %s succesfully" % fname)
        print("-------------")
        print("Shared buffer size 0x{0:x}".format(data_size))
        print("-------------")

        rzp = rzpipe.open("shm://{0:s}/{1:d}".format(shm.name, data_size), flags=["-N"])
        rzp.cmd("e scr.color=0")
        rzp.cmd("e scr.utf8=false")
        rzp.cmd("e scr.interactive=false")
        infoj = rzp.cmdj("ij")
        print(infoj["bin"])
        print(rzp.cmd("px 16"))
        rzp.cmd("aaa")
        print(rzp.cmd("afl"))
        print(rzp.cmd("pdf @ entry0"))
        rzp.quit()
        shm.close()
        shm.unlink()
