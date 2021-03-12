#!/usr/bin/env python3


import sys
sys.path.append('../build/bindings')
import rz_core as rz

if 1:
    core = rz.rz_core_t('/bin/ls')
else:
    # Use it like rzpipe
    core = rz.RZ()
    core.cmd('e io.cache=true')
    core.cmd('wx 90')
    print(core.cmd('pd 1').strip())
    print(core.cmdj('pdj 1')[0]['opcode'])

    # Use the actual API
    core = rz.RZ('/bin/ls')


