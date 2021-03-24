#!/usr/bin/env python3


import sys
sys.path.append('../build/bindings')
import rz_core as rizin

# Use it like rzpipe
core = rizin.RZ()               # TODO: Rename RZ() to open_file?
core.cmd('e io.cache=true')
core.cmd('wx 90')
print(core.cmd('pd 1').strip())
print(core.cmdj('pdj 1')[0]['opcode'])

# Use the actual bindings and API
core = rizin.RZ('/bin/ls')
sections = core.get_sections()
for i in range(len(sections)):
    print('section {:02d} {:s}'.format(i, sections[i].name))


