import rzpipe

r2 = rzpipe.open()
r2.cmd("aa")
print("\nFunction names:")
for func in r2.cmdj("aflj"):
    print(func["name"])
print("\nDisassembly of entry0:")
print(r2.cmd("pdf"))
