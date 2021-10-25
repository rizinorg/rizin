import rzpipe

rzp = rzpipe.open()
rzp.cmd("aa")
print("\nFunction names:")
for func in rzp.cmdj("aflj"):
    print(func["name"])
print("\nDisassembly of entry0:")
print(rzp.cmd("pdf"))
