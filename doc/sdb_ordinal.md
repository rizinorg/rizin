# Cannot find R2PATH/format/dll/DLLNAME.sdb

1. Execute `rz_bin -rs DLLNAME.dll | grep -i DLLNAME | grep -v Ordi |grep ^k| cut -d / -f 4- > DLLNAME.sdb.txt` 
2. Upload file `DLLNAME.sdb.txt` in https://github.com/rizinorg/rizin/tree/master/librz/bin/d/dll
3. Change the following [Makefile](https://github.com/rizinorg/rizin/blob/master/librz/bin/d/Makefile#L14)
4. Create a Pull Request to Master
