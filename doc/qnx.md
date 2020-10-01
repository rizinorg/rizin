r2 on android
=============

```
. ./bbndk-env.sh
cd ~/rizin
rm -f plugins.cfg
./configure --with-compiler=qnx --with-ostype=qnx --prefix=/accounts/devuser/rizin --without-pic --with-nonpic
make -j 4
```

