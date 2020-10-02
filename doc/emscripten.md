Building for the browser
========================

# Install emscripten:

    git clone git://github.com/kripken/emscripten.git
    export PATH=/path/to/emscripten:$PATH
    make clean


# Build radare

    sys/emscripten.sh


<!--

--- random notes ---

export CC="emcc --ignore-dynamic-linking"
./configure --prefix=/usr --disable-shared --enable-static --disable-debugger --with-compiler=emscripten --without-pic --with-nonpic
emmake make -j4 

cd binrz/rizin
 emcc ../../librz/*/*.o rizin.c -I ../../librz/include/ -DRZ_BIRTH=\"pop\" -DRZ_GITTIP=\"123\" ../../librz/db/sdb/src/*.o

binrz/rz_ax/rz_ax.js:

emcc -O2 rz_ax.o ../../librz/util/librz_util.a -o rz_ax.js

binrz/rz_asm/rz_asm.js:

emcc -O2  -L.. -o rz_asm.js   ../../shlr/sdb/src/libsdb.a -lm $A/util/librz_util.a $A/asm/librz_asm.a rz_asm.o ../../librz/util/librz_util.a  ../../librz/parse/librz_parse.a  ../../librz/db/libr_db.a ../../librz/syscall/librz_syscall.a  ../../librz/asm/librz_asm.a  ../../librz/lib/libr_lib.a ../../librz/db/libr_db.a ../../shlr/sdb/src/libsdb.a ../../librz/util/librz_util.a

-->
