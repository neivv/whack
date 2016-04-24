rustup run nightly-i686 rustc rustfile.rs -O --crate-type=staticlib
nasm -o x86.o -f elf32 asmx86.asm
gcc -L. cfile.c x86.o -lrustfile -shared -o test_x86.dll
del x86.o
del rustfile.lib
