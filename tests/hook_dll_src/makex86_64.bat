rustup run nightly-x86_64 rustc rustfile.rs -O --crate-type=staticlib
nasm -o x86_64.o -f elf64 asmx86_64.asm
gcc -L. cfile.c x86_64.o -lrustfile -shared -o test_x86_64.dll
del x86_64.o
del rustfile.lib
