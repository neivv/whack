nasm -o large_x86_64.o -f elf64 large_x86_64.asm
gcc -L. cfile.c large_x86_64.o -shared -o test_large_x86_64.dll
del large_x86_64.o
