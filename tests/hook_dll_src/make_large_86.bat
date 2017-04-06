nasm -o large_x86.o -f elf32 large_x86.asm
gcc -L. cfile.c large_x86.o -shared -o test_large_x86.dll
del large_x86.o
