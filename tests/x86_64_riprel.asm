; nasm -f bin tests/x86_64_riprel.asm -o tests/x86_64_riprel.bin

bits 64
default rel

base:
; Func count
dd (get_ref - base - 8) / 4
; Func offsets
dd get_ref - base
dd cmp_nonzero - base
dd cmp_nonzero_byte - base
dd read_value - base
dd write_value - base
dd indirected_read - base

align 16
get_ref:
lea rax, [global_var]
ret

align 16
cmp_nonzero:
cmp dword [global_var], 0
mov eax, 0
setne al
ret

align 16
cmp_nonzero_byte:
cmp byte [global_var], 0
mov eax, 0
setne al
ret

align 16
read_value:
mov eax, [global_var]
ret

align 16
write_value:
mov [global_var], ecx
ret

align 16
indirected_read:
call read_value
ret

align 16
global_var:
dd 0

align 16
