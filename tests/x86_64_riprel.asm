; nasm -f bin tests/x86_64_riprel.asm -o tests/x86_64_riprel.bin

bits 64
default rel

base:
; Func count
dd (funcs_end - base - 4) / 4
; Func offsets
dd get_ref - base
dd cmp_nonzero - base
dd cmp_nonzero_byte - base
dd read_value - base
dd write_value - base
dd indirected_read - base
dd early_short_jmp - base
dd early_short_jmp_twice - base
dd with_stack_frame_entry
dd with_stack_frame_hook_point

funcs_end:

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
early_short_jmp:
test ecx, ecx
je .end
add edx, edx
movzx ecx, cx
imul edx, ecx
call read_value
sub edx, eax
.end:
mov eax, edx
ret

align 16
early_short_jmp_twice:
test ecx, ecx
je .end
js .end
jmp .next
.next:
add edx, edx
movzx ecx, cx
imul edx, ecx
call read_value
sub edx, eax
.end:
mov eax, edx
ret

align 16
with_stack_frame_entry:
push rbx
push r14
sub rsp, 0x88
add rcx, rcx
sub rcx, rdx
add rdx, 0x5000
mov rax, rdx
with_stack_frame_hook_point:
test rcx, rcx
jne .end
sub rax, 0x300
.end:
add rsp, 0x88
pop r14
pop rbx
ret

align 16
global_var:
dd 0

align 16
