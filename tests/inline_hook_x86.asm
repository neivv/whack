; nasm -f bin inline_hook_x86.asm -o inline_hook_x86.bin
bits 32

dd hook_entry - func
dd hook_exit - func
dd func - func + 1

func:
nop
push ebp
mov ebp, esp
mov eax, [ebp + 0x8]
push esi
push edi
sub esp, 0x50
mov esi, [ebp + 0xc]
mov ecx, [ebp + 0x10]
add eax, esi
add eax, eax
xor eax, 0x50
mov [esp + 0x2c], eax
hook_entry:
mov edi, [esp + 0x2c]
add eax, edi
mov edx, eax
sub eax, 0x777
cmp eax, edx
ja .overflow
mov dword [ecx + 0x4], 0
jmp .cont
.overflow:
mov dword [ecx + 0x4], 1
.cont:
mov [ecx], eax
hook_exit:
add esi, 6
mov eax, esi
add esp, 0x50
pop edi
pop esi
pop ebp
ret
