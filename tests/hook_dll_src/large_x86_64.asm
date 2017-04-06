
global thirteen
thirteen:
    xor rax, rax
    mov [rsp + 8], ecx
    mov [rsp + 0x10], edx
    mov [rsp + 0x18], r8d
    mov [rsp + 0x20], r9d
    mov rdx, 0xd
.loop:
    xor rcx, rcx
    mov ecx, [rsp + rdx * 8]
    add rax, rcx
    rol eax, 3
    sub rax, rdx
    dec rdx
    jne .loop
    mov edx, eax
    mov rax, rdx
    ret

global test_func
test_func:
nop
