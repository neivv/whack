
global asm_reg_args_h
asm_reg_args_h:
    push rsi
    push rdi
    push rbx
    mov rsi, r8
    mov rbx, rcx
    mov rdi, rdx
    call asm_reg_args
    pop rbx
    pop rdi
    pop rsi
    ret

global asm_reg_args
asm_reg_args:
    mov rax, rbx
    mov rcx, rdi
    add ecx, esi
    shl eax, 3
    sub eax, ecx
    ret

global asm_reg_stack_args_h
asm_reg_stack_args_h:
    push rsi
    push rdi
    push rbx
    push r15
    mov rsi, r9
    mov rbx, rcx
    mov rdi, rdx
    mov r15, r8
    push rsi
    mov rsi, [rsp + 0x50]
    call asm_reg_stack_args
    pop rsi
    pop r15
    pop rbx
    pop rdi
    pop rsi
    ret

global asm_reg_stack_args
asm_reg_stack_args:
    mov rax, rbx
    mov rcx, rdi
    mov rdx, r15
    add esi, [rsp + 8]
    add eax, edx
    imul esi
    sub eax, ecx
    ret
    
