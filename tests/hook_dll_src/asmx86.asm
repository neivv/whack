

global _asm_reg_args_h
_asm_reg_args_h:
    mov eax, [esp + 4]
    mov ecx, [esp + 8]
    push esi
    mov esi, [esp + 0x10]
    call _asm_reg_args
    pop esi
    ret
global _asm_reg_args
_asm_reg_args:
    add ecx, esi
    shl eax, 3
    sub eax, ecx
    ret

db '\x90\x90\x90\x90\x90\x90\x90'

global _asm_reg_stack_args_h
_asm_reg_stack_args_h:
    mov eax, [esp + 4]
    mov ecx, [esp + 8]
    mov edx, [esp + 0xc]
    push esi
    mov esi, [esp + 0x14]
    push esi
    mov esi, [esp + 0x1c]
    call _asm_reg_stack_args
    pop esi
    pop esi
    ret

global _asm_reg_stack_args
_asm_reg_stack_args:
    add esi, [esp + 4]
    add eax, edx
    imul esi
    sub eax, ecx
    ret
    
