
global _thirteen
_thirteen:
    xor eax, eax
    mov edx, 0xd
.loop:
    add eax, [esp + edx * 4]
    rol eax, 3
    sub eax, edx
    dec edx
    jne .loop
    ret

global _test_func
_test_func:
