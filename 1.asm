section .text
global _start

%define system_call int 0x80

_start:
    mov ebx, 0x1
    mov ecx, hello
    mov edx, helloLen
    mov eax, 0x4
    system_call

    xor ebx, ebx
    mov eax, 0x1
    system_call

section .data
    hello db "1234567890", 0xa
    helloLen equ $-hello
