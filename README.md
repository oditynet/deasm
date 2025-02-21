# deasm
Моя реализация дизассемблера. Читаем и вникаем https://moss.cs.iit.edu/cs450/etc/325383-sdm-vol-2abcd.pdf

Файл исходника asm
```
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
```

Вывод программы. Похож с исходником?
```
     Секция .data (offset: 2000, size: b):
0x0011: 1234567890\0a
     Секция .strtab (offset: 20d0, size: 2e):
0x003f: \001.asm
0x0045: hello
0x004a: helloLen
0x0052: __bss_start
0x005d: _edata
0x0063: _end

     Disassembling section .text (offset: 1000, size: 1f):
0x0067: bb 01 00 00 00     mov ebx, 0x00000001
0x006c: b9 00 20 40 00     mov ecx, 0x00402000
0x0071: ba 0b 00 00 00     mov edx, 0x0000000b
0x0076: b8 04 00 00 00     mov eax, 0x00000004
0x007b: INT 80                               ;(Syscall) Video Graphics Character Table
0x007d: 31 db                xor [r/m32], r32
0x007f: b8 01 00 00 00     mov eax, 0x00000001
0x0084: INT 80                               ;(Syscall) Video Graphics Character Table
```
