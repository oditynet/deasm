nasm -f elf64 -o 1.o 1.asm
ld -o 1 1.o
rm 1.o


gcc deasm.c -o deasm

cat 1.asm
./deasm 1