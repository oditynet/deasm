#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include <stdbool.h>
#include <string.h>

size_t ind = 0;
typedef struct {
    bool pf;
    bool _0f;
    bool po;
    bool so;
    bool flda;
    bool or;
} ADC;

// Упрощённый дизассемблер для нескольких инструкций x86
void disassemble(const uint8_t *code, size_t size,size_t ind) {
    size_t i = 0;
//    ADC str = {false,false,false,false,false,false};
    while (i < size) {
        printf("0x%04lx: ", i+ind); // Выводим смещение
        
        //uint8_t prefix = 0;
/*        while (i < size && (code[i] == 0x66 || code[i] == 0x67 || code[i] == 0xF0 || code[i] == 0xF2 || code[i] == 0xF3  || code[i] == 0x2E || code[i] == 0x36 || code[i] == 0x3E
                            code[i] == 0x26 || code[i] == 0x64 || code[i] == 0x65 )) {
            //prefix = code[i];
              switch (code[i]) {
                case 0xF0: prefixes.has_lock = true; break;
                case 0xF2: prefixes.has_repne = true; break;
                case 0xF3: prefixes.has_repe = true; break;
                case 0x66: prefixes.operand_size = true; break;
                case 0x67: prefixes.address_size = true; break;
            }
            printf("%02X prefix", prefix);
            i++;
        }
*/        // Читаем опкод
        uint8_t opcode = code[i];
        switch (opcode) {
            // INT
            case 0xF3:
                if (i + 1 < size && code[i + 1] == 0x0F && code[i + 2] == 0x1E && code[i + 3] == 0xFA) {
                    printf("F3 0F 1E FA          endbr64\n");
                    i += 4;
                } else {
                    printf("%02X                   db 0x%02X\n", opcode, opcode);
                    i += 1;
                }
                break;

            case 0x48:
                if (i + 1 < size && code[i + 1] == 0x83 && code[i + 2] == 0xEC && code[i + 3] == 0x08) {
                    printf("48 83 EC 08          sub rsp, 8\n");
                    i += 4;
                } else {
                    printf("%02X                   db 0x%02X\n", opcode, opcode);
                    i += 1;
                }
                break;
            
            //INT
            case 0xCD: // MOV r/m8, r8
        	if (code[i + 1] == 0X80)
        	    printf("INT %02x                               ;(Syscall) Video Graphics Character Table\n", code[i + 1]);
        	else
            	    printf("INT %02x                \n", code[i + 1]);
                i += 2;
                break;
            //INT3
            case 0xCC: // MOV r/m8, r8
                printf("INT3 %02x                int %02x\n", code[i + 1]);
                i += 2;
                break;
            // MOV
            case 0x88: // MOV r/m8, r8
                printf("88 %02x                mov [r/m8], r8\n", code[i + 1]);
                i += 2;
                break;
            case 0x89: // MOV r/m32, r32
                printf("89 %02x                mov [r/m32], r32\n", code[i + 1]);
                i += 2;
                break;
            case 0x8A: // MOV r8, r/m8
                printf("8A %02x                mov r8, [r/m8]\n", code[i + 1]);
                i += 2;
                break;
            case 0x8B: // MOV r32, r/m32
                printf("8B %02x                mov r32, [r/m32]\n", code[i + 1]);
                i += 2;
                break;
            case 0xB0 ... 0xB7: // MOV r8, imm8
                printf("%02x %02x                mov %s, 0x%02x\n", opcode, code[i + 1],
                       (opcode == 0xB0) ? "al" : (opcode == 0xB1) ? "cl" :
                       (opcode == 0xB2) ? "dl" : (opcode == 0xB3) ? "bl" :
                       (opcode == 0xB4) ? "ah" : (opcode == 0xB5) ? "ch" :
                       (opcode == 0xB6) ? "dh" : "bh", code[i + 1]);
                i += 2;
                break;
            case 0xB8 ... 0xBF: // MOV r32, imm32
                printf("%02x %02x %02x %02x %02x     mov %s, 0x%08x\n", opcode, code[i + 1], code[i + 2], code[i + 3], code[i + 4],
                       (opcode == 0xB8) ? "eax" : (opcode == 0xB9) ? "ecx" :
                       (opcode == 0xBA) ? "edx" : (opcode == 0xBB) ? "ebx" :
                       (opcode == 0xBC) ? "esp" : (opcode == 0xBD) ? "ebp" :
                       (opcode == 0xBE) ? "esi" : "edi",
                       *(uint32_t *)(code + i + 1));
                i += 5;
                break;

            // Арифметические инструкции
            case 0x01: // ADD r/m32, r32
                printf("01 %02x                add [r/m32], r32\n", code[i + 1]);
                i += 2;
                break;
            case 0x03: // ADD r32, r/m32
                printf("03 %02x                add r32, [r/m32]\n", code[i + 1]);
                i += 2;
                break;
            case 0x29: // SUB r/m32, r32
                printf("29 %02x                sub [r/m32], r32\n", code[i + 1]);
                i += 2;
                break;
            case 0x2B: // SUB r32, r/m32
                printf("2B %02x                sub r32, [r/m32]\n", code[i + 1]);
                i += 2;
                break;
            case 0x31: // XOR r/m32, r32
                printf("31 %02x                xor [r/m32], r32\n", code[i + 1]);
                i += 2;
                break;
            case 0x33: // XOR r32, r/m32
                printf("33 %02x                xor r32, [r/m32]\n", code[i + 1]);
                i += 2;
                break;

            // Инструкции управления потоком
            case 0x74: // JE rel8
                printf("74 %02x                je 0x%04lx\n", code[i + 1], i + 2 + (int8_t)code[i + 1]);
                i += 2;
                break;
            case 0x75: // JNE rel8
                printf("75 %02x                jne 0x%04lx\n", code[i + 1], i + 2 + (int8_t)code[i + 1]);
                i += 2;
                break;
            case 0xEB: // JMP rel8
                printf("EB %02x                jmp 0x%04lx\n", code[i + 1], i + 2 + (int8_t)code[i + 1]);
                i += 2;
                break;
            case 0xE8: // CALL rel32
                printf("E8 %02x %02x %02x %02x     call 0x%04lx\n", code[i + 1], code[i + 2], code[i + 3], code[i + 4],
                       i + 5 + *(int32_t *)(code + i + 1));
                i += 5;
                break;
            case 0xC3: // RET
                printf("C3                   ret\n");
                i += 1;
                break;

            // Другие популярные инструкции
            case 0x50 ... 0x57: // PUSH r32
                printf("%02x                   push %s\n", opcode,
                       (opcode == 0x50) ? "eax" : (opcode == 0x51) ? "ecx" :
                       (opcode == 0x52) ? "edx" : (opcode == 0x53) ? "ebx" :
                       (opcode == 0x54) ? "esp" : (opcode == 0x55) ? "ebp" :
                       (opcode == 0x56) ? "esi" : "edi");
                i += 1;
                break;
            case 0x58 ... 0x5F: // POP r32
                printf("%02x                   pop %s\n", opcode,
                       (opcode == 0x58) ? "eax" : (opcode == 0x59) ? "ecx" :
                       (opcode == 0x5A) ? "edx" : (opcode == 0x5B) ? "ebx" :
                       (opcode == 0x5C) ? "esp" : (opcode == 0x5D) ? "ebp" :
                       (opcode == 0x5E) ? "esi" : "edi");
                i += 1;
                break;

            // Обработка неизвестных инструкций
            default:
                printf("%02x                   db 0x%02x\n", opcode, opcode);
                i += 1;
                break;
        }
    }
}

size_t print_strings(const char *data, size_t size, size_t ind) {
    size_t k = ind; //=0;
    printf("0x%04lx: ", k); // Выводим смещение
    for (size_t i = 0; i < size; i++) {
	if (data[i] == '\0' && data[i+1] == '\0' ) { //удаляем пустые строки подряд идущие
	    i+=1;continue;
	}
        if (data[i] == '\0' && i != 0) { //удалить первый пробел
            // Конец строки
            printf("\n");
            if (i+1 < size)
              printf("0x%04lx: ", k); // Выводим смещение
        } else if (data[i] >= 32 && data[i] <= 126) {
            // Печатаем только печатные символы
            printf("%c", data[i]);
            k++;
        }
        else {
        printf("\\%02x", data[i]);
            k++;
        }
    }
    return k;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Использование: %s <elf-файл>\n", argv[0]);
        return 1;
    }
    ind = 0;
    // Открываем файл
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("Ошибка открытия файла");
        return 1;
    }

    // Получаем размер файла
    off_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    // Отображаем файл в память
    void *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        perror("Ошибка mmap");
        close(fd);
        return 1;
    }

    // Проверяем, что это ELF файл
    Elf64_Ehdr *header = (Elf64_Ehdr *)data;
    if (header->e_ident[EI_MAG0] != ELFMAG0 ||
        header->e_ident[EI_MAG1] != ELFMAG1 ||
        header->e_ident[EI_MAG2] != ELFMAG2 ||
        header->e_ident[EI_MAG3] != ELFMAG3) {
        fprintf(stderr, "Это не ELF файл\n");
        munmap(data, size);
        close(fd);
        return 1;
    }

    // Находим секцию .text
    Elf64_Shdr *shdr = (Elf64_Shdr *)((char *)data + header->e_shoff);
    const char *shstrtab = (const char *)data + shdr[header->e_shstrndx].sh_offset;

    for (int i = 0; i < header->e_shnum; i++) {
	if ((unsigned long)shdr[i].sh_size == 0 || strcmp(shstrtab + shdr[i].sh_name, ".shstrtab") == 0) continue;
        else if (strcmp(shstrtab + shdr[i].sh_name, ".strtab") == 0) {
            printf("\n     Секция .strtab (offset: %lx, size: %lx):\n", (unsigned long)shdr[i].sh_offset, (unsigned long)shdr[i].sh_size);
            ind = print_strings((const char *)data + shdr[i].sh_offset, shdr[i].sh_size,ind);
        }
        else if (strcmp(shstrtab + shdr[i].sh_name, ".data") == 0) {
            printf("\n     Секция .data (offset: %lx, size: %lx):\n", (unsigned long)shdr[i].sh_offset, (unsigned long)shdr[i].sh_size);
            ind = print_strings((const char *)data + shdr[i].sh_offset, shdr[i].sh_size,ind);
        }
        else if (strcmp(shstrtab + shdr[i].sh_name, ".bss") == 0) {
            printf("\n     Секция .bss (offset: %lx, size: %lx):\n", (unsigned long)shdr[i].sh_offset, (unsigned long)shdr[i].sh_size);
            ind = print_strings((const char *)data + shdr[i].sh_offset, shdr[i].sh_size,ind);
        }
        else{
            printf("\n     Секция %s (offset: %lx, size: %lx):\n", shstrtab + shdr[i].sh_name,(unsigned long)shdr[i].sh_offset, (unsigned long)shdr[i].sh_size);
            ind = print_strings((const char *)data + shdr[i].sh_offset, shdr[i].sh_size,ind);
        }
    }
    printf("\n");
    for (int i = 0; i < header->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_PROGBITS && (shdr[i].sh_flags & SHF_EXECINSTR)) {
            printf("\n     Disassembling section %s (offset: %lx, size: %lx):\n",
                   shstrtab + shdr[i].sh_name, (unsigned long)shdr[i].sh_offset, (unsigned long)shdr[i].sh_size);

            // Дизассемблируем код
            disassemble((unsigned char *)data + shdr[i].sh_offset, shdr[i].sh_size, ind);
        }
    }

    // Освобождаем ресурсы
    munmap(data, size);
    close(fd);
    return 0;
}
