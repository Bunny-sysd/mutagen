#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VM_STACK_SIZE 32
#define VM_REGISTERS  8

typedef enum {
    OP_NOP   = 0,
    OP_PUSH  = 1,
    OP_POP   = 2,
    OP_ADD   = 3,
    OP_SUB   = 4,
    OP_LOAD  = 5,
    OP_STORE = 6,
    OP_RET   = 7
} OpCode;

typedef struct {
    int val;
} StackFrame;

typedef struct {
    void (*error_handler)(const char* msg);
    StackFrame stack[VM_STACK_SIZE];
    int sp; // stack pointer
    int registers[VM_REGISTERS];
    int ip; // instruction pointer
} VM;

void default_error_handler(const char* msg) {
    fprintf(stderr, "VM Error: %s\n", msg);
    exit(1);
}

void init_vm(VM* vm) {
    vm->sp = 0;
    vm->ip = 0;
    vm->error_handler = default_error_handler;
    memset(vm->registers, 0, sizeof(vm->registers));
}

void execute_vm(VM* vm, const unsigned char* bytecode, int size) {
    while (vm->ip < size) {
        unsigned char op = bytecode[vm->ip++];
        switch (op) {
            case OP_NOP:
                break;
            case OP_PUSH: {
                if (vm->ip >= size) {
                    vm->error_handler("Malformed bytecode: missing push value");
                    return;
                }
                int val = (char)bytecode[vm->ip++]; // read value
                if (vm->sp >= VM_STACK_SIZE) {
                    vm->error_handler("VM Stack Overflow");
                    return;
                }
                vm->stack[vm->sp++].val = val;
                break;
            }
            case OP_POP: {
                // Potential underflow if sp == 0
                vm->sp--;
                break;
            }
            case OP_ADD: {
                if (vm->sp < 2) {
                    vm->error_handler("VM Stack Underflow on ADD");
                    return;
                }
                int b = vm->stack[--vm->sp].val;
                int a = vm->stack[--vm->sp].val;
                vm->stack[vm->sp++].val = a + b;
                break;
            }
            case OP_LOAD: {
                // Load from register to stack
                if (vm->ip >= size) {
                    vm->error_handler("Malformed bytecode: missing load register");
                    return;
                }
                int reg_idx = (char)bytecode[vm->ip++];
                // VULNERABILITY: reg_idx is signed. A negative reg_idx (like -35) bypasses reg_idx < VM_REGISTERS check.
                if (reg_idx < VM_REGISTERS) {
                    if (vm->sp >= VM_STACK_SIZE) {
                        vm->error_handler("VM Stack Overflow");
                        return;
                    }
                    vm->stack[vm->sp++].val = vm->registers[reg_idx];
                } else {
                    vm->error_handler("Invalid register index");
                }
                break;
            }
            case OP_STORE: {
                // Store from stack to register
                if (vm->ip >= size) {
                    vm->error_handler("Malformed bytecode: missing store register");
                    return;
                }
                int reg_idx = (char)bytecode[vm->ip++];
                if (vm->sp <= 0) {
                    vm->error_handler("VM Stack Underflow on STORE");
                    return;
                }
                int val = vm->stack[--vm->sp].val;
                
                // VULNERABILITY: Signed index bypass.
                // A negative index (e.g. -35) allows overwriting memory behind vm->registers, 
                // including the error_handler function pointer (at registers[-35] on 32-bit/64-bit alignment offsets).
                if (reg_idx < VM_REGISTERS) {
                    vm->registers[reg_idx] = val;
                } else {
                    vm->error_handler("Invalid register index");
                }
                break;
            }
            case OP_RET:
                return;
            default:
                vm->error_handler("Unknown opcode");
                return;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <hex_bytecode>\n", argv[0]);
        return 0;
    }
    
    char* hex = argv[1];
    int len = strlen(hex);
    if (len % 2 != 0) {
        printf("Invalid hex length\n");
        return 1;
    }
    
    int byte_len = len / 2;
    unsigned char* bytecode = malloc(byte_len);
    if (!bytecode) return 1;
    
    for (int i = 0; i < byte_len; i++) {
        unsigned int b;
        sscanf(&hex[i * 2], "%2x", &b);
        bytecode[i] = (unsigned char)b;
    }
    
    VM vm;
    init_vm(&vm);
    execute_vm(&vm, bytecode, byte_len);
    
    free(bytecode);
    printf("Execution finished successfully.\n");
    return 0;
}
