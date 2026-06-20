/*
 * TARGET 14: TYPE CONFUSION IN DYNAMIC VARIANT RECORD (CWE-843)
 * ==============================================================
 * Simulating a modern memory-optimized engine where type transitions
 * can be triggered via sequential actions.
 *
 * THE VULNERABILITY:
 *   An object stores data in a union to optimize heap usage. 
 *   The union holds either raw strings or a structured execution callback.
 *   If we can write a raw string (which overlaps with the callback's function pointer)
 *   and then transition the type state to EXECUTABLE without re-initializing the
 *   function pointer, executing the callback triggers control flow hijacking (RCE/crash).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    VAL_INTEGER = 0,
    VAL_STRING = 1,
    VAL_EXECUTABLE = 2
} ValueType;

typedef struct {
    void (*run)(const char *);
    char context[32];
} ExecutableField;

typedef struct {
    ValueType type;
    union {
        long long integer_val;
        char string_val[40];
        ExecutableField exec_val;
    } payload;
} DataNode;

void safe_execute(const char *ctx) {
    printf("[+] Safe execution handler: %s\n", ctx);
}

DataNode g_node;

void init_node() {
    g_node.type = VAL_INTEGER;
    g_node.payload.integer_val = 0;
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 4) {
        printf("Usage: %s <action1> <val1> <action2>\n", argv[0]);
        printf("  action1: set_int, set_str\n");
        printf("  action2: switch_exec, run\n");
        return 1;
    }

    init_node();

    char *action1 = argv[1];
    char *val1 = argv[2];
    char *action2 = argv[3];

    // First action
    if (strcmp(action1, "set_int") == 0) {
        g_node.type = VAL_INTEGER;
        g_node.payload.integer_val = atoll(val1);
        printf("[+] Node initialized to Integer: %lld\n", g_node.payload.integer_val);
    } else if (strcmp(action1, "set_str") == 0) {
        g_node.type = VAL_STRING;
        // Copy input string into string_val
        strncpy(g_node.payload.string_val, val1, 39);
        g_node.payload.string_val[39] = '\0';
        printf("[+] Node initialized to String: %s\n", g_node.payload.string_val);
    } else {
        printf("[-] Unknown action1: %s\n", action1);
        return 1;
    }

    // Second action
    if (strcmp(action2, "switch_exec") == 0) {
        // VULNERABILITY: Type Confusion (CWE-843)
        // We switch the type to VAL_EXECUTABLE but DO NOT re-initialize the function pointer!
        // The data in the union remains unchanged. If we previously set a string, 
        // the first 8 bytes of that string now occupy the function pointer slot!
        g_node.type = VAL_EXECUTABLE;
        printf("[!] Node state switched to EXECUTABLE without re-initialization!\n");
        
        // Execute it immediately if switched
        printf("[!] Invoking handler...\n");
        if (g_node.payload.exec_val.run) {
            g_node.payload.exec_val.run(g_node.payload.exec_val.context);
        }
    } else if (strcmp(action2, "run") == 0) {
        if (g_node.type == VAL_EXECUTABLE) {
            printf("[+] Invoking handler...\n");
            g_node.payload.exec_val.run(g_node.payload.exec_val.context);
        } else {
            printf("[-] Node is not executable (current type: %d)\n", g_node.type);
        }
    } else {
        printf("[-] Unknown action2: %s\n", action2);
        return 1;
    }

    return 0;
}
