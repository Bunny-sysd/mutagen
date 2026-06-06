/*
 * TARGET 01: BUFFER OVERFLOW (CWE-120)
 * ======================================
 * CVE Examples: CVE-2021-3156 (sudo), CVE-2014-0160 (Heartbleed concept)
 *
 * WHAT IS A BUFFER OVERFLOW?
 * A buffer is a fixed-size chunk of memory. If you write more data
 * into it than it can hold, the extra bytes "overflow" into adjacent
 * memory — overwriting return addresses, function pointers, or other
 * critical data. This is the #1 most exploited vulnerability class
 * in the history of computing.
 *
 * WHY IS strcpy() DANGEROUS?
 * strcpy() copies bytes until it hits a null terminator (\0).
 * It has NO idea how big the destination buffer is. If the source
 * string is longer than the buffer, it just keeps writing past
 * the end — corrupting the stack.
 *
 * REAL-WORLD IMPACT:
 * - Code execution (attacker overwrites return address)
 * - Privilege escalation (sudo CVE-2021-3156)
 * - Remote code execution (Morris Worm, 1988)
 */

#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[32];  // Only 32 bytes!
    
    // VULNERABLE: No bounds checking!
    strcpy(buffer, input);
    
    printf("Processed: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}
