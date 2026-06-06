/*
 * TARGET 02: FORMAT STRING VULNERABILITY (CWE-134)
 * =================================================
 * CVE Examples: CVE-2012-0809 (sudo), CVE-2000-0573 (wu-ftpd)
 *
 * WHAT IS A FORMAT STRING BUG?
 * printf() and friends use "format specifiers" like %s, %d, %x to
 * know what arguments to expect on the stack. If an attacker controls
 * the format string itself, they can:
 *   - READ memory using %x (leak stack values)
 *   - WRITE memory using %n (write number of chars printed so far)
 *   - CRASH the program using %s (dereference arbitrary pointers)
 *
 * THE GOLDEN RULE:
 *   printf(user_input);     // VULNERABLE! User controls format string
 *   printf("%s", user_input); // SAFE! Format string is hardcoded
 *
 * WHY IS THIS DANGEROUS?
 * Format string bugs give attackers the ability to both READ and WRITE
 * arbitrary memory. This means they can:
 *   1. Leak ASLR addresses (bypassing memory protection)
 *   2. Overwrite the GOT (Global Offset Table) to hijack execution
 *   3. Crash the program (denial of service)
 *
 * REAL-WORLD IMPACT:
 * - Remote code execution in network daemons
 * - Privilege escalation in setuid programs
 * - Information disclosure (leaking secrets from memory)
 */

#include <stdio.h>
#include <string.h>

void log_message(char *msg) {
    char log_entry[256];
    snprintf(log_entry, sizeof(log_entry), msg);  // VULNERABLE: msg IS the format string!
    
    printf("LOG: ");
    printf(log_entry);  // DOUBLE VULNERABLE: log_entry used as format string again
    printf("\n");
}

void process_input(char *input) {
    char buffer[128];
    
    // Copy input (with bounds checking this time - the overflow isn't the bug here)
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    // The vulnerability is in HOW we print, not HOW we copy
    log_message(buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <message>\n", argv[0]);
        return 1;
    }
    
    printf("=== Secure Logger v2.1 ===\n");
    process_input(argv[1]);
    
    return 0;
}
