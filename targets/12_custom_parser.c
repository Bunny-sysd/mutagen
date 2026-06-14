/*
 * TARGET 12: CUSTOM STATEFUL PARSER (CWE-191 / CWE-119)
 *
 * This program processes secure data packets passed via command-line arguments.
 * It requires authentication and structure validation before processing.
 *
 * Usage:
 *   12_custom_parser <magic> <auth_token> <length_str> <payload>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void store_in_vault(const char *payload, short length) {
    char vault_buffer[64];
    
    // VULNERABILITY: Signed comparison.
    // If length is negative (e.g. -1), length < 64 is true.
    if (length < 64) {
        printf("[*] Copying payload into vault buffer...\n");
        // VULNERABLE: memcpy takes size_t (unsigned).
        // A negative signed short converts to a huge unsigned value, causing a crash.
        memcpy(vault_buffer, payload, length);
        printf("[+] Data saved: %s\n", vault_buffer);
    } else {
        printf("[-] Rejecting: Payload too large for vault buffer.\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("Usage: %s <magic> <auth_token> <length> <payload>\n", argv[0]);
        return 1;
    }
    
    char *magic = argv[1];
    char *auth_token = argv[2];
    char *length_str = argv[3];
    char *payload = argv[4];
    
    // Step 1: Validate magic prefix
    if (strcmp(magic, "MTGN") != 0) {
        printf("[-] Access Denied: Invalid magic protocol identifier.\n");
        return 1;
    }
    
    // Step 2: Validate authentication token
    if (strcmp(auth_token, "SecretPass42") != 0) {
        printf("[-] Access Denied: Authentication failed.\n");
        return 1;
    }
    
    // Step 3: Parse length as signed short
    short length = (short)atoi(length_str);
    
    printf("[+] Auth successful. Parsing payload of length %d...\n", length);
    store_in_vault(payload, length);
    
    return 0;
}
