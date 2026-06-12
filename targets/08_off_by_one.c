/*
 * TARGET 08: OFF-BY-ONE
 * 
 * This program demonstrates a classic off-by-one vulnerability in a loop
 * condition. By writing exactly one byte past the buffer, the attacker
 * can alter an adjacent control variable.
 */

#include <stdio.h>
#include <string.h>

void authenticate(const char *input) {
    // Memory layout: `is_admin` is typically placed adjacent to `buffer`.
    // An off-by-one write to `buffer` can overwrite the LSB of `is_admin`.
    int is_admin = 0;
    char buffer[16];

    printf("Checking password length...\n");
    
    int len = strlen(input);
    
    // VULNERABILITY: The condition `i <= 16` means it will write 17 bytes (0 to 16).
    // This allows an off-by-one overwrite.
    for (int i = 0; i <= 16; i++) {
        if (i < len) {
            buffer[i] = input[i];
        } else {
            buffer[i] = '\0';
        }
    }

    if (strcmp(buffer, "supersecret") == 0) {
        printf("Password correct.\n");
        is_admin = 1;
    } else {
        printf("Password incorrect.\n");
    }

    if (is_admin) {
        printf("ACCESS GRANTED: Admin privileges acquired!\n");
        // Simulated crash to prove we gained control
        int *ptr = NULL;
        *ptr = 1; 
    } else {
        printf("Access denied.\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }

    authenticate(argv[1]);

    return 0;
}
