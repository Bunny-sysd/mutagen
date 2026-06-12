/*
 * TARGET 06: COMPLEX LOGIC (EVOLUTIONARY FUZZING TEST)
 * 
 * The magic word is read from a secret file. The AI cannot guess it from the 
 * source code. It must learn it by reading the stdout error message.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(const char *input) {
    char buffer[32];
    printf("Access granted! Processing input...\n");
    // VULNERABILITY: Buffer overflow
    strcpy(buffer, input);
    printf("Data processed safely.\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <auth_token> <data>\n", argv[0]);
        return 1;
    }
    
    FILE *f = fopen("secret.txt", "r");
    if (!f) {
        printf("Error: Cannot find secret.txt\n");
        return 1;
    }
    char magic[32];
    if (fgets(magic, sizeof(magic), f) == NULL) {
        return 1;
    }
    fclose(f);
    
    // remove newline
    size_t len = strlen(magic);
    if (len > 0 && magic[len-1] == '\n') {
        magic[len-1] = '\0';
    }

    // The Fuzzer MUST guess this magic word from the stdout feedback!
    if (strcmp(argv[1], magic) != 0) {
        printf("Error: Authentication failed! Expected '%s'.\n", magic);
        return 1;
    }
    
    if (argc < 3) {
        printf("Error: Missing data payload.\n");
        return 1;
    }
    
    vulnerable_function(argv[2]);
    return 0;
}
