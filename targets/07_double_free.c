/*
 * TARGET 07: DOUBLE FREE
 * 
 * This program allocates memory, processes data, and then has a complex 
 * logic path that causes the same pointer to be freed twice.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_data(int action_code, char *input_data) {
    char *buffer = (char *)malloc(128);
    if (!buffer) {
        printf("Memory error\n");
        return;
    }

    strncpy(buffer, input_data, 127);
    buffer[127] = '\0';
    
    printf("Processing: %s\n", buffer);

    if (action_code == 42) {
        printf("Action 42 executed. Cleaning up buffer early.\n");
        free(buffer);
        // VULNERABILITY: Pointer is not set to NULL after being freed.
    } else {
        printf("Standard action executed.\n");
    }

    // VULNERABILITY: If action_code was 42, this will be a double free!
    if (action_code >= 40) {
        printf("Finalizing cleanup...\n");
        free(buffer); 
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <action_code> <data>\n", argv[0]);
        return 1;
    }

    int code = atoi(argv[1]);
    process_data(code, argv[2]);

    return 0;
}
