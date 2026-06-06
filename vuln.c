#include <stdio.h>
#include <string.h>

// A purposely vulnerable program for our fuzzer to test.
void vulnerable_function(char *input) {
    // A tiny buffer. Anything larger than 32 bytes will crash the program!
    char buffer[32];
    
    // strcpy is dangerous because it doesn't check the length of the input.
    // It will happily copy 100 bytes into a 32-byte buffer, corrupting memory.
    strcpy(buffer, input);
    
    printf("Input successfully processed: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    // Ensure the user actually passed an argument
    if (argc < 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        return 1;
    }

    // Pass the command-line argument to the vulnerable function
    vulnerable_function(argv[1]);
    
    return 0;
}
