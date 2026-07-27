#include <stdio.h>
#include <string.h>
#include "crypto.h"

void hash_password(const char *input, char *output_buffer) {
    size_t len = strlen(input);
    for (size_t i = 0; i < len && i < 64; i++) {
        output_buffer[i] = input[i] ^ 0x5A;
    }
    output_buffer[len < 64 ? len : 63] = '\0';
}
