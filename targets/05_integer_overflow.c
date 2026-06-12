/*
 * TARGET 05: INTEGER OVERFLOW TO HEAP CORRUPTION
 * 
 * This simulates a program that allocates memory based on user-supplied
 * dimensions (e.g., an image parser taking width and height, or a data 
 * structure taking count and size).
 * 
 * If count * size exceeds the maximum size of a 32-bit unsigned integer,
 * it wraps around to a very small number. malloc() allocates a tiny buffer, 
 * but the subsequent loop writes past the end of it, corrupting the heap.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_data(size_t count, size_t size) {
    // VULNERABILITY: Integer Overflow
    // Forcing 32-bit math to guarantee overflow behavior across compilers
    unsigned int total_size = (unsigned int)count * (unsigned int)size;
    
    printf("Requested: %u items of size %u\n", (unsigned int)count, (unsigned int)size);
    printf("Allocating total size: %u bytes\n", total_size);

    // If total_size wrapped around (e.g. 1073741824 * 5 = 1073741824), 
    // it allocates a much smaller buffer than required!
    char *buffer = (char *)malloc(total_size);
    if (!buffer) {
        printf("Failed to allocate memory.\n");
        return;
    }

    // THE MASSIVE WRITE
    // The program still thinks it has 'count' items to process.
    // This loop will write 'count' times, moving 'size' bytes forward each time.
    // If an overflow happened, we write waaaay past the end of the heap buffer.
    
    printf("Writing data to buffer...\n");
    size_t i;
    for (i = 0; i < count; i++) {
        // Write 'size' bytes for each item
        memset(buffer + (i * size), 'A', size);
    }

    printf("Processing complete!\n");
    free(buffer);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <count> <size>\n", argv[0]);
        return 1;
    }

    // Convert arguments to unsigned integers
    unsigned long count = strtoul(argv[1], NULL, 10);
    unsigned long size = strtoul(argv[2], NULL, 10);

    process_data((size_t)count, (size_t)size);

    return 0;
}
