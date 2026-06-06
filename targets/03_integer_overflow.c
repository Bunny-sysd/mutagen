/*
 * TARGET 03: INTEGER OVERFLOW (CWE-190)
 * ======================================
 * CVE Examples: CVE-2021-21224 (Chrome V8), CVE-2014-1266 (Apple SSL)
 *
 * WHAT IS AN INTEGER OVERFLOW?
 * Computers store integers in fixed-size containers:
 *   - unsigned int = 32 bits = max value 4,294,967,295
 *   - If you add 1 to the max value, it wraps around to 0!
 *   - If you multiply two large numbers, the result wraps around too
 *
 * WHY IS THIS DANGEROUS?
 * Integer overflows are sneaky. The math "works" (no crash), but
 * the RESULT is wrong. If that result is used to allocate memory
 * or check bounds, you get:
 *   - Tiny allocations for huge data (heap overflow)
 *   - Bounds checks that pass when they shouldn't
 *   - Buffer sizes that wrap to zero
 *
 * REAL-WORLD IMPACT:
 * - Chrome V8 engine exploits (CVE-2021-21224)
 * - iOS jailbreaks via integer overflow in kernel
 * - SSH buffer overflow via integer overflow (2002)
 *
 * THE SUBTLE PART:
 * Unlike buffer overflows (which crash immediately), integer overflows
 * cause WRONG CALCULATIONS that lead to crashes later. The AI needs
 * to understand the MATH, not just the memory layout.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// This function has an integer overflow that leads to a heap buffer overflow
void process_data(unsigned int count, unsigned int element_size) {
    // VULNERABLE: count * element_size can overflow!
    // Example: count=1073741824, element_size=8
    // Expected: 8,589,934,592 bytes
    // Actual (after overflow): 0 bytes! (wraps around)
    unsigned int total_size = count * element_size;
    
    printf("Allocating %u bytes for %u elements of size %u\n", 
           total_size, count, element_size);
    
    // malloc(0) returns a tiny (or NULL) pointer
    char *data = (char *)malloc(total_size);
    
    if (data == NULL) {
        printf("Allocation failed!\n");
        return;
    }
    
    // Now we try to write count * element_size bytes into a buffer
    // that's only total_size bytes (which could be 0 due to overflow!)
    // This causes a HEAP BUFFER OVERFLOW
    printf("Writing data...\n");
    memset(data, 'A', count * element_size);  // CRASH: writing way past allocation
    
    printf("Success!\n");
    free(data);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <count> <element_size>\n", argv[0]);
        printf("  Example: %s 100 4\n", argv[0]);
        return 1;
    }
    
    unsigned int count = (unsigned int)atoi(argv[1]);
    unsigned int elem_size = (unsigned int)atoi(argv[2]);
    
    // "Safety" check that doesn't account for overflow
    if (count > 0 && elem_size > 0) {
        process_data(count, elem_size);
    } else {
        printf("Invalid input: count and element_size must be positive\n");
    }
    
    return 0;
}
