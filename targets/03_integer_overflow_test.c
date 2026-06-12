#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_data(unsigned int count, unsigned int element_size) {
    unsigned int total_size = count * element_size;
    printf("Allocating %u bytes for %u elements of size %u\n", total_size, count, element_size);
    char *data = (char *)malloc(total_size);
    if (data == NULL) {
        printf("Allocation failed!\n");
        return;
    }
    printf("Writing data...\n");
    for (unsigned int i = 0; i < count; i++) {
        memset(&data[i * element_size], 'A', element_size);
    }
    printf("Success!\n");
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        return 1;
    }
    process_data(atoi(argv[1]), atoi(argv[2]));
    return 0;
}
