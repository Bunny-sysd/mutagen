
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "crash") == 0) {
        char *ptr = NULL;
        *ptr = 'A'; // Cause access violation
    }
    printf("Safe\n");
    return 0;
}
