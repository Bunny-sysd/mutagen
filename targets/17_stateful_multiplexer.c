#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handle_payload(const char *input) {
    char local_buf[16];
    strcpy(local_buf, input);
    printf("Processed: %s\n", local_buf);
}

int main() {
    char line[1024];
    int state = 0;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    while (fgets(line, sizeof(line), stdin)) {
        // Strip newline
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }

        if (state == 0) {
            if (strcmp(line, "HELO") == 0) {
                state = 1;
                printf("OK1\n");
            } else {
                state = 0;
                printf("ERR\n");
            }
        } else if (state == 1) {
            if (strcmp(line, "USER guest") == 0) {
                state = 2;
                printf("OK2\n");
            } else {
                state = 0;
                printf("ERR\n");
            }
        } else if (state == 2) {
            if (strcmp(line, "PASS AuthToken99!") == 0) {
                state = 3;
                printf("OK3\n");
            } else {
                state = 0;
                printf("ERR\n");
            }
        } else if (state == 3) {
            if (strncmp(line, "DATA ", 5) == 0) {
                handle_payload(line + 5);
            } else {
                state = 0;
                printf("ERR\n");
            }
        }
    }
    return 0;
}
