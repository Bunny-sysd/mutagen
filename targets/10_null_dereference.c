/*
 * TARGET 10: NULL POINTER DEREFERENCE (CWE-476)
 *
 * This program parses structured command input. If the user passes a command
 * to "admin" action without first supplying a valid auth token, it attempts
 * to access members of an uninitialized configuration struct (NULL pointer),
 * crashing the application.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char username[32];
    int access_level;
} UserConfig;

void handle_admin_action(UserConfig *config, const char *action) {
    printf("[*] Executing admin action: %s\n", action);
    // VULNERABILITY: Dereferencing config without checking if it is NULL!
    if (config->access_level > 5) {
        printf("[+] Admin access granted for username: %s\n", config->username);
    } else {
        printf("[-] Access level too low.\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <auth_status> <action_name>\n", argv[0]);
        return 1;
    }

    UserConfig *current_config = NULL;

    // Simulate authentication logic
    if (strcmp(argv[1], "authenticated") == 0) {
        current_config = (UserConfig *)malloc(sizeof(UserConfig));
        if (current_config) {
            strcpy(current_config->username, "root");
            current_config->access_level = 10;
        }
    }

    // Attempting admin action
    handle_admin_action(current_config, argv[2]);

    if (current_config) {
        free(current_config);
    }

    return 0;
}
