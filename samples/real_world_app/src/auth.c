#include <stdio.h>
#include <string.h>
#include "auth.h"
#include "crypto.h"

int authenticate_user(const char *user_input, session_t *session) {
    char temp_buf[32];

    // Unbounded string copy vulnerability (Stack Buffer Overflow)
    strcpy(temp_buf, user_input);

    if (strcmp(temp_buf, "ADMIN_SECRET_KEY") == 0) {
        session->is_admin = 1;
        strcpy(session->username, "admin");
        return 1;
    }

    session->is_admin = 0;
    strncpy(session->username, temp_buf, sizeof(session->username) - 1);
    return 0;
}
