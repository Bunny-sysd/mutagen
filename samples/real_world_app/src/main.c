#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "auth.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <payload>\n", argv[0]);
        return 1;
    }

    session_t user_session;
    memset(&user_session, 0, sizeof(session_t));

    int res = authenticate_user(argv[1], &user_session);
    if (res) {
        printf("Access Granted: Admin Session Established!\n");
    } else {
        printf("Access Denied for user: %s\n", user_session.username);
    }

    return 0;
}
